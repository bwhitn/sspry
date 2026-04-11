/// Appends a `usize` to an output buffer as a saturated little-endian `u32`.
///
/// Inputs:
/// - `out`: Destination byte buffer.
/// - `value`: Length-like value that must fit the on-wire `u32` encoding.
///
/// Output:
/// - Writes four bytes into `out`, saturating at `u32::MAX` on overflow.
fn push_u32_le(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(u32::try_from(value).unwrap_or(u32::MAX)).to_le_bytes());
}

/// Appends a `u64` to an output buffer using little-endian encoding.
///
/// Inputs:
/// - `out`: Destination byte buffer.
/// - `value`: Numeric value to encode.
///
/// Output:
/// - Writes eight bytes into `out`.
fn push_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Reads a single byte from a binary insert payload and advances the shared
/// offset.
///
/// Inputs:
/// - `payload`: Full binary row payload being decoded.
/// - `offset`: Current read cursor, updated in place on success.
/// - `field`: Field label used in truncation error messages.
///
/// Returns:
/// - The decoded byte for the requested field.
fn read_u8(payload: &[u8], offset: &mut usize, field: &str) -> Result<u8> {
    if payload.len().saturating_sub(*offset) < 1 {
        return Err(SspryError::from(format!(
            "{field} truncated while reading u8"
        )));
    }
    let value = payload[*offset];
    *offset += 1;
    Ok(value)
}

/// Reads a little-endian `u32` from a binary insert payload and advances the
/// shared offset.
///
/// Inputs:
/// - `payload`: Full binary row payload being decoded.
/// - `offset`: Current read cursor, updated in place on success.
/// - `field`: Field label used in truncation error messages.
///
/// Returns:
/// - The decoded `u32` value.
fn read_u32_le(payload: &[u8], offset: &mut usize, field: &str) -> Result<u32> {
    if payload.len().saturating_sub(*offset) < 4 {
        return Err(SspryError::from(format!(
            "{field} truncated while reading u32"
        )));
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&payload[*offset..*offset + 4]);
    *offset += 4;
    Ok(u32::from_le_bytes(bytes))
}

/// Reads a little-endian `u64` from a binary insert payload and advances the
/// shared offset.
///
/// Inputs:
/// - `payload`: Full binary row payload being decoded.
/// - `offset`: Current read cursor, updated in place on success.
/// - `field`: Field label used in truncation error messages.
///
/// Returns:
/// - The decoded `u64` value.
fn read_u64_le(payload: &[u8], offset: &mut usize, field: &str) -> Result<u64> {
    if payload.len().saturating_sub(*offset) < 8 {
        return Err(SspryError::from(format!(
            "{field} truncated while reading u64"
        )));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&payload[*offset..*offset + 8]);
    *offset += 8;
    Ok(u64::from_le_bytes(bytes))
}

/// Reads a fixed number of raw bytes from a binary insert payload and advances
/// the shared offset.
///
/// Inputs:
/// - `payload`: Full binary row payload being decoded.
/// - `offset`: Current read cursor, updated in place on success.
/// - `len`: Number of bytes to read.
/// - `field`: Field label used in truncation error messages.
///
/// Returns:
/// - A borrowed slice into `payload` covering the requested byte range.
fn read_exact_bytes<'a>(
    payload: &'a [u8],
    offset: &mut usize,
    len: usize,
    field: &str,
) -> Result<&'a [u8]> {
    if payload.len().saturating_sub(*offset) < len {
        return Err(SspryError::from(format!(
            "{field} truncated while reading {len} bytes"
        )));
    }
    let bytes = &payload[*offset..*offset + len];
    *offset += len;
    Ok(bytes)
}

/// Encodes one candidate document into the compact binary row format used by
/// remote `insert_batch` requests.
///
/// How it works:
/// - Writes fixed-size fields first so the decoder can jump to variable-length
///   payload sizes.
/// - Stores optional sections behind bit flags.
///
/// Inputs:
/// - `sha256`, `file_size`: Stable identity and size for the document.
/// - `bloom_item_estimate`, `bloom_filter`: Tier1 bloom metadata and payload.
/// - `tier2_bloom_item_estimate`, `tier2_bloom_filter`: Tier2 bloom metadata and payload.
/// - `special_population`: Whether the row belongs to a special precomputed population.
/// - `metadata`: Packed metadata sidecar bytes.
/// - `external_id`: Optional stored path or caller-provided external identifier.
///
/// Returns:
/// - The encoded binary row ready to concatenate into a request payload.
pub fn serialize_candidate_insert_binary_row_parts(
    sha256: &[u8; 32],
    file_size: u64,
    bloom_item_estimate: Option<usize>,
    bloom_filter: &[u8],
    tier2_bloom_item_estimate: Option<usize>,
    tier2_bloom_filter: &[u8],
    special_population: bool,
    metadata: &[u8],
    external_id: Option<&str>,
) -> Result<Vec<u8>> {
    let bloom_item_estimate_u64 = bloom_item_estimate
        .map(u64::try_from)
        .transpose()
        .map_err(|_| SspryError::from("bloom_item_estimate does not fit in u64"))?;
    let tier2_bloom_item_estimate_u64 = tier2_bloom_item_estimate
        .map(u64::try_from)
        .transpose()
        .map_err(|_| SspryError::from("tier2_bloom_item_estimate does not fit in u64"))?;
    let external_id_bytes = external_id.map(str::as_bytes).unwrap_or(&[]);
    for (label, len) in [
        ("bloom_filter", bloom_filter.len()),
        ("tier2_bloom_filter", tier2_bloom_filter.len()),
        ("metadata", metadata.len()),
        ("external_id", external_id_bytes.len()),
    ] {
        u32::try_from(len)
            .map_err(|_| SspryError::from(format!("{label} is too large for binary insert row")))?;
    }

    let mut flags = 0u8;
    if bloom_item_estimate_u64.is_some() {
        flags |= 1 << 0;
    }
    if tier2_bloom_item_estimate_u64.is_some() {
        flags |= 1 << 1;
    }
    if special_population {
        flags |= 1 << 2;
    }
    if !metadata.is_empty() {
        flags |= 1 << 3;
    }
    if !external_id_bytes.is_empty() {
        flags |= 1 << 4;
    }

    let mut row = Vec::with_capacity(
        32 + 8
            + 1
            + 8
            + 8
            + 4 * 4
            + bloom_filter.len()
            + tier2_bloom_filter.len()
            + metadata.len()
            + external_id_bytes.len(),
    );
    row.extend_from_slice(sha256);
    push_u64_le(&mut row, file_size);
    row.push(flags);
    push_u64_le(&mut row, bloom_item_estimate_u64.unwrap_or(0));
    push_u64_le(&mut row, tier2_bloom_item_estimate_u64.unwrap_or(0));
    push_u32_le(&mut row, bloom_filter.len());
    push_u32_le(&mut row, tier2_bloom_filter.len());
    push_u32_le(&mut row, metadata.len());
    push_u32_le(&mut row, external_id_bytes.len());
    row.extend_from_slice(bloom_filter);
    row.extend_from_slice(tier2_bloom_filter);
    row.extend_from_slice(metadata);
    row.extend_from_slice(external_id_bytes);
    Ok(row)
}

/// Decodes one candidate insert row from the custom binary wire format.
///
/// Inputs:
/// - `payload`: The row bytes to decode.
/// - `field_prefix`: Prefix used to build precise decode error messages.
///
/// Returns:
/// - The parsed candidate document tuple used by the server-side insert path.
fn parse_candidate_insert_binary_row(
    payload: &[u8],
    field_prefix: &str,
) -> Result<ParsedCandidateInsertDocument> {
    let mut offset = 0usize;
    let sha_bytes = read_exact_bytes(payload, &mut offset, 32, &format!("{field_prefix}.sha256"))?;
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(sha_bytes);
    let file_size = read_u64_le(payload, &mut offset, &format!("{field_prefix}.file_size"))?;
    let flags = read_u8(payload, &mut offset, &format!("{field_prefix}.flags"))?;
    let bloom_item_estimate = read_u64_le(
        payload,
        &mut offset,
        &format!("{field_prefix}.bloom_item_estimate"),
    )?;
    let tier2_bloom_item_estimate = read_u64_le(
        payload,
        &mut offset,
        &format!("{field_prefix}.tier2_bloom_item_estimate"),
    )?;
    let bloom_filter_len = read_u32_le(
        payload,
        &mut offset,
        &format!("{field_prefix}.bloom_filter_len"),
    )? as usize;
    let tier2_bloom_filter_len = read_u32_le(
        payload,
        &mut offset,
        &format!("{field_prefix}.tier2_bloom_filter_len"),
    )? as usize;
    let metadata_len = read_u32_le(
        payload,
        &mut offset,
        &format!("{field_prefix}.metadata_len"),
    )? as usize;
    let external_id_len = read_u32_le(
        payload,
        &mut offset,
        &format!("{field_prefix}.external_id_len"),
    )? as usize;
    let bloom_filter = read_exact_bytes(
        payload,
        &mut offset,
        bloom_filter_len,
        &format!("{field_prefix}.bloom_filter"),
    )?
    .to_vec();
    let tier2_bloom_filter = read_exact_bytes(
        payload,
        &mut offset,
        tier2_bloom_filter_len,
        &format!("{field_prefix}.tier2_bloom_filter"),
    )?
    .to_vec();
    let metadata = read_exact_bytes(
        payload,
        &mut offset,
        metadata_len,
        &format!("{field_prefix}.metadata"),
    )?
    .to_vec();
    let external_id = if external_id_len > 0 {
        Some(
            String::from_utf8(
                read_exact_bytes(
                    payload,
                    &mut offset,
                    external_id_len,
                    &format!("{field_prefix}.external_id"),
                )?
                .to_vec(),
            )
            .map_err(|_| {
                SspryError::from(format!("{field_prefix}.external_id must be valid UTF-8"))
            })?,
        )
    } else {
        None
    };
    if offset != payload.len() {
        return Err(SspryError::from(format!(
            "{field_prefix} has {} trailing bytes",
            payload.len().saturating_sub(offset)
        )));
    }
    Ok((
        sha256,
        file_size,
        if flags & (1 << 0) != 0 {
            Some(usize::try_from(bloom_item_estimate).map_err(|_| {
                SspryError::from(format!(
                    "{field_prefix}.bloom_item_estimate does not fit in usize"
                ))
            })?)
        } else {
            None
        },
        bloom_filter,
        if flags & (1 << 1) != 0 {
            Some(usize::try_from(tier2_bloom_item_estimate).map_err(|_| {
                SspryError::from(format!(
                    "{field_prefix}.tier2_bloom_item_estimate does not fit in usize"
                ))
            })?)
        } else {
            None
        },
        tier2_bloom_filter,
        flags & (1 << 2) != 0,
        metadata,
        external_id,
    ))
}

/// Exposes the binary row decoder to tests without leaking it to production
/// call sites.
///
/// Inputs:
/// - `payload`: Encoded row bytes produced by the serializer.
///
/// Returns:
/// - The decoded candidate document tuple.
#[cfg(test)]
pub(crate) fn parse_candidate_insert_binary_row_for_test(
    payload: &[u8],
) -> Result<ParsedCandidateInsertDocument> {
    parse_candidate_insert_binary_row(payload, "test.row")
}

/// Concatenates already-encoded row payloads into the binary batch format used
/// by remote insert requests.
///
/// Inputs:
/// - `rows`: Individual encoded rows.
///
/// Returns:
/// - A batch payload containing `u32` row lengths followed by row bytes.
pub(crate) fn serialized_candidate_insert_binary_batch_payload(rows: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        rows.iter()
            .map(|row| 4usize.saturating_add(row.len()))
            .sum(),
    );
    for row in rows {
        push_u32_le(&mut payload, row.len());
        payload.extend_from_slice(row);
    }
    payload
}
