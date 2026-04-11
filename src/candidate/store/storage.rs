/// Normalizes a store, workspace, or shard path back to the forest-policy root
/// that owns shared metadata files.
fn forest_policy_root(root: &Path) -> PathBuf {
    let leaf = root.file_name().and_then(|value| value.to_str());
    if leaf.is_some_and(|name| matches!(name, "current" | "work_a" | "work_b")) {
        let parent = root.parent().unwrap_or(root);
        if parent
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with("tree_"))
        {
            return parent.parent().unwrap_or(parent).to_path_buf();
        }
        return parent.to_path_buf();
    }
    if leaf.is_some_and(|name| name.starts_with("shard_")) {
        let parent = root.parent().unwrap_or(root);
        if parent
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| matches!(name, "current" | "work_a" | "work_b"))
        {
            let workspace_root = parent.parent().unwrap_or(parent);
            if workspace_root
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with("tree_"))
            {
                return workspace_root
                    .parent()
                    .unwrap_or(workspace_root)
                    .to_path_buf();
            }
            return workspace_root.to_path_buf();
        }
        return parent.to_path_buf();
    }
    root.to_path_buf()
}

/// Returns the forest-wide metadata file path.
fn forest_meta_path(root: &Path) -> PathBuf {
    root.join("meta.json")
}

#[cfg(test)]
/// Test-only alias for the forest metadata path helper.
fn meta_path(root: &Path) -> PathBuf {
    forest_meta_path(root)
}

/// Returns the path of the store-local metadata sidecar.
fn store_local_meta_path(root: &Path) -> PathBuf {
    root.join("store_meta.json")
}

/// Returns the path of the SHA-by-doc-id blob file.
fn sha_by_docid_path(root: &Path) -> PathBuf {
    root.join("sha256_by_docid.dat")
}

/// Returns the path of the primary document metadata row file.
fn doc_meta_path(root: &Path) -> PathBuf {
    root.join("doc_meta.bin")
}

/// Returns the path of the tier-2 document metadata row file.
fn tier2_doc_meta_path(root: &Path) -> PathBuf {
    root.join("tier2_doc_meta.bin")
}

/// Returns the path of the compact document metadata blob file.
fn doc_metadata_path(root: &Path) -> PathBuf {
    root.join("doc_metadata.bin")
}

/// Returns the path of the tier-1 bloom payload file.
fn blooms_path(root: &Path) -> PathBuf {
    root.join("blooms.bin")
}

/// Returns the path of the tier-2 bloom payload file.
fn tier2_blooms_path(root: &Path) -> PathBuf {
    root.join("tier2_blooms.bin")
}

/// Returns the path of the external-ID sidecar file.
fn external_ids_path(root: &Path) -> PathBuf {
    root.join("external_ids.dat")
}

/// Returns the JSON manifest that records the configured candidate shard count.
pub fn candidate_shard_manifest_path(root: &Path) -> PathBuf {
    root.join("shards.json")
}

/// Returns the hidden manifest used to coordinate shard compaction state.
fn shard_compaction_manifest_path(root: &Path) -> PathBuf {
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    let stem = root
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "candidate_db".to_owned());
    parent.join(format!(".{stem}.compaction.json"))
}

/// Loads the shard-compaction manifest if present, or returns an empty default
/// manifest when none exists yet.
fn read_shard_compaction_manifest(root: &Path) -> Result<ShardCompactionManifest> {
    let path = shard_compaction_manifest_path(root);
    if !path.exists() {
        return Ok(ShardCompactionManifest::default());
    }
    serde_json::from_slice(&fs::read(&path)?).map_err(|_| {
        SspryError::from(format!(
            "Invalid candidate compaction manifest at {}",
            path.display()
        ))
    })
}

/// Writes the shard-compaction manifest atomically.
fn write_shard_compaction_manifest(root: &Path, manifest: &ShardCompactionManifest) -> Result<()> {
    write_json(shard_compaction_manifest_path(root), manifest)
}

/// Ensures that the shard-compaction manifest exists on disk and returns the
/// current manifest contents.
fn ensure_shard_compaction_manifest(root: &Path) -> Result<ShardCompactionManifest> {
    let manifest = read_shard_compaction_manifest(root)?;
    write_shard_compaction_manifest(root, &manifest)?;
    Ok(manifest)
}

/// Returns the hidden retired-generation directory used to stage replaced
/// store roots.
fn retired_generation_root(root: &Path, generation: u64) -> PathBuf {
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    let stem = root
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "candidate_db".to_owned());
    parent.join(format!(".{stem}.retired.gen{generation:06}"))
}

/// Returns the root directory for one candidate shard, or the base root when
/// sharding is disabled.
pub fn candidate_shard_root(root: &Path, shard_count: usize, shard_idx: usize) -> PathBuf {
    if shard_count <= 1 {
        return root.to_path_buf();
    }
    root.join(format!("shard_{shard_idx:03}"))
}

/// Maps a SHA-256 document identity to its candidate shard index.
pub fn candidate_shard_index(sha256: &[u8; 32], shard_count: usize) -> usize {
    if shard_count <= 1 {
        return 0;
    }
    let head = u32::from_le_bytes([sha256[0], sha256[1], sha256[2], sha256[3]]) as usize;
    head % shard_count
}

/// Reads the configured shard count from the shard manifest when present.
pub fn read_candidate_shard_count(root: &Path) -> Result<Option<usize>> {
    let path = candidate_shard_manifest_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path)?).map_err(|_| {
        SspryError::from(format!(
            "Invalid candidate shard manifest at {}",
            path.display()
        ))
    })?;
    let count = raw
        .get("candidate_shards")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| {
            SspryError::from(format!(
                "Invalid candidate shard manifest at {}",
                path.display()
            ))
        })?;
    Ok(Some(count.max(1) as usize))
}

/// Persists the configured shard count to the shard manifest, creating the
/// store root as needed.
pub fn write_candidate_shard_count(root: &Path, shard_count: usize) -> Result<()> {
    fs::create_dir_all(root)?;
    write_json(
        candidate_shard_manifest_path(root),
        &serde_json::json!({ "candidate_shards": shard_count.max(1) }),
    )
}

/// Writes JSON via a temporary file and rename so readers do not observe a
/// partially written manifest.
fn write_json<T: Serialize>(path: PathBuf, value: &T) -> Result<()> {
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

/// Appends a raw blob to a file and returns the starting offset of the newly
/// written payload.
fn append_blob(path: PathBuf, bytes: &[u8]) -> Result<u64> {
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    let offset = handle.metadata()?.len();
    handle.write_all(bytes)?;
    Ok(offset)
}

/// Reads one blob payload from disk using the recorded offset and length,
/// returning a descriptive error for truncated state.
fn read_blob_from_path(
    path: &Path,
    offset: u64,
    len: usize,
    label: &str,
    doc_id: u64,
) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes).map_err(|err| {
        SspryError::from(format!(
            "Failed to read {label} payload for doc_id {doc_id} from {}: {err}",
            path.display()
        ))
    })?;
    Ok(bytes)
}

/// Overwrites bytes at a fixed file offset, creating the file if needed.
fn write_at(path: PathBuf, offset: u64, bytes: &[u8]) -> Result<()> {
    let mut handle = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)?;
    handle.seek(SeekFrom::Start(offset))?;
    handle.write_all(bytes)?;
    Ok(())
}

/// Builds a unique temporary work root for one compaction attempt.
pub(crate) fn compaction_work_root(root: &Path, suffix: &str) -> PathBuf {
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    let stem = root
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "candidate_db".to_owned());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0);
    parent.join(format!(".{stem}.{suffix}.{nonce}"))
}

/// Removes abandoned compaction work directories left next to the store root
/// and returns how many were deleted.
pub(crate) fn cleanup_abandoned_compaction_roots(root: &Path) -> Result<usize> {
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        return Ok(0);
    }
    let stem = root
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "candidate_db".to_owned());
    let prefix = format!(".{stem}.compact-");
    let mut removed = 0usize;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(&prefix) {
            continue;
        }
        fs::remove_dir_all(entry.path())?;
        removed += 1;
    }
    Ok(removed)
}

#[cfg(test)]
/// Appends a packed little-endian `u32` slice to a blob sidecar and returns
/// the starting offset.
fn append_u32_slice(path: PathBuf, values: &[u32]) -> Result<u64> {
    if values.is_empty() {
        return Ok(0);
    }
    let mut payload = Vec::with_capacity(values.len() * 4);
    for value in values {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    append_blob(path, &payload)
}

#[cfg(test)]
/// Recursively sums the on-disk size of a file or directory tree for storage
/// assertions.
fn dir_size(path: &Path) -> u64 {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(metadata) if metadata.is_dir() => fs::read_dir(path)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.flatten())
            .map(|entry| dir_size(&entry.path()))
            .sum(),
        _ => 0,
    }
}

/// Loads the persisted candidate document state from the current binary store
/// layout, or returns empty state when the store is uninitialized.
fn load_candidate_store_state(
    root: &Path,
) -> Result<(Vec<CandidateDoc>, Vec<DocMetaRow>, Vec<Tier2DocMetaRow>)> {
    if binary_store_exists(root) {
        return load_candidate_binary_store(root);
    }
    Ok((Vec::new(), Vec::new(), Vec::new()))
}

/// Returns whether any of the binary candidate-store sidecar files already
/// exist for this root.
fn binary_store_exists(root: &Path) -> bool {
    sha_by_docid_path(root).exists()
        || doc_meta_path(root).exists()
        || tier2_doc_meta_path(root).exists()
        || doc_metadata_path(root).exists()
}

/// Reconstructs in-memory document rows from the binary candidate-store files.
fn load_candidate_binary_store(
    root: &Path,
) -> Result<(Vec<CandidateDoc>, Vec<DocMetaRow>, Vec<Tier2DocMetaRow>)> {
    let sha_bytes = fs::read(sha_by_docid_path(root))?;
    let row_bytes = fs::read(doc_meta_path(root))?;
    let tier2_row_bytes = fs::read(tier2_doc_meta_path(root)).unwrap_or_default();
    if sha_bytes.len() % 32 != 0 || row_bytes.len() % DOC_META_ROW_BYTES != 0 {
        return Err(SspryError::from(format!(
            "Invalid candidate binary document state at {}",
            root.display()
        )));
    }
    let doc_count = sha_bytes.len() / 32;
    if doc_count != row_bytes.len() / DOC_META_ROW_BYTES {
        return Err(SspryError::from(format!(
            "Mismatched candidate binary document state at {}",
            root.display()
        )));
    }
    let mut docs = Vec::with_capacity(doc_count);
    let mut rows = Vec::with_capacity(doc_count);
    let mut tier2_rows = Vec::with_capacity(doc_count);
    for index in 0..doc_count {
        let doc_id = (index + 1) as u64;
        let sha256 = hex::encode(&sha_bytes[index * 32..(index + 1) * 32]);
        let row = DocMetaRow::decode(
            &row_bytes[index * DOC_META_ROW_BYTES..(index + 1) * DOC_META_ROW_BYTES],
        )?;
        let tier2_row = if tier2_row_bytes.len() >= (index + 1) * TIER2_DOC_META_ROW_BYTES {
            Tier2DocMetaRow::decode(
                &tier2_row_bytes
                    [index * TIER2_DOC_META_ROW_BYTES..(index + 1) * TIER2_DOC_META_ROW_BYTES],
            )?
        } else {
            Tier2DocMetaRow::default()
        };
        docs.push(CandidateDoc {
            doc_id,
            sha256,
            file_size: row.file_size,
            filter_bytes: row.filter_bytes as usize,
            bloom_hashes: usize::from(row.bloom_hashes.max(1)),
            tier2_filter_bytes: tier2_row.filter_bytes as usize,
            tier2_bloom_hashes: usize::from(tier2_row.bloom_hashes),
            special_population: (row.flags & DOC_FLAG_SPECIAL_POPULATION) != 0,
            deleted: (row.flags & DOC_FLAG_DELETED) != 0,
        });
        rows.push(row);
        tier2_rows.push(tier2_row);
    }
    Ok((docs, rows, tier2_rows))
}

#[cfg(test)]
/// Returns one stored blob slice from an in-memory sidecar image while
/// validating bounds for the requested document.
fn read_blob<'a>(
    bytes: &'a [u8],
    offset: u64,
    len: usize,
    label: &str,
    doc_id: u64,
) -> Result<&'a [u8]> {
    let offset = offset as usize;
    let end = offset.saturating_add(len);
    if end > bytes.len() {
        return Err(SspryError::from(format!(
            "Invalid {label} payload stored for doc_id {doc_id}"
        )));
    }
    Ok(&bytes[offset..end])
}

#[cfg(test)]
/// Decodes one packed `u32` vector from an in-memory sidecar image for test
/// assertions.
fn read_u32_vec(
    bytes: &[u8],
    offset: u64,
    count: u32,
    label: &str,
    doc_id: u64,
) -> Result<Vec<u32>> {
    let slice = read_blob(bytes, offset, count as usize * 4, label, doc_id)?;
    let mut out = Vec::with_capacity(count as usize);
    for chunk in slice.chunks_exact(4) {
        out.push(u32::from_le_bytes(chunk.try_into().expect("u32 chunk")));
    }
    Ok(out)
}

/// Validates candidate-store configuration values before the store is opened or
/// created.
fn validate_config(config: &CandidateConfig) -> Result<()> {
    if !matches!(
        config.id_source.as_str(),
        "sha256" | "md5" | "sha1" | "sha512"
    ) {
        return Err(SspryError::from(
            "id_source must be one of sha256, md5, sha1, sha512",
        ));
    }
    GramSizes::new(config.tier1_gram_size, config.tier2_gram_size)
        .map_err(|err| SspryError::from(format!("invalid gram size pair: {err}")))?;
    if !config.compaction_idle_cooldown_s.is_finite() || config.compaction_idle_cooldown_s < 0.0 {
        return Err(SspryError::from(
            "compaction_idle_cooldown_s must be finite and >= 0",
        ));
    }
    for (field, value) in [
        ("filter_target_fp", config.filter_target_fp),
        ("tier1_filter_target_fp", config.tier1_filter_target_fp),
        ("tier2_filter_target_fp", config.tier2_filter_target_fp),
    ] {
        if let Some(value) = value {
            if !(0.0 < value && value < 1.0) {
                return Err(SspryError::from(format!("{field} must be in range (0, 1)")));
            }
        }
    }
    Ok(())
}
