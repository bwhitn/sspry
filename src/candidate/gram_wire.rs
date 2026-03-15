use crate::{Result, SspryError};

fn encode_u32(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn encode_u64(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_u32(payload: &[u8], cursor: &mut usize) -> Result<u32> {
    let mut shift = 0u32;
    let mut value = 0u32;
    loop {
        let byte = *payload
            .get(*cursor)
            .ok_or_else(|| SspryError::from("truncated gram varint payload"))?;
        *cursor += 1;
        value |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 35 {
            return Err(SspryError::from("gram varint payload is too large"));
        }
    }
}

fn decode_u64(payload: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        let byte = *payload
            .get(*cursor)
            .ok_or_else(|| SspryError::from("truncated gram varint payload"))?;
        *cursor += 1;
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 70 {
            return Err(SspryError::from("gram varint payload is too large"));
        }
    }
}

pub fn encode_grams_delta_u32<I>(grams: I) -> Vec<u8>
where
    I: IntoIterator<Item = u32>,
{
    let mut values: Vec<u32> = grams.into_iter().collect();
    values.sort_unstable();
    values.dedup();

    let mut out = Vec::new();
    encode_u32(values.len() as u32, &mut out);
    if values.is_empty() {
        return out;
    }

    let first = values[0];
    encode_u32(first, &mut out);
    let mut prev = first;
    for value in values.into_iter().skip(1) {
        encode_u32(value - prev, &mut out);
        prev = value;
    }
    out
}

pub fn decode_grams_delta_u32(payload: &[u8]) -> Result<Vec<u32>> {
    let mut cursor = 0usize;
    let count = decode_u32(payload, &mut cursor)? as usize;
    if count == 0 {
        if cursor != payload.len() {
            return Err(SspryError::from(
                "trailing bytes after empty gram delta payload",
            ));
        }
        return Ok(Vec::new());
    }

    let first = decode_u32(payload, &mut cursor)?;
    let mut values = Vec::with_capacity(count);
    values.push(first);
    let mut prev = first;
    for _ in 1..count {
        let delta = decode_u32(payload, &mut cursor)?;
        if delta == 0 {
            return Err(SspryError::from(
                "gram delta payload contains non-positive value",
            ));
        }
        let value = prev
            .checked_add(delta)
            .ok_or_else(|| SspryError::from("decoded gram exceeds u32 range"))?;
        values.push(value);
        prev = value;
    }
    if cursor != payload.len() {
        return Err(SspryError::from("trailing bytes after gram delta payload"));
    }
    Ok(values)
}

pub fn encode_grams_delta_u64<I>(grams: I) -> Vec<u8>
where
    I: IntoIterator<Item = u64>,
{
    let mut values: Vec<u64> = grams.into_iter().collect();
    values.sort_unstable();
    values.dedup();

    let mut out = Vec::new();
    encode_u32(values.len() as u32, &mut out);
    if values.is_empty() {
        return out;
    }

    let first = values[0];
    encode_u64(first, &mut out);
    let mut prev = first;
    for value in values.into_iter().skip(1) {
        encode_u64(value - prev, &mut out);
        prev = value;
    }
    out
}

pub fn decode_grams_delta_u64(payload: &[u8]) -> Result<Vec<u64>> {
    let mut cursor = 0usize;
    let count = decode_u32(payload, &mut cursor)? as usize;
    if count == 0 {
        if cursor != payload.len() {
            return Err(SspryError::from(
                "trailing bytes after empty gram delta payload",
            ));
        }
        return Ok(Vec::new());
    }

    let first = decode_u64(payload, &mut cursor)?;
    let mut values = Vec::with_capacity(count);
    values.push(first);
    let mut prev = first;
    for _ in 1..count {
        let delta = decode_u64(payload, &mut cursor)?;
        if delta == 0 {
            return Err(SspryError::from(
                "gram delta payload contains non-positive value",
            ));
        }
        let value = prev
            .checked_add(delta)
            .ok_or_else(|| SspryError::from("decoded gram exceeds u64 range"))?;
        values.push(value);
        prev = value;
    }
    if cursor != payload.len() {
        return Err(SspryError::from("trailing bytes after gram delta payload"));
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_grams_delta_u32, decode_grams_delta_u64, encode_grams_delta_u32,
        encode_grams_delta_u64, encode_u32, encode_u64,
    };

    #[test]
    fn gram_wire_roundtrips_sorted_unique_values() {
        let encoded = encode_grams_delta_u32([0, 1, 100, 0xFFFF_FFFF, 100]);
        assert_eq!(
            decode_grams_delta_u32(&encoded).expect("decode"),
            vec![0, 1, 100, 0xFFFF_FFFF]
        );
        assert_eq!(
            decode_grams_delta_u32(&encode_grams_delta_u32(Vec::<u32>::new()))
                .expect("empty decode"),
            Vec::<u32>::new()
        );

        let encoded64 = encode_grams_delta_u64([0, 1, 100, u64::MAX, 100]);
        assert_eq!(
            decode_grams_delta_u64(&encoded64).expect("decode64"),
            vec![0, 1, 100, u64::MAX]
        );
    }

    #[test]
    fn gram_wire_rejects_invalid_payloads() {
        assert!(
            decode_grams_delta_u32(&[0, 0])
                .expect_err("trailing bytes")
                .to_string()
                .contains("trailing bytes")
        );
        assert!(
            decode_grams_delta_u32(&[1])
                .expect_err("truncated")
                .to_string()
                .contains("truncated")
        );
        let invalid_zero_delta = vec![2, 7, 0];
        assert!(
            decode_grams_delta_u32(&invalid_zero_delta)
                .expect_err("zero delta")
                .to_string()
                .contains("non-positive")
        );
        assert!(
            decode_grams_delta_u64(&invalid_zero_delta)
                .expect_err("zero delta 64")
                .to_string()
                .contains("non-positive")
        );
        assert_eq!(
            decode_grams_delta_u64(&encode_grams_delta_u64(Vec::<u64>::new()))
                .expect("empty decode64"),
            Vec::<u64>::new()
        );
        assert!(
            decode_grams_delta_u64(&[1])
                .expect_err("truncated 64")
                .to_string()
                .contains("truncated")
        );
        let mut overflow64 = Vec::new();
        encode_u32(2, &mut overflow64);
        encode_u64(u64::MAX, &mut overflow64);
        encode_u64(1, &mut overflow64);
        assert!(
            decode_grams_delta_u64(&overflow64)
                .expect_err("u64 overflow")
                .to_string()
                .contains("exceeds u64 range")
        );
        let overlong_u32 = [0x81, 0x81, 0x81, 0x81, 0x81, 0x00];
        assert!(
            decode_grams_delta_u32(&overlong_u32)
                .expect_err("u32 varint too large")
                .to_string()
                .contains("too large")
        );
        let overlong_u64 = [
            1, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00,
        ];
        assert!(
            decode_grams_delta_u64(&overlong_u64)
                .expect_err("u64 varint too large")
                .to_string()
                .contains("too large")
        );
        let mut trailing64 = encode_grams_delta_u64([1u64, 9u64]);
        trailing64.push(0);
        assert!(
            decode_grams_delta_u64(&trailing64)
                .expect_err("u64 trailing bytes")
                .to_string()
                .contains("trailing bytes")
        );
    }
}
