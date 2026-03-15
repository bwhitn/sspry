use crate::{Result, SspryError};

fn mix64(mut value: u64, seed: u64) -> u64 {
    value ^= seed;
    value ^= value >> 30;
    value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^= value >> 31;
    value
}

pub fn bloom_positions(value: u64, bits: usize, hash_count: usize) -> Result<Vec<usize>> {
    if bits == 0 {
        return Err(SspryError::from("bits must be > 0"));
    }
    if hash_count == 0 {
        return Err(SspryError::from("hash_count must be > 0"));
    }
    let h1 = mix64(value, 0x9E37_79B9_7F4A_7C15);
    let h2 = mix64(value, 0xD6E8_FEB8_6659_FD93) | 1;
    let mut positions = Vec::with_capacity(hash_count);
    for index in 0..hash_count {
        positions.push(h1.wrapping_add((index as u64).wrapping_mul(h2)) as usize % bits);
    }
    Ok(positions)
}

pub fn bloom_byte_masks(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
) -> Result<Vec<(usize, u8)>> {
    if size_bytes == 0 {
        return Err(SspryError::from("size_bytes must be > 0"));
    }
    if hash_count == 0 {
        return Err(SspryError::from("hash_count must be > 0"));
    }
    let bits = size_bytes * 8;
    let mut masks = std::collections::BTreeMap::<usize, u8>::new();
    for value in values {
        for pos in bloom_positions(*value, bits, hash_count)? {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            *masks.entry(byte_idx).or_insert(0) |= 1 << bit_idx;
        }
    }
    Ok(masks.into_iter().collect())
}

pub fn raw_filter_matches_masks(raw_filter: &[u8], required_masks: &[(usize, u8)]) -> bool {
    for (byte_idx, mask) in required_masks {
        if *byte_idx >= raw_filter.len() {
            return false;
        }
        if (raw_filter[*byte_idx] & *mask) != *mask {
            return false;
        }
    }
    true
}

#[derive(Clone, Debug)]
pub struct BloomFilter {
    hash_count: usize,
    data: Vec<u8>,
}

impl BloomFilter {
    pub fn new(size_bytes: usize, hash_count: usize) -> Result<Self> {
        if size_bytes == 0 {
            return Err(SspryError::from("size_bytes must be > 0"));
        }
        if hash_count == 0 {
            return Err(SspryError::from("hash_count must be > 0"));
        }
        Ok(Self {
            hash_count,
            data: vec![0u8; size_bytes],
        })
    }

    pub fn from_bytes(data: &[u8], hash_count: usize) -> Result<Self> {
        if data.is_empty() {
            return Err(SspryError::from("bloom payload must not be empty"));
        }
        if hash_count == 0 {
            return Err(SspryError::from("hash_count must be > 0"));
        }
        Ok(Self {
            hash_count,
            data: data.to_vec(),
        })
    }

    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }

    pub fn add(&mut self, value: u64) -> Result<()> {
        let bits = self.data.len() * 8;
        for pos in bloom_positions(value, bits, self.hash_count)? {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            self.data[byte_idx] |= 1 << bit_idx;
        }
        Ok(())
    }

    pub fn maybe_contains(&self, value: u64) -> Result<bool> {
        let bits = self.data.len() * 8;
        for pos in bloom_positions(value, bits, self.hash_count)? {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            if (self.data[byte_idx] & (1 << bit_idx)) == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn maybe_contains_all(&self, values: &[u64]) -> Result<bool> {
        for value in values {
            if !self.maybe_contains(*value)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::{BloomFilter, bloom_byte_masks, bloom_positions, raw_filter_matches_masks};

    #[test]
    fn bloom_round_trip_contains_inserted_value() {
        let mut bloom = BloomFilter::new(64, 7).expect("bloom");
        bloom.add(0x0102_0304).expect("add");
        assert!(bloom.maybe_contains(0x0102_0304).expect("contains"));
    }

    #[test]
    fn bloom_positions_are_stable() {
        assert_eq!(
            bloom_positions(0x0102_0304, 512, 4).expect("positions"),
            bloom_positions(0x0102_0304, 512, 4).expect("positions again")
        );
        assert_eq!(
            bloom_positions(0xAABB_CCDD_1020_3040, 1024, 7).expect("positions"),
            bloom_positions(0xAABB_CCDD_1020_3040, 1024, 7).expect("positions again")
        );
    }

    #[test]
    fn raw_masks_match_inserted_values() {
        let grams = [0x0102_0304, 0xAABB_CCDD_1020_3040];
        let mut bloom = BloomFilter::new(128, 7).expect("bloom");
        for gram in grams {
            bloom.add(gram).expect("add");
        }
        let required = bloom_byte_masks(&grams, 128, 7).expect("required masks");
        assert!(raw_filter_matches_masks(bloom.as_bytes(), &required));
        assert!(!raw_filter_matches_masks(&[0u8; 128], &required));
    }

    #[test]
    fn bloom_validation_and_roundtrip_helpers_cover_remaining_paths() {
        assert!(bloom_positions(1, 0, 1).is_err());
        assert!(bloom_positions(1, 64, 0).is_err());
        assert!(bloom_byte_masks(&[1], 0, 1).is_err());
        assert!(bloom_byte_masks(&[1], 8, 0).is_err());
        assert!(BloomFilter::new(0, 1).is_err());
        assert!(BloomFilter::new(8, 0).is_err());
        assert!(BloomFilter::from_bytes(&[], 1).is_err());
        assert!(BloomFilter::from_bytes(&[1u8], 0).is_err());

        let mut bloom = BloomFilter::from_bytes(&[0u8; 32], 3).expect("from bytes");
        assert_eq!(bloom.size_bytes(), 32);
        bloom.add(0x0102_0304).expect("add one");
        bloom.add(0x0506_0708).expect("add two");
        assert!(
            bloom
                .maybe_contains_all(&[0x0102_0304, 0x0506_0708])
                .expect("contains all")
        );
        assert!(
            !bloom
                .maybe_contains_all(&[0x0102_0304, 0xDEAD_BEEF])
                .expect("contains missing")
        );
        let encoded = bloom.into_bytes();
        assert_eq!(encoded.len(), 32);
        let required = bloom_byte_masks(&[0x0102_0304], 32, 3).expect("required");
        assert!(raw_filter_matches_masks(&encoded, &required));
        assert!(!raw_filter_matches_masks(
            &encoded,
            &[(encoded.len(), 0x01)]
        ));
    }
}
