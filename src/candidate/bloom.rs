use std::hash::{BuildHasher, Hasher};

use fastbloom::DefaultHasher as FastBloomDefaultHasher;

use crate::{Result, SspryError};

pub const DEFAULT_BLOOM_POSITION_LANES: usize = 4;
const FASTBLOOM_SEED: u128 = 0;

fn source_hash(value: u64) -> u64 {
    let hasher = FastBloomDefaultHasher::seeded(&FASTBLOOM_SEED.to_be_bytes());
    let mut state = hasher.build_hasher();
    state.write_u64(value);
    state.finish()
}

fn next_hash(h1: &mut u64, h2: u64) -> u64 {
    *h1 = h1.rotate_left(5).wrapping_add(h2);
    *h1
}

fn bloom_index(bits: usize, hash: u64) -> usize {
    ((hash as u128 * bits as u128) >> 64) as usize
}

pub fn bloom_positions(value: u64, bits: usize, hash_count: usize) -> Result<Vec<usize>> {
    if bits == 0 {
        return Err(SspryError::from("bits must be > 0"));
    }
    if hash_count == 0 {
        return Err(SspryError::from("hash_count must be > 0"));
    }
    let mut h1 = source_hash(value);
    let h2 = h1.wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    let mut positions = Vec::with_capacity(hash_count);
    positions.push(bloom_index(bits, h1));
    for _ in 1..hash_count {
        let hash = next_hash(&mut h1, h2);
        positions.push(bloom_index(bits, hash));
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

pub fn bloom_word_masks(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
) -> Result<Vec<(usize, u64)>> {
    if size_bytes == 0 {
        return Err(SspryError::from("size_bytes must be > 0"));
    }
    if hash_count == 0 {
        return Err(SspryError::from("hash_count must be > 0"));
    }
    let bits = size_bytes * 8;
    let mut masks = std::collections::BTreeMap::<usize, u64>::new();
    for value in values {
        for pos in bloom_positions(*value, bits, hash_count)? {
            let word_idx = pos / 64;
            let bit_idx = pos % 64;
            *masks.entry(word_idx).or_insert(0) |= 1u64 << bit_idx;
        }
    }
    Ok(masks.into_iter().collect())
}

fn validate_lane_layout(size_bytes: usize, lane_count: usize) -> Result<usize> {
    if size_bytes == 0 {
        return Err(SspryError::from("size_bytes must be > 0"));
    }
    if lane_count == 0 {
        return Err(SspryError::from("lane_count must be > 0"));
    }
    if size_bytes % lane_count != 0 {
        return Err(SspryError::from(
            "size_bytes must be divisible by lane_count",
        ));
    }
    Ok(size_bytes / lane_count)
}

pub fn bloom_word_masks_in_lane(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
    lane_idx: usize,
    lane_count: usize,
) -> Result<Vec<(usize, u64)>> {
    if hash_count == 0 {
        return Err(SspryError::from("hash_count must be > 0"));
    }
    let lane_bytes = validate_lane_layout(size_bytes, lane_count)?;
    if lane_idx >= lane_count {
        return Err(SspryError::from("lane_idx must be < lane_count"));
    }
    let lane_bits = lane_bytes * 8;
    let lane_word_offset = lane_idx * (lane_bytes / 8);
    let mut masks = std::collections::BTreeMap::<usize, u64>::new();
    for value in values {
        for pos in bloom_positions(*value, lane_bits, hash_count)? {
            let word_idx = lane_word_offset + (pos / 64);
            let bit_idx = pos % 64;
            *masks.entry(word_idx).or_insert(0) |= 1u64 << bit_idx;
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

pub fn raw_filter_matches_word_masks(raw_filter: &[u8], required_masks: &[(usize, u64)]) -> bool {
    for (word_idx, mask) in required_masks {
        let start = word_idx.saturating_mul(8);
        let end = start.saturating_add(8);
        if end > raw_filter.len() {
            return false;
        }
        let actual = u64::from_le_bytes(
            raw_filter[start..end]
                .try_into()
                .expect("word-sized bloom slice"),
        );
        if (actual & *mask) != *mask {
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

    pub fn add_in_lane(&mut self, value: u64, lane_idx: usize, lane_count: usize) -> Result<()> {
        let lane_bytes = validate_lane_layout(self.data.len(), lane_count)?;
        if lane_idx >= lane_count {
            return Err(SspryError::from("lane_idx must be < lane_count"));
        }
        let lane_bits = lane_bytes * 8;
        let lane_byte_offset = lane_idx * lane_bytes;
        for pos in bloom_positions(value, lane_bits, self.hash_count)? {
            let byte_idx = lane_byte_offset + (pos / 8);
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
    use fastbloom::BloomFilter as FastBloomFilter;

    use super::{
        BloomFilter, DEFAULT_BLOOM_POSITION_LANES, FASTBLOOM_SEED, bloom_byte_masks, bloom_positions,
        bloom_word_masks, bloom_word_masks_in_lane, raw_filter_matches_masks,
        raw_filter_matches_word_masks,
    };

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
    fn bloom_layout_matches_fastbloom_for_non_lane_filter() {
        let size_bytes = 128usize;
        let hash_count = 7usize;
        let values = [0x0102_0304_u64, 0xAABB_CCDD_1020_3040_u64, 0x9988_7766_5544_3322_u64];

        let mut ours = BloomFilter::new(size_bytes, hash_count).expect("ours");
        for value in values {
            ours.add(value).expect("ours add");
        }

        let mut theirs = FastBloomFilter::with_num_bits(size_bytes * 8)
            .seed(&FASTBLOOM_SEED)
            .hashes(hash_count as u32);
        for value in values {
            theirs.insert(&value);
        }
        let mut expected = Vec::with_capacity(size_bytes);
        for word in theirs.as_slice() {
            expected.extend_from_slice(&word.to_le_bytes());
        }
        expected.truncate(size_bytes);

        assert_eq!(ours.as_bytes(), &expected);
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
    fn raw_word_masks_match_inserted_values() {
        let grams = [0x0102_0304, 0xAABB_CCDD_1020_3040];
        let mut bloom = BloomFilter::new(128, 7).expect("bloom");
        for gram in grams {
            bloom.add(gram).expect("add");
        }
        let required = bloom_word_masks(&grams, 128, 7).expect("required word masks");
        assert!(raw_filter_matches_word_masks(bloom.as_bytes(), &required));
        assert!(!raw_filter_matches_word_masks(&[0u8; 128], &required));
    }

    #[test]
    fn bloom_validation_and_roundtrip_helpers_cover_remaining_paths() {
        assert!(bloom_positions(1, 0, 1).is_err());
        assert!(bloom_positions(1, 64, 0).is_err());
        assert!(bloom_byte_masks(&[1], 0, 1).is_err());
        assert!(bloom_word_masks(&[1], 0, 1).is_err());
        assert!(bloom_byte_masks(&[1], 8, 0).is_err());
        assert!(bloom_word_masks(&[1], 8, 0).is_err());
        assert!(bloom_word_masks_in_lane(&[1], 6, 1, 0, 4).is_err());
        assert!(bloom_word_masks_in_lane(&[1], 8, 1, 4, 4).is_err());
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
        let required_words = bloom_word_masks(&[0x0102_0304], 32, 3).expect("required words");
        assert!(raw_filter_matches_masks(&encoded, &required));
        assert!(raw_filter_matches_word_masks(&encoded, &required_words));
        assert!(!raw_filter_matches_masks(
            &encoded,
            &[(encoded.len(), 0x01)]
        ));
        assert!(!raw_filter_matches_word_masks(
            &encoded,
            &[(encoded.len() / 8, 0x01)]
        ));
    }

    #[test]
    fn lane_helpers_round_trip_inserted_values() {
        let mut bloom = BloomFilter::new(64, 3).expect("bloom");
        bloom
            .add_in_lane(0x0102_0304, 1, DEFAULT_BLOOM_POSITION_LANES)
            .expect("lane add");
        let required =
            bloom_word_masks_in_lane(&[0x0102_0304], 64, 3, 1, DEFAULT_BLOOM_POSITION_LANES)
                .expect("lane masks");
        assert!(raw_filter_matches_word_masks(bloom.as_bytes(), &required));
        let wrong_lane =
            bloom_word_masks_in_lane(&[0x0102_0304], 64, 3, 2, DEFAULT_BLOOM_POSITION_LANES)
                .expect("wrong lane masks");
        assert!(!raw_filter_matches_word_masks(
            bloom.as_bytes(),
            &wrong_lane
        ));
    }
}
