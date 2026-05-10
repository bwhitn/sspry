use std::hash::Hasher;

use rustc_hash::FxHasher;

use crate::{Result, SspryError};

pub const DEFAULT_BLOOM_POSITION_LANES: usize = 4;
const MIN_BLOCK_BYTES: usize = 8;
const BLOCK_SIZE_CHOICES_BYTES: [usize; 7] = [64, 32, 16, 8, 4, 2, 1];

/// Hashes one packed gram into the initial 64-bit value used by the bloom
/// probe sequence.
fn source_hash(value: u64) -> u64 {
    let mut hasher = FxHasher::default();
    hasher.write_u64(value);
    hasher.finish()
}

/// Advances the double-hashing sequence used to derive subsequent bloom probe
/// positions from the initial hash.
fn next_hash(h1: &mut u64, h2: u64) -> u64 {
    *h1 = h1.rotate_left(5).wrapping_add(h2);
    *h1
}

/// Maps a 64-bit hash into a range using multiplicative reduction instead of
/// integer modulo.
fn reduce_to_range(count: usize, hash: u64) -> usize {
    if count <= 1 {
        0
    } else {
        ((hash as u128 * count as u128) >> 64) as usize
    }
}

/// Maps a 64-bit hash into a bloom bit index using multiplicative reduction
/// inside one blocked bloom block.
fn bloom_index(bits: usize, hash: u64) -> usize {
    reduce_to_range(bits, hash)
}

fn validate_filter_bytes(size_bytes: usize) -> Result<()> {
    if size_bytes == 0 {
        return Err(SspryError::from("size_bytes must be > 0"));
    }
    if size_bytes % MIN_BLOCK_BYTES != 0 {
        return Err(SspryError::from(
            "size_bytes must be divisible by 8 for blocked bloom layout",
        ));
    }
    Ok(())
}

fn choose_block_size_bytes(lane_bytes: usize) -> Result<usize> {
    if lane_bytes == 0 {
        return Err(SspryError::from("lane_bytes must be > 0"));
    }
    for candidate in BLOCK_SIZE_CHOICES_BYTES {
        if lane_bytes >= candidate && lane_bytes % candidate == 0 {
            return Ok(candidate);
        }
    }
    Err(SspryError::from(
        "unable to choose blocked bloom block size for lane",
    ))
}

#[inline]
fn for_each_blocked_position_in_lane(
    value: u64,
    lane_byte_offset: usize,
    lane_bytes: usize,
    hash_count: usize,
    mut f: impl FnMut(usize),
) -> Result<()> {
    if hash_count == 0 {
        return Err(SspryError::from("hash_count must be > 0"));
    }
    let block_bytes = choose_block_size_bytes(lane_bytes)?;
    let block_bits = block_bytes * 8;
    let lane_bit_offset = lane_byte_offset * 8;
    let block_count = lane_bytes / block_bytes;

    let mut hash = source_hash(value);
    let h2 = hash.wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    let block_hash = hash ^ h2.rotate_left(17);
    let block_idx = reduce_to_range(block_count, block_hash);
    let block_bit_offset = block_idx * block_bits;

    let mut emit = |current_hash: u64| {
        let bit_pos = bloom_index(block_bits, current_hash);
        f(lane_bit_offset + block_bit_offset + bit_pos);
    };

    emit(hash);
    for _ in 1..hash_count {
        let next = next_hash(&mut hash, h2);
        emit(next);
    }
    Ok(())
}

/// Returns the ordered bloom bit positions for one packed gram value in the
/// current blocked layout.
pub fn bloom_positions(value: u64, bits: usize, hash_count: usize) -> Result<Vec<usize>> {
    if bits == 0 {
        return Err(SspryError::from("bits must be > 0"));
    }
    if bits % 8 != 0 {
        return Err(SspryError::from("bits must be divisible by 8"));
    }
    if hash_count == 0 {
        return Err(SspryError::from("hash_count must be > 0"));
    }
    let mut positions = Vec::with_capacity(hash_count);
    for_each_blocked_position_in_lane(value, 0, bits / 8, hash_count, |pos| positions.push(pos))?;
    Ok(positions)
}

/// Builds merged byte masks for all bloom positions required by `values`.
pub fn bloom_byte_masks(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
) -> Result<Vec<(usize, u8)>> {
    validate_filter_bytes(size_bytes)?;
    if hash_count == 0 {
        return Err(SspryError::from("hash_count must be > 0"));
    }
    let mut masks = std::collections::BTreeMap::<usize, u8>::new();
    for value in values {
        for pos in bloom_positions(*value, size_bytes * 8, hash_count)? {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            *masks.entry(byte_idx).or_insert(0) |= 1 << bit_idx;
        }
    }
    Ok(masks.into_iter().collect())
}

/// Builds merged 64-bit word masks for all bloom positions required by
/// `values`.
pub fn bloom_word_masks(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
) -> Result<Vec<(usize, u64)>> {
    validate_filter_bytes(size_bytes)?;
    if hash_count == 0 {
        return Err(SspryError::from("hash_count must be > 0"));
    }
    let mut masks = std::collections::BTreeMap::<usize, u64>::new();
    for value in values {
        for_each_blocked_position_in_lane(*value, 0, size_bytes, hash_count, |pos| {
            let word_idx = pos / 64;
            let bit_idx = pos % 64;
            *masks.entry(word_idx).or_insert(0) |= 1u64 << bit_idx;
        })?;
    }
    Ok(masks.into_iter().collect())
}

/// Validates that a lane-partitioned bloom layout can be split evenly and
/// returns the bytes assigned to each lane.
fn validate_lane_layout(size_bytes: usize, lane_count: usize) -> Result<usize> {
    validate_filter_bytes(size_bytes)?;
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

/// Returns the byte ranges for blocked bloom blocks touched by the supplied
/// absolute word masks. Ranges are deduplicated and adjacent blocks are
/// coalesced into one read.
pub fn bloom_block_ranges_for_word_masks(
    required_masks: &[(usize, u64)],
    size_bytes: usize,
    lane_count: usize,
) -> Result<Vec<(usize, usize)>> {
    let lane_bytes = validate_lane_layout(size_bytes, lane_count)?;
    let block_bytes = choose_block_size_bytes(lane_bytes)?;
    let mut starts = required_masks
        .iter()
        .filter_map(|(word_idx, mask)| {
            (*mask != 0).then_some(word_idx.saturating_mul(8))
        })
        .map(|byte_idx| {
            let lane_idx = byte_idx / lane_bytes;
            let within_lane = byte_idx % lane_bytes;
            lane_idx * lane_bytes + (within_lane / block_bytes) * block_bytes
        })
        .collect::<Vec<_>>();
    if starts.is_empty() {
        return Ok(Vec::new());
    }
    starts.sort_unstable();
    starts.dedup();
    let mut ranges = Vec::with_capacity(starts.len());
    let mut current_start = starts[0];
    let mut current_end = current_start + block_bytes;
    for start in starts.into_iter().skip(1) {
        let end = start + block_bytes;
        if start <= current_end {
            current_end = current_end.max(end);
        } else {
            ranges.push((current_start, current_end - current_start));
            current_start = start;
            current_end = end;
        }
    }
    ranges.push((current_start, current_end - current_start));
    Ok(ranges)
}

/// Builds merged word masks for the positions that `values` occupy within a
/// single bloom lane.
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
    let lane_byte_offset = lane_idx * lane_bytes;
    let mut masks = std::collections::BTreeMap::<usize, u64>::new();
    for value in values {
        for_each_blocked_position_in_lane(*value, lane_byte_offset, lane_bytes, hash_count, |pos| {
            let word_idx = pos / 64;
            let bit_idx = pos % 64;
            *masks.entry(word_idx).or_insert(0) |= 1u64 << bit_idx;
        })?;
    }
    Ok(masks.into_iter().collect())
}

/// Checks whether every required byte mask is present in a raw bloom payload.
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

/// Checks whether every required word mask is present in a raw bloom payload.
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
    /// Allocates an empty bloom filter with the requested byte size and hash
    /// count.
    pub fn new(size_bytes: usize, hash_count: usize) -> Result<Self> {
        validate_filter_bytes(size_bytes)?;
        if hash_count == 0 {
            return Err(SspryError::from("hash_count must be > 0"));
        }
        Ok(Self {
            hash_count,
            data: vec![0u8; size_bytes],
        })
    }

    /// Wraps an existing serialized bloom payload with the supplied hash-count
    /// configuration.
    pub fn from_bytes(data: &[u8], hash_count: usize) -> Result<Self> {
        validate_filter_bytes(data.len())?;
        if hash_count == 0 {
            return Err(SspryError::from("hash_count must be > 0"));
        }
        Ok(Self {
            hash_count,
            data: data.to_vec(),
        })
    }

    /// Returns the total bloom payload size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }

    /// Inserts one packed gram into the bloom filter.
    pub fn add(&mut self, value: u64) -> Result<()> {
        for_each_blocked_position_in_lane(value, 0, self.data.len(), self.hash_count, |pos| {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            self.data[byte_idx] |= 1 << bit_idx;
        })
    }

    /// Returns the per-lane byte width and bit width for a lane-partitioned
    /// view of this bloom filter.
    pub fn lane_geometry(&self, lane_count: usize) -> Result<(usize, usize)> {
        let lane_bytes = validate_lane_layout(self.data.len(), lane_count)?;
        Ok((lane_bytes, lane_bytes * 8))
    }

    #[inline]
    /// Inserts one packed gram into a caller-selected lane when the lane layout
    /// has already been validated by the caller.
    pub fn add_in_lane_prevalidated(
        &mut self,
        value: u64,
        lane_byte_offset: usize,
        lane_bits: usize,
    ) {
        if lane_bits == 0 {
            return;
        }
        debug_assert_eq!(lane_bits % 8, 0);
        let lane_bytes = lane_bits / 8;
        let _ = for_each_blocked_position_in_lane(
            value,
            lane_byte_offset,
            lane_bytes,
            self.hash_count,
            |pos| {
                let byte_idx = pos / 8;
                let bit_idx = pos % 8;
                self.data[byte_idx] |= 1 << bit_idx;
            },
        );
    }

    /// Inserts one packed gram into the specified bloom lane after validating
    /// the lane geometry.
    pub fn add_in_lane(&mut self, value: u64, lane_idx: usize, lane_count: usize) -> Result<()> {
        let (lane_bytes, lane_bits) = self.lane_geometry(lane_count)?;
        if lane_idx >= lane_count {
            return Err(SspryError::from("lane_idx must be < lane_count"));
        }
        let lane_byte_offset = lane_idx * lane_bytes;
        self.add_in_lane_prevalidated(value, lane_byte_offset, lane_bits);
        Ok(())
    }

    /// Returns whether the bloom filter may contain the supplied packed gram.
    pub fn maybe_contains(&self, value: u64) -> Result<bool> {
        let mut matched = true;
        for_each_blocked_position_in_lane(value, 0, self.data.len(), self.hash_count, |pos| {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            if (self.data[byte_idx] & (1 << bit_idx)) == 0 {
                matched = false;
            }
        })?;
        Ok(matched)
    }

    /// Returns whether the bloom filter may contain every gram in `values`.
    pub fn maybe_contains_all(&self, values: &[u64]) -> Result<bool> {
        for value in values {
            if !self.maybe_contains(*value)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Returns the serialized bloom payload by reference.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the bloom filter and returns its serialized payload.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BloomFilter, DEFAULT_BLOOM_POSITION_LANES, bloom_byte_masks, bloom_positions,
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
    fn bloom_positions_are_stable_and_bounded() {
        let first = bloom_positions(0x0102_0304, 512, 4).expect("positions");
        let second = bloom_positions(0x0102_0304, 512, 4).expect("positions");
        assert_eq!(first, second);
        assert_eq!(first.len(), 4);
        assert!(first.iter().all(|pos| *pos < 512));

        let third = bloom_positions(0xAABB_CCDD_1020_3040, 1024, 7).expect("positions");
        let fourth = bloom_positions(0xAABB_CCDD_1020_3040, 1024, 7).expect("positions");
        assert_eq!(third, fourth);
        assert_eq!(third.len(), 7);
        assert!(third.iter().all(|pos| *pos < 1024));
    }

    #[test]
    fn bloom_layout_matches_internal_byte_masks_for_non_lane_filter() {
        let size_bytes = 128usize;
        let hash_count = 7usize;
        let values = [
            0x0102_0304_u64,
            0xAABB_CCDD_1020_3040_u64,
            0x9988_7766_5544_3322_u64,
        ];

        let mut ours = BloomFilter::new(size_bytes, hash_count).expect("ours");
        for value in values {
            ours.add(value).expect("ours add");
        }

        let mut expected = vec![0u8; size_bytes];
        for (byte_idx, mask) in bloom_byte_masks(&values, size_bytes, hash_count).expect("masks") {
            expected[byte_idx] |= mask;
        }

        assert_eq!(ours.as_bytes(), expected.as_slice());
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
        assert!(bloom_positions(1, 65, 1).is_err());
        assert!(bloom_positions(1, 64, 0).is_err());
        assert!(bloom_byte_masks(&[1], 0, 1).is_err());
        assert!(bloom_word_masks(&[1], 0, 1).is_err());
        assert!(bloom_byte_masks(&[1], 8, 0).is_err());
        assert!(bloom_word_masks(&[1], 8, 0).is_err());
        assert!(bloom_word_masks_in_lane(&[1], 6, 1, 0, 4).is_err());
        assert!(bloom_word_masks_in_lane(&[1], 8, 1, 4, 4).is_err());
        assert!(BloomFilter::new(0, 1).is_err());
        assert!(BloomFilter::new(7, 1).is_err());
        assert!(BloomFilter::new(8, 0).is_err());
        assert!(BloomFilter::from_bytes(&[], 1).is_err());
        assert!(BloomFilter::from_bytes(&[1u8], 1).is_err());
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
