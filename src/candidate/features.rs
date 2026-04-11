use std::fs::File;
use std::io::Read;
use std::path::Path;

use hyperloglockless::HyperLogLogPlus;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::candidate::BloomFilter;
use crate::candidate::bloom::DEFAULT_BLOOM_POSITION_LANES;
use crate::candidate::grams::GramSizes;
use crate::perf::{record_counter, record_max, scope};
use crate::{Result, SspryError};

pub const HLL_DEFAULT_PRECISION: u8 = 14;
const U64_MASK: u64 = u64::MAX;
const SPECIAL_POPULATION_MIN_FILE_BYTES: u64 = 8 * 1024 * 1024;
const SPECIAL_POPULATION_MAX_SAMPLE_BYTES: u64 = 256 * 1024;
const SPECIAL_POPULATION_MIN_SAMPLED_BYTES: u64 = 16 * 1024;
const SPECIAL_POPULATION_MIN_ENTROPY_BITS_PER_BYTE: f64 = 7.75;

#[derive(Clone, Debug)]
pub struct DocumentFeatures {
    pub sha256: [u8; 32],
    pub alternate_identity: Option<[u8; 32]>,
    pub entropy_bits_per_byte: f32,
    pub file_size: u64,
    pub bloom_filter: Vec<u8>,
    pub tier2_bloom_filter: Vec<u8>,
    pub special_population: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdditionalDigestKind {
    Md5,
    Sha1,
    Sha512,
}

enum AdditionalDigestState {
    Md5(Md5),
    Sha1(Sha1),
    Sha512(Sha512),
}

impl AdditionalDigestState {
    /// Creates the streaming digest state for the requested alternate identity
    /// algorithm.
    fn new(kind: AdditionalDigestKind) -> Self {
        match kind {
            AdditionalDigestKind::Md5 => Self::Md5(Md5::new()),
            AdditionalDigestKind::Sha1 => Self::Sha1(Sha1::new()),
            AdditionalDigestKind::Sha512 => Self::Sha512(Sha512::new()),
        }
    }

    /// Feeds one file chunk into the alternate identity digest state.
    fn update(&mut self, chunk: &[u8]) {
        match self {
            Self::Md5(digest) => digest.update(chunk),
            Self::Sha1(digest) => digest.update(chunk),
            Self::Sha512(digest) => digest.update(chunk),
        }
    }

    /// Finalizes the alternate digest and folds it into the normalized
    /// 32-byte identity namespace used by the index.
    fn finalize_normalized(self) -> [u8; 32] {
        match self {
            Self::Md5(digest) => normalize_identity_digest("md5", &digest.finalize()),
            Self::Sha1(digest) => normalize_identity_digest("sha1", &digest.finalize()),
            Self::Sha512(digest) => normalize_identity_digest("sha512", &digest.finalize()),
        }
    }
}

/// Namespaces an arbitrary digest into the project's canonical 32-byte
/// identity representation.
fn normalize_identity_digest(kind: &str, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"sspry-identity\0");
    digest.update(kind.as_bytes());
    digest.update(b"\0");
    digest.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest.finalize());
    out
}

/// Computes sampled Shannon entropy from the sparse byte histogram collected
/// during the feature pass.
fn sampled_entropy_bits_per_byte(sample_counts: &[u32; 256], sampled_bytes: u64) -> f64 {
    if sampled_bytes == 0 {
        return 0.0;
    }
    let total = sampled_bytes as f64;
    let mut entropy = 0.0;
    for count in sample_counts {
        if *count == 0 {
            continue;
        }
        let probability = *count as f64 / total;
        entropy -= probability * probability.log2();
    }
    entropy
}

/// Computes exact Shannon entropy for the full-file byte histogram.
fn entropy_bits_per_byte(counts: &[u64; 256], total_bytes: u64) -> f32 {
    if total_bytes == 0 {
        return 0.0;
    }
    let total = total_bytes as f64;
    let mut entropy = 0.0f64;
    for count in counts {
        if *count == 0 {
            continue;
        }
        let probability = *count as f64 / total;
        entropy -= probability * probability.log2();
    }
    entropy as f32
}

/// Classifies a file as special-population content when it is both large and
/// sufficiently high entropy.
fn classify_special_population(file_size: u64, sampled_entropy_bits_per_byte: f64) -> bool {
    file_size >= SPECIAL_POPULATION_MIN_FILE_BYTES
        && sampled_entropy_bits_per_byte >= SPECIAL_POPULATION_MIN_ENTROPY_BITS_PER_BYTE
}

#[cfg(test)]
/// Test helper that packs every exact sliding gram of the requested size into
/// `u64` values.
fn iter_grams_from_bytes_exact_u64(data: &[u8], gram_size: usize) -> Vec<u64> {
    if data.len() < gram_size {
        return Vec::new();
    }
    (0..=(data.len() - gram_size))
        .map(|idx| crate::candidate::grams::pack_exact_gram(&data[idx..idx + gram_size]))
        .collect()
}

/// Mixes a packed gram into the hash domain expected by HyperLogLog.
fn mix_u64_to_u64(value: u64) -> u64 {
    let mut x = value;
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = ((x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9)) & U64_MASK;
    x = ((x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB)) & U64_MASK;
    (x ^ (x >> 31)) & U64_MASK
}

#[derive(Clone, Copy, Debug)]
struct RollingGramState {
    gram_size: usize,
    filled: usize,
    value: u64,
}

impl RollingGramState {
    /// Creates an empty sliding gram window for the requested gram size.
    fn new(gram_size: usize) -> Self {
        Self {
            gram_size,
            filled: 0,
            value: 0,
        }
    }

    /// Pushes one byte into the sliding window and returns the packed gram once
    /// enough bytes have been seen.
    fn push(&mut self, byte: u8) -> Option<u64> {
        if self.filled < self.gram_size {
            self.value |= u64::from(byte) << (self.filled * 8);
            self.filled += 1;
            if self.filled == self.gram_size {
                Some(self.value)
            } else {
                None
            }
        } else {
            self.value = slide_exact_gram(self.value, byte, self.gram_size);
            Some(self.value)
        }
    }
}

#[inline]
/// Slides a packed exact gram forward by one byte and returns the new packed
/// window.
fn slide_exact_gram(value: u64, next_byte: u8, gram_size: usize) -> u64 {
    debug_assert!((1..=8).contains(&gram_size));
    (value >> 8) | (u64::from(next_byte) << ((gram_size - 1) * 8))
}

#[inline]
/// Assigns a gram start offset to one of the fixed bloom-position lanes.
fn bloom_lane_for_start(start_offset: u64) -> usize {
    debug_assert!(DEFAULT_BLOOM_POSITION_LANES.is_power_of_two());
    (start_offset as usize) & (DEFAULT_BLOOM_POSITION_LANES - 1)
}

/// Estimates the number of unique exact grams in a file by streaming it once
/// through a HyperLogLog sketch.
fn estimate_unique_grams_hll(
    path: impl AsRef<Path>,
    gram_size: usize,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    if chunk_size == 0 {
        return Err(SspryError::from("chunk_size must be > 0"));
    }
    if !(4..=18).contains(&precision) {
        return Err(SspryError::from("precision must be in range 4..18"));
    }
    if gram_size == 0 {
        return Err(SspryError::from("gram_size must be > 0"));
    }

    let mut hll = HyperLogLogPlus::new(precision);
    let mut rolling = RollingGramState::new(gram_size);
    let mut saw_gram = false;
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let read_len = file.read(&mut buf)?;
        if read_len == 0 {
            break;
        }
        for byte in &buf[..read_len] {
            if let Some(gram) = rolling.push(*byte) {
                hll.insert_hash(mix_u64_to_u64(gram));
                saw_gram = true;
            }
        }
    }

    if !saw_gram {
        return Ok(0);
    }
    Ok(hll.count().max(1))
}

/// Estimates unique-gram counts for two gram sizes in a single streaming pass
/// over the file.
pub fn estimate_unique_grams_pair_hll(
    path: impl AsRef<Path>,
    first_gram_size: usize,
    second_gram_size: usize,
    chunk_size: usize,
    precision: u8,
) -> Result<(usize, usize)> {
    if chunk_size == 0 {
        return Err(SspryError::from("chunk_size must be > 0"));
    }
    if !(4..=18).contains(&precision) {
        return Err(SspryError::from("precision must be in range 4..18"));
    }
    if first_gram_size == 0 || second_gram_size == 0 {
        return Err(SspryError::from("gram_size must be > 0"));
    }
    if first_gram_size == second_gram_size {
        let estimate = estimate_unique_grams_hll(path, first_gram_size, chunk_size, precision)?;
        return Ok((estimate, estimate));
    }

    let mut first_hll = HyperLogLogPlus::new(precision);
    let mut second_hll = HyperLogLogPlus::new(precision);
    let mut first_state = RollingGramState::new(first_gram_size);
    let mut second_state = RollingGramState::new(second_gram_size);
    let mut saw_first = false;
    let mut saw_second = false;
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let read_len = file.read(&mut buf)?;
        if read_len == 0 {
            break;
        }
        for byte in &buf[..read_len] {
            if let Some(gram) = first_state.push(*byte) {
                first_hll.insert_hash(mix_u64_to_u64(gram));
                saw_first = true;
            }
            if let Some(gram) = second_state.push(*byte) {
                second_hll.insert_hash(mix_u64_to_u64(gram));
                saw_second = true;
            }
        }
    }

    Ok((
        if saw_first {
            first_hll.count().max(1)
        } else {
            0
        },
        if saw_second {
            second_hll.count().max(1)
        } else {
            0
        },
    ))
}

/// Convenience wrapper that estimates unique grams for one explicit gram size.
pub fn estimate_unique_grams_for_size_hll(
    path: impl AsRef<Path>,
    gram_size: usize,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_hll(path, gram_size, chunk_size, precision)
}

#[cfg(test)]
/// Test-only wrapper that estimates unique 4-byte grams through the shared HLL
/// implementation.
fn estimate_unique_grams4_hll(
    path: impl AsRef<Path>,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_for_size_hll(path, 4, chunk_size, precision)
}

#[cfg(test)]
/// Test-only wrapper that estimates unique default tier2 grams through the
/// shared HLL implementation.
fn estimate_unique_default_tier2_grams_hll(
    path: impl AsRef<Path>,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_for_size_hll(path, 5, chunk_size, precision)
}

#[cfg(test)]
/// Test-only wrapper that estimates unique explicit tier2 gram sizes through
/// the shared HLL implementation.
fn estimate_unique_tier2_grams_hll(
    path: impl AsRef<Path>,
    tier2_gram_size: usize,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_for_size_hll(path, tier2_gram_size, chunk_size, precision)
}

#[cfg(test)]
/// Test helper that expands the shared exact-gram iterator for 4-byte grams.
fn iter_grams4_from_bytes(data: &[u8]) -> Vec<u64> {
    iter_grams_from_bytes_exact_u64(data, 4)
}

#[cfg(test)]
/// Test helper that expands the shared exact-gram iterator for default tier2
/// grams.
fn iter_default_tier2_grams_from_bytes(data: &[u8]) -> Vec<u64> {
    iter_grams_from_bytes_exact_u64(data, 5)
}

#[cfg(test)]
/// Test helper that expands the shared exact-gram iterator for caller-selected
/// tier2 gram sizes.
fn iter_tier2_grams_from_bytes(data: &[u8], tier2_gram_size: usize) -> Vec<u64> {
    iter_grams_from_bytes_exact_u64(data, tier2_gram_size)
}

#[allow(clippy::too_many_arguments)]
/// Scans one file once to compute content hashes, bloom filters, entropy, and
/// special-population classification for the configured gram sizes.
pub fn scan_file_features_bloom_only_with_gram_sizes(
    path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    filter_bytes: usize,
    bloom_hashes: usize,
    tier2_filter_bytes: usize,
    tier2_bloom_hashes: usize,
    chunk_size: usize,
    additional_digest: Option<AdditionalDigestKind>,
) -> Result<DocumentFeatures> {
    let mut total_scope = scope("candidate.scan_file_features");
    if chunk_size == 0 {
        return Err(SspryError::from("chunk_size must be > 0"));
    }

    let file_path = path.as_ref();
    let mut file = File::open(file_path)?;
    let declared_file_size = file.metadata()?.len();
    let mut digest = Sha256::new();
    let mut alternate_identity = additional_digest.map(AdditionalDigestState::new);
    let mut bloom = Some(BloomFilter::new(filter_bytes, bloom_hashes)?);
    let mut tier2_bloom = if tier2_filter_bytes > 0 && tier2_bloom_hashes > 0 {
        Some(BloomFilter::new(tier2_filter_bytes, tier2_bloom_hashes)?)
    } else {
        None
    };
    let tier1_lane_geometry = bloom
        .as_ref()
        .map(|bloom_ref| bloom_ref.lane_geometry(DEFAULT_BLOOM_POSITION_LANES))
        .transpose()?;
    let tier2_lane_geometry = tier2_bloom
        .as_ref()
        .map(|bloom_ref| bloom_ref.lane_geometry(DEFAULT_BLOOM_POSITION_LANES))
        .transpose()?;
    let mut file_size = 0u64;
    let mut buf = vec![0u8; chunk_size];
    let mut gram_windows = 0u64;
    let mut processed_bytes = 0u64;
    let sample_stride = (declared_file_size
        .saturating_add(SPECIAL_POPULATION_MAX_SAMPLE_BYTES - 1)
        / SPECIAL_POPULATION_MAX_SAMPLE_BYTES)
        .max(1);
    let mut sample_counts = [0u32; 256];
    let mut sampled_bytes = 0u64;
    let mut next_sample_offset = 0u64;
    let mut exact_byte_counts = [0u64; 256];
    let mut tier1_state = RollingGramState::new(gram_sizes.tier1);
    let mut tier2_state = tier2_bloom
        .as_ref()
        .map(|_| RollingGramState::new(gram_sizes.tier2));

    loop {
        let read_len = file.read(&mut buf)?;
        if read_len == 0 {
            break;
        }
        let chunk = &buf[..read_len];
        for byte in chunk {
            exact_byte_counts[*byte as usize] = exact_byte_counts[*byte as usize].saturating_add(1);
        }
        while sampled_bytes < SPECIAL_POPULATION_MAX_SAMPLE_BYTES
            && next_sample_offset < processed_bytes.saturating_add(read_len as u64)
        {
            let rel = next_sample_offset.saturating_sub(processed_bytes) as usize;
            if rel >= chunk.len() {
                break;
            }
            sample_counts[chunk[rel] as usize] =
                sample_counts[chunk[rel] as usize].saturating_add(1);
            sampled_bytes = sampled_bytes.saturating_add(1);
            next_sample_offset = next_sample_offset.saturating_add(sample_stride);
        }
        file_size = file_size.saturating_add(read_len as u64);
        digest.update(chunk);
        if let Some(alternate_identity_ref) = alternate_identity.as_mut() {
            alternate_identity_ref.update(chunk);
        }
        let (tier1_lane_bytes, tier1_lane_bits) =
            tier1_lane_geometry.expect("tier1 lane geometry when tier1 bloom exists");
        let tier2_lane = tier2_lane_geometry;
        for (idx, byte) in chunk.iter().enumerate() {
            let absolute_end = processed_bytes.saturating_add(idx as u64);
            if let Some(gram) = tier1_state.push(*byte) {
                if let Some(bloom_ref) = bloom.as_mut() {
                    let start = absolute_end.saturating_add(1) - gram_sizes.tier1 as u64;
                    let lane = bloom_lane_for_start(start);
                    bloom_ref.add_in_lane_prevalidated(
                        gram,
                        lane * tier1_lane_bytes,
                        tier1_lane_bits,
                    );
                    gram_windows = gram_windows.saturating_add(1);
                }
            }
            if let (Some(state), Some(tier2_bloom_ref), Some((lane_bytes, lane_bits))) =
                (tier2_state.as_mut(), tier2_bloom.as_mut(), tier2_lane)
            {
                if let Some(gram) = state.push(*byte) {
                    let start = absolute_end.saturating_add(1) - gram_sizes.tier2 as u64;
                    let lane = bloom_lane_for_start(start);
                    tier2_bloom_ref.add_in_lane_prevalidated(gram, lane * lane_bytes, lane_bits);
                }
            }
        }
        processed_bytes = processed_bytes.saturating_add(read_len as u64);
    }

    let digest_bytes = digest.finalize();
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&digest_bytes);
    let exact_entropy = entropy_bits_per_byte(&exact_byte_counts, file_size);
    let sampled_entropy = if sampled_bytes >= SPECIAL_POPULATION_MIN_SAMPLED_BYTES {
        sampled_entropy_bits_per_byte(&sample_counts, sampled_bytes)
    } else {
        0.0
    };

    total_scope.add_bytes(file_size);
    total_scope.add_items(gram_windows);
    record_counter("candidate.scan_file_features_bytes_total", file_size);
    record_counter("candidate.scan_file_features_windows_total", gram_windows);
    record_max("candidate.scan_file_features_max_bytes", file_size);

    Ok(DocumentFeatures {
        sha256,
        alternate_identity: alternate_identity.map(AdditionalDigestState::finalize_normalized),
        entropy_bits_per_byte: exact_entropy,
        file_size,
        bloom_filter: bloom.map(BloomFilter::into_bytes).unwrap_or_default(),
        tier2_bloom_filter: tier2_bloom.map(BloomFilter::into_bytes).unwrap_or_default(),
        special_population: classify_special_population(file_size, sampled_entropy),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use md5::Digest as _;
    use std::collections::HashSet;
    use tempfile::tempdir;

    use super::{
        HLL_DEFAULT_PRECISION, estimate_unique_default_tier2_grams_hll,
        estimate_unique_grams_pair_hll, estimate_unique_grams4_hll,
        estimate_unique_tier2_grams_hll, iter_default_tier2_grams_from_bytes,
        iter_grams4_from_bytes, iter_tier2_grams_from_bytes,
        scan_file_features_bloom_only_with_gram_sizes,
    };
    use crate::candidate::grams::{DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes};

    /// Uses the default tier1/tier2 gram sizes while delegating to the shared
    /// feature scanner used in production.
    fn scan_file_features_default_grams(
        path: impl AsRef<std::path::Path>,
        filter_bytes: usize,
        bloom_hashes: usize,
        tier2_filter_bytes: usize,
        tier2_bloom_hashes: usize,
        chunk_size: usize,
    ) -> crate::Result<super::DocumentFeatures> {
        scan_file_features_bloom_only_with_gram_sizes(
            path,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
                .expect("default gram sizes"),
            filter_bytes,
            bloom_hashes,
            tier2_filter_bytes,
            tier2_bloom_hashes,
            chunk_size,
            None,
        )
    }

    #[test]
    /// Verifies the 4-byte sliding gram helper emits the expected number of
    /// windows and handles short inputs.
    fn grams4_iterates_sliding_windows() {
        let grams = iter_grams4_from_bytes(b"ABCDE");
        assert_eq!(grams.len(), 2);
        assert!(iter_grams4_from_bytes(b"ABC").is_empty());
    }

    #[test]
    /// Verifies the document-feature hash field remains easy to serialize as
    /// lowercase hex.
    fn document_features_sha256_hex_formats_hash() {
        let features = super::DocumentFeatures {
            sha256: [0xAB; 32],
            alternate_identity: None,
            entropy_bits_per_byte: 0.0,
            file_size: 0,
            bloom_filter: Vec::new(),
            tier2_bloom_filter: Vec::new(),
            special_population: false,
        };
        assert_eq!(hex::encode(features.sha256), hex::encode([0xAB; 32]));
    }

    #[test]
    /// Verifies the bloom-only scanner rejects zero chunk sizes and still
    /// hashes small files correctly.
    fn bloom_only_scan_hashes_file_and_validates_chunk_size() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("doc.bin");
        fs::write(&path, b"xxABCDyy").expect("write");
        assert!(
            scan_file_features_default_grams(&path, 64, 4, 0, 0, 0)
                .expect_err("chunk size zero")
                .to_string()
                .contains("chunk_size must be > 0")
        );
        let features =
            scan_file_features_default_grams(&path, 64, 4, 0, 0, 1024).expect("features");
        assert_eq!(features.file_size, 8);
        assert!(!features.bloom_filter.is_empty());
    }

    #[test]
    /// Verifies the bloom-only scanner honors caller-supplied gram sizes and
    /// produces both bloom tiers.
    fn bloom_only_scan_supports_custom_gram_sizes() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("custom.bin");
        fs::write(&path, b"ABCDEFGHABCDEFGH").expect("write");
        let features = scan_file_features_bloom_only_with_gram_sizes(
            &path,
            GramSizes::new(4, 5).expect("sizes"),
            64,
            4,
            64,
            4,
            8,
            None,
        )
        .expect("features");
        assert_eq!(features.file_size, 16);
        assert!(!features.bloom_filter.is_empty());
        assert!(!features.tier2_bloom_filter.is_empty());
    }

    #[test]
    /// Verifies the sampled-entropy heuristic only marks large, high-entropy
    /// files as special-population content.
    fn sampled_entropy_classifier_distinguishes_special_population() {
        assert!(!super::classify_special_population(1024, 8.0));
        assert!(!super::classify_special_population(16 * 1024 * 1024, 7.0));
        assert!(super::classify_special_population(16 * 1024 * 1024, 7.9));
    }

    #[test]
    /// Verifies the 4-byte HLL wrapper enforces validation limits and stays
    /// reasonably close to the exact unique-gram count.
    fn estimate_unique_grams4_hll_validation_and_accuracy_work() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("hll.bin");
        let payload = b"ABCD1234WXYZABCD9876QWER";
        fs::write(&path, payload).expect("write");
        let exact = iter_grams4_from_bytes(payload)
            .into_iter()
            .collect::<HashSet<_>>()
            .len();

        assert!(
            estimate_unique_grams4_hll(&path, 0, HLL_DEFAULT_PRECISION)
                .expect_err("chunk size zero")
                .to_string()
                .contains("chunk_size must be > 0")
        );
        assert!(
            estimate_unique_grams4_hll(&path, 5, 3)
                .expect_err("precision too low")
                .to_string()
                .contains("precision must be in range 4..18")
        );
        assert!(
            estimate_unique_grams4_hll(&path, 5, 19)
                .expect_err("precision too high")
                .to_string()
                .contains("precision must be in range 4..18")
        );

        let estimate = estimate_unique_grams4_hll(&path, 5, 10).expect("estimate");
        assert!(estimate > 0);
        let error_ratio =
            ((estimate as isize - exact as isize).unsigned_abs() as f64) / exact.max(1) as f64;
        assert!(error_ratio < 0.35, "estimate={estimate} exact={exact}");
    }

    #[test]
    /// Verifies the tier2 iterator and HLL wrappers behave correctly across
    /// alternate tier2 gram sizes.
    fn wrapper_iterators_and_hll_helpers_cover_tier2_sizes() {
        let payload = b"ABCDEFG";
        assert_eq!(iter_default_tier2_grams_from_bytes(payload).len(), 3);
        assert_eq!(iter_tier2_grams_from_bytes(payload, 3).len(), 5);
        assert!(iter_tier2_grams_from_bytes(b"AB", 3).is_empty());

        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("wrappers.bin");
        fs::write(&path, payload).expect("write");
        let estimate_default_tier2 =
            estimate_unique_default_tier2_grams_hll(&path, 4, 4).expect("estimate_default_tier2");
        let estimate_tier2 =
            estimate_unique_tier2_grams_hll(&path, 3, 4, 5).expect("estimate tier2");
        assert!(estimate_default_tier2 > 0);
        assert!(estimate_tier2 > 0);
    }

    #[test]
    /// Verifies the paired HLL pass matches the single-size wrappers for both
    /// different-size and same-size requests.
    fn paired_hll_estimate_matches_individual_estimates() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("paired-hll.bin");
        let payload = b"ABCDEFGHABCDEFGH12345678IJKLMNOP";
        fs::write(&path, payload).expect("write");

        let exact4 = estimate_unique_grams4_hll(&path, 8, 10).expect("exact4");
        let exact_default_tier2 =
            estimate_unique_default_tier2_grams_hll(&path, 8, 10).expect("exact_default_tier2");
        let (paired4, paired5) = estimate_unique_grams_pair_hll(&path, 4, 5, 8, 10).expect("pair");
        assert_eq!(paired4, exact4);
        assert_eq!(paired5, exact_default_tier2);

        let (same_left, same_right) =
            estimate_unique_grams_pair_hll(&path, 4, 4, 8, 10).expect("same");
        assert_eq!(same_left, exact4);
        assert_eq!(same_right, exact4);
    }

    #[test]
    /// Verifies the HLL helpers and bloom scanner still behave on short files
    /// and low HLL precision values.
    fn hll_small_precision_branches_and_short_file_paths_work() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("short.bin");
        fs::write(&path, b"ABCD").expect("write");
        assert!(estimate_unique_grams4_hll(&path, 8, 4).expect("p4") > 0);
        assert_eq!(
            estimate_unique_default_tier2_grams_hll(&path, 8, 5).expect("p5"),
            0
        );
        assert!(estimate_unique_tier2_grams_hll(&path, 3, 8, 6).expect("p6 tier2") > 0);

        let features = scan_file_features_bloom_only_with_gram_sizes(
            &path,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE).expect("sizes"),
            64,
            4,
            64,
            4,
            16,
            None,
        )
        .expect("features");
        assert_eq!(features.file_size, 4);
        assert!(!features.tier2_bloom_filter.is_empty());
    }

    #[test]
    /// Verifies the feature scan can compute an alternate identity digest
    /// during the same pass used for bloom construction.
    fn bloom_only_scan_can_compute_alternate_identity_during_feature_pass() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("digest.bin");
        fs::write(&path, b"identity-check-bytes").expect("write");

        let features = scan_file_features_bloom_only_with_gram_sizes(
            &path,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE).expect("sizes"),
            64,
            4,
            64,
            4,
            8,
            Some(super::AdditionalDigestKind::Md5),
        )
        .expect("features");

        assert_eq!(
            features.alternate_identity,
            Some(crate::app::normalize_identity_digest(
                "md5",
                &md5::Md5::digest(b"identity-check-bytes"),
            ))
        );
    }
}
