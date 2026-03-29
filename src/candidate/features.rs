use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::candidate::BloomFilter;
use crate::candidate::bloom::DEFAULT_BLOOM_POSITION_LANES;
use crate::candidate::grams::{GramSizes, pack_exact_gram};
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
    pub file_size: u64,
    pub bloom_filter: Vec<u8>,
    pub tier2_bloom_filter: Vec<u8>,
    pub special_population: bool,
}

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

fn classify_special_population(file_size: u64, sampled_entropy_bits_per_byte: f64) -> bool {
    file_size >= SPECIAL_POPULATION_MIN_FILE_BYTES
        && sampled_entropy_bits_per_byte >= SPECIAL_POPULATION_MIN_ENTROPY_BITS_PER_BYTE
}

#[cfg(test)]
fn iter_grams_from_bytes_exact_u64(data: &[u8], gram_size: usize) -> Vec<u64> {
    if data.len() < gram_size {
        return Vec::new();
    }
    (0..=(data.len() - gram_size))
        .map(|idx| pack_exact_gram(&data[idx..idx + gram_size]))
        .collect()
}

fn mix_u64_to_u64(value: u64) -> u64 {
    let mut x = value;
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = ((x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9)) & U64_MASK;
    x = ((x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB)) & U64_MASK;
    (x ^ (x >> 31)) & U64_MASK
}

fn hll_alpha(m: usize) -> f64 {
    match m {
        16 => 0.673,
        32 => 0.697,
        64 => 0.709,
        _ => 0.7213 / (1.0 + 1.079 / m as f64),
    }
}

fn hll_add(registers: &mut [u8], precision: u8, value: u64) {
    let hashed = mix_u64_to_u64(value);
    let idx = (hashed >> (64 - precision)) as usize;
    let suffix = (hashed << precision) & U64_MASK;
    let suffix_bits = 64 - precision;
    let mut rank = if suffix == 0 {
        suffix_bits + 1
    } else {
        (suffix.leading_zeros() as u8) + 1
    };
    if rank > suffix_bits + 1 {
        rank = suffix_bits + 1;
    }
    if rank > registers[idx] {
        registers[idx] = rank;
    }
}

fn hll_estimate(registers: &[u8], precision: u8) -> usize {
    let m = 1usize << precision;
    let mut inv_sum = 0.0;
    let mut zeros = 0usize;
    for register in registers {
        inv_sum += 2f64.powi(-(*register as i32));
        if *register == 0 {
            zeros += 1;
        }
    }
    let mut estimate = hll_alpha(m) * (m * m) as f64 / inv_sum;
    if estimate <= 2.5 * m as f64 && zeros > 0 {
        estimate = m as f64 * (m as f64 / zeros as f64).ln();
    }
    estimate.round().max(0.0) as usize
}

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

    let mut registers = vec![0u8; 1usize << precision];
    let mut trailing = Vec::<u8>::new();
    let mut saw_gram = false;
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let read_len = file.read(&mut buf)?;
        if read_len == 0 {
            break;
        }
        let mut data = trailing;
        data.extend_from_slice(&buf[..read_len]);
        let limit = data.len().saturating_sub(gram_size).saturating_add(1);
        if limit > 0 && data.len() >= gram_size {
            saw_gram = true;
            for idx in 0..limit {
                hll_add(
                    &mut registers,
                    precision,
                    pack_exact_gram(&data[idx..idx + gram_size]),
                );
            }
            trailing = data[data.len() - (gram_size - 1)..].to_vec();
        } else {
            trailing = data;
        }
    }

    if !saw_gram {
        return Ok(0);
    }
    Ok(hll_estimate(&registers, precision))
}

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

    let mut first_registers = vec![0u8; 1usize << precision];
    let mut second_registers = vec![0u8; 1usize << precision];
    let max_gram_size = first_gram_size.max(second_gram_size);
    let trailing_len = max_gram_size - 1;
    let mut trailing = Vec::<u8>::new();
    let mut saw_first = false;
    let mut saw_second = false;
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let read_len = file.read(&mut buf)?;
        if read_len == 0 {
            break;
        }
        let mut data = trailing;
        data.extend_from_slice(&buf[..read_len]);
        if data.len() >= first_gram_size {
            saw_first = true;
            for idx in 0..=(data.len() - first_gram_size) {
                hll_add(
                    &mut first_registers,
                    precision,
                    pack_exact_gram(&data[idx..idx + first_gram_size]),
                );
            }
        }
        if data.len() >= second_gram_size {
            saw_second = true;
            for idx in 0..=(data.len() - second_gram_size) {
                hll_add(
                    &mut second_registers,
                    precision,
                    pack_exact_gram(&data[idx..idx + second_gram_size]),
                );
            }
        }
        trailing = if data.len() >= max_gram_size {
            data[data.len() - trailing_len..].to_vec()
        } else {
            data
        };
    }

    Ok((
        if saw_first {
            hll_estimate(&first_registers, precision)
        } else {
            0
        },
        if saw_second {
            hll_estimate(&second_registers, precision)
        } else {
            0
        },
    ))
}

pub fn estimate_unique_grams_for_size_hll(
    path: impl AsRef<Path>,
    gram_size: usize,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_hll(path, gram_size, chunk_size, precision)
}

#[cfg(test)]
fn estimate_unique_grams4_hll(
    path: impl AsRef<Path>,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_for_size_hll(path, 4, chunk_size, precision)
}

#[cfg(test)]
fn estimate_unique_default_tier2_grams_hll(
    path: impl AsRef<Path>,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_for_size_hll(path, 5, chunk_size, precision)
}

#[cfg(test)]
fn estimate_unique_tier2_grams_hll(
    path: impl AsRef<Path>,
    tier2_gram_size: usize,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_for_size_hll(path, tier2_gram_size, chunk_size, precision)
}

#[cfg(test)]
fn iter_grams4_from_bytes(data: &[u8]) -> Vec<u64> {
    iter_grams_from_bytes_exact_u64(data, 4)
}

#[cfg(test)]
fn iter_default_tier2_grams_from_bytes(data: &[u8]) -> Vec<u64> {
    iter_grams_from_bytes_exact_u64(data, 5)
}

#[cfg(test)]
fn iter_tier2_grams_from_bytes(data: &[u8], tier2_gram_size: usize) -> Vec<u64> {
    iter_grams_from_bytes_exact_u64(data, tier2_gram_size)
}

#[allow(clippy::too_many_arguments)]
pub fn scan_file_features_bloom_only_with_gram_sizes(
    path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    filter_bytes: usize,
    bloom_hashes: usize,
    tier2_filter_bytes: usize,
    tier2_bloom_hashes: usize,
    chunk_size: usize,
) -> Result<DocumentFeatures> {
    let mut total_scope = scope("candidate.scan_file_features");
    if chunk_size == 0 {
        return Err(SspryError::from("chunk_size must be > 0"));
    }

    let file_path = path.as_ref();
    let mut file = File::open(file_path)?;
    let declared_file_size = file.metadata()?.len();
    let mut digest = Sha256::new();
    let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes)?;
    let mut tier2_bloom = if tier2_filter_bytes > 0 && tier2_bloom_hashes > 0 {
        Some(BloomFilter::new(tier2_filter_bytes, tier2_bloom_hashes)?)
    } else {
        None
    };
    let trailing_bytes = if tier2_bloom.is_some() {
        gram_sizes.tier2 - 1
    } else {
        gram_sizes.tier1 - 1
    };
    let mut file_size = 0u64;
    let mut trailing = Vec::<u8>::new();
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

    loop {
        let read_len = file.read(&mut buf)?;
        if read_len == 0 {
            break;
        }
        let chunk = &buf[..read_len];
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
        let mut data = trailing.clone();
        data.extend_from_slice(chunk);
        let data_start_offset = processed_bytes.saturating_sub(trailing.len() as u64);
        if data.len() < gram_sizes.tier1 {
            trailing = data;
            processed_bytes = processed_bytes.saturating_add(read_len as u64);
            continue;
        }
        for idx in 0..=(data.len() - gram_sizes.tier1) {
            let gram = pack_exact_gram(&data[idx..idx + gram_sizes.tier1]);
            let lane = ((data_start_offset + idx as u64) as usize) % DEFAULT_BLOOM_POSITION_LANES;
            bloom.add_in_lane(gram, lane, DEFAULT_BLOOM_POSITION_LANES)?;
            gram_windows = gram_windows.saturating_add(1);
        }
        if let Some(tier2_bloom_ref) = tier2_bloom.as_mut() {
            if data.len() >= gram_sizes.tier2 {
                for idx in 0..=(data.len() - gram_sizes.tier2) {
                    let gram = pack_exact_gram(&data[idx..idx + gram_sizes.tier2]);
                    let lane =
                        ((data_start_offset + idx as u64) as usize) % DEFAULT_BLOOM_POSITION_LANES;
                    tier2_bloom_ref.add_in_lane(gram, lane, DEFAULT_BLOOM_POSITION_LANES)?;
                }
            }
        }
        trailing = data[data.len() - trailing_bytes..].to_vec();
        processed_bytes = processed_bytes.saturating_add(read_len as u64);
    }

    let digest_bytes = digest.finalize();
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&digest_bytes);
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
        file_size,
        bloom_filter: bloom.into_bytes(),
        tier2_bloom_filter: tier2_bloom.map(BloomFilter::into_bytes).unwrap_or_default(),
        special_population: classify_special_population(file_size, sampled_entropy),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

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
        )
    }

    #[test]
    fn grams4_iterates_sliding_windows() {
        let grams = iter_grams4_from_bytes(b"ABCDE");
        assert_eq!(grams.len(), 2);
        assert!(iter_grams4_from_bytes(b"ABC").is_empty());
    }

    #[test]
    fn document_features_sha256_hex_formats_hash() {
        let features = super::DocumentFeatures {
            sha256: [0xAB; 32],
            file_size: 0,
            bloom_filter: Vec::new(),
            tier2_bloom_filter: Vec::new(),
            special_population: false,
        };
        assert_eq!(hex::encode(features.sha256), hex::encode([0xAB; 32]));
    }

    #[test]
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
        )
        .expect("features");
        assert_eq!(features.file_size, 16);
        assert!(!features.bloom_filter.is_empty());
        assert!(!features.tier2_bloom_filter.is_empty());
    }

    #[test]
    fn sampled_entropy_classifier_distinguishes_special_population() {
        assert!(!super::classify_special_population(1024, 8.0));
        assert!(!super::classify_special_population(16 * 1024 * 1024, 7.0));
        assert!(super::classify_special_population(16 * 1024 * 1024, 7.9));
    }

    #[test]
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
        )
        .expect("features");
        assert_eq!(features.file_size, 4);
        assert!(!features.tier2_bloom_filter.is_empty());
    }
}
