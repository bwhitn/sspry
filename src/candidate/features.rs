use std::fs::File;
use std::io::Read;
use std::path::Path;

use hashbrown::HashSet;
use sha2::{Digest, Sha256};

use crate::candidate::BloomFilter;
use crate::candidate::grams::{
    DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes, pack_exact_gram,
};
use crate::perf::{record_counter, record_max, scope};
use crate::{Result, TgsError};

const ENTROPY_WINDOW_BYTES: usize = 1024;
const ENTROPY_REGION_COUNT: usize = 16;
const ENTROPY_BUCKET_MAXIMA: [f64; 6] = [4.94, 6.83, 7.55, 7.82, 7.93, 8.00];
const ENTROPY_BUCKET_WEIGHTS: [usize; 6] = [455, 318, 145, 55, 18, 5];
const MIN_SCALED_GRAM_BUDGET: usize = 1024;
const MAX_SCALED_GRAM_BUDGET: usize = 16_384;
pub const HLL_DEFAULT_PRECISION: u8 = 14;
const U64_MASK: u64 = u64::MAX;

#[derive(Clone, Debug)]
pub struct DocumentFeatures {
    pub sha256: [u8; 32],
    pub file_size: u64,
    pub bloom_filter: Vec<u8>,
    pub tier2_bloom_filter: Vec<u8>,
    pub unique_grams: Vec<u64>,
    pub unique_grams_truncated: bool,
    pub effective_diversity: Option<f64>,
}

impl DocumentFeatures {
    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

#[derive(Clone, Debug)]
struct EntropyWindow {
    window_index: usize,
    entropy: f64,
    unique_grams: Vec<u64>,
}

pub fn iter_grams_from_bytes_exact_u64(data: &[u8], gram_size: usize) -> Vec<u64> {
    if data.len() < gram_size {
        return Vec::new();
    }
    (0..=(data.len() - gram_size))
        .map(|idx| pack_exact_gram(&data[idx..idx + gram_size]))
        .collect()
}

fn stable_gram_rank(gram: u64, sha256_prefix: &[u8], hash_seed: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(hash_seed.to_le_bytes());
    hasher.update(gram.to_le_bytes());
    hasher.update(sha256_prefix);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]))
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
        return Err(TgsError::from("chunk_size must be > 0"));
    }
    if !(4..=18).contains(&precision) {
        return Err(TgsError::from("precision must be in range 4..18"));
    }
    if gram_size == 0 {
        return Err(TgsError::from("gram_size must be > 0"));
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
        return Err(TgsError::from("chunk_size must be > 0"));
    }
    if !(4..=18).contains(&precision) {
        return Err(TgsError::from("precision must be in range 4..18"));
    }
    if first_gram_size == 0 || second_gram_size == 0 {
        return Err(TgsError::from("gram_size must be > 0"));
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

pub fn estimate_unique_grams4_hll(
    path: impl AsRef<Path>,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_for_size_hll(path, 4, chunk_size, precision)
}

pub fn estimate_unique_grams5_hll(
    path: impl AsRef<Path>,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_for_size_hll(path, 5, chunk_size, precision)
}

pub fn estimate_unique_tier2_grams_hll(
    path: impl AsRef<Path>,
    tier2_gram_size: usize,
    chunk_size: usize,
    precision: u8,
) -> Result<usize> {
    estimate_unique_grams_for_size_hll(path, tier2_gram_size, chunk_size, precision)
}

pub fn iter_grams4_from_bytes(data: &[u8]) -> Vec<u64> {
    iter_grams_from_bytes_exact_u64(data, 4)
}

pub fn iter_grams5_from_bytes(data: &[u8]) -> Vec<u64> {
    iter_grams_from_bytes_exact_u64(data, 5)
}

pub fn iter_tier2_grams_from_bytes(data: &[u8], tier2_gram_size: usize) -> Vec<u64> {
    iter_grams_from_bytes_exact_u64(data, tier2_gram_size)
}

pub fn scale_tier1_gram_budget(base_budget: usize, estimated_unique_grams: usize) -> usize {
    if base_budget == 0 {
        return 0;
    }
    if estimated_unique_grams == 0 {
        return 0;
    }
    if estimated_unique_grams <= base_budget {
        return estimated_unique_grams;
    }
    let scaled = ((base_budget as f64) * (estimated_unique_grams as f64))
        .sqrt()
        .round() as usize;
    let min_cap = base_budget.max(MIN_SCALED_GRAM_BUDGET.min(base_budget));
    let max_cap = MAX_SCALED_GRAM_BUDGET.max(base_budget);
    scaled.clamp(min_cap, max_cap)
}

fn entropy_for_window(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u16; 256];
    for byte in data {
        counts[*byte as usize] = counts[*byte as usize].saturating_add(1);
    }
    let size = data.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / size;
        entropy -= probability * probability.log2();
    }
    entropy
}

fn entropy_bucket(entropy: f64) -> usize {
    for (index, maximum) in ENTROPY_BUCKET_MAXIMA.iter().enumerate() {
        if entropy <= *maximum {
            return index;
        }
    }
    ENTROPY_BUCKET_MAXIMA.len() - 1
}

fn split_weighted(total: usize, weights: &[usize]) -> Vec<usize> {
    if total == 0 {
        return vec![0; weights.len()];
    }
    let weight_total: usize = weights.iter().sum();
    let mut quotas = vec![0usize; weights.len()];
    let mut remainders: Vec<(usize, usize)> = Vec::with_capacity(weights.len());
    let mut assigned = 0usize;
    for (index, weight) in weights.iter().copied().enumerate() {
        let numerator = total.saturating_mul(weight);
        let quota = numerator / weight_total;
        quotas[index] = quota;
        assigned = assigned.saturating_add(quota);
        remainders.push((numerator % weight_total, index));
    }
    remainders.sort_unstable_by(|left, right| right.cmp(left));
    for (_remainder, index) in remainders.into_iter().take(total.saturating_sub(assigned)) {
        quotas[index] = quotas[index].saturating_add(1);
    }
    quotas
}

fn split_evenly(total: usize, buckets: usize) -> Vec<usize> {
    if buckets == 0 {
        return Vec::new();
    }
    if total == 0 {
        return vec![0; buckets];
    }
    let base = total / buckets;
    let remainder = total % buckets;
    (0..buckets)
        .map(|index| base + usize::from(index < remainder))
        .collect()
}

fn normalized_entropy_from_counts(counts: &[usize]) -> f64 {
    let total: usize = counts.iter().sum();
    let occupied = counts.iter().filter(|count| **count > 0).count();
    if total == 0 || occupied <= 1 {
        return 0.0;
    }
    let total = total as f64;
    let mut entropy = 0.0;
    for count in counts {
        if *count == 0 {
            continue;
        }
        let probability = *count as f64 / total;
        entropy -= probability * probability.log2();
    }
    let max_entropy = (occupied as f64).log2().max(1.0);
    (entropy / max_entropy).clamp(0.0, 1.0)
}

fn compute_effective_diversity(
    tier1_gram_estimate: Option<usize>,
    selected_count: usize,
    tier1_windows: u64,
    bucket_selected_counts: &[u64; 6],
    bucket_region_grams: &[Vec<Vec<u64>>],
    bucket_spill_grams: &[Vec<u64>],
    region_count: usize,
) -> f64 {
    if selected_count == 0 || tier1_windows == 0 {
        return 0.0;
    }

    let unique_estimate = tier1_gram_estimate
        .unwrap_or(selected_count)
        .max(selected_count);
    let uniqueness_ratio = (unique_estimate as f64 / tier1_windows as f64).clamp(0.0, 1.0);

    let mut region_counts = vec![0usize; region_count.max(1)];
    for bucket_regions in bucket_region_grams {
        for (region_index, grams) in bucket_regions.iter().enumerate() {
            if let Some(count) = region_counts.get_mut(region_index) {
                *count = count.saturating_add(grams.len());
            }
        }
    }
    let occupied_regions = region_counts.iter().filter(|count| **count > 0).count();
    let region_coverage =
        (occupied_regions as f64 / region_counts.len().max(1) as f64).clamp(0.0, 1.0);
    let region_evenness = normalized_entropy_from_counts(&region_counts);

    let mut bucket_counts: Vec<usize> = bucket_selected_counts
        .iter()
        .map(|count| *count as usize)
        .collect();
    if bucket_counts.iter().all(|count| *count == 0) {
        bucket_counts = bucket_region_grams
            .iter()
            .zip(bucket_spill_grams.iter())
            .map(|(regions, spill)| regions.iter().map(Vec::len).sum::<usize>() + spill.len())
            .collect();
    }
    let bucket_diversity = normalized_entropy_from_counts(&bucket_counts);

    (0.30 * uniqueness_ratio
        + 0.25 * region_coverage
        + 0.20 * region_evenness
        + 0.25 * bucket_diversity)
        .clamp(0.0, 1.0)
}

fn resolve_collection_budget(
    max_unique_grams: Option<usize>,
    tier1_gram_budget: usize,
    tier1_gram_estimate: Option<usize>,
) -> usize {
    let scaled_budget = tier1_gram_estimate
        .map(|estimate| scale_tier1_gram_budget(tier1_gram_budget, estimate))
        .unwrap_or(tier1_gram_budget);
    match max_unique_grams {
        Some(limit) if scaled_budget > 0 => limit.min(scaled_budget),
        Some(limit) => limit,
        None => scaled_budget,
    }
}

fn push_unique(vec: &mut Vec<u64>, gram: u64) {
    if !vec.contains(&gram) {
        vec.push(gram);
    }
}

#[allow(clippy::too_many_arguments)]
fn flush_entropy_window(
    window: EntropyWindow,
    total_windows: usize,
    region_count: usize,
    bucket_region_remaining: &mut [Vec<usize>],
    bucket_spill_remaining: &mut [usize],
    bucket_region_grams: &mut [Vec<Vec<u64>>],
    bucket_spill_grams: &mut [Vec<u64>],
    global_pool: &mut HashSet<u64>,
    bucket_window_counts: &mut [u64; 6],
) -> bool {
    let bucket = entropy_bucket(window.entropy);
    bucket_window_counts[bucket] = bucket_window_counts[bucket].saturating_add(1);
    let region = ((window.window_index.saturating_mul(region_count)) / total_windows.max(1))
        .min(region_count.saturating_sub(1));
    let mut truncated = false;
    for gram in window.unique_grams {
        if global_pool.contains(&gram) {
            continue;
        }
        if bucket_region_remaining[bucket][region] > 0 {
            bucket_region_grams[bucket][region].push(gram);
            bucket_region_remaining[bucket][region] -= 1;
            global_pool.insert(gram);
            continue;
        }
        if bucket_spill_remaining[bucket] > 0 {
            bucket_spill_grams[bucket].push(gram);
            bucket_spill_remaining[bucket] -= 1;
            global_pool.insert(gram);
            continue;
        }
        truncated = true;
    }
    truncated
}

#[allow(clippy::too_many_arguments)]
fn push_ready_window(
    queue: &mut Vec<EntropyWindow>,
    window: EntropyWindow,
    total_windows: usize,
    region_count: usize,
    bucket_region_remaining: &mut [Vec<usize>],
    bucket_spill_remaining: &mut [usize],
    bucket_region_grams: &mut [Vec<Vec<u64>>],
    bucket_spill_grams: &mut [Vec<u64>],
    global_pool: &mut HashSet<u64>,
    bucket_window_counts: &mut [u64; 6],
) -> bool {
    queue.push(window);
    if queue.len() < 3 {
        return false;
    }
    let middle = queue[1].clone();
    let smoothed = (queue[0].entropy + queue[1].entropy + queue[2].entropy) / 3.0;
    let truncated = flush_entropy_window(
        EntropyWindow {
            window_index: middle.window_index,
            entropy: smoothed,
            unique_grams: middle.unique_grams,
        },
        total_windows,
        region_count,
        bucket_region_remaining,
        bucket_spill_remaining,
        bucket_region_grams,
        bucket_spill_grams,
        global_pool,
        bucket_window_counts,
    );
    queue.remove(0);
    truncated
}

fn bucket_window_counter_name(bucket: usize) -> &'static str {
    match bucket {
        0 => "candidate.scan_file_features_entropy_bucket0_windows_total",
        1 => "candidate.scan_file_features_entropy_bucket1_windows_total",
        2 => "candidate.scan_file_features_entropy_bucket2_windows_total",
        3 => "candidate.scan_file_features_entropy_bucket3_windows_total",
        4 => "candidate.scan_file_features_entropy_bucket4_windows_total",
        _ => "candidate.scan_file_features_entropy_bucket5_windows_total",
    }
}

fn bucket_selected_counter_name(bucket: usize) -> &'static str {
    match bucket {
        0 => "candidate.scan_file_features_entropy_bucket0_selected_total",
        1 => "candidate.scan_file_features_entropy_bucket1_selected_total",
        2 => "candidate.scan_file_features_entropy_bucket2_selected_total",
        3 => "candidate.scan_file_features_entropy_bucket3_selected_total",
        4 => "candidate.scan_file_features_entropy_bucket4_selected_total",
        _ => "candidate.scan_file_features_entropy_bucket5_selected_total",
    }
}

pub fn select_tier1_grams(
    grams: &[u64],
    sha256: &[u8; 32],
    tier1_gram_budget: usize,
    tier1_gram_sample_mod: usize,
    tier1_gram_hash_seed: u64,
    grams_sorted_unique: bool,
    tier1_gram_estimate: Option<usize>,
) -> Result<(Vec<u64>, bool)> {
    if tier1_gram_sample_mod == 0 {
        return Err(TgsError::from("tier1_gram_sample_mod must be >= 1"));
    }
    let budget = match tier1_gram_estimate {
        Some(value) if tier1_gram_budget > 0 => scale_tier1_gram_budget(tier1_gram_budget, value),
        _ => tier1_gram_budget,
    };
    let unique_grams: Vec<u64> = if grams_sorted_unique {
        let mut prev = None;
        let mut valid = true;
        for gram in grams {
            if prev.is_some_and(|value| *gram <= value) {
                valid = false;
                break;
            }
            prev = Some(*gram);
        }
        if valid {
            grams.to_vec()
        } else {
            let mut dedup: Vec<u64> = grams
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            dedup.sort_unstable();
            dedup
        }
    } else {
        let mut dedup: Vec<u64> = grams
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        dedup.sort_unstable();
        dedup
    };
    if unique_grams.is_empty() {
        return Ok((Vec::new(), false));
    }
    if tier1_gram_sample_mod == 1 && (budget == 0 || unique_grams.len() <= budget) {
        return Ok((unique_grams, false));
    }

    let sha_prefix = &sha256[..8];
    let mut dropped = false;
    let mut ranked = Vec::with_capacity(unique_grams.len());
    for gram in unique_grams {
        let rank = stable_gram_rank(gram, sha_prefix, tier1_gram_hash_seed);
        if rank % tier1_gram_sample_mod as u64 != 0 {
            dropped = true;
            continue;
        }
        ranked.push((rank, gram));
    }

    if budget > 0 && ranked.len() > budget {
        ranked.sort_unstable_by_key(|item| (item.0, item.1));
        ranked.truncate(budget);
        dropped = true;
    }

    let mut selected: Vec<u64> = ranked.into_iter().map(|(_, gram)| gram).collect();
    selected.sort_unstable();
    Ok((selected, dropped))
}

#[allow(clippy::too_many_arguments)]
pub fn scan_file_features(
    path: impl AsRef<Path>,
    filter_bytes: usize,
    bloom_hashes: usize,
    tier2_filter_bytes: usize,
    tier2_bloom_hashes: usize,
    chunk_size: usize,
    collect_unique_grams: bool,
    max_unique_grams: Option<usize>,
    tier1_gram_estimate: Option<usize>,
    tier1_gram_budget: usize,
    tier1_gram_sample_mod: usize,
    tier1_gram_hash_seed: u64,
) -> Result<DocumentFeatures> {
    scan_file_features_with_gram_sizes(
        path,
        GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)?,
        filter_bytes,
        bloom_hashes,
        tier2_filter_bytes,
        tier2_bloom_hashes,
        chunk_size,
        collect_unique_grams,
        max_unique_grams,
        tier1_gram_estimate,
        tier1_gram_budget,
        tier1_gram_sample_mod,
        tier1_gram_hash_seed,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn scan_file_features_with_gram_sizes(
    path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    filter_bytes: usize,
    bloom_hashes: usize,
    tier2_filter_bytes: usize,
    tier2_bloom_hashes: usize,
    chunk_size: usize,
    collect_unique_grams: bool,
    max_unique_grams: Option<usize>,
    tier1_gram_estimate: Option<usize>,
    tier1_gram_budget: usize,
    tier1_gram_sample_mod: usize,
    tier1_gram_hash_seed: u64,
) -> Result<DocumentFeatures> {
    let mut total_scope = scope("candidate.scan_file_features");
    if chunk_size == 0 {
        return Err(TgsError::from("chunk_size must be > 0"));
    }
    if let Some(value) = max_unique_grams {
        if value == 0 {
            return Err(TgsError::from("max_unique_grams must be > 0 when set"));
        }
    }

    let file_path = path.as_ref();
    let expected_file_size = file_path.metadata()?.len();
    let mut file = File::open(file_path)?;
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
    let mut truncated = false;
    let mut buf = vec![0u8; chunk_size];
    let mut gram_windows = 0u64;

    let target_budget =
        resolve_collection_budget(max_unique_grams, tier1_gram_budget, tier1_gram_estimate);
    let total_windows = (((expected_file_size.max(1) as usize) + ENTROPY_WINDOW_BYTES - 1)
        / ENTROPY_WINDOW_BYTES)
        .max(1);
    let region_count = ENTROPY_REGION_COUNT.min(total_windows).max(1);
    let bucket_target_quotas = split_weighted(target_budget, &ENTROPY_BUCKET_WEIGHTS);
    let oversample_factor = tier1_gram_sample_mod.clamp(2, 4);
    let mut pool_budget = if target_budget > 0 {
        target_budget.saturating_mul(oversample_factor)
    } else {
        0
    };
    if let Some(limit) = max_unique_grams {
        pool_budget = pool_budget.min(limit);
    }
    let bucket_pool_quotas = split_weighted(pool_budget, &ENTROPY_BUCKET_WEIGHTS);
    let mut bucket_region_remaining = Vec::with_capacity(bucket_pool_quotas.len());
    let mut bucket_spill_remaining = Vec::with_capacity(bucket_pool_quotas.len());
    let mut bucket_region_grams = Vec::with_capacity(bucket_pool_quotas.len());
    let mut bucket_spill_grams = Vec::with_capacity(bucket_pool_quotas.len());
    for bucket_pool_quota in &bucket_pool_quotas {
        if *bucket_pool_quota == 0 {
            bucket_region_remaining.push(vec![0usize; region_count]);
            bucket_spill_remaining.push(0usize);
            bucket_region_grams.push(vec![Vec::<u64>::new(); region_count]);
            bucket_spill_grams.push(Vec::<u64>::new());
            continue;
        }
        let coverage_target = (*bucket_pool_quota)
            .min(((f64::from(*bucket_pool_quota as u32) * 0.75).ceil() as usize).max(1));
        bucket_region_remaining.push(split_evenly(coverage_target, region_count));
        bucket_spill_remaining.push(bucket_pool_quota.saturating_sub(coverage_target));
        bucket_region_grams.push(vec![Vec::<u64>::new(); region_count]);
        bucket_spill_grams.push(Vec::<u64>::new());
    }
    let mut bucket_window_counts = [0u64; 6];
    let mut global_pool = HashSet::<u64>::new();
    let mut pending_window: Option<EntropyWindow> = None;
    let mut smoothing_queue: Vec<EntropyWindow> = Vec::new();
    let mut current_window_index = 0usize;
    let mut stream_buffer = Vec::<u8>::new();
    let mut buffer_start = 0usize;

    if collect_unique_grams && target_budget > 0 {
        loop {
            let read_len = file.read(&mut buf)?;
            if read_len == 0 {
                break;
            }
            let chunk = &buf[..read_len];
            file_size = file_size.saturating_add(read_len as u64);
            digest.update(chunk);
            stream_buffer.extend_from_slice(chunk);
            while stream_buffer.len().saturating_sub(buffer_start) >= ENTROPY_WINDOW_BYTES {
                let current =
                    stream_buffer[buffer_start..buffer_start + ENTROPY_WINDOW_BYTES].to_vec();
                buffer_start += ENTROPY_WINDOW_BYTES;
                let mut data = trailing.clone();
                data.extend_from_slice(&current);
                let mut current_unique = Vec::<u64>::new();
                let mut current_seen = HashSet::<u64>::new();
                if data.len() >= gram_sizes.tier1 {
                    for idx in 0..=(data.len() - gram_sizes.tier1) {
                        let gram = pack_exact_gram(&data[idx..idx + gram_sizes.tier1]);
                        bloom.add(gram)?;
                        gram_windows = gram_windows.saturating_add(1);
                        if idx < trailing.len() {
                            if let Some(window) = pending_window.as_mut() {
                                push_unique(&mut window.unique_grams, gram);
                            }
                        } else if current_seen.insert(gram) {
                            current_unique.push(gram);
                        }
                    }
                }
                if let Some(tier2_bloom_ref) = tier2_bloom.as_mut() {
                    if data.len() >= gram_sizes.tier2 {
                        for idx in 0..=(data.len() - gram_sizes.tier2) {
                            tier2_bloom_ref
                                .add(pack_exact_gram(&data[idx..idx + gram_sizes.tier2]))?;
                        }
                    }
                }
                if let Some(window) = pending_window.take() {
                    truncated = push_ready_window(
                        &mut smoothing_queue,
                        window,
                        total_windows,
                        region_count,
                        &mut bucket_region_remaining,
                        &mut bucket_spill_remaining,
                        &mut bucket_region_grams,
                        &mut bucket_spill_grams,
                        &mut global_pool,
                        &mut bucket_window_counts,
                    ) || truncated;
                }
                pending_window = Some(EntropyWindow {
                    window_index: current_window_index,
                    entropy: entropy_for_window(&current),
                    unique_grams: current_unique,
                });
                current_window_index = current_window_index.saturating_add(1);
                trailing = if current.len() >= trailing_bytes {
                    current[current.len() - trailing_bytes..].to_vec()
                } else {
                    current.clone()
                };
            }
            if buffer_start > 0 {
                stream_buffer.drain(..buffer_start);
                buffer_start = 0;
            }
        }

        if !stream_buffer.is_empty() {
            let current = stream_buffer.clone();
            let mut data = trailing.clone();
            data.extend_from_slice(&current);
            let mut current_unique = Vec::<u64>::new();
            let mut current_seen = HashSet::<u64>::new();
            if data.len() >= gram_sizes.tier1 {
                for idx in 0..=(data.len() - gram_sizes.tier1) {
                    let gram = pack_exact_gram(&data[idx..idx + gram_sizes.tier1]);
                    bloom.add(gram)?;
                    gram_windows = gram_windows.saturating_add(1);
                    if idx < trailing.len() {
                        if let Some(window) = pending_window.as_mut() {
                            push_unique(&mut window.unique_grams, gram);
                        }
                    } else if current_seen.insert(gram) {
                        current_unique.push(gram);
                    }
                }
            }
            if let Some(tier2_bloom_ref) = tier2_bloom.as_mut() {
                if data.len() >= gram_sizes.tier2 {
                    for idx in 0..=(data.len() - gram_sizes.tier2) {
                        tier2_bloom_ref.add(pack_exact_gram(&data[idx..idx + gram_sizes.tier2]))?;
                    }
                }
            }
            if let Some(window) = pending_window.take() {
                truncated = push_ready_window(
                    &mut smoothing_queue,
                    window,
                    total_windows,
                    region_count,
                    &mut bucket_region_remaining,
                    &mut bucket_spill_remaining,
                    &mut bucket_region_grams,
                    &mut bucket_spill_grams,
                    &mut global_pool,
                    &mut bucket_window_counts,
                ) || truncated;
            }
            pending_window = Some(EntropyWindow {
                window_index: current_window_index,
                entropy: entropy_for_window(&current),
                unique_grams: current_unique,
            });
        }

        if let Some(window) = pending_window.take() {
            smoothing_queue.push(window);
        }
        match smoothing_queue.len() {
            0 => {}
            1 => {
                truncated = flush_entropy_window(
                    smoothing_queue.remove(0),
                    total_windows,
                    region_count,
                    &mut bucket_region_remaining,
                    &mut bucket_spill_remaining,
                    &mut bucket_region_grams,
                    &mut bucket_spill_grams,
                    &mut global_pool,
                    &mut bucket_window_counts,
                ) || truncated;
            }
            _ => {
                let avg = (smoothing_queue[0].entropy + smoothing_queue[1].entropy) / 2.0;
                while let Some(window) = smoothing_queue.pop() {
                    truncated = flush_entropy_window(
                        EntropyWindow {
                            window_index: window.window_index,
                            entropy: avg,
                            unique_grams: window.unique_grams,
                        },
                        total_windows,
                        region_count,
                        &mut bucket_region_remaining,
                        &mut bucket_spill_remaining,
                        &mut bucket_region_grams,
                        &mut bucket_spill_grams,
                        &mut global_pool,
                        &mut bucket_window_counts,
                    ) || truncated;
                }
            }
        }
    } else {
        loop {
            let read_len = file.read(&mut buf)?;
            if read_len == 0 {
                break;
            }
            let chunk = &buf[..read_len];
            file_size = file_size.saturating_add(read_len as u64);
            digest.update(chunk);
            let mut data = trailing.clone();
            data.extend_from_slice(chunk);
            if data.len() < gram_sizes.tier1 {
                trailing = data;
                continue;
            }
            for idx in 0..=(data.len() - gram_sizes.tier1) {
                bloom.add(pack_exact_gram(&data[idx..idx + gram_sizes.tier1]))?;
                gram_windows = gram_windows.saturating_add(1);
            }
            if let Some(tier2_bloom_ref) = tier2_bloom.as_mut() {
                if data.len() >= gram_sizes.tier2 {
                    for idx in 0..=(data.len() - gram_sizes.tier2) {
                        tier2_bloom_ref.add(pack_exact_gram(&data[idx..idx + gram_sizes.tier2]))?;
                    }
                }
            }
            trailing = data[data.len() - trailing_bytes..].to_vec();
        }
    }

    let digest_bytes = digest.finalize();
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&digest_bytes);

    let mut bucket_selected_counts = [0u64; 6];
    let (unique_grams, dropped) = if collect_unique_grams {
        if target_budget > 0 {
            let mut selected = Vec::<u64>::new();
            let mut selected_set = HashSet::<u64>::new();
            let mut leftovers = Vec::<u64>::new();
            for (bucket_index, bucket_quota) in bucket_target_quotas.iter().copied().enumerate() {
                let mut candidates = Vec::<u64>::new();
                for region_values in &bucket_region_grams[bucket_index] {
                    candidates.extend(region_values.iter().copied());
                }
                candidates.extend(bucket_spill_grams[bucket_index].iter().copied());
                if candidates.is_empty() {
                    continue;
                }
                if bucket_quota == 0 {
                    leftovers.extend(candidates.iter().copied());
                    truncated = true;
                    continue;
                }
                let (selected_bucket, bucket_dropped) = select_tier1_grams(
                    &candidates,
                    &sha256,
                    bucket_quota,
                    tier1_gram_sample_mod,
                    tier1_gram_hash_seed,
                    false,
                    None,
                )?;
                let bucket_set: HashSet<u64> = selected_bucket.iter().copied().collect();
                bucket_selected_counts[bucket_index] = bucket_selected_counts[bucket_index]
                    .saturating_add(selected_bucket.len() as u64);
                for gram in &selected_bucket {
                    if selected_set.insert(*gram) {
                        selected.push(*gram);
                    }
                }
                leftovers.extend(
                    candidates
                        .into_iter()
                        .filter(|gram| !bucket_set.contains(gram)),
                );
                truncated = truncated
                    || bucket_dropped
                    || bucket_set.len()
                        < bucket_region_grams[bucket_index]
                            .iter()
                            .map(Vec::len)
                            .sum::<usize>()
                            + bucket_spill_grams[bucket_index].len();
            }

            let remaining = target_budget.saturating_sub(selected_set.len());
            if remaining > 0 && !leftovers.is_empty() {
                let (refill, refill_dropped) = select_tier1_grams(
                    &leftovers,
                    &sha256,
                    remaining,
                    tier1_gram_sample_mod,
                    tier1_gram_hash_seed,
                    false,
                    None,
                )?;
                for gram in refill {
                    if selected_set.insert(gram) {
                        selected.push(gram);
                    }
                }
                truncated = truncated || refill_dropped;
            }
            selected.sort_unstable();
            truncated = truncated || global_pool.len() > selected.len();
            (selected, truncated)
        } else {
            let mut replay = File::open(file_path)?;
            let mut replay_buf = vec![0u8; chunk_size];
            let mut replay_trailing = Vec::<u8>::new();
            let mut grams_set = HashSet::<u64>::new();
            loop {
                let read_len = replay.read(&mut replay_buf)?;
                if read_len == 0 {
                    break;
                }
                let chunk = &replay_buf[..read_len];
                let mut data = replay_trailing.clone();
                data.extend_from_slice(chunk);
                if data.len() < gram_sizes.tier1 {
                    replay_trailing = data;
                    continue;
                }
                for idx in 0..=(data.len() - gram_sizes.tier1) {
                    grams_set.insert(pack_exact_gram(&data[idx..idx + gram_sizes.tier1]));
                }
                replay_trailing = data[data.len() - (gram_sizes.tier1 - 1)..].to_vec();
            }
            let mut grams: Vec<u64> = grams_set.into_iter().collect();
            grams.sort_unstable();
            select_tier1_grams(
                &grams,
                &sha256,
                tier1_gram_budget,
                tier1_gram_sample_mod,
                tier1_gram_hash_seed,
                true,
                tier1_gram_estimate,
            )?
        }
    } else {
        (Vec::new(), false)
    };

    total_scope.add_bytes(file_size);
    total_scope.add_items(gram_windows);
    record_counter("candidate.scan_file_features_bytes_total", file_size);
    record_counter("candidate.scan_file_features_windows_total", gram_windows);
    record_counter(
        "candidate.scan_file_features_unique_grams_total",
        unique_grams.len() as u64,
    );
    record_counter(
        "candidate.scan_file_features_effective_budget_total",
        target_budget as u64,
    );
    record_max("candidate.scan_file_features_max_bytes", file_size);
    record_max(
        "candidate.scan_file_features_max_unique_grams",
        unique_grams.len() as u64,
    );
    record_max(
        "candidate.scan_file_features_max_effective_budget",
        target_budget as u64,
    );
    for (bucket, count) in bucket_window_counts.iter().copied().enumerate() {
        if count > 0 {
            record_counter(bucket_window_counter_name(bucket), count);
        }
    }
    for (bucket, count) in bucket_selected_counts.iter().copied().enumerate() {
        if count > 0 {
            record_counter(bucket_selected_counter_name(bucket), count);
        }
    }

    let retained_unique_grams = unique_grams.len();
    Ok(DocumentFeatures {
        sha256,
        file_size,
        bloom_filter: bloom.into_bytes(),
        tier2_bloom_filter: tier2_bloom.map(BloomFilter::into_bytes).unwrap_or_default(),
        unique_grams,
        unique_grams_truncated: dropped,
        effective_diversity: if collect_unique_grams {
            Some(compute_effective_diversity(
                tier1_gram_estimate,
                retained_unique_grams,
                gram_windows,
                &bucket_selected_counts,
                &bucket_region_grams,
                &bucket_spill_grams,
                region_count,
            ))
        } else {
            None
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub fn scan_file_features_with_tier2_gram_size(
    path: impl AsRef<Path>,
    tier2_gram_size: usize,
    filter_bytes: usize,
    bloom_hashes: usize,
    tier2_filter_bytes: usize,
    tier2_bloom_hashes: usize,
    chunk_size: usize,
    collect_unique_grams: bool,
    max_unique_grams: Option<usize>,
    tier1_gram_estimate: Option<usize>,
    tier1_gram_budget: usize,
    tier1_gram_sample_mod: usize,
    tier1_gram_hash_seed: u64,
) -> Result<DocumentFeatures> {
    scan_file_features_with_gram_sizes(
        path,
        GramSizes::new(tier2_gram_size, DEFAULT_TIER1_GRAM_SIZE)?,
        filter_bytes,
        bloom_hashes,
        tier2_filter_bytes,
        tier2_bloom_hashes,
        chunk_size,
        collect_unique_grams,
        max_unique_grams,
        tier1_gram_estimate,
        tier1_gram_budget,
        tier1_gram_sample_mod,
        tier1_gram_hash_seed,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use hashbrown::HashSet;
    use tempfile::tempdir;

    use super::{
        EntropyWindow, HLL_DEFAULT_PRECISION, bucket_selected_counter_name,
        bucket_window_counter_name, entropy_bucket, entropy_for_window,
        estimate_unique_grams_for_size_hll, estimate_unique_grams_pair_hll,
        estimate_unique_grams4_hll, estimate_unique_grams5_hll, estimate_unique_tier2_grams_hll,
        flush_entropy_window, iter_grams4_from_bytes, iter_grams5_from_bytes,
        iter_tier2_grams_from_bytes, push_ready_window, push_unique, resolve_collection_budget,
        scale_tier1_gram_budget, scan_file_features, scan_file_features_with_tier2_gram_size,
        select_tier1_grams, split_evenly, split_weighted,
    };
    use crate::candidate::grams::{DEFAULT_TIER1_GRAM_SIZE, GramSizes};

    #[test]
    fn grams4_iterates_sliding_windows() {
        let grams = iter_grams4_from_bytes(b"ABCDE");
        assert_eq!(grams.len(), 2);
        assert!(iter_grams4_from_bytes(b"ABC").is_empty());
    }

    #[test]
    fn scaled_budget_is_sublinear() {
        assert_eq!(scale_tier1_gram_budget(4096, 1024), 1024);
        assert_eq!(scale_tier1_gram_budget(4096, 4096), 4096);
        assert_eq!(scale_tier1_gram_budget(4096, 16_384), 8192);
        assert_eq!(scale_tier1_gram_budget(4096, 65_536), 16_384);
        assert_eq!(scale_tier1_gram_budget(4, 32), 11);
    }

    #[test]
    fn select_tier1_grams_respects_scaled_budget() {
        let sha = [7u8; 32];
        let grams: Vec<u64> = (0..10_000u64).collect();
        let budget = scale_tier1_gram_budget(4096, 16_384);
        let (selected, dropped) =
            select_tier1_grams(&grams, &sha, 4096, 1, 1337, false, Some(16_384))
                .expect("scaled selection");
        assert_eq!(selected.len(), budget);
        assert!(dropped);
    }

    #[test]
    fn scan_file_features_hashes_and_collects_grams() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("doc.bin");
        fs::write(&path, b"xxABCDyy").expect("write");
        let features =
            scan_file_features(&path, 64, 4, 0, 0, 1024, true, None, None, 1024, 1, 1337)
                .expect("features");
        assert_eq!(features.file_size, 8);
        assert!(!features.unique_grams.is_empty());
    }

    #[test]
    fn scan_file_features_scales_budget_for_large_files() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("large.bin");
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let payload: Vec<u8> = (0..(2 * 1024 * 1024))
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xFF) as u8
            })
            .collect();
        fs::write(&path, payload.as_slice()).expect("write");
        let estimate = estimate_unique_grams_for_size_hll(
            &path,
            DEFAULT_TIER1_GRAM_SIZE,
            4096,
            HLL_DEFAULT_PRECISION,
        )
        .expect("estimate");
        let features = scan_file_features(
            &path,
            2048,
            7,
            0,
            0,
            4096,
            true,
            None,
            Some(estimate),
            4096,
            1,
            1337,
        )
        .expect("features");
        assert!(features.unique_grams.len() > 128);
        assert!(features.unique_grams.len() <= scale_tier1_gram_budget(4096, estimate));
        assert!(features.unique_grams_truncated);
    }

    #[test]
    fn entropy_and_budget_helpers_cover_branches() {
        assert_eq!(
            super::DocumentFeatures {
                sha256: [0xAB; 32],
                file_size: 0,
                bloom_filter: Vec::new(),
                tier2_bloom_filter: Vec::new(),
                unique_grams: Vec::new(),
                unique_grams_truncated: false,
                effective_diversity: None,
            }
            .sha256_hex(),
            hex::encode([0xAB; 32])
        );
        assert_eq!(entropy_for_window(&[]), 0.0);
        assert_eq!(entropy_bucket(0.0), 0);
        assert_eq!(entropy_bucket(8.5), 5);
        assert_eq!(split_weighted(0, &[1, 2, 3]), vec![0, 0, 0]);
        assert_eq!(split_evenly(0, 3), vec![0, 0, 0]);
        assert!(split_evenly(5, 0).is_empty());
        assert_eq!(resolve_collection_budget(Some(16), 1024, Some(32)), 16);
        assert_eq!(resolve_collection_budget(None, 1024, Some(32)), 32);
        assert_eq!(resolve_collection_budget(None, 0, None), 0);
        let mut values = vec![1u64];
        push_unique(&mut values, 1);
        push_unique(&mut values, 2);
        assert_eq!(values, vec![1, 2]);
        assert_eq!(
            bucket_window_counter_name(0),
            "candidate.scan_file_features_entropy_bucket0_windows_total"
        );
        assert_eq!(
            bucket_selected_counter_name(5),
            "candidate.scan_file_features_entropy_bucket5_selected_total"
        );
    }

    #[test]
    fn entropy_window_selection_helpers_cover_smoothing_and_truncation() {
        let mut bucket_region_remaining = vec![vec![1usize; 2]; 6];
        let mut bucket_spill_remaining = vec![0usize; 6];
        let mut bucket_region_grams = vec![vec![Vec::<u64>::new(); 2]; 6];
        let mut bucket_spill_grams = vec![Vec::<u64>::new(); 6];
        let mut global_pool = HashSet::<u64>::new();
        let mut bucket_window_counts = [0u64; 6];
        let truncated = flush_entropy_window(
            EntropyWindow {
                window_index: 0,
                entropy: 3.0,
                unique_grams: vec![1, 2],
            },
            2,
            2,
            &mut bucket_region_remaining,
            &mut bucket_spill_remaining,
            &mut bucket_region_grams,
            &mut bucket_spill_grams,
            &mut global_pool,
            &mut bucket_window_counts,
        );
        assert!(truncated);
        assert_eq!(bucket_window_counts[0], 1);
        assert_eq!(bucket_region_grams[0][0], vec![1]);

        let mut queue = Vec::new();
        let mut bucket_region_remaining = vec![vec![2usize; 2]; 6];
        let mut bucket_spill_remaining = vec![1usize; 6];
        let mut bucket_region_grams = vec![vec![Vec::<u64>::new(); 2]; 6];
        let mut bucket_spill_grams = vec![Vec::<u64>::new(); 6];
        let mut global_pool = HashSet::<u64>::new();
        let mut bucket_window_counts = [0u64; 6];
        assert!(!push_ready_window(
            &mut queue,
            EntropyWindow {
                window_index: 0,
                entropy: 5.0,
                unique_grams: vec![10],
            },
            4,
            2,
            &mut bucket_region_remaining,
            &mut bucket_spill_remaining,
            &mut bucket_region_grams,
            &mut bucket_spill_grams,
            &mut global_pool,
            &mut bucket_window_counts,
        ));
        assert!(!push_ready_window(
            &mut queue,
            EntropyWindow {
                window_index: 1,
                entropy: 5.5,
                unique_grams: vec![11],
            },
            4,
            2,
            &mut bucket_region_remaining,
            &mut bucket_spill_remaining,
            &mut bucket_region_grams,
            &mut bucket_spill_grams,
            &mut global_pool,
            &mut bucket_window_counts,
        ));
        assert!(!push_ready_window(
            &mut queue,
            EntropyWindow {
                window_index: 2,
                entropy: 6.0,
                unique_grams: vec![12],
            },
            4,
            2,
            &mut bucket_region_remaining,
            &mut bucket_spill_remaining,
            &mut bucket_region_grams,
            &mut bucket_spill_grams,
            &mut global_pool,
            &mut bucket_window_counts,
        ));
        assert_eq!(queue.len(), 2);
        assert!(bucket_window_counts.iter().sum::<u64>() >= 1);
    }

    #[test]
    fn select_tier1_grams_and_scan_errors_cover_remaining_paths() {
        let sha = [9u8; 32];
        assert!(
            select_tier1_grams(&[1, 2], &sha, 4, 0, 1337, false, None)
                .expect_err("sample modulus zero")
                .to_string()
                .contains("must be >= 1")
        );
        let (selected, dropped) = select_tier1_grams(&[3, 2, 2, 1], &sha, 8, 1, 1337, true, None)
            .expect("dedup unsorted");
        assert_eq!(selected, vec![1, 2, 3]);
        assert!(!dropped);
        let (sampled, dropped) = select_tier1_grams(
            &(0..128u64).collect::<Vec<_>>(),
            &sha,
            16,
            3,
            1337,
            false,
            None,
        )
        .expect("sampled grams");
        assert!(sampled.len() <= 16);
        assert!(dropped);

        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("small.bin");
        fs::write(&path, b"ABCDE").expect("write");
        assert!(
            scan_file_features(&path, 64, 4, 0, 0, 0, true, None, None, 1024, 1, 1337)
                .expect_err("chunk size zero")
                .to_string()
                .contains("chunk_size must be > 0")
        );
        assert!(
            scan_file_features(&path, 64, 4, 0, 0, 1024, true, Some(0), None, 1024, 1, 1337)
                .expect_err("max grams zero")
                .to_string()
                .contains("max_unique_grams must be > 0")
        );
        let no_grams =
            scan_file_features(&path, 64, 4, 0, 0, 1024, false, None, None, 1024, 1, 1337)
                .expect("no grams");
        assert!(no_grams.unique_grams.is_empty());
        let replay = scan_file_features(&path, 64, 4, 0, 0, 1024, true, None, None, 1024, 2, 1337)
            .expect("replay path");
        assert!(replay.unique_grams.len() <= iter_grams4_from_bytes(b"ABCDE").len());
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
    fn wrapper_iterators_and_hll_helpers_cover_secondary_sizes() {
        let payload = b"ABCDEFG";
        assert_eq!(iter_grams5_from_bytes(payload).len(), 3);
        assert_eq!(iter_tier2_grams_from_bytes(payload, 3).len(), 5);
        assert!(iter_tier2_grams_from_bytes(b"AB", 3).is_empty());

        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("wrappers.bin");
        fs::write(&path, payload).expect("write");
        let estimate5 = estimate_unique_grams5_hll(&path, 4, 4).expect("estimate5");
        let estimate_secondary =
            estimate_unique_tier2_grams_hll(&path, 3, 4, 5).expect("estimate secondary");
        assert!(estimate5 > 0);
        assert!(estimate_secondary > 0);
    }

    #[test]
    fn paired_hll_estimate_matches_individual_estimates() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("paired-hll.bin");
        let payload = b"ABCDEFGHABCDEFGH12345678IJKLMNOP";
        fs::write(&path, payload).expect("write");

        let exact4 = estimate_unique_grams4_hll(&path, 8, 10).expect("exact4");
        let exact5 = estimate_unique_grams5_hll(&path, 8, 10).expect("exact5");
        let (paired4, paired5) = estimate_unique_grams_pair_hll(&path, 4, 5, 8, 10).expect("pair");
        assert_eq!(paired4, exact4);
        assert_eq!(paired5, exact5);

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
        assert_eq!(estimate_unique_grams5_hll(&path, 8, 5).expect("p5"), 0);
        assert!(estimate_unique_tier2_grams_hll(&path, 3, 8, 6).expect("p6 secondary") > 0);

        let features = scan_file_features_with_tier2_gram_size(
            &path,
            3,
            64,
            4,
            64,
            4,
            16,
            true,
            Some(1),
            None,
            0,
            1,
            1337,
        )
        .expect("features");
        assert_eq!(features.file_size, 4);
        assert_eq!(features.unique_grams.len(), 1);
        assert!(!features.tier2_bloom_filter.is_empty());
    }

    #[test]
    fn scan_with_custom_gram_sizes_and_zero_budget_paths_work() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("custom.bin");
        fs::write(&path, b"ABCDEFGHABCDEFGH").expect("write");
        let features = super::scan_file_features_with_gram_sizes(
            &path,
            GramSizes::new(4, 5).expect("sizes"),
            64,
            4,
            64,
            4,
            8,
            true,
            None,
            None,
            0,
            1,
            1337,
        )
        .expect("features");
        assert!(!features.unique_grams.is_empty());
        assert!(!features.unique_grams_truncated);
        assert!(!features.bloom_filter.is_empty());
        assert!(!features.tier2_bloom_filter.is_empty());

        let direct = super::iter_grams_from_bytes_exact_u64(b"ABCDEFGH", DEFAULT_TIER1_GRAM_SIZE);
        assert_eq!(direct.len(), 5);
    }
}
