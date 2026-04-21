use crate::{Result, SspryError};

const LN_2: f64 = std::f64::consts::LN_2;
const LN_2_SQ: f64 = LN_2 * LN_2;
const BLOOM_WORD_BYTES: usize = 8;
pub const MIN_FILTER_TARGET_FP: f64 = 0.01;
pub const MAX_FILTER_TARGET_FP: f64 = 0.5;

/// Returns the integer hash-count target implied by a bloom false-positive
/// rate using the standard `k ~= log2(1 / p)` approximation.
fn optimal_hash_count_for_target_fp(value: f64) -> usize {
    ((1.0 / value).log2().round() as usize).max(1)
}

/// Returns the largest hash count supported by the current target-fp policy.
pub fn max_supported_bloom_hashes() -> usize {
    optimal_hash_count_for_target_fp(MIN_FILTER_TARGET_FP)
}

/// Validates that a configured bloom target false-positive rate stays within
/// the supported operating range for the current sizing policy.
fn validate_target_fp(value: f64, field: &str) -> Result<()> {
    if (MIN_FILTER_TARGET_FP..=MAX_FILTER_TARGET_FP).contains(&value) {
        return Ok(());
    }
    Err(SspryError::from(format!(
        "{field} must be in range [{MIN_FILTER_TARGET_FP}, {MAX_FILTER_TARGET_FP}]",
    )))
}

/// Rounds a bloom payload size up to the nearest whole machine word so mask
/// operations can stay word-aligned.
pub(crate) fn align_filter_bytes(value: usize) -> usize {
    value.max(1).div_ceil(BLOOM_WORD_BYTES) * BLOOM_WORD_BYTES
}

/// Rounds a positive size up to the next power of two, clamping tiny values to
/// one byte.
fn round_up_power_of_two(value: usize) -> usize {
    if value <= 1 {
        return 1;
    }
    value.next_power_of_two()
}

/// Rounds a theoretical bloom size to the nearest KiB while enforcing a 1 KiB
/// minimum for very small filters.
fn round_to_nearest_kib(value: usize) -> usize {
    if value == 0 {
        return 1024;
    }
    if value < 1024 {
        return 1024;
    }
    ((value + 512) / 1024) * 1024
}

/// Normalizes the caller's bloom sizing policy into aligned minimum and
/// maximum bounds plus an optional target false-positive rate.
fn normalize_filter_policy(
    base_filter_bytes: usize,
    filter_min_bytes: Option<usize>,
    filter_max_bytes: Option<usize>,
    filter_target_fp: Option<f64>,
) -> Result<(usize, usize, Option<f64>)> {
    let base = align_filter_bytes(base_filter_bytes);
    let minimum = align_filter_bytes(round_up_power_of_two(filter_min_bytes.unwrap_or(base)));
    let raw_maximum = filter_max_bytes.unwrap_or(base);
    let mut maximum = if raw_maximum == 0 {
        0
    } else {
        align_filter_bytes(round_up_power_of_two(raw_maximum))
    };
    if maximum != 0 && maximum < minimum {
        maximum = minimum;
    }
    if let Some(value) = filter_target_fp {
        validate_target_fp(value, "filter_target_fp")?;
    }
    Ok((minimum, maximum, filter_target_fp))
}

/// Derives an overall bloom hash count from a target false-positive rate, or
/// falls back to the configured default when no target is set.
pub fn derive_bloom_hash_count(target_fp: Option<f64>, fallback_hashes: usize) -> Result<usize> {
    let maximum = max_supported_bloom_hashes();
    let fallback = fallback_hashes.max(1).min(maximum);
    let Some(fp) = target_fp else {
        return Ok(fallback);
    };
    validate_target_fp(fp, "target_fp")?;
    let estimate = optimal_hash_count_for_target_fp(fp);
    Ok(estimate.clamp(1, maximum))
}

/// Estimates a per-document bloom hash count from the filter density implied
/// by the current item estimate.
pub fn derive_document_bloom_hash_count(
    filter_bytes: usize,
    bloom_item_estimate: Option<usize>,
    fallback_hashes: usize,
) -> usize {
    let maximum = max_supported_bloom_hashes();
    let fallback = fallback_hashes.max(1).min(maximum);
    let Some(bloom_item_estimate) = bloom_item_estimate else {
        return fallback;
    };
    let gram_count = bloom_item_estimate.max(1) as f64;
    let bits = (filter_bytes.max(1) * 8) as f64;
    let estimate = ((bits / gram_count) * LN_2).round() as usize;
    estimate.clamp(1, maximum)
}

/// Chooses the filter size for one document by combining file-size heuristics,
/// optional bounds, and optional false-positive-rate targeting.
pub fn choose_filter_bytes_for_file_size(
    file_size: u64,
    base_filter_bytes: usize,
    filter_min_bytes: Option<usize>,
    filter_max_bytes: Option<usize>,
    filter_target_fp: Option<f64>,
    bloom_item_estimate: Option<usize>,
) -> Result<usize> {
    let (minimum, maximum, target_fp) = normalize_filter_policy(
        base_filter_bytes,
        filter_min_bytes,
        filter_max_bytes,
        filter_target_fp,
    )?;
    let size = file_size as usize;
    let size_target = minimum.max(size);
    let target = if let Some(fp) = target_fp {
        let gram_count =
            bloom_item_estimate.unwrap_or_else(|| size.saturating_sub(3).max(1)) as f64;
        let bits = ((-gram_count * fp.ln()) / LN_2_SQ).ceil() as usize;
        let theoretical_bytes = bits.div_ceil(8).max(1);
        let _ = (minimum, maximum, size_target);
        align_filter_bytes(round_to_nearest_kib(theoretical_bytes))
    } else {
        align_filter_bytes(round_up_power_of_two(if maximum == 0 {
            size_target
        } else {
            size_target.min(maximum)
        }))
    };
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_FILTER_TARGET_FP, MIN_FILTER_TARGET_FP, align_filter_bytes,
        choose_filter_bytes_for_file_size, derive_bloom_hash_count,
        derive_document_bloom_hash_count, max_supported_bloom_hashes, normalize_filter_policy,
    };

    #[test]
    fn variable_filter_size_rounds_to_power_of_two() {
        let selected =
            choose_filter_bytes_for_file_size(10_000, 2048, Some(2048), Some(131_072), None, None)
                .expect("size");
        assert!(selected.is_power_of_two());
        assert!(selected >= 2048);
    }

    #[test]
    fn target_fp_mode_uses_bloom_item_estimate_when_present() {
        let from_size = choose_filter_bytes_for_file_size(
            1024 * 1024,
            512 * 1024,
            Some(8 * 1024),
            Some(512 * 1024),
            Some(0.25),
            None,
        )
        .expect("size-based filter");
        let from_hll = choose_filter_bytes_for_file_size(
            1024 * 1024,
            512 * 1024,
            Some(8 * 1024),
            Some(512 * 1024),
            Some(0.25),
            Some(4096),
        )
        .expect("estimate-based filter");
        assert_eq!(from_size, 377_856);
        assert_eq!(from_hll, 1024);
    }

    #[test]
    fn unbounded_target_fp_mode_uses_theoretical_bytes_rounded_to_kib() {
        let selected = choose_filter_bytes_for_file_size(
            18_801_212,
            2048,
            Some(2048),
            Some(0),
            Some(0.01),
            Some(22_000_000),
        )
        .expect("theoretical size");
        assert_eq!(selected, 26_358_784);
    }

    #[test]
    fn document_hash_count_uses_filter_density_when_estimate_present() {
        assert_eq!(
            derive_document_bloom_hash_count(262_144, Some(1_000_000), 13),
            1
        );
        assert_eq!(derive_document_bloom_hash_count(2048, None, 7), 7);
        assert_eq!(derive_document_bloom_hash_count(2048, None, 13), 7);
        assert_eq!(derive_document_bloom_hash_count(2048, Some(1), 7), 7);
    }

    #[test]
    fn filter_policy_helpers_cover_validation_and_rounding_edges() {
        let (minimum, maximum, fp) =
            normalize_filter_policy(2048, Some(3000), Some(1024), None).expect("normalized");
        assert_eq!(minimum, 4096);
        assert_eq!(maximum, 4096);
        assert_eq!(fp, None);

        normalize_filter_policy(2048, None, None, Some(MIN_FILTER_TARGET_FP))
            .expect("minimum target fp");
        normalize_filter_policy(2048, None, None, Some(MAX_FILTER_TARGET_FP))
            .expect("maximum target fp");
        assert_eq!(max_supported_bloom_hashes(), 7);
        assert!(normalize_filter_policy(2048, None, None, Some(0.009)).is_err());
        assert!(normalize_filter_policy(2048, None, None, Some(0.51)).is_err());
        assert_eq!(derive_bloom_hash_count(None, 0).expect("fallback"), 1);
        assert_eq!(
            derive_bloom_hash_count(None, 13).expect("capped fallback"),
            7
        );
        assert_eq!(derive_bloom_hash_count(Some(0.25), 13).expect("derived"), 2);
        assert_eq!(
            derive_bloom_hash_count(Some(MIN_FILTER_TARGET_FP), 13).expect("minimum fp cap"),
            7
        );
        assert!(derive_bloom_hash_count(Some(0.009), 13).is_err());
        assert!(derive_bloom_hash_count(Some(0.51), 13).is_err());

        let selected =
            choose_filter_bytes_for_file_size(1, 1, Some(1), Some(0), Some(0.5), Some(1))
                .expect("kib rounding");
        assert_eq!(selected, 1024);
        assert_eq!(align_filter_bytes(1), 8);
        assert_eq!(align_filter_bytes(9), 16);
        assert_eq!(selected % 8, 0);
    }
}
