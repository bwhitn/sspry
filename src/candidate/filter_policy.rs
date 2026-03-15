use crate::{Result, SspryError};

const LN_2: f64 = std::f64::consts::LN_2;
const LN_2_SQ: f64 = LN_2 * LN_2;

fn round_up_power_of_two(value: usize) -> usize {
    if value <= 1 {
        return 1;
    }
    value.next_power_of_two()
}

fn round_to_nearest_kib(value: usize) -> usize {
    if value == 0 {
        return 1024;
    }
    if value < 1024 {
        return 1024;
    }
    ((value + 512) / 1024) * 1024
}

pub fn normalize_filter_policy(
    legacy_filter_bytes: usize,
    filter_min_bytes: Option<usize>,
    filter_max_bytes: Option<usize>,
    filter_size_divisor: usize,
    filter_target_fp: Option<f64>,
) -> Result<(usize, usize, usize, Option<f64>)> {
    let base = legacy_filter_bytes.max(1);
    let minimum = round_up_power_of_two(filter_min_bytes.unwrap_or(base).max(1));
    let raw_maximum = filter_max_bytes.unwrap_or(base);
    let mut maximum = if raw_maximum == 0 {
        0
    } else {
        round_up_power_of_two(raw_maximum.max(1))
    };
    let divisor = filter_size_divisor.max(1);
    if maximum != 0 && maximum < minimum {
        maximum = minimum;
    }
    if let Some(value) = filter_target_fp {
        if !(0.0 < value && value < 1.0) {
            return Err(SspryError::from(
                "filter_target_fp must be in range (0, 1) when set",
            ));
        }
    }
    Ok((minimum, maximum, divisor, filter_target_fp))
}

pub fn derive_bloom_hash_count(target_fp: Option<f64>, fallback_hashes: usize) -> Result<usize> {
    let fallback = fallback_hashes.max(1);
    let Some(fp) = target_fp else {
        return Ok(fallback);
    };
    if !(0.0 < fp && fp < 1.0) {
        return Err(SspryError::from("target_fp must be in range (0, 1)"));
    }
    let estimate = (1.0 / fp).log2().round() as usize;
    Ok(estimate.clamp(1, 16))
}

pub fn derive_document_bloom_hash_count(
    filter_bytes: usize,
    gram_count_estimate: Option<usize>,
    fallback_hashes: usize,
) -> usize {
    let fallback = fallback_hashes.max(1);
    let Some(gram_count_estimate) = gram_count_estimate else {
        return fallback;
    };
    let gram_count = gram_count_estimate.max(1) as f64;
    let bits = (filter_bytes.max(1) * 8) as f64;
    let estimate = ((bits / gram_count) * LN_2).round() as usize;
    estimate.clamp(1, 16)
}

pub fn choose_filter_bytes_for_file_size(
    file_size: u64,
    legacy_filter_bytes: usize,
    filter_min_bytes: Option<usize>,
    filter_max_bytes: Option<usize>,
    filter_size_divisor: usize,
    filter_target_fp: Option<f64>,
    gram_count_estimate: Option<usize>,
) -> Result<usize> {
    let (minimum, maximum, divisor, target_fp) = normalize_filter_policy(
        legacy_filter_bytes,
        filter_min_bytes,
        filter_max_bytes,
        filter_size_divisor,
        filter_target_fp,
    )?;
    let size = file_size as usize;
    let size_target = minimum.max(size.div_ceil(divisor));
    let target = if let Some(fp) = target_fp {
        let gram_count =
            gram_count_estimate.unwrap_or_else(|| size.saturating_sub(3).max(1)) as f64;
        let bits = ((-gram_count * fp.ln()) / LN_2_SQ).ceil() as usize;
        let theoretical_bytes = bits.div_ceil(8).max(1);
        let _ = (minimum, maximum, size_target);
        round_to_nearest_kib(theoretical_bytes)
    } else {
        round_up_power_of_two(if maximum == 0 {
            size_target
        } else {
            size_target.min(maximum)
        })
    };
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::{
        choose_filter_bytes_for_file_size, derive_bloom_hash_count,
        derive_document_bloom_hash_count, normalize_filter_policy,
    };

    #[test]
    fn variable_filter_size_rounds_to_power_of_two() {
        let selected = choose_filter_bytes_for_file_size(
            10_000,
            2048,
            Some(2048),
            Some(131_072),
            64,
            None,
            None,
        )
        .expect("size");
        assert!(selected.is_power_of_two());
        assert!(selected >= 2048);
    }

    #[test]
    fn target_fp_mode_uses_gram_count_estimate_when_present() {
        let from_size = choose_filter_bytes_for_file_size(
            1024 * 1024,
            512 * 1024,
            Some(8 * 1024),
            Some(512 * 1024),
            8,
            Some(0.25),
            None,
        )
        .expect("size-based filter");
        let from_hll = choose_filter_bytes_for_file_size(
            1024 * 1024,
            512 * 1024,
            Some(8 * 1024),
            Some(512 * 1024),
            8,
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
            64,
            Some(0.0001),
            Some(22_000_000),
        )
        .expect("theoretical size");
        assert_eq!(selected, 52_717_568);
    }

    #[test]
    fn document_hash_count_uses_filter_density_when_estimate_present() {
        assert_eq!(
            derive_document_bloom_hash_count(262_144, Some(1_000_000), 13),
            1
        );
        assert_eq!(derive_document_bloom_hash_count(2048, None, 7), 7);
    }

    #[test]
    fn filter_policy_helpers_cover_validation_and_rounding_edges() {
        let (minimum, maximum, divisor, fp) =
            normalize_filter_policy(2048, Some(3000), Some(1024), 0, None).expect("normalized");
        assert_eq!(minimum, 4096);
        assert_eq!(maximum, 4096);
        assert_eq!(divisor, 1);
        assert_eq!(fp, None);

        assert!(normalize_filter_policy(2048, None, None, 64, Some(1.0)).is_err());
        assert_eq!(derive_bloom_hash_count(None, 0).expect("fallback"), 1);
        assert_eq!(derive_bloom_hash_count(Some(0.25), 13).expect("derived"), 2);
        assert!(derive_bloom_hash_count(Some(0.0), 13).is_err());

        let selected =
            choose_filter_bytes_for_file_size(1, 1, Some(1), Some(0), 64, Some(0.5), Some(1))
                .expect("kib rounding");
        assert_eq!(selected, 1024);
    }
}
