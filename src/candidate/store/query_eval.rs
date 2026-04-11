/// Validates and normalizes a SHA-256 string used by local search helpers.
///
/// Inputs:
/// - `value`: Candidate hexadecimal digest string.
///
/// Returns:
/// - The lowercase 64-character digest string.
fn normalize_sha256_hex(value: &str) -> Result<String> {
    let text = value.trim().to_ascii_lowercase();
    if text.len() != 64 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(SspryError::from(
            "sha256 must be exactly 64 hexadecimal characters.",
        ));
    }
    Ok(text)
}

type RequiredMasksByKey = FxHashMap<(usize, usize), Vec<(usize, u64)>>;

#[derive(Clone, Debug, Default)]
struct ShiftedRequiredMasks {
    shifts: Vec<RequiredMasksByKey>,
    any_lane_values: Vec<Vec<RequiredMasksByKey>>,
    any_lane_grams: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
struct PreparedPatternMasks {
    tier1: Vec<ShiftedRequiredMasks>,
    tier2: Vec<ShiftedRequiredMasks>,
}

type PatternMaskCache = HashMap<String, PreparedPatternMasks>;

const MAX_LANE_POSITION_VARIANTS: usize = 64;
const PREPARED_QUERY_MASK_CACHE_BUDGET_BYTES: u64 = 128 * 1024 * 1024;

/// Estimates the heap retained by one required-mask map keyed by filter size
/// and hash count.
fn required_masks_by_key_memory_bytes(masks: &RequiredMasksByKey) -> u64 {
    (masks.len() as u64)
        .saturating_mul(std::mem::size_of::<((usize, usize), Vec<(usize, u64)>)>() as u64)
        .saturating_add(
            masks
                .values()
                .map(|values| {
                    (std::mem::size_of::<Vec<(usize, u64)>>() as u64).saturating_add(
                        (values.capacity() as u64)
                            .saturating_mul(std::mem::size_of::<(usize, u64)>() as u64),
                    )
                })
                .sum::<u64>(),
        )
}

/// Estimates the heap retained by one shifted required-mask structure.
fn shifted_required_masks_memory_bytes(masks: &ShiftedRequiredMasks) -> u64 {
    (std::mem::size_of::<ShiftedRequiredMasks>() as u64)
        .saturating_add(
            (masks.shifts.capacity() as u64)
                .saturating_mul(std::mem::size_of::<RequiredMasksByKey>() as u64),
        )
        .saturating_add(
            masks
                .shifts
                .iter()
                .map(required_masks_by_key_memory_bytes)
                .sum::<u64>(),
        )
        .saturating_add(
            (masks.any_lane_values.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<RequiredMasksByKey>>() as u64),
        )
        .saturating_add(
            masks
                .any_lane_values
                .iter()
                .map(|lane_maps| {
                    (std::mem::size_of::<Vec<RequiredMasksByKey>>() as u64)
                        .saturating_add(
                            (lane_maps.capacity() as u64).saturating_mul(std::mem::size_of::<
                                RequiredMasksByKey,
                            >(
                            )
                                as u64),
                        )
                        .saturating_add(
                            lane_maps
                                .iter()
                                .map(required_masks_by_key_memory_bytes)
                                .sum::<u64>(),
                        )
                })
                .sum::<u64>(),
        )
        .saturating_add(
            (masks.any_lane_grams.capacity() as u64)
                .saturating_mul(std::mem::size_of::<u64>() as u64),
        )
}

/// Estimates the heap retained by all prepared masks for one pattern.
fn prepared_pattern_masks_memory_bytes(masks: &PreparedPatternMasks) -> u64 {
    (std::mem::size_of::<PreparedPatternMasks>() as u64)
        .saturating_add(
            (masks.tier1.capacity() as u64)
                .saturating_mul(std::mem::size_of::<ShiftedRequiredMasks>() as u64),
        )
        .saturating_add(
            masks
                .tier1
                .iter()
                .map(shifted_required_masks_memory_bytes)
                .sum::<u64>(),
        )
        .saturating_add(
            (masks.tier2.capacity() as u64)
                .saturating_mul(std::mem::size_of::<ShiftedRequiredMasks>() as u64),
        )
        .saturating_add(
            masks
                .tier2
                .iter()
                .map(shifted_required_masks_memory_bytes)
                .sum::<u64>(),
        )
}

/// Estimates the heap retained by one prepared pattern plan.
fn prepared_pattern_plan_memory_bytes(pattern: &PatternPlan) -> u64 {
    let alternatives_bytes = pattern
        .alternatives
        .iter()
        .map(|alts| {
            (std::mem::size_of::<Vec<u64>>() as u64).saturating_add(
                (alts.capacity() as u64).saturating_mul(std::mem::size_of::<u64>() as u64),
            )
        })
        .sum::<u64>();
    let tier2_alternatives_bytes = pattern
        .tier2_alternatives
        .iter()
        .map(|alts| {
            (std::mem::size_of::<Vec<u64>>() as u64).saturating_add(
                (alts.capacity() as u64).saturating_mul(std::mem::size_of::<u64>() as u64),
            )
        })
        .sum::<u64>();
    let anchor_literals_bytes = pattern
        .anchor_literals
        .iter()
        .map(|literal| {
            (std::mem::size_of::<Vec<u8>>() as u64).saturating_add(literal.capacity() as u64)
        })
        .sum::<u64>();
    let fixed_literals_bytes = pattern
        .fixed_literals
        .iter()
        .map(|literal| {
            (std::mem::size_of::<Vec<u8>>() as u64).saturating_add(literal.capacity() as u64)
        })
        .sum::<u64>();
    (std::mem::size_of::<PatternPlan>() as u64)
        .saturating_add(pattern.pattern_id.capacity() as u64)
        .saturating_add(
            (pattern.alternatives.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<u64>>() as u64),
        )
        .saturating_add(alternatives_bytes)
        .saturating_add(
            (pattern.tier2_alternatives.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<u64>>() as u64),
        )
        .saturating_add(tier2_alternatives_bytes)
        .saturating_add(
            (pattern.anchor_literals.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<u8>>() as u64),
        )
        .saturating_add(anchor_literals_bytes)
        .saturating_add(
            (pattern.fixed_literals.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<u8>>() as u64),
        )
        .saturating_add(fixed_literals_bytes)
        .saturating_add(
            (pattern.fixed_literal_wide.capacity() as u64)
                .saturating_mul(std::mem::size_of::<bool>() as u64),
        )
        .saturating_add(
            (pattern.fixed_literal_fullword.capacity() as u64)
                .saturating_mul(std::mem::size_of::<bool>() as u64),
        )
}

/// Estimates the total heap footprint of all prepared-query artifacts cached
/// for one compiled plan.
///
/// Inputs:
/// - `artifacts`: Prepared patterns plus precomputed bloom mask cache.
///
/// Returns:
/// - Approximate bytes retained by the prepared-query cache entry.
pub(crate) fn prepared_query_artifacts_memory_bytes(artifacts: &PreparedQueryArtifacts) -> u64 {
    let patterns_bytes = artifacts
        .patterns
        .iter()
        .map(|(key, pattern)| {
            (std::mem::size_of::<String>() as u64)
                .saturating_add(key.capacity() as u64)
                .saturating_add(prepared_pattern_plan_memory_bytes(pattern))
        })
        .sum::<u64>();
    let mask_cache_bytes = artifacts
        .mask_cache
        .iter()
        .map(|(key, masks)| {
            (std::mem::size_of::<String>() as u64)
                .saturating_add(key.capacity() as u64)
                .saturating_add(prepared_pattern_masks_memory_bytes(masks))
        })
        .sum::<u64>();
    (std::mem::size_of::<PreparedQueryArtifacts>() as u64)
        .saturating_add(patterns_bytes)
        .saturating_add(mask_cache_bytes)
}

/// Summarizes one prepared-query artifact set into the telemetry structure shown
/// in verbose search output.
///
/// Inputs:
/// - `artifacts`: Prepared-query data built from a compiled plan.
///
/// Returns:
/// - A profile containing memory, mask, and pattern-count statistics.
pub(crate) fn prepared_query_artifacts_profile(
    artifacts: &PreparedQueryArtifacts,
) -> CandidatePreparedQueryProfile {
    let mut profile = CandidatePreparedQueryProfile {
        impossible_query: artifacts.impossible_query,
        prepared_query_bytes: prepared_query_artifacts_memory_bytes(artifacts),
        ..CandidatePreparedQueryProfile::default()
    };
    for (pattern_id, pattern) in &artifacts.patterns {
        profile.pattern_count = profile.pattern_count.saturating_add(1);
        profile.fixed_literal_count = profile
            .fixed_literal_count
            .saturating_add(pattern.fixed_literals.len() as u64);
        profile.tier1_alternatives = profile
            .tier1_alternatives
            .saturating_add(pattern.alternatives.len() as u64);
        profile.tier2_alternatives = profile
            .tier2_alternatives
            .saturating_add(pattern.tier2_alternatives.len() as u64);

        let pattern_bytes = prepared_pattern_plan_memory_bytes(pattern);
        profile.prepared_pattern_plan_bytes = profile
            .prepared_pattern_plan_bytes
            .saturating_add(pattern_bytes);
        if pattern_bytes > profile.max_pattern_bytes {
            profile.max_pattern_bytes = pattern_bytes;
            profile.max_pattern_id = Some(pattern_id.clone());
        }
    }
    for masks in artifacts.mask_cache.values() {
        profile.mask_cache_entries = profile.mask_cache_entries.saturating_add(1);
        profile.prepared_mask_cache_bytes = profile
            .prepared_mask_cache_bytes
            .saturating_add(prepared_pattern_masks_memory_bytes(masks));
        for shifted in &masks.tier1 {
            profile.accumulate_shifted(shifted, false);
        }
        for shifted in &masks.tier2 {
            profile.accumulate_shifted(shifted, true);
        }
    }
    profile
}

/// Builds all possible lane-position variants for a fixed literal when grams can
/// land in multiple bloom lanes.
///
/// Inputs:
/// - `values`: Packed gram values for one alternative.
/// - `fixed_literal`: Exact literal bytes for that alternative.
/// - `gram_size`: Active gram size for the lane computation.
/// - `lane_count`: Number of bloom position lanes in the filter.
///
/// Returns:
/// - Candidate lane assignments for each gram position in the literal.
/// Returns all lane-position variants a pattern may occupy, capped to keep the
/// prepared mask cache bounded.
fn lane_position_variants_for_pattern(
    values: &[u64],
    fixed_literal: &[u8],
    gram_size: usize,
    lane_count: usize,
) -> Vec<Vec<usize>> {
    if fixed_literal.is_empty() || fixed_literal.len() < gram_size {
        return vec![Vec::new()];
    }
    let mut positions_per_gram = Vec::<Vec<usize>>::with_capacity(values.len());
    let mut positions_by_gram = HashMap::<u64, Vec<usize>>::new();
    for idx in 0..=(fixed_literal.len() - gram_size) {
        let gram = pack_exact_gram(&fixed_literal[idx..idx + gram_size]);
        positions_by_gram.entry(gram).or_default().push(idx);
    }
    for (gram_idx, value) in values.iter().enumerate() {
        positions_per_gram.push(
            positions_by_gram
                .get(value)
                .cloned()
                .filter(|positions| !positions.is_empty())
                .unwrap_or_else(|| vec![gram_idx]),
        );
    }

    let mut combos = vec![Vec::<usize>::new()];
    for positions in positions_per_gram {
        let mut next = Vec::<Vec<usize>>::new();
        for combo in &combos {
            for position in &positions {
                if next.len() >= MAX_LANE_POSITION_VARIANTS {
                    break;
                }
                let mut variant = combo.clone();
                variant.push(*position);
                next.push(variant);
            }
            if next.len() >= MAX_LANE_POSITION_VARIANTS {
                break;
            }
        }
        combos = next;
        if combos.is_empty() {
            combos.push(Vec::new());
        }
    }

    let mut variants = Vec::<Vec<usize>>::new();
    for shift in 0..lane_count.max(1) {
        for combo in &combos {
            if variants.len() >= MAX_LANE_POSITION_VARIANTS {
                return variants;
            }
            variants.push(
                combo
                    .iter()
                    .map(|position| (shift + position) % lane_count.max(1))
                    .collect(),
            );
        }
    }
    if variants.is_empty() {
        variants.push(Vec::new());
    }
    variants
}

/// Returns whether a pattern's exact literal can map its grams to more than one
/// lane layout, forcing any-lane handling instead of exact shifted masks.
/// Returns whether a fixed-literal pattern can align to multiple lane
/// positions and therefore needs any-lane handling.
fn exact_pattern_has_ambiguous_positions(
    values: &[u64],
    fixed_literal: &[u8],
    gram_size: usize,
) -> bool {
    if fixed_literal.is_empty() || fixed_literal.len() < gram_size {
        return false;
    }
    let mut positions_by_gram = HashMap::<u64, Vec<usize>>::new();
    for idx in 0..=(fixed_literal.len() - gram_size) {
        let gram = pack_exact_gram(&fixed_literal[idx..idx + gram_size]);
        positions_by_gram.entry(gram).or_default().push(idx);
    }
    values.iter().any(|value| {
        positions_by_gram
            .get(value)
            .map(|positions| positions.len() > 1)
            .unwrap_or(false)
    })
}

/// Builds and caches the merged word-mask requirements for one exact lane
/// layout.
///
/// Inputs:
/// - `values`: Packed gram values for one pattern alternative.
/// - `filter_bytes`, `bloom_hashes`: Target bloom configuration.
/// - `positions`: Resolved bloom positions for each gram.
/// - `lane_count`: Number of bloom lanes in the filter.
/// - `cache`: Reusable per-gram word-mask cache.
///
/// Returns:
/// - The merged required word masks for the requested lane layout.
/// Merges cached bloom word masks for all grams in one lane-position variant.
fn merge_cached_lane_bloom_word_masks(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
    lanes: &[usize],
    lane_count: usize,
    cache: &mut HashMap<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>,
) -> Result<Vec<(usize, u64)>> {
    let mut merged = FxHashMap::<usize, u64>::default();
    for (gram_idx, value) in values.iter().enumerate() {
        let cached_masks = if let Some(lane) = lanes.get(gram_idx).copied() {
            let key = (*value, size_bytes, hash_count, lane, lane_count);
            if let Some(entry) = cache.get(&key) {
                entry.clone()
            } else {
                let entry =
                    bloom_word_masks_in_lane(&[*value], size_bytes, hash_count, lane, lane_count)?;
                cache.insert(key, entry.clone());
                entry
            }
        } else {
            let mut any_lane = FxHashMap::<usize, u64>::default();
            for lane in 0..lane_count.max(1) {
                let key = (*value, size_bytes, hash_count, lane, lane_count);
                let cached = if let Some(entry) = cache.get(&key) {
                    entry.clone()
                } else {
                    let entry = bloom_word_masks_in_lane(
                        &[*value],
                        size_bytes,
                        hash_count,
                        lane,
                        lane_count,
                    )?;
                    cache.insert(key, entry.clone());
                    entry
                };
                for (word_idx, mask) in cached {
                    *any_lane.entry(word_idx).or_insert(0) |= mask;
                }
            }
            any_lane.into_iter().collect()
        };
        for (word_idx, mask) in cached_masks {
            *merged.entry(word_idx).or_insert(0) |= mask;
        }
    }
    Ok(merged.into_iter().collect())
}

/// Builds the broader any-lane mask representation used when exact gram
/// positions are ambiguous.
///
/// Inputs:
/// - `values`: Packed gram values for one pattern alternative.
/// - `filter_keys`: Distinct `(filter_bytes, bloom_hashes)` pairs seen in the store.
/// - `lane_count`: Number of bloom lanes in the filter.
/// - `cache`: Reusable per-gram word-mask cache.
///
/// Returns:
/// - Required masks grouped by lane/value combination.
/// Builds the any-lane mask variants used when a pattern can land in multiple
/// lane positions.
fn build_any_lane_required_masks(
    values: &[u64],
    filter_keys: &[(usize, usize)],
    lane_count: usize,
    cache: &mut HashMap<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>,
) -> Result<Vec<Vec<RequiredMasksByKey>>> {
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let mut per_lane = Vec::with_capacity(lane_count.max(1));
        for lane in 0..lane_count.max(1) {
            let mut by_key = RequiredMasksByKey::default();
            for (filter_bytes, bloom_hashes) in filter_keys {
                let key = (*value, *filter_bytes, *bloom_hashes, lane, lane_count);
                let cached = if let Some(entry) = cache.get(&key) {
                    entry.clone()
                } else {
                    let entry = bloom_word_masks_in_lane(
                        &[*value],
                        *filter_bytes,
                        *bloom_hashes,
                        lane,
                        lane_count,
                    )?;
                    cache.insert(key, entry.clone());
                    entry
                };
                by_key.insert((*filter_bytes, *bloom_hashes), cached);
            }
            per_lane.push(by_key);
        }
        out.push(per_lane);
    }
    Ok(out)
}

/// Opportunistically compacts any-lane mask sets into plain gram values once
/// the prepared-query cache reaches its soft budget.
///
/// Inputs:
/// - `shifted`: Mask set that may be rewritten in place.
/// - `alternative`: Gram values for the same pattern alternative.
/// - `current_budget_bytes`: Running cache size estimate.
///
/// Output:
/// - May rewrite `shifted` in place to a more compact representation.
/// Compacts a shifted any-lane mask set in place when it would exceed the
/// prepared-query cache budget.
fn maybe_compact_any_lane_masks(
    shifted: &mut ShiftedRequiredMasks,
    values: &[u64],
    current_budget_bytes: &mut u64,
) {
    let current_bytes = shifted_required_masks_memory_bytes(shifted);
    if shifted.any_lane_values.is_empty()
        || current_budget_bytes.saturating_add(current_bytes)
            <= PREPARED_QUERY_MASK_CACHE_BUDGET_BYTES
    {
        *current_budget_bytes = current_budget_bytes.saturating_add(current_bytes);
        return;
    }
    shifted.any_lane_values.clear();
    shifted.any_lane_grams = values.to_vec();
    *current_budget_bytes =
        current_budget_bytes.saturating_add(shifted_required_masks_memory_bytes(shifted));
}

/// Returns whether a query subtree is structurally impossible before touching
/// any bloom filters.
fn node_structurally_impossible(node: &QueryNode) -> bool {
    match node.kind.as_str() {
        "pattern" => false,
        "identity_eq" => false,
        "not" => false,
        "verifier_only_eq" => false,
        "verifier_only_at" => false,
        "verifier_only_count" => false,
        "verifier_only_in_range" => false,
        "verifier_only_loop" => false,
        "filesize_eq" => false,
        "filesize_ne" => false,
        "filesize_lt" => false,
        "filesize_le" => false,
        "filesize_gt" => false,
        "filesize_ge" => false,
        "metadata_eq" => false,
        "metadata_ne" => false,
        "metadata_lt" => false,
        "metadata_le" => false,
        "metadata_gt" => false,
        "metadata_ge" => false,
        "metadata_float_eq" => false,
        "metadata_float_ne" => false,
        "metadata_float_lt" => false,
        "metadata_float_le" => false,
        "metadata_float_gt" => false,
        "metadata_float_ge" => false,
        "metadata_time_eq" => false,
        "metadata_time_ne" => false,
        "metadata_time_lt" => false,
        "metadata_time_le" => false,
        "metadata_time_gt" => false,
        "metadata_time_ge" => false,
        "metadata_field_eq" => false,
        "metadata_field_ne" => false,
        "metadata_field_lt" => false,
        "metadata_field_le" => false,
        "metadata_field_gt" => false,
        "metadata_field_ge" => false,
        "time_now_eq" => false,
        "time_now_ne" => false,
        "time_now_lt" => false,
        "time_now_le" => false,
        "time_now_gt" => false,
        "time_now_ge" => false,
        "and" => node.children.iter().any(node_structurally_impossible),
        "or" => !node.children.is_empty() && node.children.iter().all(node_structurally_impossible),
        "n_of" => {
            let threshold = node.threshold.unwrap_or(usize::MAX);
            if threshold > node.children.len() {
                return true;
            }
            let possible_children = node
                .children
                .iter()
                .filter(|child| !node_structurally_impossible(child))
                .count();
            possible_children < threshold
        }
        _ => false,
    }
}

/// Returns whether a query subtree relies on pattern bloom lookups.
fn query_node_uses_pattern_blooms(node: &QueryNode) -> bool {
    match node.kind.as_str() {
        "pattern" => true,
        "and" | "or" | "n_of" | "not" => node.children.iter().any(query_node_uses_pattern_blooms),
        _ => false,
    }
}

/// Returns whether a query subtree still contains verifier-only conditions that
/// require exact metadata or prefix checks.
fn query_node_contains_verifier_only(node: &QueryNode) -> bool {
    matches!(
        node.kind.as_str(),
        "verifier_only_eq"
            | "verifier_only_at"
            | "verifier_only_count"
            | "verifier_only_in_range"
            | "verifier_only_loop"
    ) || node.children.iter().any(query_node_contains_verifier_only)
}

/// Precomputes the per-pattern bloom word masks needed to evaluate a query
/// against the specific filter configurations present in the store.
///
/// Inputs:
/// - `patterns`: Compiled pattern plans from the query.
/// - `tier1_filter_keys`, `tier2_filter_keys`: Distinct filter layouts seen in the store.
/// - `tier1_gram_size`, `tier2_gram_size`: Active gram sizes for each tier.
///
/// Returns:
/// - A mask cache keyed by pattern id and tier.
/// Builds the prepared bloom-mask cache for every pattern in a compiled plan.
fn build_pattern_mask_cache(
    patterns: &[PatternPlan],
    tier1_filter_keys: &[(usize, usize)],
    tier2_filter_keys: &[(usize, usize)],
    tier1_gram_size: usize,
    tier2_gram_size: usize,
) -> Result<PatternMaskCache> {
    let mut out = HashMap::with_capacity(patterns.len());
    let mut tier1_gram_cache =
        HashMap::<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>::new();
    let mut tier2_gram_cache =
        HashMap::<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>::new();
    let mut current_budget_bytes = 0u64;
    for pattern in patterns {
        let mut tier1_masks = Vec::with_capacity(pattern.alternatives.len());
        for (alt_index, alternative) in pattern.alternatives.iter().enumerate() {
            let anchor_literal = pattern
                .anchor_literals
                .get(alt_index)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut shifted_tier1 = ShiftedRequiredMasks::default();
            if anchor_literal.is_empty()
                || anchor_literal.len() < tier1_gram_size
                || exact_pattern_has_ambiguous_positions(
                    alternative,
                    anchor_literal,
                    tier1_gram_size,
                )
            {
                shifted_tier1.any_lane_values = build_any_lane_required_masks(
                    alternative,
                    tier1_filter_keys,
                    DEFAULT_BLOOM_POSITION_LANES,
                    &mut tier1_gram_cache,
                )?;
            } else {
                let lane_variants = lane_position_variants_for_pattern(
                    alternative,
                    anchor_literal,
                    tier1_gram_size,
                    DEFAULT_BLOOM_POSITION_LANES,
                );
                shifted_tier1.shifts = Vec::with_capacity(lane_variants.len());
                for lanes in &lane_variants {
                    let mut by_key = RequiredMasksByKey::default();
                    for (filter_bytes, bloom_hashes) in tier1_filter_keys {
                        let required = merge_cached_lane_bloom_word_masks(
                            alternative,
                            *filter_bytes,
                            *bloom_hashes,
                            lanes,
                            DEFAULT_BLOOM_POSITION_LANES,
                            &mut tier1_gram_cache,
                        )?;
                        by_key.insert((*filter_bytes, *bloom_hashes), required);
                    }
                    shifted_tier1.shifts.push(by_key);
                }
            }
            maybe_compact_any_lane_masks(
                &mut shifted_tier1,
                alternative,
                &mut current_budget_bytes,
            );
            tier1_masks.push(shifted_tier1);
        }

        let mut tier2_masks = Vec::with_capacity(pattern.tier2_alternatives.len());
        for (alt_index, alternative) in pattern.tier2_alternatives.iter().enumerate() {
            let anchor_literal = pattern
                .anchor_literals
                .get(alt_index)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut shifted_tier2 = ShiftedRequiredMasks::default();
            if anchor_literal.is_empty()
                || anchor_literal.len() < tier2_gram_size
                || exact_pattern_has_ambiguous_positions(
                    alternative,
                    anchor_literal,
                    tier2_gram_size,
                )
            {
                shifted_tier2.any_lane_values = build_any_lane_required_masks(
                    alternative,
                    tier2_filter_keys,
                    DEFAULT_BLOOM_POSITION_LANES,
                    &mut tier2_gram_cache,
                )?;
            } else {
                let lane_variants = lane_position_variants_for_pattern(
                    alternative,
                    anchor_literal,
                    tier2_gram_size,
                    DEFAULT_BLOOM_POSITION_LANES,
                );
                shifted_tier2.shifts = Vec::with_capacity(lane_variants.len());
                for lanes in &lane_variants {
                    let mut by_key = RequiredMasksByKey::default();
                    for (filter_bytes, bloom_hashes) in tier2_filter_keys {
                        let required = merge_cached_lane_bloom_word_masks(
                            alternative,
                            *filter_bytes,
                            *bloom_hashes,
                            lanes,
                            DEFAULT_BLOOM_POSITION_LANES,
                            &mut tier2_gram_cache,
                        )?;
                        by_key.insert((*filter_bytes, *bloom_hashes), required);
                    }
                    shifted_tier2.shifts.push(by_key);
                }
            }
            maybe_compact_any_lane_masks(
                &mut shifted_tier2,
                alternative,
                &mut current_budget_bytes,
            );
            tier2_masks.push(shifted_tier2);
        }

        out.insert(
            pattern.pattern_id.clone(),
            PreparedPatternMasks {
                tier1: tier1_masks,
                tier2: tier2_masks,
            },
        );
    }
    Ok(out)
}

/// Builds the prepared-query artifact bundle cached by the candidate store.
///
/// Inputs:
/// - `plan`: Compiled query plan to prepare.
/// - `tier1_filter_keys`, `tier2_filter_keys`: Distinct filter layouts seen in the store.
///
/// Returns:
/// - Shared prepared artifacts containing pattern maps, mask cache, and the
///   impossible-query fast path flag.
pub(crate) fn build_prepared_query_artifacts(
    plan: &CompiledQueryPlan,
    tier1_filter_keys: &[(usize, usize)],
    tier2_filter_keys: &[(usize, usize)],
) -> Result<Arc<PreparedQueryArtifacts>> {
    let patterns = plan
        .patterns
        .iter()
        .cloned()
        .map(|pattern| (pattern.pattern_id.clone(), pattern))
        .collect::<HashMap<_, _>>();
    let mask_cache = build_pattern_mask_cache(
        &plan.patterns,
        tier1_filter_keys,
        tier2_filter_keys,
        plan.tier1_gram_size,
        plan.tier2_gram_size,
    )?;
    Ok(Arc::new(PreparedQueryArtifacts {
        patterns,
        mask_cache,
        impossible_query: node_structurally_impossible(&plan.root),
    }))
}

/// Encodes the literal bytes used by verifier-only numeric-read comparisons.
fn numeric_read_literal_bytes(name: &str, literal_text: &str) -> Result<Vec<u8>> {
    match name {
        "int16" => Ok(literal_text
            .parse::<i16>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "uint16" => Ok(literal_text
            .parse::<u16>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "int16be" => Ok(literal_text
            .parse::<i16>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "uint16be" => Ok(literal_text
            .parse::<u16>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "int32" => Ok(literal_text
            .parse::<i32>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "uint32" => Ok(literal_text
            .parse::<u32>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "int32be" => Ok(literal_text
            .parse::<i32>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "uint32be" => Ok(literal_text
            .parse::<u32>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "int64" => Ok(literal_text
            .parse::<i64>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "uint64" => Ok(literal_text
            .parse::<u64>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "int64be" => Ok(literal_text
            .parse::<i64>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "uint64be" => Ok(literal_text
            .parse::<u64>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "float32" => Ok(literal_text
            .parse::<f32>()
            .map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?
            .to_bits()
            .to_le_bytes()
            .to_vec()),
        "float32be" => Ok(literal_text
            .parse::<f32>()
            .map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?
            .to_bits()
            .to_be_bytes()
            .to_vec()),
        "float64" => Ok(literal_text
            .parse::<f64>()
            .map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?
            .to_bits()
            .to_le_bytes()
            .to_vec()),
        "float64be" => Ok(literal_text
            .parse::<f64>()
            .map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?
            .to_bits()
            .to_be_bytes()
            .to_vec()),
        _ => Err(SspryError::from(format!(
            "Unsupported numeric read anchor function: {name}"
        ))),
    }
}

/// Evaluates a verifier-only equality expression against the stored file
/// prefix bytes.
fn verifier_only_eq_matches_file_prefix(
    expr: &str,
    file_prefix: &[u8],
    file_size: u64,
) -> Result<Option<bool>> {
    let Some((name, rest)) = expr.split_once('(') else {
        return Ok(None);
    };
    let Some((offset_text, literal_text)) = rest.split_once(")==") else {
        return Ok(None);
    };
    let Ok(offset) = offset_text.parse::<usize>() else {
        return Ok(None);
    };
    let expected = match numeric_read_literal_bytes(name, literal_text) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    if expected.len() > 8 {
        return Ok(None);
    }
    let required_len = offset.saturating_add(expected.len());
    if required_len > 8 {
        return Ok(None);
    }
    if file_size < required_len as u64 || file_prefix.len() < required_len {
        return Ok(Some(false));
    }
    Ok(Some(file_prefix[offset..required_len] == expected))
}

/// Returns whether a prepared pattern matches exactly at file offset zero.
fn pattern_matches_file_prefix_at_zero(
    pattern: &PatternPlan,
    file_prefix: &[u8],
    file_size: u64,
) -> Option<bool> {
    let _ = file_size;
    pattern_matches_prefix_window(pattern, file_prefix, 0, 8)
}

/// Returns whether a prepared pattern fits fully inside the provided prefix
/// window at the requested offset.
fn pattern_matches_prefix_window(
    pattern: &PatternPlan,
    prefix: &[u8],
    offset: usize,
    max_window_bytes: usize,
) -> Option<bool> {
    let mut saw_supported = false;
    let mut all_supported = true;
    for idx in 0..pattern.alternatives.len() {
        let literal = pattern.fixed_literals.get(idx)?;
        let wide = pattern
            .fixed_literal_wide
            .get(idx)
            .copied()
            .unwrap_or(false);
        let fullword = pattern
            .fixed_literal_fullword
            .get(idx)
            .copied()
            .unwrap_or(false);
        if literal.is_empty()
            || wide
            || fullword
            || offset.saturating_add(literal.len()) > max_window_bytes
        {
            all_supported = false;
            continue;
        }
        saw_supported = true;
        let required_len = offset.saturating_add(literal.len());
        if prefix.len() < required_len {
            continue;
        }
        if prefix[offset..required_len] == *literal {
            return Some(true);
        }
    }
    if saw_supported && all_supported {
        Some(false)
    } else {
        None
    }
}

/// Parses the supported entry-point-relative prefix offsets used by
/// verifier-only prefix checks.
fn entry_point_prefix_offset(offset_text: &str) -> Option<usize> {
    if offset_text == "pe.entry_point" {
        Some(0)
    } else {
        offset_text
            .strip_prefix("pe.entry_point+")?
            .parse::<usize>()
            .ok()
    }
}

/// Applies an integer metadata comparison operator.
fn compare_u64(lhs: u64, rhs: u64, op: MetadataCompareOp) -> bool {
    match op {
        MetadataCompareOp::Eq => lhs == rhs,
        MetadataCompareOp::Ne => lhs != rhs,
        MetadataCompareOp::Lt => lhs < rhs,
        MetadataCompareOp::Le => lhs <= rhs,
        MetadataCompareOp::Gt => lhs > rhs,
        MetadataCompareOp::Ge => lhs >= rhs,
    }
}

/// Maps a query-node kind to the metadata comparison operator it represents.
fn compare_op_for_node_kind(kind: &str) -> Option<MetadataCompareOp> {
    if kind.ends_with("_eq") {
        Some(MetadataCompareOp::Eq)
    } else if kind.ends_with("_ne") {
        Some(MetadataCompareOp::Ne)
    } else if kind.ends_with("_lt") {
        Some(MetadataCompareOp::Lt)
    } else if kind.ends_with("_le") {
        Some(MetadataCompareOp::Le)
    } else if kind.ends_with("_gt") {
        Some(MetadataCompareOp::Gt)
    } else if kind.ends_with("_ge") {
        Some(MetadataCompareOp::Ge)
    } else {
        None
    }
}

/// Resolves the left and right metadata field names referenced by a
/// field-versus-field comparison node.
fn metadata_field_pair(node: &QueryNode, kind_name: &str) -> Result<(String, String)> {
    let pair = node
        .pattern_id
        .as_deref()
        .ok_or_else(|| SspryError::from(format!("{kind_name} node requires pattern_id")))?;
    let Some((lhs, rhs)) = pair.split_once('|') else {
        return Err(SspryError::from(format!(
            "{kind_name} node requires lhs|rhs pattern_id"
        )));
    };
    Ok((lhs.to_owned(), rhs.to_owned()))
}

/// Evaluates one pattern alternative against the tier1/tier2 bloom data and
/// returns which tiers were actually used.
///
/// Inputs:
/// - `pattern`: Prepared pattern plan to evaluate.
/// - `pattern_masks`: Precomputed bloom word masks for that pattern.
/// - `doc_inputs`: Lazy accessors for the current document's bloom payloads.
/// - `load_tier1`, `load_tier2`: Deferred bloom payload loaders.
/// - `plan`: Query-level tier policy flags.
///
/// Returns:
/// - Whether the pattern matched the current document and which tiers were used.
fn evaluate_pattern<'a, FT1, FT2>(
    pattern: &PatternPlan,
    pattern_masks: &PreparedPatternMasks,
    doc_inputs: &mut LazyDocQueryInputs<'a>,
    load_tier1: &mut FT1,
    load_tier2: &mut FT2,
    plan: &CompiledQueryPlan,
) -> Result<MatchOutcome>
where
    FT1: FnMut() -> Result<Cow<'a, [u8]>>,
    FT2: FnMut() -> Result<Cow<'a, [u8]>>,
{
    let allow_tier2 = !plan.force_tier1_only && plan.allow_tier2_fallback;
    let tier2_only =
        experiment_tier2_only_enabled() || experiment_tier2_and_metadata_only_enabled();
    for (alt_index, alternative) in pattern.alternatives.iter().enumerate() {
        let tier2_alternative = pattern
            .tier2_alternatives
            .get(alt_index)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if alternative.is_empty() && tier2_alternative.is_empty() {
            return Ok(MatchOutcome {
                matched: true,
                tiers: TierFlags {
                    used_tier1: !tier2_only,
                    used_tier2: false,
                },
            });
        }
        let doc = doc_inputs.doc;
        let mut used_tier1 = false;
        if !tier2_only && !alternative.is_empty() {
            let bloom_bytes = doc_inputs.tier1_bloom_bytes(load_tier1)?;
            let primary_match = pattern_masks.tier1.get(alt_index).is_some_and(|shifted| {
                if !shifted.any_lane_grams.is_empty() {
                    shifted.any_lane_grams.iter().all(|value| {
                        (0..DEFAULT_BLOOM_POSITION_LANES).any(|lane| {
                            bloom_word_masks_in_lane(
                                &[*value],
                                doc.filter_bytes,
                                doc.bloom_hashes,
                                lane,
                                DEFAULT_BLOOM_POSITION_LANES,
                            )
                            .ok()
                            .is_some_and(|required| {
                                raw_filter_matches_word_masks(bloom_bytes, &required)
                            })
                        })
                    })
                } else if !shifted.any_lane_values.is_empty() {
                    shifted.any_lane_values.iter().all(|lanes| {
                        lanes.iter().any(|by_key| {
                            by_key
                                .get(&(doc.filter_bytes, doc.bloom_hashes))
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(bloom_bytes, required)
                                })
                        })
                    })
                } else {
                    shifted.shifts.iter().any(|by_key| {
                        by_key
                            .get(&(doc.filter_bytes, doc.bloom_hashes))
                            .is_some_and(|required| {
                                raw_filter_matches_word_masks(bloom_bytes, required)
                            })
                    })
                }
            });
            if !primary_match {
                continue;
            }
            used_tier1 = true;
        }
        let mut used_tier2 = false;
        if !tier2_alternative.is_empty() {
            if tier2_only {
                if doc.tier2_filter_bytes == 0 || doc.tier2_bloom_hashes == 0 {
                    continue;
                }
                let tier2_bloom_bytes = doc_inputs.tier2_bloom_bytes(load_tier2)?;
                if tier2_bloom_bytes.is_empty() {
                    continue;
                }
                let tier2_match = pattern_masks.tier2.get(alt_index).is_some_and(|shifted| {
                    if !shifted.any_lane_grams.is_empty() {
                        shifted.any_lane_grams.iter().all(|value| {
                            (0..DEFAULT_BLOOM_POSITION_LANES).any(|lane| {
                                bloom_word_masks_in_lane(
                                    &[*value],
                                    doc.tier2_filter_bytes,
                                    doc.tier2_bloom_hashes,
                                    lane,
                                    DEFAULT_BLOOM_POSITION_LANES,
                                )
                                .ok()
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(tier2_bloom_bytes, &required)
                                })
                            })
                        })
                    } else if !shifted.any_lane_values.is_empty() {
                        shifted.any_lane_values.iter().all(|lanes| {
                            lanes.iter().any(|by_key| {
                                by_key
                                    .get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                                    .is_some_and(|required| {
                                        raw_filter_matches_word_masks(tier2_bloom_bytes, required)
                                    })
                            })
                        })
                    } else {
                        shifted.shifts.iter().any(|by_key| {
                            by_key
                                .get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(tier2_bloom_bytes, required)
                                })
                        })
                    }
                });
                if !tier2_match {
                    continue;
                }
                used_tier2 = true;
            } else if allow_tier2 && doc.tier2_filter_bytes > 0 && doc.tier2_bloom_hashes > 0 {
                let tier2_bloom_bytes = doc_inputs.tier2_bloom_bytes(load_tier2)?;
                if tier2_bloom_bytes.is_empty() {
                    continue;
                }
                let tier2_match = pattern_masks.tier2.get(alt_index).is_some_and(|shifted| {
                    if !shifted.any_lane_grams.is_empty() {
                        shifted.any_lane_grams.iter().all(|value| {
                            (0..DEFAULT_BLOOM_POSITION_LANES).any(|lane| {
                                bloom_word_masks_in_lane(
                                    &[*value],
                                    doc.tier2_filter_bytes,
                                    doc.tier2_bloom_hashes,
                                    lane,
                                    DEFAULT_BLOOM_POSITION_LANES,
                                )
                                .ok()
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(tier2_bloom_bytes, &required)
                                })
                            })
                        })
                    } else if !shifted.any_lane_values.is_empty() {
                        shifted.any_lane_values.iter().all(|lanes| {
                            lanes.iter().any(|by_key| {
                                by_key
                                    .get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                                    .is_some_and(|required| {
                                        raw_filter_matches_word_masks(tier2_bloom_bytes, required)
                                    })
                            })
                        })
                    } else {
                        shifted.shifts.iter().any(|by_key| {
                            by_key
                                .get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(tier2_bloom_bytes, required)
                                })
                        })
                    }
                });
                if !tier2_match {
                    continue;
                }
                used_tier2 = true;
            }
        }
        return Ok(MatchOutcome {
            matched: true,
            tiers: TierFlags {
                used_tier1,
                used_tier2,
            },
        });
    }
    Ok(MatchOutcome::default())
}

/// Recursively evaluates the compiled query tree for one document using bloom
/// filters, metadata, and verifier-only prefix checks as needed.
///
/// How it works:
/// - Reuses cached pattern outcomes where possible.
/// - Dispatches on node kind for logical operators, metadata predicates, and
///   verifier-only checks.
/// - Propagates which bloom tiers were used so callers can report tier usage.
///
/// Inputs:
/// - `node`: Current query-plan node to evaluate.
/// - `doc_inputs`: Lazy access to the current document and sidecar payloads.
/// - `load_metadata`, `load_tier1`, `load_tier2`: Deferred sidecar loaders.
/// - `patterns`, `mask_cache`: Prepared query state keyed by pattern id.
/// - `plan`: Query-level tier policy flags.
/// - `query_now_unix`: Timestamp used by `time.now` predicates.
/// - `eval_cache`: Per-document cache of already-evaluated pattern outcomes.
///
/// Returns:
/// - Whether the subtree matched and which tiers were consumed.
fn evaluate_node<'a, FM, FT1, FT2>(
    node: &QueryNode,
    doc_inputs: &mut LazyDocQueryInputs<'a>,
    load_metadata: &mut FM,
    load_tier1: &mut FT1,
    load_tier2: &mut FT2,
    patterns: &HashMap<String, PatternPlan>,
    mask_cache: &PatternMaskCache,
    plan: &CompiledQueryPlan,
    query_now_unix: u64,
    eval_cache: &mut QueryEvalCache,
) -> Result<MatchOutcome>
where
    FM: FnMut() -> Result<Cow<'a, [u8]>>,
    FT1: FnMut() -> Result<Cow<'a, [u8]>>,
    FT2: FnMut() -> Result<Cow<'a, [u8]>>,
{
    match node.kind.as_str() {
        "pattern" => {
            let pattern_id = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| SspryError::from("pattern node requires pattern_id"))?;
            if let Some(outcome) = eval_cache.pattern_outcomes.get(pattern_id).copied() {
                return Ok(outcome);
            }
            let pattern = patterns
                .get(pattern_id)
                .ok_or_else(|| SspryError::from(format!("Unknown pattern id: {pattern_id}")))?;
            let pattern_masks = mask_cache
                .get(pattern_id)
                .ok_or_else(|| SspryError::from(format!("Unknown pattern id: {pattern_id}")))?;
            let outcome = evaluate_pattern(
                pattern,
                pattern_masks,
                doc_inputs,
                load_tier1,
                load_tier2,
                plan,
            )?;
            eval_cache
                .pattern_outcomes
                .insert(pattern_id.clone(), outcome);
            Ok(outcome)
        }
        "identity_eq" => {
            let expected = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| SspryError::from("identity_eq node requires pattern_id"))?;
            Ok(MatchOutcome {
                matched: doc_inputs.doc.sha256 == *expected,
                tiers: TierFlags::default(),
            })
        }
        "not" => {
            let child = node
                .children
                .first()
                .ok_or_else(|| SspryError::from("not node requires one child"))?;
            if query_node_uses_pattern_blooms(child) || query_node_contains_verifier_only(child) {
                return Ok(MatchOutcome {
                    matched: true,
                    tiers: TierFlags::default(),
                });
            }
            let outcome = evaluate_node(
                child,
                doc_inputs,
                load_metadata,
                load_tier1,
                load_tier2,
                patterns,
                mask_cache,
                plan,
                query_now_unix,
                eval_cache,
            )?;
            Ok(MatchOutcome {
                matched: !outcome.matched,
                tiers: TierFlags::default(),
            })
        }
        "verifier_only_eq" => {
            let matched = if let Some(expr) = node.pattern_id.as_deref() {
                let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
                if let Some(file_prefix) = metadata_file_prefix_8(metadata_bytes)? {
                    verifier_only_eq_matches_file_prefix(
                        expr,
                        &file_prefix,
                        doc_inputs.doc.file_size,
                    )?
                    .unwrap_or(true)
                } else {
                    true
                }
            } else {
                true
            };
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "verifier_only_at" => {
            let matched = if let Some(expr) = node.pattern_id.as_deref() {
                if let Some((pattern_id, offset_text)) = expr.split_once('@') {
                    if offset_text == "0" {
                        let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
                        if let Some(file_prefix) = metadata_file_prefix_8(metadata_bytes)? {
                            if let Some(pattern) = patterns.get(pattern_id) {
                                pattern_matches_file_prefix_at_zero(
                                    pattern,
                                    &file_prefix,
                                    doc_inputs.doc.file_size,
                                )
                                .unwrap_or(true)
                            } else {
                                true
                            }
                        } else {
                            true
                        }
                    } else if let Some(offset) = entry_point_prefix_offset(offset_text) {
                        let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
                        if let Some(entry_point_prefix) =
                            metadata_pe_entry_point_prefix(metadata_bytes)?
                        {
                            if let Some(pattern) = patterns.get(pattern_id) {
                                pattern_matches_prefix_window(
                                    pattern,
                                    &entry_point_prefix,
                                    offset,
                                    PE_ENTRY_POINT_PREFIX_BYTES,
                                )
                                .unwrap_or(true)
                            } else {
                                true
                            }
                        } else if let Some(pattern) = patterns.get(pattern_id) {
                            pattern_matches_prefix_window(
                                pattern,
                                &[],
                                offset,
                                PE_ENTRY_POINT_PREFIX_BYTES,
                            )
                            .unwrap_or(true)
                        } else {
                            true
                        }
                    } else {
                        true
                    }
                } else {
                    true
                }
            } else {
                true
            };
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "verifier_only_count" | "verifier_only_in_range" | "verifier_only_loop" => {
            Ok(MatchOutcome {
                matched: true,
                tiers: TierFlags::default(),
            })
        }
        "filesize_eq" | "filesize_ne" | "filesize_lt" | "filesize_le" | "filesize_gt"
        | "filesize_ge" => {
            let expected_size = node
                .threshold
                .ok_or_else(|| SspryError::from(format!("{} node requires threshold", node.kind)))?
                as u64;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported filesize node: {}", node.kind))
            })?;
            Ok(MatchOutcome {
                matched: compare_u64(doc_inputs.doc.file_size, expected_size, op),
                tiers: TierFlags::default(),
            })
        }
        "metadata_eq" | "metadata_ne" | "metadata_lt" | "metadata_le" | "metadata_gt"
        | "metadata_ge" => {
            let field = node.pattern_id.as_deref().ok_or_else(|| {
                SspryError::from(format!("{} node requires pattern_id", node.kind))
            })?;
            let expected = node
                .threshold
                .ok_or_else(|| SspryError::from(format!("{} node requires threshold", node.kind)))?
                as u64;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported metadata node: {}", node.kind))
            })?;
            let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
            let matched = metadata_field_matches_compare(metadata_bytes, field, op, expected)?
                .unwrap_or(true);
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "metadata_float_eq" | "metadata_float_ne" | "metadata_float_lt" | "metadata_float_le"
        | "metadata_float_gt" | "metadata_float_ge" => {
            let field = node.pattern_id.as_deref().ok_or_else(|| {
                SspryError::from(format!("{} node requires pattern_id", node.kind))
            })?;
            let expected = node
                .threshold
                .ok_or_else(|| SspryError::from(format!("{} node requires threshold", node.kind)))?
                as u32;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported metadata-float node: {}", node.kind))
            })?;
            let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
            let matched = metadata_field_matches_compare_f32(
                metadata_bytes,
                field,
                op,
                f32::from_bits(expected),
            )?
            .unwrap_or(true);
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "metadata_time_eq" | "metadata_time_ne" | "metadata_time_lt" | "metadata_time_le"
        | "metadata_time_gt" | "metadata_time_ge" => {
            let field = node.pattern_id.as_deref().ok_or_else(|| {
                SspryError::from(format!("{} node requires pattern_id", node.kind))
            })?;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported metadata-time node: {}", node.kind))
            })?;
            let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
            let matched =
                metadata_field_matches_compare(metadata_bytes, field, op, query_now_unix)?
                    .unwrap_or(true);
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "metadata_field_eq" | "metadata_field_ne" | "metadata_field_lt" | "metadata_field_le"
        | "metadata_field_gt" | "metadata_field_ge" => {
            let (lhs_field, rhs_field) = metadata_field_pair(node, &node.kind)?;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported metadata-field node: {}", node.kind))
            })?;
            let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
            let matched = metadata_fields_compare(metadata_bytes, &lhs_field, op, &rhs_field)?
                .unwrap_or(true);
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "time_now_eq" | "time_now_ne" | "time_now_lt" | "time_now_le" | "time_now_gt"
        | "time_now_ge" => {
            let expected = node
                .threshold
                .ok_or_else(|| SspryError::from(format!("{} node requires threshold", node.kind)))?
                as u64;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported time.now node: {}", node.kind))
            })?;
            Ok(MatchOutcome {
                matched: compare_u64(query_now_unix, expected, op),
                tiers: TierFlags::default(),
            })
        }
        "and" => {
            let mut merged = TierFlags::default();
            for child in &node.children {
                let outcome = evaluate_node(
                    child,
                    doc_inputs,
                    load_metadata,
                    load_tier1,
                    load_tier2,
                    patterns,
                    mask_cache,
                    plan,
                    query_now_unix,
                    eval_cache,
                )?;
                if !outcome.matched {
                    return Ok(MatchOutcome::default());
                }
                merged.merge(outcome.tiers);
            }
            Ok(MatchOutcome {
                matched: true,
                tiers: merged,
            })
        }
        "or" => {
            for child in &node.children {
                let outcome = evaluate_node(
                    child,
                    doc_inputs,
                    load_metadata,
                    load_tier1,
                    load_tier2,
                    patterns,
                    mask_cache,
                    plan,
                    query_now_unix,
                    eval_cache,
                )?;
                if outcome.matched {
                    return Ok(outcome);
                }
            }
            Ok(MatchOutcome::default())
        }
        "n_of" => {
            let threshold = node
                .threshold
                .ok_or_else(|| SspryError::from("n_of node requires threshold"))?;
            let mut matched_count = 0usize;
            let mut merged = TierFlags::default();
            for child in &node.children {
                let outcome = evaluate_node(
                    child,
                    doc_inputs,
                    load_metadata,
                    load_tier1,
                    load_tier2,
                    patterns,
                    mask_cache,
                    plan,
                    query_now_unix,
                    eval_cache,
                )?;
                if outcome.matched {
                    matched_count += 1;
                    merged.merge(outcome.tiers);
                    if matched_count >= threshold {
                        return Ok(MatchOutcome {
                            matched: true,
                            tiers: merged,
                        });
                    }
                }
            }
            Ok(MatchOutcome {
                matched: matched_count >= threshold,
                tiers: if matched_count >= threshold {
                    merged
                } else {
                    TierFlags::default()
                },
            })
        }
        other => Err(SspryError::from(format!(
            "Unsupported ast node kind: {other}"
        ))),
    }
}
