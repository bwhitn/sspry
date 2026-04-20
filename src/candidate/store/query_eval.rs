type RuntimeGramMaskCache = HashMap<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>;

const MAX_LANE_POSITION_VARIANTS: usize = 64;

/// Estimates the heap retained by one cached query pattern plan.
fn query_pattern_plan_memory_bytes(pattern: &PatternPlan) -> u64 {
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

/// Estimates the heap retained by one runtime-query alternative descriptor.
fn runtime_alternative_artifacts_memory_bytes(artifacts: &RuntimeAlternativeArtifacts) -> u64 {
    (std::mem::size_of::<RuntimeAlternativeArtifacts>() as u64)
        .saturating_add(
            (artifacts.lane_variants.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<usize>>() as u64),
        )
        .saturating_add(
            artifacts
                .lane_variants
                .iter()
                .map(|lanes| {
                    (std::mem::size_of::<Vec<usize>>() as u64).saturating_add(
                        (lanes.capacity() as u64).saturating_mul(std::mem::size_of::<usize>() as u64),
                    )
                })
                .sum::<u64>(),
        )
}

/// Estimates the heap retained by one runtime-query pattern descriptor.
fn runtime_pattern_artifacts_memory_bytes(artifacts: &RuntimePatternArtifacts) -> u64 {
    (std::mem::size_of::<RuntimePatternArtifacts>() as u64)
        .saturating_add(
            (artifacts.tier1.capacity() as u64)
                .saturating_mul(std::mem::size_of::<RuntimeAlternativeArtifacts>() as u64),
        )
        .saturating_add(
            artifacts
                .tier1
                .iter()
                .map(runtime_alternative_artifacts_memory_bytes)
                .sum::<u64>(),
        )
        .saturating_add(
            (artifacts.tier2.capacity() as u64)
                .saturating_mul(std::mem::size_of::<RuntimeAlternativeArtifacts>() as u64),
        )
        .saturating_add(
            artifacts
                .tier2
                .iter()
                .map(runtime_alternative_artifacts_memory_bytes)
                .sum::<u64>(),
        )
}

/// Estimates the total heap footprint of one runtime-query artifact entry.
pub(crate) fn runtime_query_artifacts_memory_bytes(artifacts: &RuntimeQueryArtifacts) -> u64 {
    let patterns_bytes = artifacts
        .patterns
        .iter()
        .map(|(key, pattern)| {
            (std::mem::size_of::<String>() as u64)
                .saturating_add(key.capacity() as u64)
                .saturating_add(query_pattern_plan_memory_bytes(pattern))
        })
        .sum::<u64>();
    let runtime_patterns_bytes = artifacts
        .runtime_patterns
        .iter()
        .map(|(key, pattern)| {
            (std::mem::size_of::<String>() as u64)
                .saturating_add(key.capacity() as u64)
                .saturating_add(runtime_pattern_artifacts_memory_bytes(pattern))
        })
        .sum::<u64>();
    (std::mem::size_of::<RuntimeQueryArtifacts>() as u64)
        .saturating_add(patterns_bytes)
        .saturating_add(runtime_patterns_bytes)
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

/// Builds the runtime-query artifact bundle used by the hash-at-evaluation
/// search path.
pub(crate) fn build_runtime_query_artifacts(
    plan: &CompiledQueryPlan,
) -> Result<Arc<RuntimeQueryArtifacts>> {
    let patterns = plan
        .patterns
        .iter()
        .cloned()
        .map(|pattern| (pattern.pattern_id.clone(), pattern))
        .collect::<HashMap<_, _>>();
    let runtime_patterns = plan
        .patterns
        .iter()
        .map(|pattern| {
            let tier1 = pattern
                .alternatives
                .iter()
                .enumerate()
                .map(|(alt_index, alternative)| {
                    let anchor_literal = pattern
                        .anchor_literals
                        .get(alt_index)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    let use_any_lane = anchor_literal.is_empty()
                        || anchor_literal.len() < plan.tier1_gram_size
                        || exact_pattern_has_ambiguous_positions(
                            alternative,
                            anchor_literal,
                            plan.tier1_gram_size,
                        );
                    RuntimeAlternativeArtifacts {
                        use_any_lane,
                        lane_variants: if use_any_lane {
                            Vec::new()
                        } else {
                            lane_position_variants_for_pattern(
                                alternative,
                                anchor_literal,
                                plan.tier1_gram_size,
                                DEFAULT_BLOOM_POSITION_LANES,
                            )
                        },
                    }
                })
                .collect::<Vec<_>>();
            let tier2 = pattern
                .tier2_alternatives
                .iter()
                .enumerate()
                .map(|(alt_index, alternative)| {
                    let anchor_literal = pattern
                        .anchor_literals
                        .get(alt_index)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    let use_any_lane = anchor_literal.is_empty()
                        || anchor_literal.len() < plan.tier2_gram_size
                        || exact_pattern_has_ambiguous_positions(
                            alternative,
                            anchor_literal,
                            plan.tier2_gram_size,
                        );
                    RuntimeAlternativeArtifacts {
                        use_any_lane,
                        lane_variants: if use_any_lane {
                            Vec::new()
                        } else {
                            lane_position_variants_for_pattern(
                                alternative,
                                anchor_literal,
                                plan.tier2_gram_size,
                                DEFAULT_BLOOM_POSITION_LANES,
                            )
                        },
                    }
                })
                .collect::<Vec<_>>();
            Ok::<(String, RuntimePatternArtifacts), SspryError>((
                pattern.pattern_id.clone(),
                RuntimePatternArtifacts { tier1, tier2 },
            ))
        })
        .collect::<Result<HashMap<_, _>>>()?;
    Ok(Arc::new(RuntimeQueryArtifacts {
        patterns,
        runtime_patterns,
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

/// Reuses or materializes the bloom word masks for one gram/lane combination.
fn cached_bloom_word_masks_in_lane(
    value: u64,
    size_bytes: usize,
    hash_count: usize,
    lane: usize,
    lane_count: usize,
    cache: &mut RuntimeGramMaskCache,
) -> Result<Vec<(usize, u64)>> {
    let key = (value, size_bytes, hash_count, lane, lane_count);
    if let Some(entry) = cache.get(&key) {
        return Ok(entry.clone());
    }
    let entry = bloom_word_masks_in_lane(&[value], size_bytes, hash_count, lane, lane_count)?;
    cache.insert(key, entry.clone());
    Ok(entry)
}

/// Checks whether every gram in an alternative can match at least one lane.
fn runtime_any_lane_matches(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
    bloom_bytes: &[u8],
    cache: &mut RuntimeGramMaskCache,
) -> Result<bool> {
    for value in values {
        let mut matched = false;
        for lane in 0..DEFAULT_BLOOM_POSITION_LANES {
            let required = cached_bloom_word_masks_in_lane(
                *value,
                size_bytes,
                hash_count,
                lane,
                DEFAULT_BLOOM_POSITION_LANES,
                cache,
            )?;
            if raw_filter_matches_word_masks(bloom_bytes, &required) {
                matched = true;
                break;
            }
        }
        if !matched {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Checks whether any exact lane-position variant of an alternative matches.
fn runtime_shifted_matches(
    values: &[u64],
    lane_variants: &[Vec<usize>],
    size_bytes: usize,
    hash_count: usize,
    bloom_bytes: &[u8],
    cache: &mut RuntimeGramMaskCache,
) -> Result<bool> {
    for lanes in lane_variants {
        let required = merge_cached_lane_bloom_word_masks(
            values,
            size_bytes,
            hash_count,
            lanes,
            DEFAULT_BLOOM_POSITION_LANES,
            cache,
        )?;
        if raw_filter_matches_word_masks(bloom_bytes, &required) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Evaluates one pattern alternative by hashing query grams on demand.
fn evaluate_pattern_runtime<'a, FT1, FT2>(
    pattern: &PatternPlan,
    runtime_pattern: &RuntimePatternArtifacts,
    doc_inputs: &mut LazyDocQueryInputs<'a>,
    load_tier1: &mut FT1,
    load_tier2: &mut FT2,
    plan: &CompiledQueryPlan,
    gram_cache: &mut RuntimeGramMaskCache,
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
            let runtime_alternative = runtime_pattern
                .tier1
                .get(alt_index)
                .ok_or_else(|| SspryError::from("Runtime tier1 alternative missing"))?;
            let primary_match = if runtime_alternative.use_any_lane {
                runtime_any_lane_matches(
                    alternative,
                    doc.filter_bytes,
                    doc.bloom_hashes,
                    bloom_bytes,
                    gram_cache,
                )?
            } else {
                runtime_shifted_matches(
                    alternative,
                    &runtime_alternative.lane_variants,
                    doc.filter_bytes,
                    doc.bloom_hashes,
                    bloom_bytes,
                    gram_cache,
                )?
            };
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
                let runtime_alternative = runtime_pattern
                    .tier2
                    .get(alt_index)
                    .ok_or_else(|| SspryError::from("Runtime tier2 alternative missing"))?;
                let tier2_match = if runtime_alternative.use_any_lane {
                    runtime_any_lane_matches(
                        tier2_alternative,
                        doc.tier2_filter_bytes,
                        doc.tier2_bloom_hashes,
                        tier2_bloom_bytes,
                        gram_cache,
                    )?
                } else {
                    runtime_shifted_matches(
                        tier2_alternative,
                        &runtime_alternative.lane_variants,
                        doc.tier2_filter_bytes,
                        doc.tier2_bloom_hashes,
                        tier2_bloom_bytes,
                        gram_cache,
                    )?
                };
                if !tier2_match {
                    continue;
                }
                used_tier2 = true;
            } else if allow_tier2 && doc.tier2_filter_bytes > 0 && doc.tier2_bloom_hashes > 0 {
                let tier2_bloom_bytes = doc_inputs.tier2_bloom_bytes(load_tier2)?;
                if tier2_bloom_bytes.is_empty() {
                    continue;
                }
                let runtime_alternative = runtime_pattern
                    .tier2
                    .get(alt_index)
                    .ok_or_else(|| SspryError::from("Runtime tier2 alternative missing"))?;
                let tier2_match = if runtime_alternative.use_any_lane {
                    runtime_any_lane_matches(
                        tier2_alternative,
                        doc.tier2_filter_bytes,
                        doc.tier2_bloom_hashes,
                        tier2_bloom_bytes,
                        gram_cache,
                    )?
                } else {
                    runtime_shifted_matches(
                        tier2_alternative,
                        &runtime_alternative.lane_variants,
                        doc.tier2_filter_bytes,
                        doc.tier2_bloom_hashes,
                        tier2_bloom_bytes,
                        gram_cache,
                    )?
                };
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

/// Shared query-tree walker used by both prepared-mask and runtime-hash
/// pattern evaluators.
fn evaluate_node_with_patterns<'a, FM, FT1, FT2, FE>(
    node: &QueryNode,
    doc_inputs: &mut LazyDocQueryInputs<'a>,
    load_metadata: &mut FM,
    load_tier1: &mut FT1,
    load_tier2: &mut FT2,
    patterns: &HashMap<String, PatternPlan>,
    plan: &CompiledQueryPlan,
    query_now_unix: u64,
    eval_cache: &mut QueryEvalCache,
    eval_pattern: &mut FE,
) -> Result<MatchOutcome>
where
    FM: FnMut() -> Result<Cow<'a, [u8]>>,
    FT1: FnMut() -> Result<Cow<'a, [u8]>>,
    FT2: FnMut() -> Result<Cow<'a, [u8]>>,
    FE: FnMut(
        &str,
        &mut LazyDocQueryInputs<'a>,
        &mut FT1,
        &mut FT2,
        &CompiledQueryPlan,
    ) -> Result<MatchOutcome>,
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
            let outcome = eval_pattern(pattern_id, doc_inputs, load_tier1, load_tier2, plan)?;
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
                matched: doc_inputs.doc.identity == *expected,
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
            let outcome = evaluate_node_with_patterns(
                child,
                doc_inputs,
                load_metadata,
                load_tier1,
                load_tier2,
                patterns,
                plan,
                query_now_unix,
                eval_cache,
                eval_pattern,
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
                let outcome = evaluate_node_with_patterns(
                    child,
                    doc_inputs,
                    load_metadata,
                    load_tier1,
                    load_tier2,
                    patterns,
                    plan,
                    query_now_unix,
                    eval_cache,
                    eval_pattern,
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
                let outcome = evaluate_node_with_patterns(
                    child,
                    doc_inputs,
                    load_metadata,
                    load_tier1,
                    load_tier2,
                    patterns,
                    plan,
                    query_now_unix,
                    eval_cache,
                    eval_pattern,
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
                let outcome = evaluate_node_with_patterns(
                    child,
                    doc_inputs,
                    load_metadata,
                    load_tier1,
                    load_tier2,
                    patterns,
                    plan,
                    query_now_unix,
                    eval_cache,
                    eval_pattern,
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

/// Runtime-hash query-tree evaluator wrapper.
fn evaluate_node_runtime<'a, FM, FT1, FT2>(
    node: &QueryNode,
    doc_inputs: &mut LazyDocQueryInputs<'a>,
    load_metadata: &mut FM,
    load_tier1: &mut FT1,
    load_tier2: &mut FT2,
    runtime: &RuntimeQueryArtifacts,
    plan: &CompiledQueryPlan,
    query_now_unix: u64,
    eval_cache: &mut QueryEvalCache,
    gram_cache: &mut RuntimeGramMaskCache,
) -> Result<MatchOutcome>
where
    FM: FnMut() -> Result<Cow<'a, [u8]>>,
    FT1: FnMut() -> Result<Cow<'a, [u8]>>,
    FT2: FnMut() -> Result<Cow<'a, [u8]>>,
{
    let mut eval_pattern = |pattern_id: &str,
                            doc_inputs: &mut LazyDocQueryInputs<'a>,
                            load_tier1: &mut FT1,
                            load_tier2: &mut FT2,
                            plan: &CompiledQueryPlan|
     -> Result<MatchOutcome> {
        let pattern = runtime
            .patterns
            .get(pattern_id)
            .ok_or_else(|| SspryError::from(format!("Unknown pattern id: {pattern_id}")))?;
        let runtime_pattern = runtime
            .runtime_patterns
            .get(pattern_id)
            .ok_or_else(|| SspryError::from(format!("Unknown runtime pattern id: {pattern_id}")))?;
        evaluate_pattern_runtime(
            pattern,
            runtime_pattern,
            doc_inputs,
            load_tier1,
            load_tier2,
            plan,
            gram_cache,
        )
    };
    evaluate_node_with_patterns(
        node,
        doc_inputs,
        load_metadata,
        load_tier1,
        load_tier2,
        &runtime.patterns,
        plan,
        query_now_unix,
        eval_cache,
        &mut eval_pattern,
    )
}
