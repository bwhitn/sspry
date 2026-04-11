/// Namespaces a pattern identifier so helper-rule patterns cannot collide with
/// the root rule's local identifiers.
fn namespace_pattern_id(rule_name: &str, pattern_id: &str) -> String {
    format!("{RULE_DEP_PATTERN_PREFIX}{rule_name}::{pattern_id}")
}

/// Merges one compiled rule fragment into another while rejecting any
/// conflicting pattern definitions.
///
/// Inputs:
/// - `into`: Destination fragment being accumulated.
/// - `other`: Helper fragment whose pattern maps should be merged in.
///
/// Returns:
/// - `Ok(())` when all overlapping definitions are identical.
/// - An error if the two fragments define the same pattern differently.
fn merge_rule_fragment(into: &mut RulePlanFragment, other: &RulePlanFragment) -> Result<()> {
    for (key, value) in &other.pattern_alternatives {
        if let Some(existing) = into.pattern_alternatives.insert(key.clone(), value.clone())
            && existing != *value
        {
            return Err(SspryError::from(format!(
                "Conflicting pattern alternatives for {key}"
            )));
        }
    }
    for (key, value) in &other.pattern_tier2_alternatives {
        if let Some(existing) = into
            .pattern_tier2_alternatives
            .insert(key.clone(), value.clone())
            && existing != *value
        {
            return Err(SspryError::from(format!(
                "Conflicting tier2 pattern alternatives for {key}"
            )));
        }
    }
    for (key, value) in &other.pattern_anchor_literals {
        if let Some(existing) = into
            .pattern_anchor_literals
            .insert(key.clone(), value.clone())
            && existing != *value
        {
            return Err(SspryError::from(format!(
                "Conflicting anchor literals for {key}"
            )));
        }
    }
    for (key, value) in &other.pattern_fixed_literals {
        if let Some(existing) = into
            .pattern_fixed_literals
            .insert(key.clone(), value.clone())
            && existing != *value
        {
            return Err(SspryError::from(format!(
                "Conflicting fixed literals for {key}"
            )));
        }
    }
    for (key, value) in &other.pattern_fixed_literal_wide {
        if let Some(existing) = into
            .pattern_fixed_literal_wide
            .insert(key.clone(), value.clone())
            && existing != *value
        {
            return Err(SspryError::from(format!(
                "Conflicting fixed literal wide flags for {key}"
            )));
        }
    }
    for (key, value) in &other.pattern_fixed_literal_fullword {
        if let Some(existing) = into
            .pattern_fixed_literal_fullword
            .insert(key.clone(), value.clone())
            && existing != *value
        {
            return Err(SspryError::from(format!(
                "Conflicting fixed literal fullword flags for {key}"
            )));
        }
    }
    Ok(())
}

/// Collects the pattern identifiers defined locally by a rule fragment before
/// dependency namespacing is applied.
fn collect_local_pattern_ids(fragment: &RulePlanFragment) -> HashSet<String> {
    fragment
        .pattern_alternatives
        .keys()
        .filter(|key| !key.starts_with(RULE_DEP_PATTERN_PREFIX))
        .cloned()
        .collect()
}

/// Rewrites a verifier-only pattern reference so helper-rule patterns are
/// namespaced consistently with the owning rule.
///
/// Inputs:
/// - `kind`: AST node kind that determines the pattern-id encoding.
/// - `pattern_id`: Existing pattern reference from the AST.
/// - `local_pattern_ids`: Local pattern ids that must be namespaced.
/// - `rule_name`: Rule name used for the namespace prefix.
///
/// Returns:
/// - The original or rewritten pattern identifier.
fn rename_verifier_pattern_id(
    kind: &str,
    pattern_id: &str,
    local_pattern_ids: &HashSet<String>,
    rule_name: &str,
) -> String {
    match kind {
        "pattern" | "identity_eq" => {
            if local_pattern_ids.contains(pattern_id) {
                namespace_pattern_id(rule_name, pattern_id)
            } else {
                pattern_id.to_owned()
            }
        }
        "verifier_only_at" => {
            if let Some((raw_id, offset)) = pattern_id.split_once('@')
                && local_pattern_ids.contains(raw_id)
            {
                return format!("{}@{offset}", namespace_pattern_id(rule_name, raw_id));
            }
            pattern_id.to_owned()
        }
        "verifier_only_count" => {
            let mut parts = pattern_id.split(':');
            let prefix = parts.next();
            let raw_id = parts.next();
            let op = parts.next();
            let value = parts.next();
            if prefix == Some("count")
                && let (Some(raw_id), Some(op), Some(value)) = (raw_id, op, value)
                && local_pattern_ids.contains(raw_id)
            {
                return format!(
                    "count:{}:{op}:{value}",
                    namespace_pattern_id(rule_name, raw_id)
                );
            }
            pattern_id.to_owned()
        }
        "verifier_only_in_range" => {
            let mut parts = pattern_id.split(':');
            let prefix = parts.next();
            let raw_id = parts.next();
            let start = parts.next();
            let end = parts.next();
            if prefix == Some("range")
                && let (Some(raw_id), Some(start), Some(end)) = (raw_id, start, end)
                && local_pattern_ids.contains(raw_id)
            {
                return format!(
                    "range:{}:{start}:{end}",
                    namespace_pattern_id(rule_name, raw_id)
                );
            }
            pattern_id.to_owned()
        }
        "verifier_only_loop" => {
            if local_pattern_ids.contains(pattern_id) {
                namespace_pattern_id(rule_name, pattern_id)
            } else {
                pattern_id.to_owned()
            }
        }
        _ => pattern_id.to_owned(),
    }
}

/// Applies helper-rule namespacing to every locally defined pattern and all AST
/// references that point at those patterns.
///
/// Inputs:
/// - `fragment`: Helper-rule fragment to rewrite in place.
/// - `rule_name`: Rule name used as the namespace prefix.
///
/// Output:
/// - Updates the fragment maps and root AST so they can be merged safely.
fn rename_fragment_for_rule_dependency(fragment: &mut RulePlanFragment, rule_name: &str) {
    let local_pattern_ids = collect_local_pattern_ids(fragment);
    if local_pattern_ids.is_empty() {
        return;
    }
    let rename_map = local_pattern_ids
        .iter()
        .map(|pattern_id| {
            (
                pattern_id.clone(),
                namespace_pattern_id(rule_name, pattern_id),
            )
        })
        .collect::<HashMap<_, _>>();

    let remap_map = |map: &mut BTreeMap<String, Vec<Vec<u64>>>| {
        let mut next = BTreeMap::<String, Vec<Vec<u64>>>::new();
        for (key, value) in std::mem::take(map) {
            let new_key = rename_map.get(&key).cloned().unwrap_or(key);
            next.insert(new_key, value);
        }
        *map = next;
    };
    remap_map(&mut fragment.pattern_alternatives);
    remap_map(&mut fragment.pattern_tier2_alternatives);

    let remap_bytes = |map: &mut BTreeMap<String, Vec<Vec<u8>>>| {
        let mut next = BTreeMap::<String, Vec<Vec<u8>>>::new();
        for (key, value) in std::mem::take(map) {
            let new_key = rename_map.get(&key).cloned().unwrap_or(key);
            next.insert(new_key, value);
        }
        *map = next;
    };
    remap_bytes(&mut fragment.pattern_anchor_literals);
    remap_bytes(&mut fragment.pattern_fixed_literals);

    let remap_bools = |map: &mut BTreeMap<String, Vec<bool>>| {
        let mut next = BTreeMap::<String, Vec<bool>>::new();
        for (key, value) in std::mem::take(map) {
            let new_key = rename_map.get(&key).cloned().unwrap_or(key);
            next.insert(new_key, value);
        }
        *map = next;
    };
    remap_bools(&mut fragment.pattern_fixed_literal_wide);
    remap_bools(&mut fragment.pattern_fixed_literal_fullword);

    // Rewrites local pattern ids throughout the query tree so helper-rule
    // fragments can be merged into the caller's namespace.
    fn recurse(node: &mut QueryNode, local_pattern_ids: &HashSet<String>, rule_name: &str) {
        if let Some(pattern_id) = node.pattern_id.as_mut() {
            *pattern_id =
                rename_verifier_pattern_id(&node.kind, pattern_id, local_pattern_ids, rule_name);
        }
        for child in &mut node.children {
            recurse(child, local_pattern_ids, rule_name);
        }
    }
    if let Some(root) = fragment.root.as_mut() {
        recurse(root, &local_pattern_ids, rule_name);
    }
}

/// Parses one rule block into a local rule fragment before helper-rule
/// dependencies are resolved.
///
/// How it works:
/// - Parses string, regex, and hex declarations into pattern alternatives.
/// - Tracks patterns that are only usable during verification.
/// - Rewrites the condition text before feeding it into the condition parser.
///
/// Inputs:
/// - `rule`: Parsed rule block to compile.
/// - `known_rule_names`: Other rule names visible for rule references.
/// - `gram_sizes`: Active tier1/tier2 gram sizes.
/// - `active_identity_source`: Optional whole-file hash identity policy.
///
/// Returns:
/// - The partially compiled fragment containing local patterns and a root AST.
fn build_local_rule_fragment(
    rule: &ParsedRuleBlock,
    known_rule_names: HashSet<String>,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
) -> Result<RulePlanFragment> {
    let mut fragment = RulePlanFragment::default();
    let mut next_anonymous_pattern_id = 0usize;
    let mut verifier_only_pattern_ids = HashSet::<String>::new();
    for line in &rule.strings_lines {
        if let Some(def) = parse_literal_line(line)? {
            let pattern_id = if def.pattern_id == "$" {
                let id = format!("{ANONYMOUS_PATTERN_PREFIX}{next_anonymous_pattern_id}");
                next_anonymous_pattern_id += 1;
                id
            } else {
                def.pattern_id.clone()
            };
            let mut alternatives = Vec::new();
            let mut tier2_alternatives = Vec::new();
            let mut anchor_literals = Vec::new();
            let mut fixed_literals = Vec::new();
            let mut wide_flags = Vec::new();
            let mut fullword_flags = Vec::new();
            for (((alt, wide), fullword), nocase) in def
                .alternatives
                .iter()
                .zip(def.wide_flags.iter())
                .zip(def.fullword_flags.iter())
                .zip(def.nocase_flags.iter())
            {
                let effective_nocase = *nocase && alt.iter().any(u8::is_ascii_alphabetic);
                let search_variants = if effective_nocase {
                    derive_nocase_search_alternatives(alt, *wide, gram_sizes)?
                } else {
                    vec![alt.clone()]
                };
                for search_alt in search_variants {
                    alternatives.push(grams_tier1_from_bytes(&search_alt, gram_sizes.tier1));
                    tier2_alternatives.push(grams_tier2_from_bytes(&search_alt, gram_sizes.tier2));
                    anchor_literals.push(search_alt.clone());
                    fixed_literals.push(if def.exact_literals && !effective_nocase {
                        alt.clone()
                    } else {
                        Vec::new()
                    });
                    wide_flags.push(*wide);
                    fullword_flags.push(*fullword);
                }
            }
            if !pattern_has_searchable_anchor(&alternatives, &tier2_alternatives, &fixed_literals) {
                verifier_only_pattern_ids.insert(pattern_id);
                continue;
            }
            fragment
                .pattern_alternatives
                .insert(pattern_id.clone(), alternatives);
            fragment
                .pattern_tier2_alternatives
                .insert(pattern_id.clone(), tier2_alternatives);
            fragment
                .pattern_anchor_literals
                .insert(pattern_id.clone(), anchor_literals);
            fragment
                .pattern_fixed_literals
                .insert(pattern_id.clone(), fixed_literals);
            fragment
                .pattern_fixed_literal_wide
                .insert(pattern_id.clone(), wide_flags);
            fragment
                .pattern_fixed_literal_fullword
                .insert(pattern_id, fullword_flags);
            continue;
        }
        match parse_regex_line(line, gram_sizes) {
            Ok(Some(def)) => {
                let pattern_id = if def.pattern_id == "$" {
                    let id = format!("{ANONYMOUS_PATTERN_PREFIX}{next_anonymous_pattern_id}");
                    next_anonymous_pattern_id += 1;
                    id
                } else {
                    def.pattern_id.clone()
                };
                let alternatives = def
                    .alternatives
                    .iter()
                    .map(|alt| grams_tier1_from_bytes(alt, gram_sizes.tier1))
                    .collect::<Vec<_>>();
                let tier2_alternatives = def
                    .alternatives
                    .iter()
                    .map(|alt| grams_tier2_from_bytes(alt, gram_sizes.tier2))
                    .collect::<Vec<_>>();
                let fixed_literals = if def.exact_literals {
                    def.alternatives.clone()
                } else {
                    vec![Vec::new(); def.alternatives.len()]
                };
                let anchor_literals = def.alternatives.clone();
                if !pattern_has_searchable_anchor(
                    &alternatives,
                    &tier2_alternatives,
                    &fixed_literals,
                ) {
                    verifier_only_pattern_ids.insert(pattern_id);
                    continue;
                }
                fragment
                    .pattern_alternatives
                    .insert(pattern_id.clone(), alternatives);
                fragment
                    .pattern_tier2_alternatives
                    .insert(pattern_id.clone(), tier2_alternatives);
                fragment
                    .pattern_anchor_literals
                    .insert(pattern_id.clone(), anchor_literals);
                fragment
                    .pattern_fixed_literals
                    .insert(pattern_id.clone(), fixed_literals);
                fragment
                    .pattern_fixed_literal_wide
                    .insert(pattern_id.clone(), def.wide_flags);
                fragment
                    .pattern_fixed_literal_fullword
                    .insert(pattern_id, def.fullword_flags);
                continue;
            }
            Ok(None) => {}
            Err(err) => {
                if err
                    .to_string()
                    .contains("anchorable mandatory literal for the active gram sizes")
                    && let Some(raw_pattern_id) = parse_regex_pattern_id(line)
                {
                    let pattern_id = if raw_pattern_id == "$" {
                        let id = format!("{ANONYMOUS_PATTERN_PREFIX}{next_anonymous_pattern_id}");
                        next_anonymous_pattern_id += 1;
                        id
                    } else {
                        raw_pattern_id
                    };
                    verifier_only_pattern_ids.insert(pattern_id);
                    continue;
                }
                return Err(err);
            }
        }
        if let Some((raw_pattern_id, alternatives, tier2_alternatives, fixed_literals)) =
            parse_hex_line_to_grams(line, gram_sizes)?
        {
            let pattern_id = if raw_pattern_id == "$" {
                let id = format!("{ANONYMOUS_PATTERN_PREFIX}{next_anonymous_pattern_id}");
                next_anonymous_pattern_id += 1;
                id
            } else {
                raw_pattern_id
            };
            let alt_count = alternatives.len();
            if !pattern_has_searchable_anchor(&alternatives, &tier2_alternatives, &fixed_literals) {
                verifier_only_pattern_ids.insert(pattern_id);
                continue;
            }
            fragment
                .pattern_alternatives
                .insert(pattern_id.clone(), alternatives);
            fragment
                .pattern_tier2_alternatives
                .insert(pattern_id.clone(), tier2_alternatives);
            fragment
                .pattern_anchor_literals
                .insert(pattern_id.clone(), fixed_literals.clone());
            fragment
                .pattern_fixed_literals
                .insert(pattern_id.clone(), fixed_literals);
            fragment
                .pattern_fixed_literal_wide
                .insert(pattern_id.clone(), vec![false; alt_count]);
            fragment
                .pattern_fixed_literal_fullword
                .insert(pattern_id, vec![false; alt_count]);
            continue;
        }
        return Err(SspryError::from(format!(
            "Unsupported strings declaration: {:?}. Supported forms: $id = \"...\" [ascii|wide|fullword|nocase], $id = /.../ [ascii|wide|fullword], $id = {{ ... }}",
            line.trim()
        )));
    }

    let mut known_pattern_names = fragment
        .pattern_alternatives
        .keys()
        .cloned()
        .chain(verifier_only_pattern_ids.iter().cloned())
        .collect::<Vec<_>>();
    known_pattern_names.sort();
    known_pattern_names.dedup();
    let rewritten_condition =
        rewrite_verifier_only_for_of_at_loops(&rule.condition_text, &known_pattern_names)?;
    let mut parser = ConditionParser::new_with_rules(
        &rewritten_condition,
        fragment
            .pattern_alternatives
            .keys()
            .cloned()
            .chain(verifier_only_pattern_ids.iter().cloned())
            .collect(),
        verifier_only_pattern_ids,
        known_rule_names,
        active_identity_source,
    )?;
    fragment.root = Some(parser.parse()?);
    Ok(fragment)
}

/// Replaces `rule_ref` nodes with compiled helper-rule fragments and merges the
/// helper patterns into the current fragment.
///
/// Inputs:
/// - `node`: Current AST node being rewritten recursively.
/// - `fragment`: Fragment that should receive merged helper patterns.
/// - `rules`, `cache`, `visiting`: Rule graph state used to compile dependencies safely.
/// - `current_rule_name`: Name of the rule currently being compiled.
/// - `gram_sizes`, `active_identity_source`, `max_anchors_per_alt`,
///   `force_tier1_only`, `allow_tier2_fallback`, `max_candidates`: Compiler settings.
///
/// Returns:
/// - `Ok(())` after the subtree has been rewritten in place.
fn resolve_rule_refs(
    node: &mut QueryNode,
    fragment: &mut RulePlanFragment,
    rules: &HashMap<String, ParsedRuleBlock>,
    cache: &mut HashMap<String, RulePlanFragment>,
    visiting: &mut HashSet<String>,
    current_rule_name: &str,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: f64,
) -> Result<()> {
    if node.kind == "rule_ref" {
        let referenced = node
            .pattern_id
            .clone()
            .ok_or_else(|| SspryError::from("Rule reference node is missing a rule name."))?;
        let helper = compile_rule_fragment(
            &referenced,
            rules,
            cache,
            visiting,
            current_rule_name,
            gram_sizes,
            active_identity_source,
            max_anchors_per_alt,
            force_tier1_only,
            allow_tier2_fallback,
            max_candidates,
        )?;
        merge_rule_fragment(fragment, &helper)?;
        *node = helper.root.clone().ok_or_else(|| {
            SspryError::from(format!("Rule {referenced} compiled without a root."))
        })?;
        return Ok(());
    }
    for child in &mut node.children {
        resolve_rule_refs(
            child,
            fragment,
            rules,
            cache,
            visiting,
            current_rule_name,
            gram_sizes,
            active_identity_source,
            max_anchors_per_alt,
            force_tier1_only,
            allow_tier2_fallback,
            max_candidates,
        )?;
    }
    Ok(())
}

/// Finalizes a compiled rule fragment after all helper rules have been merged.
///
/// How it works:
/// - Prunes ignored module predicates.
/// - Injects numeric-read anchor patterns.
/// - Reorders and deduplicates the AST.
/// - Builds optimized per-pattern structures used by query execution.
///
/// Inputs:
/// - `fragment`: Partially compiled fragment whose maps still need optimization.
/// - `gram_sizes`, `max_anchors_per_alt`, `force_tier1_only`,
///   `allow_tier2_fallback`: Compiler settings that shape the final plan.
/// - `_max_candidates`: Reserved tuning input kept for interface consistency.
///
/// Returns:
/// - The finalized fragment ready to convert into a public `CompiledQueryPlan`.
fn finalize_rule_fragment(
    mut fragment: RulePlanFragment,
    gram_sizes: GramSizes,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    _max_candidates: f64,
) -> Result<RulePlanFragment> {
    let mut root = prune_ignored_module_predicates(
        fragment
            .root
            .take()
            .ok_or_else(|| SspryError::from("Rule fragment is missing a root."))?,
    )
    .ok_or_else(|| {
        SspryError::from(
            "Rule condition does not contain searchable anchors after pruning ignored module predicates.",
        )
    })?;

    let mut next_numeric_anchor_id = 0usize;
    inject_numeric_read_anchor_patterns(
        &mut root,
        &mut fragment.pattern_alternatives,
        &mut fragment.pattern_tier2_alternatives,
        &mut fragment.pattern_anchor_literals,
        &mut fragment.pattern_fixed_literals,
        &mut fragment.pattern_fixed_literal_wide,
        &mut fragment.pattern_fixed_literal_fullword,
        gram_sizes,
        &mut next_numeric_anchor_id,
    )?;
    let has_pattern = contains_pattern_node(&root);
    let has_identity = contains_identity_node(&root);
    if fragment.pattern_alternatives.is_empty() && !has_identity {
        return Err(SspryError::from(
            "Rule does not contain a strings section with supported entries.",
        ));
    }
    if !has_pattern && !has_identity && contains_verifier_only_node(&root) {
        return Err(SspryError::from(
            "Verifier-only indexed conditions require an anchorable literal for the current gram sizes or another string/hex anchor.",
        ));
    }
    reorder_or_nodes_for_selectivity(&mut root, &fragment.pattern_alternatives);
    dedupe_or_nodes(&mut root);
    let mut branch_budgets = HashMap::<String, usize>::new();
    collect_or_branch_budgets(&root, max_anchors_per_alt, &mut branch_budgets);

    let mut patterns = Vec::new();
    for (pattern_id, alternatives) in std::mem::take(&mut fragment.pattern_alternatives) {
        let tier2_alternatives = fragment
            .pattern_tier2_alternatives
            .remove(&pattern_id)
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let anchor_literals = fragment
            .pattern_anchor_literals
            .remove(&pattern_id)
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let fixed_literals = fragment
            .pattern_fixed_literals
            .remove(&pattern_id)
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let fixed_literal_wide = fragment
            .pattern_fixed_literal_wide
            .remove(&pattern_id)
            .unwrap_or_else(|| vec![false; alternatives.len()]);
        let fixed_literal_fullword = fragment
            .pattern_fixed_literal_fullword
            .remove(&pattern_id)
            .unwrap_or_else(|| vec![false; alternatives.len()]);
        let (
            alternatives,
            tier2_alternatives,
            anchor_literals,
            fixed_literals,
            fixed_literal_wide,
            fixed_literal_fullword,
        ) = dedupe_pattern_alternatives(
            alternatives,
            tier2_alternatives,
            anchor_literals,
            fixed_literals,
            fixed_literal_wide,
            fixed_literal_fullword,
        );
        let budget = branch_budgets
            .get(&pattern_id)
            .copied()
            .unwrap_or(max_anchors_per_alt)
            .max(1);
        let optimized = alternatives
            .iter()
            .zip(tier2_alternatives.iter())
            .zip(anchor_literals.iter())
            .map(|((alt, tier2_alt), anchor_literal)| {
                if allow_tier2_fallback
                    && !force_tier1_only
                    && alt.is_empty()
                    && !tier2_alt.is_empty()
                    && anchor_literal.is_empty()
                {
                    Vec::new()
                } else {
                    optimize_grams(alt, anchor_literal, gram_sizes.tier1, budget)
                }
            })
            .collect::<Vec<_>>();
        patterns.push(PatternPlan {
            pattern_id,
            alternatives: optimized,
            tier2_alternatives,
            anchor_literals,
            fixed_literals,
            fixed_literal_wide,
            fixed_literal_fullword,
        });
    }
    fragment.root = Some(root);
    fragment.pattern_alternatives = patterns
        .iter()
        .map(|pattern| (pattern.pattern_id.clone(), pattern.alternatives.clone()))
        .collect();
    fragment.pattern_tier2_alternatives = patterns
        .iter()
        .map(|pattern| {
            (
                pattern.pattern_id.clone(),
                pattern.tier2_alternatives.clone(),
            )
        })
        .collect();
    fragment.pattern_anchor_literals = patterns
        .iter()
        .map(|pattern| (pattern.pattern_id.clone(), pattern.anchor_literals.clone()))
        .collect();
    fragment.pattern_fixed_literals = patterns
        .iter()
        .map(|pattern| (pattern.pattern_id.clone(), pattern.fixed_literals.clone()))
        .collect();
    fragment.pattern_fixed_literal_wide = patterns
        .iter()
        .map(|pattern| {
            (
                pattern.pattern_id.clone(),
                pattern.fixed_literal_wide.clone(),
            )
        })
        .collect();
    fragment.pattern_fixed_literal_fullword = patterns
        .iter()
        .map(|pattern| {
            (
                pattern.pattern_id.clone(),
                pattern.fixed_literal_fullword.clone(),
            )
        })
        .collect();
    // Rebuild the optimized patterns as maps above, then return the root-bearing fragment.
    fragment.pattern_alternatives = patterns
        .iter()
        .map(|pattern| (pattern.pattern_id.clone(), pattern.alternatives.clone()))
        .collect();
    fragment.pattern_tier2_alternatives = patterns
        .iter()
        .map(|pattern| {
            (
                pattern.pattern_id.clone(),
                pattern.tier2_alternatives.clone(),
            )
        })
        .collect();
    fragment.pattern_anchor_literals = patterns
        .iter()
        .map(|pattern| (pattern.pattern_id.clone(), pattern.anchor_literals.clone()))
        .collect();
    fragment.pattern_fixed_literals = patterns
        .iter()
        .map(|pattern| (pattern.pattern_id.clone(), pattern.fixed_literals.clone()))
        .collect();
    fragment.pattern_fixed_literal_wide = patterns
        .iter()
        .map(|pattern| {
            (
                pattern.pattern_id.clone(),
                pattern.fixed_literal_wide.clone(),
            )
        })
        .collect();
    fragment.pattern_fixed_literal_fullword = patterns
        .iter()
        .map(|pattern| {
            (
                pattern.pattern_id.clone(),
                pattern.fixed_literal_fullword.clone(),
            )
        })
        .collect();
    if !force_tier1_only {
        // Keep the finalized patterns available to the outer compiler via the fragment maps.
    }
    Ok(fragment)
}

/// Compiles one named rule, recursively compiling and caching any helper-rule
/// dependencies it references.
///
/// Inputs:
/// - `rule_name`: Rule to compile.
/// - `rules`: All parsed rule blocks keyed by normalized rule name.
/// - `cache`, `visiting`: Dependency-tracking state used for reuse and cycle detection.
/// - `root_rule_name`: The top-level rule requested by the caller.
/// - `gram_sizes`, `active_identity_source`, `max_anchors_per_alt`,
///   `force_tier1_only`, `allow_tier2_fallback`, `max_candidates`: Compiler settings.
///
/// Returns:
/// - The fully compiled fragment for `rule_name`.
#[allow(clippy::too_many_arguments)]
fn compile_rule_fragment(
    rule_name: &str,
    rules: &HashMap<String, ParsedRuleBlock>,
    cache: &mut HashMap<String, RulePlanFragment>,
    visiting: &mut HashSet<String>,
    root_rule_name: &str,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: f64,
) -> Result<RulePlanFragment> {
    if rule_name != root_rule_name
        && let Some(fragment) = cache.get(rule_name)
    {
        return Ok(fragment.clone());
    }
    let rule = rules.get(rule_name).ok_or_else(|| {
        SspryError::from(format!("Condition references unknown rule: {rule_name}"))
    })?;
    if !visiting.insert(rule_name.to_owned()) {
        return Err(SspryError::from(format!(
            "Recursive rule reference cycle detected at {rule_name}"
        )));
    }
    let known_rule_names = rules
        .keys()
        .filter(|name| name.as_str() != rule_name)
        .cloned()
        .collect::<HashSet<_>>();
    let mut fragment =
        build_local_rule_fragment(rule, known_rule_names, gram_sizes, active_identity_source)?;
    if let Some(mut root) = fragment.root.take() {
        resolve_rule_refs(
            &mut root,
            &mut fragment,
            rules,
            cache,
            visiting,
            rule_name,
            gram_sizes,
            active_identity_source,
            max_anchors_per_alt,
            force_tier1_only,
            allow_tier2_fallback,
            max_candidates,
        )?;
        fragment.root = Some(root);
    }
    let mut fragment = finalize_rule_fragment(
        fragment,
        gram_sizes,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )?;
    if rule_name != root_rule_name {
        rename_fragment_for_rule_dependency(&mut fragment, rule_name);
        cache.insert(rule_name.to_owned(), fragment.clone());
    }
    visiting.remove(rule_name);
    Ok(fragment)
}

/// Compiles the active rule from a rule file into the query plan used for
/// candidate search.
///
/// Inputs:
/// - `rule_text`: Raw YARA source text.
/// - `gram_sizes`: Active tier1/tier2 gram sizes.
/// - `active_identity_source`: Optional whole-file hash identity policy.
/// - `max_anchors_per_alt`, `force_tier1_only`, `allow_tier2_fallback`,
///   `max_candidates`: Plan-shaping settings for candidate search.
///
/// Returns:
/// - The fully assembled `CompiledQueryPlan` for the selected top-level rule.
pub fn compile_query_plan_with_gram_sizes_and_identity_source(
    rule_text: &str,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    let max_candidates = normalize_max_candidates(max_candidates.into());
    let rule_blocks = parse_rule_blocks(rule_text)?;
    let root_rule_name = rule_blocks
        .iter()
        .find(|rule| !rule.is_private)
        .or_else(|| rule_blocks.first())
        .map(|rule| normalize_rule_name(&rule.name))
        .ok_or_else(|| SspryError::from("Rule file does not contain a compilable rule."))?;
    let rules = rule_blocks
        .into_iter()
        .map(|rule| (normalize_rule_name(&rule.name), rule))
        .collect::<HashMap<_, _>>();
    let mut cache = HashMap::<String, RulePlanFragment>::new();
    let mut visiting = HashSet::<String>::new();
    let fragment = compile_rule_fragment(
        &root_rule_name,
        &rules,
        &mut cache,
        &mut visiting,
        &root_rule_name,
        gram_sizes,
        active_identity_source,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )?;
    let root = fragment
        .root
        .clone()
        .ok_or_else(|| SspryError::from("Compiled rule fragment is missing a root."))?;
    let mut pattern_ids = fragment
        .pattern_alternatives
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    pattern_ids.sort();
    let mut patterns = Vec::with_capacity(pattern_ids.len());
    for pattern_id in pattern_ids {
        let alternatives = fragment
            .pattern_alternatives
            .get(&pattern_id)
            .cloned()
            .unwrap_or_default();
        let tier2_alternatives = fragment
            .pattern_tier2_alternatives
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let anchor_literals = fragment
            .pattern_anchor_literals
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let fixed_literals = fragment
            .pattern_fixed_literals
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let fixed_literal_wide = fragment
            .pattern_fixed_literal_wide
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![false; alternatives.len()]);
        let fixed_literal_fullword = fragment
            .pattern_fixed_literal_fullword
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![false; alternatives.len()]);
        patterns.push(PatternPlan {
            pattern_id,
            alternatives,
            tier2_alternatives,
            anchor_literals,
            fixed_literals,
            fixed_literal_wide,
            fixed_literal_fullword,
        });
    }
    reject_overbroad_pattern_union(&root, &patterns)?;
    reject_low_information_entrypoint_stub(&root, &patterns)?;
    reject_low_information_range_rule(&root, &patterns)?;
    reject_low_information_single_pattern(&root, &patterns)?;
    Ok(CompiledQueryPlan {
        patterns,
        root,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
        tier2_gram_size: gram_sizes.tier2,
        tier1_gram_size: gram_sizes.tier1,
    })
}

/// Compiles a specific named rule out of a multi-rule file into the query plan
/// used for candidate search.
fn compile_query_plan_for_rule_name_with_gram_sizes_and_identity_source(
    rule_blocks: &[ParsedRuleBlock],
    root_rule_name: &str,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    let max_candidates = normalize_max_candidates(max_candidates.into());
    let normalized_root_rule_name = normalize_rule_name(root_rule_name);
    let rules = rule_blocks
        .iter()
        .cloned()
        .map(|rule| (normalize_rule_name(&rule.name), rule))
        .collect::<HashMap<_, _>>();
    if !rules.contains_key(&normalized_root_rule_name) {
        return Err(SspryError::from(format!(
            "Condition references unknown rule: {root_rule_name}"
        )));
    }
    let mut cache = HashMap::<String, RulePlanFragment>::new();
    let mut visiting = HashSet::<String>::new();
    let fragment = compile_rule_fragment(
        &normalized_root_rule_name,
        &rules,
        &mut cache,
        &mut visiting,
        &normalized_root_rule_name,
        gram_sizes,
        active_identity_source,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )?;
    let root = fragment
        .root
        .clone()
        .ok_or_else(|| SspryError::from("Compiled rule fragment is missing a root."))?;
    let mut pattern_ids = fragment
        .pattern_alternatives
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    pattern_ids.sort();
    let mut patterns = Vec::with_capacity(pattern_ids.len());
    for pattern_id in pattern_ids {
        let alternatives = fragment
            .pattern_alternatives
            .get(&pattern_id)
            .cloned()
            .unwrap_or_default();
        let tier2_alternatives = fragment
            .pattern_tier2_alternatives
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let anchor_literals = fragment
            .pattern_anchor_literals
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let fixed_literals = fragment
            .pattern_fixed_literals
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let fixed_literal_wide = fragment
            .pattern_fixed_literal_wide
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![false; alternatives.len()]);
        let fixed_literal_fullword = fragment
            .pattern_fixed_literal_fullword
            .get(&pattern_id)
            .cloned()
            .unwrap_or_else(|| vec![false; alternatives.len()]);
        patterns.push(PatternPlan {
            pattern_id,
            alternatives,
            tier2_alternatives,
            anchor_literals,
            fixed_literals,
            fixed_literal_wide,
            fixed_literal_fullword,
        });
    }
    reject_overbroad_pattern_union(&root, &patterns)?;
    reject_low_information_entrypoint_stub(&root, &patterns)?;
    reject_low_information_range_rule(&root, &patterns)?;
    reject_low_information_single_pattern(&root, &patterns)?;
    Ok(CompiledQueryPlan {
        patterns,
        root,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
        tier2_gram_size: gram_sizes.tier2,
        tier1_gram_size: gram_sizes.tier1,
    })
}

/// Convenience wrapper that compiles a rule string without an explicit identity
/// source override.
pub fn compile_query_plan_with_gram_sizes(
    rule_text: &str,
    gram_sizes: GramSizes,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_with_gram_sizes_and_identity_source(
        rule_text,
        gram_sizes,
        None,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

/// Reads a rule file from disk and compiles it with an explicit identity-source
/// override.
pub fn compile_query_plan_from_file_with_gram_sizes_and_identity_source(
    rule_path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    let text = fs::read_to_string(rule_path)?;
    compile_query_plan_with_gram_sizes_and_identity_source(
        &text,
        gram_sizes,
        active_identity_source,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

/// Reads a rule file from disk and compiles it without an explicit
/// identity-source override.
pub fn compile_query_plan_from_file_with_gram_sizes(
    rule_path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_from_file_with_gram_sizes_and_identity_source(
        rule_path,
        gram_sizes,
        None,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

/// Produces the rule-check report for the active rule in a rule string while
/// preserving an explicit identity-source override.
pub fn rule_check_with_gram_sizes_and_identity_source(
    rule_text: &str,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> RuleCheckReport {
    let report = rule_check_all_with_gram_sizes_and_identity_source(
        rule_text,
        gram_sizes,
        active_identity_source,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    );
    if let Some(active_rule) = report
        .rules
        .iter()
        .find(|rule| !rule.is_private)
        .or_else(|| report.rules.first())
    {
        return RuleCheckReport {
            status: active_rule.status,
            issues: active_rule.issues.clone(),
            verifier_only_kinds: active_rule.verifier_only_kinds.clone(),
            ignored_module_calls: active_rule.ignored_module_calls.clone(),
        };
    }
    RuleCheckReport {
        status: report.status,
        issues: report.issues,
        verifier_only_kinds: report.verifier_only_kinds,
        ignored_module_calls: report.ignored_module_calls,
    }
}

/// Produces the rule-check report for the active rule in a rule string without
/// an explicit identity-source override.
pub fn rule_check_with_gram_sizes(
    rule_text: &str,
    gram_sizes: GramSizes,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> RuleCheckReport {
    rule_check_with_gram_sizes_and_identity_source(
        rule_text,
        gram_sizes,
        None,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

/// Produces per-rule rule-check reports for every rule in a file-sized source
/// string, keeping the explicit identity-source override.
pub fn rule_check_all_with_gram_sizes_and_identity_source(
    rule_text: &str,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> RuleCheckFileReport {
    let max_candidates = max_candidates.into();
    match parse_rule_blocks(rule_text) {
        Ok(rule_blocks) => {
            let mut rules = Vec::<RuleCheckRuleReport>::with_capacity(rule_blocks.len());
            for block in &rule_blocks {
                let source_context = RuleSourceContext {
                    full_text: rule_text,
                    block_text: &block.block_text,
                    block_start_offset: block.block_start_offset,
                };
                let ignored_module_calls =
                    collect_ignored_module_call_names(&block.raw_condition_text)
                        .into_iter()
                        .collect::<Vec<_>>();
                let report = build_rule_check_report(
                    &source_context,
                    Some(&block.name),
                    compile_query_plan_for_rule_name_with_gram_sizes_and_identity_source(
                        &rule_blocks,
                        &block.name,
                        gram_sizes,
                        active_identity_source,
                        max_anchors_per_alt,
                        force_tier1_only,
                        allow_tier2_fallback,
                        max_candidates,
                    ),
                    ignored_module_calls,
                );
                rules.push(RuleCheckRuleReport {
                    rule: block.name.clone(),
                    is_private: block.is_private,
                    status: report.status,
                    issues: report.issues,
                    verifier_only_kinds: report.verifier_only_kinds,
                    ignored_module_calls: report.ignored_module_calls,
                });
            }
            summarize_rule_check_rules(rules)
        }
        Err(err) => {
            let source_context = RuleSourceContext {
                full_text: rule_text,
                block_text: rule_text,
                block_start_offset: 0,
            };
            let report = build_rule_check_report(&source_context, None, Err(err), Vec::new());
            RuleCheckFileReport {
                status: report.status,
                issues: report.issues,
                verifier_only_kinds: report.verifier_only_kinds,
                ignored_module_calls: report.ignored_module_calls,
                rules: Vec::new(),
            }
        }
    }
}

/// Produces per-rule rule-check reports for every rule in a source string
/// without an explicit identity-source override.
pub fn rule_check_all_with_gram_sizes(
    rule_text: &str,
    gram_sizes: GramSizes,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> RuleCheckFileReport {
    rule_check_all_with_gram_sizes_and_identity_source(
        rule_text,
        gram_sizes,
        None,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

/// Reads a rule file and returns the active rule's rule-check report while
/// preserving an explicit identity-source override.
pub fn rule_check_from_file_with_gram_sizes_and_identity_source(
    rule_path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<RuleCheckReport> {
    let text = fs::read_to_string(rule_path)?;
    Ok(rule_check_with_gram_sizes_and_identity_source(
        &text,
        gram_sizes,
        active_identity_source,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    ))
}

/// Reads a rule file and returns the active rule's rule-check report without an
/// explicit identity-source override.
pub fn rule_check_from_file_with_gram_sizes(
    rule_path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<RuleCheckReport> {
    rule_check_from_file_with_gram_sizes_and_identity_source(
        rule_path,
        gram_sizes,
        None,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

/// Reads a rule file and returns per-rule rule-check reports while preserving
/// an explicit identity-source override.
pub fn rule_check_all_from_file_with_gram_sizes_and_identity_source(
    rule_path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<RuleCheckFileReport> {
    let text = fs::read_to_string(rule_path)?;
    Ok(rule_check_all_with_gram_sizes_and_identity_source(
        &text,
        gram_sizes,
        active_identity_source,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    ))
}

/// Reads a rule file and returns per-rule rule-check reports without an
/// explicit identity-source override.
pub fn rule_check_all_from_file_with_gram_sizes(
    rule_path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<RuleCheckFileReport> {
    rule_check_all_from_file_with_gram_sizes_and_identity_source(
        rule_path,
        gram_sizes,
        None,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}
