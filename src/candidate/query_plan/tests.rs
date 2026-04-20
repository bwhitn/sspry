use std::collections::{HashMap, HashSet};
use std::fs;

use tempfile::tempdir;

use crate::candidate::{DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE};

use super::*;

fn default_gram_sizes() -> GramSizes {
    GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE).expect("default gram sizes")
}

fn compile_query_plan_default(
    rule_text: &str,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_with_gram_sizes(
        rule_text,
        default_gram_sizes(),
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates.into(),
    )
}

fn compile_query_plan_default_with_identity(
    rule_text: &str,
    active_identity_source: Option<&str>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_with_gram_sizes_and_identity_source(
        rule_text,
        default_gram_sizes(),
        active_identity_source,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates.into(),
    )
}

fn compile_query_plan_from_file_default(
    rule_path: impl AsRef<Path>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_from_file_with_gram_sizes(
        rule_path,
        default_gram_sizes(),
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates.into(),
    )
}

fn compile_query_plan_with_tier1_default_tier2(
    rule_text: &str,
    tier1_gram_size: usize,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_with_gram_sizes(
        rule_text,
        GramSizes::new(tier1_gram_size, DEFAULT_TIER2_GRAM_SIZE)?,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates.into(),
    )
}

fn compile_query_plan_from_file_with_tier1_default_tier2(
    rule_path: impl AsRef<Path>,
    tier1_gram_size: usize,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_from_file_with_gram_sizes(
        rule_path,
        GramSizes::new(tier1_gram_size, DEFAULT_TIER2_GRAM_SIZE)?,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates.into(),
    )
}

#[test]
fn compile_restricted_yara_rule() {
    let rule = r#"
rule sample {
  strings:
    $a = "ABCD"
    $b = "EF" wide
    $c = { 01 02 ?? 04 05 [1-2] 06 07 08 09 }
  condition:
    $a and ($b or 1 of ($a, $c))
}
"#;
    let plan = compile_query_plan_default(rule, 16, false, true, 100_000).expect("plan");
    assert!(matches!(plan, CompiledQueryPlan { .. }));
    let patterns = plan
        .patterns
        .iter()
        .map(|item| (item.pattern_id.as_str(), item))
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(patterns["$a"].alternatives.len(), 1);
    assert_eq!(patterns["$a"].alternatives[0].len(), 2);
    assert_eq!(patterns["$b"].alternatives.len(), 1);
    assert_eq!(patterns["$b"].alternatives[0].len(), 2);
    assert_eq!(
        patterns["$c"].alternatives,
        vec![vec![
            pack_exact_gram(&[0x06, 0x07, 0x08]),
            pack_exact_gram(&[0x07, 0x08, 0x09]),
        ]]
    );
}

#[test]
fn unsupported_construct_raises() {
    let rule = r#"
rule bad {
  strings:
    $a = /[0-9]+/
  condition:
    $a
}
"#;
    assert!(compile_query_plan_default(rule, 8, false, true, 100_000).is_err());
}

#[test]
fn compile_rule_with_whole_file_hash_identity_condition() {
    let rule = r#"
rule hashed {
  condition:
    hash.sha256(0, filesize) == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
"#;
    let plan =
        compile_query_plan_default_with_identity(rule, Some("sha256"), 8, false, true, 100_000)
            .expect("plan");
    assert!(plan.patterns.is_empty());
    assert_eq!(plan.root.kind, "identity_eq");
    assert_eq!(
        plan.root.pattern_id.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn whole_file_hash_identity_requires_matching_db_source() {
    let rule = r#"
rule hashed {
  condition:
    hash.md5(0, filesize) == "00112233445566778899aabbccddeeff"
}
"#;
    assert!(
        compile_query_plan_default_with_identity(rule, Some("sha256"), 8, false, true, 100_000)
            .expect_err("mismatched source")
            .to_string()
            .contains("current source is sha256")
    );
    assert!(
        compile_query_plan_default_with_identity(rule, None, 8, false, true, 100_000)
            .expect_err("missing source")
            .to_string()
            .contains("requires a known DB identity source")
    );
}

#[test]
fn compile_rule_with_md5_identity_uses_raw_store_identity() {
    let rule = r#"
rule hashed {
  condition:
    hash.md5(0, filesize) == "00112233445566778899aabbccddeeff"
}
"#;
    let plan = compile_query_plan_default_with_identity(rule, Some("md5"), 8, false, true, 100_000)
        .expect("plan");
    let expected = "00112233445566778899aabbccddeeff";
    assert_eq!(plan.root.kind, "identity_eq");
    assert_eq!(plan.root.pattern_id.as_deref(), Some(expected));
}

#[test]
fn compile_rule_with_filesize_equality_condition() {
    let rule = r#"
rule sized {
  strings:
    $a = "ABCD"
  condition:
    $a and filesize == 8
}
"#;
    let plan = compile_query_plan_default(rule, 8, false, true, 100_000).expect("plan");
    assert_eq!(plan.patterns.len(), 1);
    assert_eq!(plan.root.kind, "and");
    assert_eq!(plan.root.children.len(), 2);
    assert!(
        plan.root
            .children
            .iter()
            .any(|child| child.kind == "filesize_eq"
                && child.pattern_id.as_deref() == Some("filesize")
                && child.threshold == Some(8))
    );
}

#[test]
fn compile_rule_with_filesize_comparisons_and_not() {
    let rule = r#"
rule sized {
  strings:
    $a = "ABCD"
    $b = "WXYZ"
  condition:
    $a and not $b and filesize <= 10KB and filesize > 1KB
}
"#;
    let plan = compile_query_plan_default(rule, 8, false, true, 100_000).expect("plan");
    assert_eq!(plan.root.kind, "and");
    assert!(plan.root.children.iter().any(|child| child.kind == "not"));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "filesize_le"
            && child.pattern_id.as_deref() == Some("filesize")
            && child.threshold == Some(10 * 1024)
    }));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "filesize_gt"
            && child.pattern_id.as_deref() == Some("filesize")
            && child.threshold == Some(1024)
    }));
}

#[test]
fn compile_rule_with_metadata_and_time_conditions() {
    let rule = r#"
rule module_meta {
  strings:
    $a = "ABCD"
  condition:
    $a and pe.is_pe and PE.Machine == 0x14c and pe.is_64bit == true and ELF.OSABI == 3 and time.now == 42
}
"#;
    let plan = compile_query_plan_default(rule, 8, false, true, 100_000).expect("plan");
    assert_eq!(plan.patterns.len(), 1);
    assert_eq!(plan.root.kind, "and");
    assert_eq!(plan.root.children.len(), 6);
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "metadata_eq"
            && child.pattern_id.as_deref() == Some("pe.is_pe")
            && child.threshold == Some(1)
    }));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "metadata_eq"
            && child.pattern_id.as_deref() == Some("pe.machine")
            && child.threshold == Some(0x14c)
    }));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "metadata_eq"
            && child.pattern_id.as_deref() == Some("pe.is_64bit")
            && child.threshold == Some(1)
    }));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "metadata_eq"
            && child.pattern_id.as_deref() == Some("elf.os_abi")
            && child.threshold == Some(3)
    }));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "time_now_eq"
            && child.pattern_id.as_deref() == Some("time.now")
            && child.threshold == Some(42)
    }));
}

#[test]
fn compile_rule_with_extended_metadata_and_time_comparisons() {
    let rule = r#"
rule metadata_cmp {
  strings:
    $a = "ABCD"
  condition:
    $a and lnk.creation_time < time.now and time.now >= 1700000000 and lnk.write_time != 5 and lnk.access_time <= lnk.write_time
}
"#;
    let plan = compile_query_plan_default(rule, 8, false, true, 100_000).expect("plan");
    assert_eq!(plan.root.kind, "and");
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "metadata_time_lt" && child.pattern_id.as_deref() == Some("lnk.creation_time")
    }));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "time_now_ge"
            && child.pattern_id.as_deref() == Some("time.now")
            && child.threshold == Some(1_700_000_000)
    }));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "metadata_ne"
            && child.pattern_id.as_deref() == Some("lnk.write_time")
            && child.threshold == Some(5)
    }));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "metadata_field_le"
            && child.pattern_id.as_deref() == Some("lnk.access_time|lnk.write_time")
    }));
}

#[test]
fn compile_rule_with_math_entropy_whole_file_comparison() {
    let rule = r#"
rule entropy_cmp {
  strings:
    $a = "ABCD"
  condition:
    $a and math.entropy(0, filesize) > 7.2
}
"#;
    let plan = compile_query_plan_default(rule, 8, false, true, 100_000).expect("plan");
    assert_eq!(plan.root.kind, "and");
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "metadata_float_gt" && child.pattern_id.as_deref() == Some("math.entropy")
    }));
}

#[test]
fn compile_rule_header_magic_numeric_reads_stay_as_numeric_checks() {
    fn contains_verifier_eq(node: &QueryNode, expr: &str) -> bool {
        (node.kind == "verifier_only_eq" && node.pattern_id.as_deref() == Some(expr))
            || node
                .children
                .iter()
                .any(|child| contains_verifier_eq(child, expr))
    }

    let rule = r#"
rule header_magic {
  strings:
    $a = "ABCD"
  condition:
    $a and uint16(0) == 0x5A4D and uint32(4) == 0x14c and uint32(0) == 0x464c457f and uint32(0) == 0x04034b50
}
"#;
    let plan = compile_query_plan_default(rule, 8, false, true, 100_000).expect("plan");
    assert_eq!(plan.root.kind, "and");
    assert!(contains_verifier_eq(&plan.root, "uint16(0)==23117"));
    assert!(contains_verifier_eq(&plan.root, "uint32(4)==332"));
    assert!(contains_verifier_eq(&plan.root, "uint32(0)==1179403647"));
    assert!(contains_verifier_eq(&plan.root, "uint32(0)==67324752"));
    assert!(
        !plan
            .root
            .children
            .iter()
            .any(|child| child.kind == "metadata_eq")
    );
}

#[test]
fn compile_rule_with_numeric_read_verifier_nodes() {
    let rule = r#"
rule numeric_reads {
  strings:
    $a = "ABCD"
  condition:
    $a and uint32(0) == 0x14c and float32be(4) == 2.5
}
"#;
    let plan = compile_query_plan_default(rule, 8, false, true, 100_000).expect("plan");
    assert_eq!(plan.patterns.len(), 3);
    assert_eq!(plan.root.kind, "and");
    assert!(plan.patterns.iter().any(|pattern| {
        pattern.pattern_id.starts_with(NUMERIC_READ_ANCHOR_PREFIX)
            && pattern
                .fixed_literals
                .iter()
                .any(|literal| literal == &0x14cu32.to_le_bytes())
    }));
    assert!(plan.patterns.iter().any(|pattern| {
        pattern.pattern_id.starts_with(NUMERIC_READ_ANCHOR_PREFIX)
            && pattern
                .fixed_literals
                .iter()
                .any(|literal| literal == &2.5f32.to_bits().to_be_bytes())
    }));
    let mut verifier_children = 0usize;
    for child in &plan.root.children {
        if child.kind == "and" {
            assert_eq!(child.children.len(), 2);
            assert!(child.children.iter().any(|grandchild| {
                grandchild.kind == "pattern"
                    && grandchild
                        .pattern_id
                        .as_deref()
                        .is_some_and(|id| id.starts_with(NUMERIC_READ_ANCHOR_PREFIX))
            }));
            assert!(child.children.iter().any(|grandchild| {
                grandchild.kind == "verifier_only_eq" && grandchild.pattern_id.as_deref().is_some()
            }));
            verifier_children += 1;
        }
    }
    assert_eq!(verifier_children, 2);
}

#[test]
fn compile_rule_with_extended_integer_read_verifier_nodes() {
    fn contains_verifier_eq(node: &QueryNode, expr: &str) -> bool {
        (node.kind == "verifier_only_eq" && node.pattern_id.as_deref() == Some(expr))
            || node
                .children
                .iter()
                .any(|child| contains_verifier_eq(child, expr))
    }

    let rule = r#"
rule numeric_reads_ext {
  strings:
    $a = "ABCD"
  condition:
    $a and int16be(0) == -2 and uint64(0) == 0x1122334455667788
}
"#;
    let plan = compile_query_plan_default(rule, 8, false, true, 100_000).expect("plan");
    assert!(plan.patterns.iter().any(|pattern| {
        pattern.pattern_id.starts_with(NUMERIC_READ_ANCHOR_PREFIX)
            && pattern
                .fixed_literals
                .iter()
                .any(|literal| literal == &0x1122_3344_5566_7788u64.to_le_bytes())
    }));
    assert!(contains_verifier_eq(&plan.root, "int16be(0)==-2"));
    assert!(contains_verifier_eq(
        &plan.root,
        "uint64(0)==1234605616436508552"
    ));
}

#[test]
fn compile_rule_with_numeric_only_condition_uses_injected_anchor() {
    let rule = r#"
rule numeric_only {
  strings:
    $unused = "UNUSED"
  condition:
    uint32(0) == 0x4000
}
"#;
    let plan = compile_query_plan_default(rule, 8, false, true, 100_000).expect("plan");
    assert_eq!(plan.patterns.len(), 2);
    assert_eq!(plan.root.kind, "and");
    assert!(plan.patterns.iter().any(|pattern| {
        pattern.pattern_id.starts_with(NUMERIC_READ_ANCHOR_PREFIX)
            && pattern
                .fixed_literals
                .iter()
                .any(|literal| literal == &0x0000_4000u32.to_le_bytes())
    }));
    assert!(
        plan.patterns
            .iter()
            .any(|pattern| pattern.pattern_id.as_str() == "$unused")
    );
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "pattern"
            && child
                .pattern_id
                .as_deref()
                .is_some_and(|id| id.starts_with(NUMERIC_READ_ANCHOR_PREFIX))
    }));
    assert!(plan.root.children.iter().any(|child| {
        child.kind == "verifier_only_eq" && child.pattern_id.as_deref() == Some("uint32(0)==16384")
    }));
}

#[test]
fn numeric_only_condition_rejects_unanchorable_literal_without_other_anchor() {
    let rule = r#"
rule numeric_only_unanchorable {
  strings:
    $unused = "UNUSED"
  condition:
    uint32(0) == 0x4000
}
"#;
    let plan = compile_query_plan_with_gram_sizes(
        rule,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, 5).expect("gram sizes"),
        8,
        false,
        true,
        100_000,
    )
    .expect("numeric-only condition now has enough anchor grams");
    assert_eq!(plan.patterns.len(), 2);
    assert_eq!(plan.patterns[1].pattern_id, "__numeric_eq_anchor_0");
}

#[test]
fn tokenizer_parser_and_rule_sections_cover_edge_cases() {
    assert!(
        tokenize_condition("")
            .expect("empty token stream")
            .is_empty()
    );
    assert!(
        tokenize_condition("$a and 2 of ($b, $c)")
            .expect("tokenize supported condition")
            .len()
            > 4
    );
    assert!(
        tokenize_condition("any of them and all of $a*")
            .expect("tokenize any/all condition")
            .len()
            > 4
    );
    assert!(
        tokenize_condition("filesize == 32 or $a")
            .expect("tokenize filesize condition")
            .len()
            > 4
    );
    assert!(
        tokenize_condition("not $a and filesize <= 10KB")
            .expect("tokenize not/filesize comparison")
            .len()
            > 4
    );
    assert!(
        tokenize_condition("filesize == 8B")
            .expect_err("reject non-yara byte suffix")
            .to_string()
            .contains("Unsupported numeric suffix")
    );
    assert!(
        tokenize_condition("PE.Machine == 0x14c and pe.is_pe == true and time.now == 42")
            .expect("tokenize metadata condition")
            .len()
            > 8
    );
    assert!(
        tokenize_condition("uint32(0) == 0x14c and float64(8) == 3.5")
            .expect("tokenize numeric-read condition")
            .len()
            > 8
    );
    assert!(
        tokenize_condition("#a > 2 and $a at 0")
            .expect("tokenize count/at condition")
            .len()
            > 6
    );
    assert!(
        tokenize_condition("$a in (filesize - 256 .. filesize)")
            .expect("tokenize range condition")
            .len()
            > 8
    );
    assert!(
        tokenize_condition("@")
            .expect_err("unsupported token")
            .to_string()
            .contains("Unsupported token in condition")
    );

    let mut parser = ConditionParser::new("", HashSet::new(), None).expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("empty condition")
            .to_string()
            .contains("Condition section is empty")
    );

    let mut parser = ConditionParser::new(
        "$a $b",
        HashSet::from(["$a".to_owned(), "$b".to_owned()]),
        None,
    )
    .expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("trailing token")
            .to_string()
            .contains("Unexpected trailing token")
    );

    let mut parser =
        ConditionParser::new("$missing", HashSet::from(["$a".to_owned()]), None).expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("unknown pattern")
            .to_string()
            .contains("unknown string id")
    );

    let mut parser =
        ConditionParser::new("0 of ($a)", HashSet::from(["$a".to_owned()]), None).expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("zero threshold")
            .to_string()
            .contains("threshold must be > 0")
    );

    let mut parser = ConditionParser::new(
        "pe.machine",
        HashSet::from(["$a".to_owned(), "$b".to_owned()]),
        None,
    )
    .expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("missing metadata equality")
            .to_string()
            .contains("requires == <literal>")
    );

    let mut parser = ConditionParser::new("uint32(x) == 1", HashSet::from(["$a".to_owned()]), None)
        .expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("invalid numeric offset")
            .to_string()
            .contains("requires an integer byte offset")
    );

    let mut parser = ConditionParser::new(
        "1 of ($a $b)",
        HashSet::from(["$a".to_owned(), "$b".to_owned()]),
        None,
    )
    .expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("missing comma")
            .to_string()
            .contains("Expected ',' or ')'")
    );

    let mut parser = ConditionParser::new(
        "all of $a*",
        HashSet::from(["$a1".to_owned(), "$a2".to_owned(), "$b1".to_owned()]),
        None,
    )
    .expect("parser");
    let wildcard = parser.parse().expect("wildcard parse");
    assert_eq!(wildcard.kind, "n_of");
    assert_eq!(wildcard.threshold, Some(2));
    assert_eq!(wildcard.children.len(), 2);
    assert_eq!(wildcard.children[0].pattern_id.as_deref(), Some("$a1"));
    assert_eq!(wildcard.children[1].pattern_id.as_deref(), Some("$a2"));

    let mut parser = ConditionParser::new(
        "any of them",
        HashSet::from(["$a".to_owned(), "$b".to_owned()]),
        None,
    )
    .expect("parser");
    let them = parser.parse().expect("them parse");
    assert_eq!(them.kind, "n_of");
    assert_eq!(them.threshold, Some(1));
    assert_eq!(them.children.len(), 2);

    let mut parser =
        ConditionParser::new("$a at 0", HashSet::from(["$a".to_owned()]), None).expect("parser");
    let at_node = parser.parse().expect("at parse");
    assert_eq!(at_node.kind, "and");
    assert_eq!(at_node.children.len(), 2);
    assert_eq!(at_node.children[0].kind, "pattern");
    assert_eq!(at_node.children[0].pattern_id.as_deref(), Some("$a"));
    assert_eq!(at_node.children[1].kind, "verifier_only_at");
    assert_eq!(at_node.children[1].pattern_id.as_deref(), Some("$a@0"));

    let mut parser = ConditionParser::new(
        "$a at pe.entry_point",
        HashSet::from(["$a".to_owned()]),
        None,
    )
    .expect("parser");
    let at_entry = parser.parse().expect("entry at parse");
    assert_eq!(at_entry.kind, "and");
    assert_eq!(at_entry.children[1].kind, "verifier_only_at");
    assert_eq!(
        at_entry.children[1].pattern_id.as_deref(),
        Some("$a@pe.entry_point")
    );

    let mut parser = ConditionParser::new(
        "$a at (pe.entry_point + 4)",
        HashSet::from(["$a".to_owned()]),
        None,
    )
    .expect("parser");
    let at_entry_plus = parser.parse().expect("entry at plus parse");
    assert_eq!(at_entry_plus.kind, "and");
    assert_eq!(at_entry_plus.children[1].kind, "verifier_only_at");
    assert_eq!(
        at_entry_plus.children[1].pattern_id.as_deref(),
        Some("$a@pe.entry_point+4")
    );

    let mut parser =
        ConditionParser::new("#a > 2", HashSet::from(["$a".to_owned()]), None).expect("parser");
    let count_node = parser.parse().expect("count parse");
    assert_eq!(count_node.kind, "and");
    assert_eq!(count_node.children.len(), 2);
    assert_eq!(count_node.children[0].kind, "pattern");
    assert_eq!(count_node.children[0].pattern_id.as_deref(), Some("$a"));
    assert_eq!(count_node.children[1].kind, "verifier_only_count");
    assert_eq!(
        count_node.children[1].pattern_id.as_deref(),
        Some("count:$a:gt:2")
    );

    let mut parser =
        ConditionParser::new("#a > 0", HashSet::from(["$a".to_owned()]), None).expect("parser");
    let count_exists = parser.parse().expect("count exists parse");
    assert_eq!(count_exists.kind, "pattern");
    assert_eq!(count_exists.pattern_id.as_deref(), Some("$a"));

    let mut parser =
        ConditionParser::new("#a == 0", HashSet::from(["$a".to_owned()]), None).expect("parser");
    let count_zero = parser.parse().expect("count zero parse");
    assert_eq!(count_zero.kind, "not");
    assert_eq!(count_zero.children.len(), 1);
    assert_eq!(count_zero.children[0].kind, "pattern");
    assert_eq!(count_zero.children[0].pattern_id.as_deref(), Some("$a"));

    let mut parser = ConditionParser::new(
        "$a in (filesize - 256 .. filesize)",
        HashSet::from(["$a".to_owned()]),
        None,
    )
    .expect("parser");
    let range_node = parser.parse().expect("range parse");
    assert_eq!(range_node.kind, "and");
    assert_eq!(range_node.children.len(), 2);
    assert_eq!(range_node.children[0].kind, "pattern");
    assert_eq!(range_node.children[0].pattern_id.as_deref(), Some("$a"));
    assert_eq!(range_node.children[1].kind, "verifier_only_in_range");
    assert_eq!(
        range_node.children[1].pattern_id.as_deref(),
        Some("range:$a:filesize-256:filesize")
    );

    let mut parser = ConditionParser::new(
        "1 of $missing*",
        HashSet::from(["$a".to_owned(), "$b".to_owned()]),
        None,
    )
    .expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("missing wildcard selector")
            .to_string()
            .contains("matched no string ids")
    );

    let mut parser =
        ConditionParser::new("( $a ", HashSet::from(["$a".to_owned()]), None).expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("unterminated paren")
            .to_string()
            .contains("Unexpected end of condition")
    );

    let plan = compile_query_plan_default(
        r#"
rule anon {
  strings:
    $ = "AAAA"
    $ = "BBBB"
    $ = { 43 43 43 43 }
  condition:
    any of them
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("anonymous strings plan");
    assert_eq!(plan.patterns.len(), 3);
    assert_eq!(plan.root.kind, "n_of");
    assert_eq!(plan.root.threshold, Some(1));
    assert_eq!(plan.root.children.len(), 3);
    let mut ids = plan
        .patterns
        .iter()
        .map(|pattern| pattern.pattern_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3);
    assert!(
        ids.iter()
            .all(|id| id.starts_with(ANONYMOUS_PATTERN_PREFIX))
    );

    let (strings, _raw_condition, condition) = parse_rule_sections(
        r#"
rule sample {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
    )
    .expect("rule sections");
    assert_eq!(strings.len(), 1);
    assert_eq!(condition.trim(), "$a");
    let (strings, _raw_condition, condition) = parse_rule_sections(
        r#"
rule commented {
  /*
    header comment
  */
  strings:
    $a = "ABCD" /* inline string comment */
    /* block between strings */
    $b = /foo\/bar/ /* regex comment */
  condition:
    /* condition comment */
    $a or $b
}
"#,
    )
    .expect("rule sections");
    assert_eq!(strings.len(), 2);
    assert!(strings[0].contains(r#"$a = "ABCD""#));
    assert!(strings[1].contains(r#"$b = /foo\/bar/"#));
    assert_eq!(condition.trim(), "$a or $b");
    let (strings, _raw_condition, condition) = parse_rule_sections(
        r#"
rule empty {
  condition:
    true
}
"#,
    )
    .expect("condition-only rule");
    assert!(strings.is_empty());
    assert_eq!(condition.trim(), "true");
    let (_strings, _raw_condition, condition) = parse_rule_sections(
        r#"
rule looped {
  strings:
    $a = { FF 75 ?? FF 55 ?? }
  condition:
    for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}
"#,
    )
    .expect("for-any loop rewrite");
    assert_eq!(condition.trim(), "verifierloop($a)");
    let rewritten = rewrite_verifier_only_for_of_at_loops(
        "for any of ($*): ($ at pe.entry_point)",
        &["$a".to_owned(), "$b".to_owned()],
    )
    .expect("for-of at rewrite");
    assert_eq!(
        rewritten,
        "(($a at pe.entry_point) or ($b at pe.entry_point))"
    );
    assert!(
        parse_rule_sections(
            r#"
rule empty {
  strings:
    $a = "x"
}
"#,
        )
        .expect_err("missing condition")
        .to_string()
        .contains("condition section")
    );
}

#[test]
fn literal_hex_and_optimization_helpers_cover_branches() {
    let ascii_wide = parse_literal_line(r#"$a = "Ab" ascii wide"#)
        .expect("literal")
        .expect("pattern");
    assert_eq!(ascii_wide.pattern_id, "$a");
    assert_eq!(ascii_wide.alternatives.len(), 2);
    let fullword = parse_literal_line(r#"$a = "Ab" fullword"#)
        .expect("literal")
        .expect("pattern");
    assert_eq!(fullword.fullword_flags, vec![true]);
    let nocase = parse_literal_line(r#"$a = "AbCd" nocase"#)
        .expect("literal")
        .expect("pattern");
    assert_eq!(nocase.alternatives, vec![b"AbCd".to_vec()]);
    assert_eq!(nocase.nocase_flags, vec![true]);
    assert!(!nocase.exact_literals);
    assert!(
        parse_literal_line(r#"$a = "unterminated"#)
            .expect_err("unterminated literal")
            .to_string()
            .contains("Invalid literal string")
    );
    assert!(
        parse_literal_line("$a = { 01 02 }")
            .expect("hex line is ignored")
            .is_none()
    );
    assert!(
        parse_literal_line("identifier = \"x\"")
            .expect("non pattern line")
            .is_none()
    );

    let (pattern_id, alternatives, tier2_alternatives, fixed_literals) = parse_hex_line_to_grams(
        "$h = { 41 42 43 44 ?? 45 46 47 48 [2-4] 49 4A 4B 4C }",
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
    )
    .expect("hex line")
    .expect("parsed hex");
    assert_eq!(pattern_id, "$h");
    assert_eq!(alternatives.len(), 1);
    assert_eq!(alternatives[0].len(), 6);
    assert_eq!(tier2_alternatives[0].len(), 3);
    assert!(fixed_literals[0].is_empty());
    let packed = parse_hex_line_to_grams(
        "$p = { 8bec 83ec10 }",
        GramSizes::new(3, 4).expect("gram sizes"),
    )
    .expect("packed hex")
    .expect("parsed packed");
    assert_eq!(packed.0, "$p");
    assert_eq!(packed.3, vec![vec![0x8b, 0xec, 0x83, 0xec, 0x10]]);
    let grouped_hex = parse_hex_line_to_grams(
        "$g = { 41 (42|43) 44 }",
        GramSizes::new(3, 4).expect("gram sizes"),
    )
    .expect("grouped hex")
    .expect("parsed grouped");
    assert_eq!(grouped_hex.0, "$g");
    assert_eq!(grouped_hex.1.len(), 2);
    assert_eq!(
        grouped_hex.3,
        vec![vec![0x41, 0x42, 0x44], vec![0x41, 0x43, 0x44]]
    );
    assert!(
        parse_hex_line_to_grams(
            "$g = { 41 (42|4344) 45 }",
            GramSizes::new(3, 4).expect("gram sizes"),
        )
        .expect_err("mismatched group lengths")
        .to_string()
        .contains("same non-zero byte length")
    );
    assert!(is_gap_token("[3]"));
    assert!(is_gap_token("[1-9]"));
    assert!(!is_gap_token("[a-b]"));
    assert!(
        parse_hex_line_to_grams(
            "$h = { }",
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
                .expect("default gram sizes"),
        )
        .expect_err("empty hex body")
        .to_string()
        .contains("is empty")
    );
    assert!(
        parse_hex_line_to_grams(
            "$h = { GG }",
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
                .expect("default gram sizes"),
        )
        .expect_err("bad hex token")
        .to_string()
        .contains("Unsupported hex token")
    );
    let nibble_hex = parse_hex_line_to_grams(
        "$h = { 41 4? 42 ?3 43 }",
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
    )
    .expect("nibble wildcard hex")
    .expect("parsed nibble wildcard hex");
    assert_eq!(nibble_hex.0, "$h");
    assert_eq!(nibble_hex.1.len(), 1);
    assert!(nibble_hex.3[0].is_empty());
    assert!(
        parse_hex_line_to_grams(
            "$h = \"ABCD\"",
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
                .expect("default gram sizes"),
        )
        .expect("literal line should be ignored")
        .is_none()
    );

    let grams = grams_from_bytes(b"ABCDEABCDE", 4);
    assert_eq!(grams.len(), 5);
    let ranked = optimize_grams(&grams, b"ABCDEABCDE", 4, 2);
    assert_eq!(ranked.len(), 2);
    assert_eq!(optimize_grams(&grams, b"", 4, 0), grams);

    let regex = parse_regex_line(
        r#"$r = /[A-Z]+applesause[0-9]+/"#,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
    )
    .expect("regex parse")
    .expect("regex pattern");
    assert_eq!(regex.alternatives, vec![b"applesause".to_vec()]);
    assert!(!regex.exact_literals);

    let regex_escaped = parse_regex_line(
        r#"$r = /https?:\/\/evil\.com/"#,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
    )
    .expect("regex parse")
    .expect("regex pattern");
    assert_eq!(regex_escaped.alternatives, vec![b"://evil.com".to_vec()]);
    let regex_alt = parse_regex_line(
        r#"$r = /(apple|apricot)juice/"#,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
    )
    .expect("regex parse")
    .expect("regex pattern");
    assert_eq!(regex_alt.alternatives, vec![b"juice".to_vec()]);
    assert!(
        parse_regex_line(
            r#"$r = /(apple|orange)/"#,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
                .expect("default gram sizes"),
        )
        .expect_err("common anchor too short")
        .to_string()
        .contains("anchorable mandatory literal")
    );
    let grouped = parse_regex_line(
        r#"$r = /fooba(bar|baz)qux/"#,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
    )
    .expect("regex parse")
    .expect("regex pattern");
    assert_eq!(grouped.alternatives, vec![b"fooba".to_vec()]);

    let repeated_group = parse_regex_line(
        r#"$r = /(90){2,20}/"#,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
    )
    .expect("regex parse")
    .expect("regex pattern");
    assert_eq!(repeated_group.alternatives, vec![b"9090".to_vec()]);
    assert!(
        parse_regex_line(
            r#"$r = /[0-9]+abc/"#,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
                .expect("default gram sizes"),
        )
        .expect_err("regex should now be unanchorable")
        .to_string()
        .contains("anchorable mandatory literal")
    );
}

#[test]
fn compile_query_plan_covers_more_supported_and_error_paths() {
    let rule = r#"
rule sample {
  strings:
    $a = "ABCD" ascii
    $b = "hi" wide
    $c = { 01 02 03 04 [2] 05 06 07 08 }
  condition:
    ($a or $b) and 1 of ($a, $c)
}
"#;
    let plan = compile_query_plan_default(rule, 1, true, false, 9).expect("compile");
    assert!(plan.force_tier1_only);
    assert!(!plan.allow_tier2_fallback);
    assert_eq!(plan.max_candidates, 9.0);
    assert_eq!(plan.patterns.len(), 3);
    assert!(matches!(plan.root.kind.as_str(), "and"));
    assert!(plan.patterns.iter().all(|pattern| {
        pattern
            .alternatives
            .iter()
            .all(|alternative| alternative.len() <= 1)
    }));

    assert_eq!(
        compile_query_plan_default(rule, 1, false, true, 0.0)
            .expect("zero remains unlimited percentage")
            .max_candidates,
        0.0
    );
    assert!(
        compile_query_plan_default(
            r#"
rule bad {
  strings:
    $a = "ABCD"
  condition:
    1 of ($a, $missing)
}
"#,
            8,
            false,
            true,
            100,
        )
        .expect_err("unknown pattern in condition")
        .to_string()
        .contains("unknown string id")
    );

    let numeric_only = compile_query_plan_default(
        r#"
rule numeric_only {
  strings:
    $a = "ABCD"
  condition:
    uint32(0) == 1
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("numeric-only search should use numeric anchors");
    assert_eq!(numeric_only.patterns.len(), 2);
    assert!(
        numeric_only
            .patterns
            .iter()
            .any(|pattern| { pattern.pattern_id.starts_with(NUMERIC_READ_ANCHOR_PREFIX) })
    );

    let wildcard_sets = compile_query_plan_default(
        r#"
rule wildcard_sets {
  strings:
    $ruleA = "ABCD"
    $ruleB = "BCDE"
    $other = "CDEF"
  condition:
    any of ($ruleA, $ruleB) and all of $rule*
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("wildcard/set search support");
    assert_eq!(wildcard_sets.patterns.len(), 3);
    assert_eq!(wildcard_sets.root.kind, "and");
    assert_eq!(wildcard_sets.root.children.len(), 2);
    assert!(
        wildcard_sets
            .root
            .children
            .iter()
            .all(|child| child.kind == "n_of")
    );

    let verifier_constraints = compile_query_plan_default(
        r#"
rule verifier_constraints {
  strings:
    $a = "ABCD"
  condition:
    $a at 0 and #a > 1
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("compile verifier-only constraints");
    assert_eq!(verifier_constraints.patterns.len(), 1);
    assert_eq!(verifier_constraints.root.kind, "and");
    assert!(verifier_constraints.root.children.iter().any(|child| {
        child.kind == "and"
            && child
                .children
                .iter()
                .any(|grandchild| grandchild.kind == "verifier_only_at")
    }));
    assert!(verifier_constraints.root.children.iter().any(|child| {
        child.kind == "and"
            && child
                .children
                .iter()
                .any(|grandchild| grandchild.kind == "verifier_only_count")
    }));

    let verifier_at_entry = compile_query_plan_default(
        r#"
rule verifier_at_entry {
  strings:
    $a = "ABCD"
  condition:
    $a at pe.entry_point
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("compile verifier-only entry-point at");
    assert_eq!(verifier_at_entry.patterns.len(), 1);
    assert_eq!(verifier_at_entry.root.kind, "and");
    assert!(
        verifier_at_entry
            .root
            .children
            .iter()
            .any(|child| child.kind == "verifier_only_at")
    );
    let verifier_for_of_at = compile_query_plan_default(
        r#"
rule verifier_for_of_at {
  strings:
    $a = { 41 42 43 44 }
    $b = { 45 46 47 48 }
  condition:
    for any of ($*) : ( $ at pe.entry_point )
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("compile verifier-only for-of at");
    assert_eq!(verifier_for_of_at.root.kind, "or");
    assert_eq!(verifier_for_of_at.root.children.len(), 2);
    assert!(verifier_for_of_at.root.children.iter().all(|child| {
        child.kind == "and"
            && child
                .children
                .iter()
                .any(|grandchild| grandchild.kind == "verifier_only_at")
    }));

    let verifier_loop = compile_query_plan_default(
        r#"
rule verifier_loop {
  strings:
    $a = { 41 42 43 44 }
  condition:
    for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("compile verifier-only loop");
    assert_eq!(verifier_loop.patterns.len(), 1);
    assert_eq!(verifier_loop.root.kind, "and");
    assert!(
        verifier_loop
            .root
            .children
            .iter()
            .any(|child| child.kind == "verifier_only_loop")
    );
    assert!(
        compile_query_plan_default(
            r#"
rule bad_unanchorable_pattern {
  strings:
    $a = { 41 ?? 42 }
  condition:
    $a
}
"#,
            8,
            false,
            true,
            100,
        )
        .expect_err("unanchorable direct hex should fail")
        .to_string()
        .contains("requires an anchorable literal for direct search use")
    );
    assert!(
        compile_query_plan_default(
            r#"
rule bad_unanchorable_at {
  strings:
    $a = { E8 ?? ?? ?? ?? 5D }
  condition:
    $a at pe.entry_point
}
"#,
            8,
            false,
            true,
            100,
        )
        .expect_err("unanchorable at should fail")
        .to_string()
        .contains("requires an anchorable literal for at/in search use")
    );
    assert!(
        compile_query_plan_default(
            r#"
rule bad_unanchorable_loop {
  strings:
    $a = { FF 75 ?? FF 55 ?? }
  condition:
    verifierloop($a)
}
"#,
            8,
            false,
            true,
            100,
        )
        .expect_err("unanchorable verifier loop should fail")
        .to_string()
        .contains("requires an anchorable literal for verifier-loop search use")
    );

    let nocase = compile_query_plan_default(
        r#"
rule nocase_anchor {
  strings:
    $a = "AbCd" nocase
  condition:
    $a
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("compile nocase");
    assert_eq!(nocase.patterns.len(), 1);
    assert!(nocase.patterns[0].alternatives.len() > 1);
    assert!(nocase.patterns[0].fixed_literals.iter().all(Vec::is_empty));

    let balanced_nocase = derive_nocase_search_alternatives(
        b"AbCdE-00!!",
        false,
        GramSizes {
            tier2: DEFAULT_TIER2_GRAM_SIZE,
            tier1: DEFAULT_TIER1_GRAM_SIZE,
        },
    )
    .expect("balanced nocase");
    assert_eq!(balanced_nocase.len(), 4);

    let short_nocase = compile_query_plan_default(
        r#"
rule short_nocase_anchor {
  strings:
    $a = ".js" nocase
  condition:
    $a
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("compile short nocase");
    assert_eq!(short_nocase.patterns.len(), 1);
    assert!(short_nocase.patterns[0].alternatives.len() > 1);
    assert!(
        short_nocase.patterns[0]
            .alternatives
            .iter()
            .all(|alt| !alt.is_empty())
    );
    assert!(
        short_nocase.patterns[0]
            .tier2_alternatives
            .iter()
            .all(|alt| alt.is_empty())
    );

    let ignored_modules = compile_query_plan_default(
        r#"
rule ignored_modules {
  strings:
    $a = "ABCD"
    $b = "WXYZ"
  condition:
    ($a and androguard.url(/evil\.example/)) or
    (not cuckoo.sync.mutex(/demo/) and console.log("dbg") and $b)
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("compile ignored imports");
    assert_eq!(ignored_modules.patterns.len(), 2);
    assert_eq!(ignored_modules.root.kind, "or");
    assert_eq!(ignored_modules.root.children.len(), 2);
    assert!(
        ignored_modules
            .root
            .children
            .iter()
            .all(|child| child.kind == "pattern")
    );

    assert!(
        compile_query_plan_with_gram_sizes(
            r#"
rule numeric_too_short_for_gram_sizes {
  strings:
    $a = "ABCD"
  condition:
    uint32(0) == 1
}
"#,
            GramSizes::new(5, 6).expect("gram sizes"),
            8,
            false,
            true,
            100,
        )
        .is_err()
    );

    assert!(
        compile_query_plan_default(
            r#"
rule numeric_rhs {
  strings:
    $a = "ABCD"
  condition:
    $a and uint32(0) == filesize
}
"#,
            8,
            false,
            true,
            100,
        )
        .expect_err("non-literal numeric rhs")
        .to_string()
        .contains("requires equality against a literal constant")
    );
}

#[test]
fn rule_check_marks_simple_rule_as_searchable() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule simple_rule {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Searchable);
    assert!(report.issues.is_empty());
}

#[test]
fn rule_check_all_reports_each_rule_in_multi_rule_file() {
    let report = rule_check_all_with_gram_sizes_and_identity_source(
        r#"
rule searchable_rule {
  strings:
    $a = "ABCD"
  condition:
    $a
}

rule unsupported_rule {
  strings:
    $b = "WXYZ"
  condition:
    not $b
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );

    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    assert_eq!(report.rules.len(), 2);
    assert_eq!(report.rules[0].rule, "searchable_rule");
    assert_eq!(report.rules[0].status, RuleCheckStatus::Searchable);
    assert_eq!(report.rules[1].rule, "unsupported_rule");
    assert_eq!(report.rules[1].status, RuleCheckStatus::Unsupported);
    assert_eq!(
        report.rules[1]
            .issues
            .first()
            .and_then(|issue| issue.snippet.as_deref()),
        Some("not $b")
    );
}

#[test]
fn rule_check_all_ignores_private_helper_status_in_file_summary() {
    let report = rule_check_all_with_gram_sizes_and_identity_source(
        r#"
private rule helper {
  strings:
    $a = "ABCD"
  condition:
    not $a
}

rule top {
  strings:
    $b = "WXYZ"
  condition:
    $b
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );

    assert_eq!(report.status, RuleCheckStatus::Searchable);
    assert!(report.issues.is_empty());
    assert_eq!(report.rules.len(), 2);
    assert!(report.rules[0].is_private);
    assert_eq!(report.rules[0].status, RuleCheckStatus::Unsupported);
    assert_eq!(report.rules[1].rule, "top");
    assert_eq!(report.rules[1].status, RuleCheckStatus::Searchable);
}

#[test]
fn rule_check_all_preserves_file_locations_with_comments_before_later_rules() {
    let report = rule_check_all_with_gram_sizes_and_identity_source(
        r#"
// leading comment with enough text to skew offsets
rule one {
  strings:
    $a = "ABCD"
  condition:
    $a
}

// another long comment line to change stripped length
rule two {
  strings:
    $b = "WXYZ"
  condition:
    not $b
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );

    let issue = report.rules[1]
        .issues
        .iter()
        .find(|issue| issue.code == "negated-search-unbounded")
        .expect("negated issue");
    assert_eq!(issue.rule.as_deref(), Some("two"));
    assert_eq!(issue.line, Some(15));
    assert_eq!(issue.column, Some(5));
    assert_eq!(issue.snippet.as_deref(), Some("not $b"));
}

#[test]
fn rule_check_marks_verifier_only_constraints_as_needing_verify() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule exact_entrypoint_rule {
  strings:
    $a = "ABCD"
  condition:
    $a at pe.entry_point
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Searchable);
    assert!(report.verifier_only_kinds.is_empty());
    assert!(report.issues.is_empty());
}

#[test]
fn rule_check_marks_long_entrypoint_literals_as_needing_verify() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule verifier_rule {
  strings:
    $a = "ABCDEFGHIJKLMNOPQ"
  condition:
    $a at pe.entry_point
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::SearchableNeedsVerify);
    assert_eq!(
        report.verifier_only_kinds,
        vec!["verifier_only_at".to_owned()]
    );
    assert!(report.issues.iter().any(|issue| {
        issue.code == "verifier-only-offset" && issue.message.contains("specific offset")
    }));
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "verifier-only-offset")
        .expect("verifier issue");
    assert_eq!(issue.rule.as_deref(), Some("verifier_rule"));
    assert_eq!(issue.line, Some(6));
    assert!(issue.column.is_some());
    assert_eq!(issue.snippet.as_deref(), Some("$a at pe.entry_point"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("search --verify")
    );
}

#[test]
fn rule_check_marks_prefix_numeric_reads_as_searchable() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule exact_prefix_numeric_rule {
  condition:
    uint32(0) == 16909060
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Searchable);
    assert!(report.verifier_only_kinds.is_empty());
    assert!(report.issues.is_empty());
}

#[test]
fn rule_check_marks_in_prefix_numeric_reads_as_searchable() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule in_prefix_numeric_rule {
  condition:
    uint32(4) == 16909060
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Searchable);
    assert!(report.verifier_only_kinds.is_empty());
    assert!(report.issues.is_empty());
}

#[test]
fn rule_check_marks_out_of_prefix_numeric_reads_as_needing_verify() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule verifier_numeric_rule {
  condition:
    uint32(5) == 16909060
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::SearchableNeedsVerify);
    assert_eq!(
        report.verifier_only_kinds,
        vec!["verifier_only_eq".to_owned()]
    );
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "verifier-only-byte-equality")
        .expect("verifier issue");
    assert_eq!(issue.rule.as_deref(), Some("verifier_numeric_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("uint32(5) == 16909060"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("8-byte file prefix")
    );
}

#[test]
fn rule_check_marks_count_constraints_with_specific_issue_details() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule count_rule {
  strings:
    $a = "ABCD"
  condition:
    #a > 1
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::SearchableNeedsVerify);
    assert_eq!(
        report.verifier_only_kinds,
        vec!["verifier_only_count".to_owned()]
    );
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "verifier-only-count")
        .expect("count issue");
    assert_eq!(issue.rule.as_deref(), Some("count_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("#a > 1"));
    assert!(issue.message.contains("number of string matches"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("count constraints")
    );
}

#[test]
fn rule_check_marks_trivial_positive_count_constraints_as_searchable() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule trivial_count_exists_rule {
  strings:
    $a = "ABCD"
  condition:
    #a > 0
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Searchable);
    assert!(report.verifier_only_kinds.is_empty());
    assert!(report.issues.is_empty());
}

#[test]
fn rule_check_marks_trivial_zero_count_constraints_as_unsupported() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule trivial_count_zero_rule {
  strings:
    $a = "ABCD"
  condition:
    #a == 0
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "negated-search-unbounded")
        .expect("negated-search issue");
    assert_eq!(issue.snippet.as_deref(), Some("#a == 0"));
}

#[test]
fn rule_check_marks_range_constraints_with_specific_issue_details() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule range_rule {
  strings:
    $a = "ABCD"
  condition:
    $a in (filesize-64..filesize)
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::SearchableNeedsVerify);
    assert_eq!(
        report.verifier_only_kinds,
        vec!["verifier_only_in_range".to_owned()]
    );
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "verifier-only-range")
        .expect("range issue");
    assert_eq!(issue.rule.as_deref(), Some("range_rule"));
    assert_eq!(
        issue.snippet.as_deref(),
        Some("$a in (filesize-64..filesize)")
    );
    assert!(issue.message.contains("byte range"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("range constraints")
    );
}

#[test]
fn rule_check_marks_loop_constraints_with_specific_issue_details() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule loop_rule {
  strings:
    $a = { 41 42 43 44 }
  condition:
    for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::SearchableNeedsVerify);
    assert_eq!(
        report.verifier_only_kinds,
        vec!["verifier_only_loop".to_owned()]
    );
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "verifier-only-loop")
        .expect("loop issue");
    assert_eq!(issue.rule.as_deref(), Some("loop_rule"));
    assert_eq!(
        issue.snippet.as_deref(),
        Some("for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))")
    );
    assert!(issue.message.contains("for-any or for-all iterator"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("for any")
    );
}

#[test]
fn rule_check_marks_negated_search_constraints_as_needing_verify() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule negated_search_rule {
  strings:
    $a = "ABCD"
    $b = "WXYZ"
  condition:
    $a and not $b and filesize >= 8 and filesize < 9
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::SearchableNeedsVerify);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "verifier-only-negation")
        .expect("negation issue");
    assert_eq!(issue.rule.as_deref(), Some("negated_search_rule"));
    assert_eq!(
        issue.snippet.as_deref(),
        Some("$a and not $b and filesize >= 8 and filesize < 9")
    );
    assert!(issue.message.contains("negates searchable"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("search --verify")
    );
}

#[test]
fn rule_check_marks_unbounded_negated_search_as_unsupported() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule negated_only_rule {
  strings:
    $a = "ABCD"
  condition:
    not $a
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "negated-search-unbounded")
        .expect("negated unbounded issue");
    assert_eq!(issue.rule.as_deref(), Some("negated_only_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("not $a"));
    assert!(issue.message.contains("always true"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("positive searchable anchor")
    );
}

#[test]
fn rule_check_keeps_metadata_negation_with_positive_anchor_as_searchable() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule metadata_negation_rule {
  strings:
    $a = "ABCD"
  condition:
    $a and not filesize < 5KB
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Searchable);
    assert!(report.issues.is_empty());
}

#[test]
fn rule_check_marks_ignored_modules_as_needing_verify() {
    let direct_ignored = collect_ignored_module_call_names(
        r#"$a and console.log("dbg") and androguard.url(/evil\.example/)"#,
    );
    assert_eq!(
        direct_ignored.into_iter().collect::<Vec<_>>(),
        vec!["androguard.url".to_owned(), "console.log".to_owned()]
    );
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule ignored_module_rule {
  strings:
    $a = "ABCD"
  condition:
    $a and console.log("dbg") and androguard.url(/evil\.example/)
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::SearchableNeedsVerify);
    assert_eq!(
        report.ignored_module_calls,
        vec!["androguard.url".to_owned(), "console.log".to_owned()]
    );
    assert!(report.issues.iter().any(|issue| {
        issue.code == "ignored-module-predicate" && issue.message.contains("Use --verify")
    }));
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.message.contains("console.log"))
        .expect("console issue");
    assert_eq!(issue.rule.as_deref(), Some("ignored_module_rule"));
    assert_eq!(issue.line, Some(6));
    assert!(issue.column.is_some());
    assert_eq!(
        issue.snippet.as_deref(),
        Some("$a and console.log(\"dbg\") and androguard.url(/evil\\.example/)")
    );
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("module predicates")
    );
}

#[test]
fn rule_check_marks_hash_identity_mismatch_as_unsupported() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule mismatched_hash {
  condition:
    hash.md5(0, filesize) == "0123456789abcdef0123456789abcdef"
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    assert!(report.issues.iter().any(|issue| {
        issue.code == "hash-identity-mismatch" && issue.message.contains("current source is sha256")
    }));
    let issue = report.issues.first().expect("unsupported issue");
    assert_eq!(issue.rule.as_deref(), Some("mismatched_hash"));
    assert_eq!(issue.line, Some(4));
    assert!(issue.column.is_some());
    assert_eq!(
        issue.snippet.as_deref(),
        Some("hash.md5(0, filesize) == \"0123456789abcdef0123456789abcdef\"")
    );
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("--id-source")
    );
}

#[test]
fn rule_check_marks_parseable_rule_block_errors_with_specific_issue_code() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"include "index.yar""#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report.issues.first().expect("unsupported issue");
    assert_eq!(issue.code, "no-parseable-rule-block");
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("real YARA rule file")
    );
}

#[test]
fn rule_check_marks_ignored_module_only_rules_with_specific_issue_code() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule ignored_only_rule {
  condition:
    console.log("dbg")
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "ignored-module-no-anchor")
        .expect("ignored-module-no-anchor issue");
    assert_eq!(issue.rule.as_deref(), Some("ignored_only_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("console.log(\"dbg\")"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("searchable string or hex anchor")
    );
}

#[test]
fn rule_check_marks_unsupported_regex_flags_with_specific_issue_code() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule regex_flag_rule {
  strings:
    $a = /evil/ nocase
  condition:
    $a
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "unsupported-regex-flags")
        .expect("regex flag issue");
    assert_eq!(issue.rule.as_deref(), Some("regex_flag_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("$a = /evil/ nocase"));
}

#[test]
fn rule_check_marks_unsupported_hex_syntax_with_specific_issue_code() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule bad_hex_rule {
  strings:
    $a = { 6a?? }
  condition:
    $a
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "unsupported-hex-syntax")
        .expect("hex syntax issue");
    assert_eq!(issue.rule.as_deref(), Some("bad_hex_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("$a = { 6a?? }"));
}

#[test]
fn rule_check_marks_nonliteral_byte_offsets_with_specific_issue_code() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule dynamic_offset_rule {
  condition:
    uint32(filesize) == 1
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "nonliteral-byte-offset")
        .expect("byte offset issue");
    assert_eq!(issue.rule.as_deref(), Some("dynamic_offset_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("uint32(filesize) == 1"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("literal constant")
    );
}

#[test]
fn rule_check_marks_short_nocase_literals_without_anchor_window() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule short_nocase_rule {
  strings:
    $a = "ab" nocase
  condition:
    $a
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "nocase-no-anchorable-window")
        .expect("nocase anchor issue");
    assert_eq!(issue.rule.as_deref(), Some("short_nocase_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("$a = \"ab\" nocase"));
}

#[test]
fn rule_check_marks_missing_rule_references_with_specific_issue_code() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule parent_rule {
  strings:
    $a = "ABCD"
  condition:
    $a and missing_helper
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "unknown-rule-reference")
        .expect("unknown rule issue");
    assert_eq!(issue.rule.as_deref(), Some("parent_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("$a and missing_helper"));
}

#[test]
fn rule_check_marks_unsupported_comparison_operator_with_specific_issue_code() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule unsupported_comparison_rule {
  strings:
    $a = "ABCD"
  condition:
    #a != 1
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "unsupported-comparison-operator")
        .expect("unsupported comparison issue");
    assert_eq!(issue.rule.as_deref(), Some("unsupported_comparison_rule"));
    assert_eq!(issue.snippet.as_deref(), Some("#a != 1"));
}

#[test]
fn rule_check_marks_overbroad_union_as_specific_unsupported_issue() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule overbroad_iron_tiger_style {
  strings:
    $a = "Game Over Good Luck By Wind" nocase wide ascii
    $b = "ReleiceName" nocase wide ascii
    $c = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
    $d = "Winds Update" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and any of them
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "overbroad-union")
        .expect("overbroad issue");
    assert_eq!(issue.rule.as_deref(), Some("overbroad_iron_tiger_style"));
    assert_eq!(
        issue.snippet.as_deref(),
        Some("uint16(0) == 0x5a4d and any of them")
    );
    assert!(issue.message.contains("union fanout"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("mandatory anchor")
    );
}

#[test]
fn rule_check_marks_low_information_entrypoint_stub_as_specific_unsupported_issue() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule low_information_entrypoint_stub {
  strings:
    $a0 = { 50 BE [4] 8D BE [4] 57 83 CD }
  condition:
    $a0 at pe.entry_point
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "low-information-entrypoint-stub")
        .expect("entrypoint issue");
    assert_eq!(
        issue.rule.as_deref(),
        Some("low_information_entrypoint_stub")
    );
    assert_eq!(issue.snippet.as_deref(), Some("$a0 at pe.entry_point"));
    assert!(issue.message.contains("entry-point stub"));
    assert!(
        issue
            .remediation
            .as_deref()
            .unwrap_or_default()
            .contains("longer mandatory literal")
    );
}

#[test]
fn rule_check_marks_direct_unanchorable_pattern_with_direct_condition_snippet() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule bad_unanchorable_pattern {
  strings:
    $a = { 41 ?? 42 }
  condition:
    $a
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "requires-anchorable-literal-direct")
        .expect("direct anchorability issue");
    assert_eq!(issue.rule.as_deref(), Some("bad_unanchorable_pattern"));
    assert_eq!(issue.snippet.as_deref(), Some("$a"));
}

#[test]
fn rule_check_marks_at_in_unanchorable_pattern_with_condition_snippet() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule bad_unanchorable_at {
  strings:
    $a = { E8 ?? ?? ?? ?? 5D }
  condition:
    $a at pe.entry_point
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "requires-anchorable-literal-at-in")
        .expect("at/in anchorability issue");
    assert_eq!(issue.rule.as_deref(), Some("bad_unanchorable_at"));
    assert_eq!(issue.snippet.as_deref(), Some("$a at pe.entry_point"));
}

#[test]
fn rule_check_marks_loop_unanchorable_pattern_with_condition_snippet() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule bad_unanchorable_loop {
  strings:
    $a = { FF 75 ?? FF 55 ?? }
  condition:
    for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "requires-anchorable-literal-loop")
        .expect("loop anchorability issue");
    assert_eq!(issue.rule.as_deref(), Some("bad_unanchorable_loop"));
    assert_eq!(
        issue.snippet.as_deref(),
        Some("for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))")
    );
}

#[test]
fn rule_check_marks_n_of_unanchorable_pattern_with_condition_snippet() {
    let report = rule_check_with_gram_sizes_and_identity_source(
        r#"
rule bad_unanchorable_n_of {
  strings:
    $a = { 41 ?? 42 }
    $b = "ABCD"
  condition:
    any of ($a, $b)
}
"#,
        default_gram_sizes(),
        Some("sha256"),
        8,
        false,
        true,
        7.5,
    );
    assert_eq!(report.status, RuleCheckStatus::Unsupported);
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.code == "requires-anchorable-literal-n-of")
        .expect("n-of anchorability issue");
    assert_eq!(issue.rule.as_deref(), Some("bad_unanchorable_n_of"));
    assert_eq!(issue.snippet.as_deref(), Some("any of ($a, $b)"));
}

#[test]
fn fixed_literal_match_plan_roundtrips_simple_pattern_and_or() {
    let rule = r#"
rule sample {
  strings:
    $a = { 41 42 43 44 }
    $b = { 45 46 47 48 }
  condition:
    $a or $b
}
"#;
    let plan = compile_query_plan_default(rule, 16, false, true, 100_000).expect("plan");
    let literal_plan = fixed_literal_match_plan(&plan).expect("fixed literal plan");
    assert_eq!(literal_plan.literals["$a"], vec![b"ABCD".to_vec()]);
    assert_eq!(literal_plan.literal_wide["$a"], vec![false]);
    assert_eq!(literal_plan.literal_fullword["$a"], vec![false]);
    let mut matches = HashMap::new();
    matches.insert("$a".to_owned(), false);
    matches.insert("$b".to_owned(), true);
    assert!(evaluate_fixed_literal_match(&literal_plan.root, &matches).expect("eval"));
}

#[test]
fn fixed_literal_match_plan_accepts_multi_literal_patterns() {
    let rule = r#"
rule sample {
  strings:
    $a = "AB" ascii wide fullword
  condition:
    $a
}
"#;
    let plan = compile_query_plan_default(rule, 16, false, true, 100_000).expect("plan");
    let literal_plan = fixed_literal_match_plan(&plan).expect("fixed literal plan");
    let literals = literal_plan.literals.get("$a").expect("literals");
    assert_eq!(literals.len(), 2);
    assert_eq!(literals[0], b"AB".to_vec());
    assert_eq!(literals[1], vec![b'A', 0, b'B', 0]);
    assert_eq!(literal_plan.literal_wide["$a"], vec![false, true]);
    assert_eq!(literal_plan.literal_fullword["$a"], vec![true, true]);

    let regex_rule = r#"
rule sample {
  strings:
    $a = /[A-Z]+applesause[0-9]+/
  condition:
    $a
}
"#;
    let regex_plan =
        compile_query_plan_default(regex_rule, 16, false, true, 100_000).expect("plan");
    assert!(fixed_literal_match_plan(&regex_plan).is_none());

    let grouped_regex_rule = r#"
rule sample {
  strings:
    $a = /fooba(bar|baz)qux/
  condition:
    $a
}
"#;
    let grouped_regex_plan =
        compile_query_plan_default(grouped_regex_rule, 16, false, true, 100_000).expect("plan");
    assert_eq!(grouped_regex_plan.patterns.len(), 1);
    assert!(fixed_literal_match_plan(&grouped_regex_plan).is_none());
}

#[test]
fn branch_local_budget_reduces_or_branch_anchor_count() {
    let rule = r#"
rule sample {
  strings:
    $a = { 01 02 03 04 05 06 07 08 09 0A 0B 0C }
    $b = { 11 12 13 14 15 16 17 18 19 1A 1B 1C }
    $c = { 21 22 23 24 25 26 27 28 29 2A 2B 2C }
  condition:
    $a or $b or $c
}
"#;
    let plan = compile_query_plan_default(rule, 4, false, true, 100_000).expect("plan");
    for pattern in &plan.patterns {
        assert!(pattern.alternatives[0].len() <= 2);
    }
}

#[test]
fn compile_query_plan_from_file_roundtrip_works() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("rule.yar");
    fs::write(
        &rule_path,
        r#"
rule disk_rule {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
    )
    .expect("write rule");
    let plan = compile_query_plan_from_file_default(&rule_path, 8, false, true, 100)
        .expect("plan from file");
    assert_eq!(plan.patterns.len(), 1);
}

#[test]
fn compile_query_plan_inlines_sibling_rule_references() {
    let rule = r#"
rule parent_rule {
  strings:
    $a = "ABCD"
  condition:
    $a and helper_rule
}

private rule helper_rule {
  strings:
    $b = "WXYZ"
  condition:
    $b
}
"#;
    let plan = compile_query_plan_default(rule, 4, false, true, 100_000).expect("plan");
    let pattern_ids = plan
        .patterns
        .iter()
        .map(|pattern| pattern.pattern_id.as_str())
        .collect::<HashSet<_>>();
    assert!(pattern_ids.contains("$a"));
    assert!(pattern_ids.contains("__ruledep::helper_rule::$b"));
    assert!(contains_pattern_node(&plan.root));
}

#[test]
fn compile_query_plan_inlines_case_insensitive_sibling_rule_references() {
    let rule = r#"
rule ParentRule {
  strings:
    $a = "ABCD"
  condition:
    HelperRule and $a
}

private rule HelperRule {
  strings:
    $b = "WXYZ"
  condition:
    $b
}
"#;
    let plan = compile_query_plan_default(rule, 4, false, true, 100_000).expect("plan");
    let pattern_ids = plan
        .patterns
        .iter()
        .map(|pattern| pattern.pattern_id.as_str())
        .collect::<HashSet<_>>();
    assert!(pattern_ids.contains("$a"));
    assert!(pattern_ids.contains("__ruledep::helperrule::$b"));
}

#[test]
fn compile_query_plan_reports_missing_rule_reference() {
    let rule = r#"
rule parent_rule {
  strings:
    $a = "ABCD"
  condition:
    $a and missing_helper
}
"#;
    let err = compile_query_plan_default(rule, 4, false, true, 100_000)
        .expect_err("missing helper should fail");
    assert!(
        err.to_string()
            .contains("Condition references unknown rule")
    );
}

#[test]
fn parser_and_helper_edge_cases_cover_remaining_branches() {
    let mut parser =
        ConditionParser::new("$a", HashSet::from(["$a".to_owned()]), None).expect("parser");
    assert!(
        parser
            .consume(Some(&Token::LParen))
            .expect_err("mismatched token")
            .to_string()
            .contains("Expected token")
    );

    let mut parser = ConditionParser::new(
        "1 of ($a,)",
        HashSet::from(["$a".to_owned(), "$b".to_owned()]),
        None,
    )
    .expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("expected pattern id")
            .to_string()
            .contains("Expected pattern id")
    );

    let mut parser =
        ConditionParser::new("1 of ($a,", HashSet::from(["$a".to_owned()]), None).expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("unterminated n-of")
            .to_string()
            .contains("Unexpected end of condition")
    );

    let mut parser =
        ConditionParser::new("and", HashSet::from(["$a".to_owned()]), None).expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("unsupported condition token")
            .to_string()
            .contains("Unsupported condition token")
    );

    let mut parser = ConditionParser::new("xor == 7", HashSet::new(), None).expect("parser");
    assert!(
        parser
            .parse()
            .expect_err("unknown rule")
            .to_string()
            .contains("Condition references unknown rule")
    );

    assert!(
        parse_literal_line("no equals here")
            .expect("ignored")
            .is_none()
    );
    assert!(
        parse_literal_line("identifier = \"x\"")
            .expect("non pattern")
            .is_none()
    );
    assert!(
        parse_literal_line("$a = { 01 02 }")
            .expect("hex line ignored")
            .is_none()
    );
    let escaped = parse_literal_line(r#"$a = "A\"B""#)
        .expect("escaped literal")
        .expect("pattern");
    assert_eq!(escaped.alternatives[0], b"A\"B".to_vec());

    let fixed = parse_hex_line_to_grams(
        "$hex = { 41 42 43 44 45 }",
        GramSizes::new(3, 4).expect("gram sizes"),
    )
    .expect("hex parse")
    .expect("pattern");
    assert_eq!(fixed.0, "$hex");
    assert_eq!(fixed.3, vec![b"ABCDE".to_vec()]);
    assert_eq!(fixed.1.len(), 1);
    assert_eq!(fixed.1[0].len(), 3);
    assert_eq!(fixed.2[0].len(), 2);
    assert!(
        parse_hex_line_to_grams(
            "identifier = { 41 42 }",
            GramSizes::new(3, 4).expect("gram sizes"),
        )
        .expect("ignored")
        .is_none()
    );
    assert!(
        parse_hex_line_to_grams(
            "$hex = { 41 42 [x-y] 43 }",
            GramSizes::new(3, 4).expect("gram sizes"),
        )
        .expect_err("bad gap token")
        .to_string()
        .contains("Unsupported hex token")
    );

    assert!(!is_gap_token("[]"));
    assert!(!is_gap_token("[1-]"));
    assert!(!is_gap_token("[abc]"));
    assert_eq!(grams_from_bytes(b"abc", 4), Vec::<u64>::new());

    let patterns = BTreeMap::from([
        ("$a".to_owned(), vec![vec![1u64, 2u64]]),
        ("$b".to_owned(), vec![vec![3u64]]),
    ]);
    let mut root = QueryNode {
        kind: "or".to_owned(),
        pattern_id: None,
        threshold: None,
        children: vec![
            QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$b".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
        ],
    };
    reorder_or_nodes_for_selectivity(&mut root, &patterns);
    assert_eq!(root.children[0].pattern_id.as_deref(), Some("$b"));
    assert_eq!(pattern_selectivity_score("$missing", &patterns), u128::MAX);
    assert_eq!(
        node_selectivity_score(
            &QueryNode {
                kind: "bogus".to_owned(),
                pattern_id: None,
                threshold: None,
                children: Vec::new(),
            },
            &patterns
        ),
        u128::MAX
    );
}

#[test]
fn tier2_gram_size_wrapper_helpers_work() {
    let rule = r#"
rule q {
  strings:
    $a = { 41 42 43 44 45 }
  condition:
    $a
}
"#;
    let plan =
        compile_query_plan_with_tier1_default_tier2(rule, 3, 8, false, true, 50).expect("plan");
    assert_eq!(plan.tier1_gram_size, 3);
    assert_eq!(plan.tier2_gram_size, DEFAULT_TIER2_GRAM_SIZE);

    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("rule.yar");
    fs::write(&rule_path, rule).expect("rule");
    let plan =
        compile_query_plan_from_file_with_tier1_default_tier2(&rule_path, 3, 8, false, true, 50)
            .expect("plan from file");
    assert_eq!(plan.tier1_gram_size, 3);
    assert_eq!(plan.max_candidates, 50.0);
}

#[test]
fn fixed_literal_helpers_cover_invalid_shapes_and_ast_variants() {
    let mut patterns = BTreeMap::new();
    patterns.insert("$a".to_owned(), vec![vec![1_u64, 2, 3]]);
    patterns.insert("$b".to_owned(), vec![vec![4_u64, 5]]);
    assert_eq!(
        node_selectivity_score(
            &QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: None,
                threshold: None,
                children: Vec::new(),
            },
            &patterns,
        ),
        u128::MAX
    );
    let pattern_b_score = pattern_selectivity_score("$b", &patterns);
    assert_eq!(
        node_selectivity_score(
            &QueryNode {
                kind: "and".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("$a".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("$b".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                ],
            },
            &patterns,
        ),
        pattern_b_score
    );
    assert_eq!(
        node_selectivity_score(
            &QueryNode {
                kind: "or".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("$a".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("$b".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                ],
            },
            &patterns,
        ),
        pattern_b_score
    );
    assert_eq!(
        node_selectivity_score(
            &QueryNode {
                kind: "n_of".to_owned(),
                pattern_id: None,
                threshold: Some(1),
                children: vec![QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("$b".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                }],
            },
            &patterns,
        ),
        pattern_b_score
    );

    let invalid_empty = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$bad".to_owned(),
            alternatives: vec![vec![1_u64]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("$bad".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 1.0,
        tier2_gram_size: 3,
        tier1_gram_size: 4,
    };
    assert!(fixed_literal_match_plan(&invalid_empty).is_none());

    let invalid_alternatives = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$bad".to_owned(),
            alternatives: vec![vec![1_u64], vec![2_u64]],
            tier2_alternatives: vec![Vec::new(), Vec::new()],
            anchor_literals: vec![vec![0x41], vec![0x42]],
            fixed_literals: vec![vec![0x41]],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("$bad".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 1.0,
        tier2_gram_size: 3,
        tier1_gram_size: 4,
    };
    assert!(fixed_literal_match_plan(&invalid_alternatives).is_none());

    let matches = HashMap::from([
        ("$a".to_owned(), true),
        ("$b".to_owned(), false),
        ("$c".to_owned(), true),
    ]);
    let n_of = QueryNode {
        kind: "n_of".to_owned(),
        pattern_id: None,
        threshold: Some(2),
        children: vec![
            QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$b".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$c".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
        ],
    };
    assert!(evaluate_fixed_literal_match(&n_of, &matches).expect("n_of match"));
    let n_of_missing_threshold = QueryNode {
        kind: "n_of".to_owned(),
        pattern_id: None,
        threshold: None,
        children: Vec::new(),
    };
    assert!(evaluate_fixed_literal_match(&n_of_missing_threshold, &matches).is_err());
    let pattern_missing_id = QueryNode {
        kind: "pattern".to_owned(),
        pattern_id: None,
        threshold: None,
        children: Vec::new(),
    };
    assert!(evaluate_fixed_literal_match(&pattern_missing_id, &matches).is_err());
    let unsupported = QueryNode {
        kind: "xor".to_owned(),
        pattern_id: None,
        threshold: None,
        children: Vec::new(),
    };
    assert!(evaluate_fixed_literal_match(&unsupported, &matches).is_err());
}

#[test]
fn dedupe_helpers_remove_duplicate_or_branches_and_alternatives() {
    let mut root = QueryNode {
        kind: "or".to_owned(),
        pattern_id: None,
        threshold: None,
        children: vec![
            QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$b".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
        ],
    };
    dedupe_or_nodes(&mut root);
    assert_eq!(root.children.len(), 2);
    assert_eq!(root.children[0].pattern_id.as_deref(), Some("$a"));
    assert_eq!(root.children[1].pattern_id.as_deref(), Some("$b"));

    let (alts, alts5, anchors, literals, wide, fullword) = dedupe_pattern_alternatives(
        vec![vec![1_u64, 2], vec![1_u64, 2], vec![3_u64]],
        vec![vec![7_u64], vec![7_u64], vec![8_u64]],
        vec![b"XY".to_vec(), b"XY".to_vec(), b"ZZ".to_vec()],
        vec![b"AB".to_vec(), b"AB".to_vec(), b"CD".to_vec()],
        vec![false, false, true],
        vec![false, false, true],
    );
    assert_eq!(alts, vec![vec![1_u64, 2], vec![3_u64]]);
    assert_eq!(alts5, vec![vec![7_u64], vec![8_u64]]);
    assert_eq!(anchors, vec![b"XY".to_vec(), b"ZZ".to_vec()]);
    assert_eq!(literals, vec![b"AB".to_vec(), b"CD".to_vec()]);
    assert_eq!(wide, vec![false, true]);
    assert_eq!(fullword, vec![false, true]);
}

#[test]
fn optimize_grams_prefers_more_selective_bytes_without_literal_positions() {
    let gram_letters = pack_exact_gram(b"ASPX");
    let gram_suffix = pack_exact_gram(b".pas");
    let optimized = optimize_grams(&[gram_letters, gram_suffix], &[], 4, 1);
    assert_eq!(optimized, vec![gram_suffix]);
}

#[test]
fn nocase_window_selection_prefers_fixed_byte_heavy_suffixes() {
    let alts = derive_nocase_search_alternatives(
        br"\UnitFrmManagerKeyLog.pas",
        false,
        GramSizes::default(),
    )
    .expect("nocase alternatives");
    assert!(alts.iter().all(|alt| {
        let lowered = alt
            .iter()
            .map(|byte| byte.to_ascii_lowercase())
            .collect::<Vec<_>>();
        lowered.windows(4).any(|window| window == b".pas")
    }));
}

#[test]
fn overbroad_high_fanout_union_requires_mandatory_anchor() {
    let err = compile_query_plan_default(
        r#"
rule overbroad_iron_tiger_style {
  strings:
    $a = "Game Over Good Luck By Wind" nocase wide ascii
    $b = "ReleiceName" nocase wide ascii
    $c = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
    $d = "Winds Update" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and any of them
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect_err("overbroad union should fail");
    assert!(err.to_string().contains("overbroad for scalable search"));

    compile_query_plan_default(
        r#"
rule narrow_all_of {
  strings:
    $a = "Game Over Good Luck By Wind" nocase wide ascii
    $b = "ReleiceName" nocase wide ascii
    $c = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
    $d = "Winds Update" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and all of them
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("all-of rule should stay searchable");
}

#[test]
fn low_information_entrypoint_stub_is_rejected() {
    let err = compile_query_plan_default(
        r#"
rule low_information_entrypoint_stub {
  strings:
    $a0 = { 50 BE [4] 8D BE [4] 57 83 CD }
  condition:
    $a0 at pe.entry_point
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect_err("low-information entrypoint stub should fail");
    assert!(
        err.to_string()
            .contains("entry-point stub provides only low-information gram anchors")
    );

    compile_query_plan_default(
        r#"
rule stronger_entrypoint_anchor {
  strings:
    $a0 = { 50 BE [4] 8D BE [4] 57 83 CD 11 22 33 44 55 66 77 88 99 AA BB CC }
  condition:
    $a0 at pe.entry_point
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("stronger entrypoint anchor should compile");
}

#[test]
fn low_information_range_rule_is_rejected() {
    compile_query_plan_default(
        r#"
rule low_information_range_rule {
  strings:
    $hdr = { 50 4B 03 04 }
    $ext = ".js" nocase
  condition:
    $hdr at 0 and $ext in (filesize-100..filesize)
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("smaller tier1 grams now make the range rule anchorable");

    compile_query_plan_default(
        r#"
rule stronger_range_rule {
  strings:
    $hdr = { 50 4B 03 04 }
    $ext = ".download-javascript-payload.js" nocase
  condition:
    $hdr at 0 and $ext in (filesize-100..filesize)
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("stronger range rule should compile");
}

#[test]
fn low_information_single_pattern_is_rejected() {
    compile_query_plan_default(
        r#"
rule low_information_single_pattern {
  strings:
    $a = { C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }
  condition:
    $a
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("smaller tier1 grams now make the single-pattern rule anchorable");

    compile_query_plan_default(
        r#"
rule stronger_single_pattern {
  strings:
    $a = "LongerAnchorLiteral"
  condition:
    $a
}
"#,
        8,
        false,
        true,
        100,
    )
    .expect("stronger single-pattern rule should compile");
}
