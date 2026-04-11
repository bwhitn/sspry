use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::candidate::{
    GramSizes, PE_ENTRY_POINT_PREFIX_BYTES, metadata_field_is_boolean, metadata_field_is_float,
    metadata_field_is_integer, normalize_query_metadata_field, pack_exact_gram,
};
use crate::{Result, SspryError};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueryNode {
    pub kind: String,
    pub pattern_id: Option<String>,
    pub threshold: Option<usize>,
    pub children: Vec<QueryNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternPlan {
    pub pattern_id: String,
    pub alternatives: Vec<Vec<u64>>,
    #[serde(default)]
    pub tier2_alternatives: Vec<Vec<u64>>,
    #[serde(default)]
    pub anchor_literals: Vec<Vec<u8>>,
    #[serde(default)]
    pub fixed_literals: Vec<Vec<u8>>,
    #[serde(default)]
    pub fixed_literal_wide: Vec<bool>,
    #[serde(default)]
    pub fixed_literal_fullword: Vec<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompiledQueryPlan {
    pub patterns: Vec<PatternPlan>,
    pub root: QueryNode,
    pub force_tier1_only: bool,
    pub allow_tier2_fallback: bool,
    pub max_candidates: f64,
    pub tier2_gram_size: usize,
    pub tier1_gram_size: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleCheckStatus {
    Searchable,
    SearchableNeedsVerify,
    Unsupported,
}

impl RuleCheckStatus {
    /// Returns the stable wire-format label used in JSON responses and CLI
    /// output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Searchable => "searchable",
            Self::SearchableNeedsVerify => "searchable-needs-verify",
            Self::Unsupported => "unsupported",
        }
    }

    /// Combines two rule-check outcomes, keeping the most severe status.
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unsupported, _) | (_, Self::Unsupported) => Self::Unsupported,
            (Self::SearchableNeedsVerify, _) | (_, Self::SearchableNeedsVerify) => {
                Self::SearchableNeedsVerify
            }
            _ => Self::Searchable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleCheckSeverity {
    Error,
    Warning,
}

impl RuleCheckSeverity {
    /// Returns the stable wire-format label used in JSON responses and CLI
    /// output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCheckIssue {
    pub code: String,
    pub severity: RuleCheckSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCheckReport {
    pub status: RuleCheckStatus,
    #[serde(default)]
    pub issues: Vec<RuleCheckIssue>,
    #[serde(default)]
    pub verifier_only_kinds: Vec<String>,
    #[serde(default)]
    pub ignored_module_calls: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCheckRuleReport {
    pub rule: String,
    pub is_private: bool,
    pub status: RuleCheckStatus,
    #[serde(default)]
    pub issues: Vec<RuleCheckIssue>,
    #[serde(default)]
    pub verifier_only_kinds: Vec<String>,
    #[serde(default)]
    pub ignored_module_calls: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCheckFileReport {
    pub status: RuleCheckStatus,
    #[serde(default)]
    pub issues: Vec<RuleCheckIssue>,
    #[serde(default)]
    pub verifier_only_kinds: Vec<String>,
    #[serde(default)]
    pub ignored_module_calls: Vec<String>,
    #[serde(default)]
    pub rules: Vec<RuleCheckRuleReport>,
}

#[cfg(test)]
/// Estimates the heap footprint owned by one compiled pattern plan for tests
/// that enforce cache-size limits.
fn pattern_plan_memory_bytes(pattern: &PatternPlan) -> u64 {
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

#[cfg(test)]
/// Estimates the recursive heap footprint of a query node tree for tests that
/// enforce cache-size limits.
fn query_node_memory_bytes(node: &QueryNode) -> u64 {
    (std::mem::size_of::<QueryNode>() as u64)
        .saturating_add(node.kind.capacity() as u64)
        .saturating_add(
            node.pattern_id
                .as_ref()
                .map(|value| value.capacity() as u64)
                .unwrap_or(0),
        )
        .saturating_add(
            (node.children.capacity() as u64)
                .saturating_mul(std::mem::size_of::<QueryNode>() as u64),
        )
        .saturating_add(
            node.children
                .iter()
                .map(query_node_memory_bytes)
                .sum::<u64>(),
        )
}

#[cfg(test)]
/// Estimates the total memory retained by a compiled query plan for cache-size
/// tests.
pub(crate) fn compiled_query_plan_memory_bytes(plan: &CompiledQueryPlan) -> u64 {
    (std::mem::size_of::<CompiledQueryPlan>() as u64)
        .saturating_add(
            (plan.patterns.capacity() as u64)
                .saturating_mul(std::mem::size_of::<PatternPlan>() as u64),
        )
        .saturating_add(
            plan.patterns
                .iter()
                .map(pattern_plan_memory_bytes)
                .sum::<u64>(),
        )
        .saturating_add(query_node_memory_bytes(&plan.root))
}

/// Normalizes the user-facing max-candidates percentage into the supported
/// `0..=100` range, treating non-positive or invalid values as unlimited.
pub fn normalize_max_candidates(max_candidates: f64) -> f64 {
    if !max_candidates.is_finite() || max_candidates <= 0.0 {
        0.0
    } else {
        max_candidates.clamp(0.0, 100.0)
    }
}

/// Converts a max-candidates percentage into an absolute candidate cap for the
/// current document count.
pub fn resolve_max_candidates(doc_count: usize, max_candidates_pct: f64) -> usize {
    if !max_candidates_pct.is_finite() || max_candidates_pct <= 0.0 {
        return usize::MAX;
    }
    if doc_count == 0 {
        return 0;
    }
    let resolved = ((doc_count as f64) * (max_candidates_pct / 100.0)).ceil();
    resolved.max(1.0).min(usize::MAX as f64) as usize
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedLiteralMatchPlan {
    pub literals: HashMap<String, Vec<Vec<u8>>>,
    pub literal_wide: HashMap<String, Vec<bool>>,
    pub literal_fullword: HashMap<String, Vec<bool>>,
    pub root: QueryNode,
}

#[derive(Clone, Debug)]
struct PatternDef {
    pattern_id: String,
    alternatives: Vec<Vec<u8>>,
    wide_flags: Vec<bool>,
    fullword_flags: Vec<bool>,
    nocase_flags: Vec<bool>,
    exact_literals: bool,
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    LParen,
    RParen,
    Comma,
    DotDot,
    EqEq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Plus,
    Minus,
    And,
    Any,
    All,
    At,
    In,
    Not,
    Or,
    Of,
    Them,
    Hash,
    Int(usize),
    Float(f64),
    Bool(bool),
    Quoted(String),
    Id(String),
    Name(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComparisonOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

impl ComparisonOp {
    /// Reverses the direction of a comparison when the parser swaps the left
    /// and right operands.
    fn reverse(self) -> Self {
        match self {
            Self::Eq => Self::Eq,
            Self::Ne => Self::Ne,
            Self::Gt => Self::Lt,
            Self::Ge => Self::Le,
            Self::Lt => Self::Gt,
            Self::Le => Self::Ge,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NumericReadKind {
    Integer,
    Float,
}

const NUMERIC_READ_ANCHOR_PREFIX: &str = "__numeric_eq_anchor_";
const ANONYMOUS_PATTERN_PREFIX: &str = "$__anon_";
const MAX_HEX_GROUP_ALTERNATIVES: usize = 16;
const MAX_NOCASE_LITERAL_VARIANTS: usize = 32;
const IGNORED_MODULE_PLACEHOLDER_PREFIX: &str = "ignoredmodulepred";
const IGNORED_SEARCH_MODULES: &[&str] = &["androguard", "console", "cuckoo"];
const RULE_DEP_PATTERN_PREFIX: &str = "__ruledep::";

#[derive(Clone, Debug, PartialEq, Eq)]
enum RangeBoundExpr {
    Literal(usize),
    Filesize,
    FilesizePlus(usize),
    FilesizeMinus(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AtOffsetExpr {
    Literal(usize),
    Field(String),
    FieldPlus(String, usize),
    FieldMinus(String, usize),
}

struct ConditionParser {
    tokens: Vec<Token>,
    index: usize,
    known_patterns: HashSet<String>,
    known_pattern_names: Vec<String>,
    verifier_only_pattern_ids: HashSet<String>,
    known_rule_names: HashSet<String>,
    active_identity_source: Option<String>,
}

#[derive(Clone, Debug)]
struct ParsedRuleBlock {
    name: String,
    is_private: bool,
    block_start_offset: usize,
    block_text: String,
    strings_lines: Vec<String>,
    raw_condition_text: String,
    condition_text: String,
}

#[derive(Clone, Debug, Default)]
struct RulePlanFragment {
    pattern_alternatives: BTreeMap<String, Vec<Vec<u64>>>,
    pattern_tier2_alternatives: BTreeMap<String, Vec<Vec<u64>>>,
    pattern_anchor_literals: BTreeMap<String, Vec<Vec<u8>>>,
    pattern_fixed_literals: BTreeMap<String, Vec<Vec<u8>>>,
    pattern_fixed_literal_wide: BTreeMap<String, Vec<bool>>,
    pattern_fixed_literal_fullword: BTreeMap<String, Vec<bool>>,
    root: Option<QueryNode>,
}

/// Canonicalizes a rule name for case-insensitive matching across rule
/// references.
fn normalize_rule_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

/// Maps a tokenized comparison operator to the internal enum used by the query
/// planner.
fn comparison_op_from_token(token: &Token) -> Option<ComparisonOp> {
    match token {
        Token::EqEq => Some(ComparisonOp::Eq),
        Token::Ne => Some(ComparisonOp::Ne),
        Token::Gt => Some(ComparisonOp::Gt),
        Token::Ge => Some(ComparisonOp::Ge),
        Token::Lt => Some(ComparisonOp::Lt),
        Token::Le => Some(ComparisonOp::Le),
        _ => None,
    }
}

/// Builds the normalized query-node kind for a typed comparison.
fn comparison_kind(prefix: &str, op: ComparisonOp) -> String {
    format!(
        "{prefix}_{}",
        match op {
            ComparisonOp::Eq => "eq",
            ComparisonOp::Ne => "ne",
            ComparisonOp::Gt => "gt",
            ComparisonOp::Ge => "ge",
            ComparisonOp::Lt => "lt",
            ComparisonOp::Le => "le",
        }
    )
}

/// Returns true when a pattern has at least one searchable anchor in tier 1,
/// tier 2, or the fixed-literal verifier fast path.
fn pattern_has_searchable_anchor(
    alternatives: &[Vec<u64>],
    tier2_alternatives: &[Vec<u64>],
    fixed_literals: &[Vec<u8>],
) -> bool {
    alternatives.iter().any(|alt| !alt.is_empty())
        || tier2_alternatives.iter().any(|alt| !alt.is_empty())
        || fixed_literals.iter().any(|literal| !literal.is_empty())
}

/// Decodes a fixed-width hexadecimal digest while validating length and
/// character set.
fn decode_exact_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let text = value.trim().to_ascii_lowercase();
    if text.len() != N * 2 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(SspryError::from(format!(
            "{label} must be exactly {} hexadecimal characters.",
            N * 2
        )));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out)?;
    Ok(out)
}

/// Re-encodes a digest into the store's normalized 32-byte identity namespace.
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

/// Normalizes a user-supplied hash literal into the searchable identity form
/// used by the candidate store.
fn normalize_identity_literal(hash_kind: &str, value: &str) -> Result<String> {
    match hash_kind {
        "md5" => Ok(hex::encode(normalize_identity_digest(
            "md5",
            &decode_exact_hex::<16>(value, "md5")?,
        ))),
        "sha1" => Ok(hex::encode(normalize_identity_digest(
            "sha1",
            &decode_exact_hex::<20>(value, "sha1")?,
        ))),
        "sha256" => Ok(hex::encode(decode_exact_hex::<32>(value, "sha256")?)),
        other => Err(SspryError::from(format!(
            "Unsupported searchable hash function: {other}"
        ))),
    }
}

/// Returns true when a module call is intentionally ignored by the searchable
/// query subset.
fn ignored_search_module_name(name: &str) -> bool {
    IGNORED_SEARCH_MODULES.iter().any(|module| {
        name == *module
            || name
                .strip_prefix(module)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// Scans condition text and records ignored module calls so rule-check output
/// can explain why they were dropped.
fn collect_ignored_module_call_names(condition_text: &str) -> BTreeSet<String> {
    let chars = condition_text.chars().collect::<Vec<_>>();
    let mut out = BTreeSet::<String>::new();
    let mut index = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        if ch.is_ascii_alphabetic() {
            let mut cursor = index + 1;
            while cursor < chars.len()
                && (chars[cursor].is_ascii_alphanumeric()
                    || chars[cursor] == '_'
                    || chars[cursor] == '.')
            {
                cursor += 1;
            }
            let name = chars[index..cursor].iter().collect::<String>();
            if ignored_search_module_name(&name) {
                let mut next = cursor;
                while next < chars.len() && chars[next].is_whitespace() {
                    next += 1;
                }
                if let Some(end) = consume_parenthesized_span(&chars, next) {
                    out.insert(name);
                    index = end;
                    continue;
                }
            }
        }
        index += 1;
    }
    out
}

impl ConditionParser {
    #[cfg(test)]
    /// Test-only constructor that builds a parser without rule-reference
    /// metadata.
    fn new(
        text: &str,
        known_patterns: HashSet<String>,
        active_identity_source: Option<&str>,
    ) -> Result<Self> {
        Self::new_with_rules(
            text,
            known_patterns,
            HashSet::new(),
            HashSet::new(),
            active_identity_source,
        )
    }

    /// Builds a parser over one tokenized condition, including pattern and rule
    /// metadata used for selector expansion and validation.
    fn new_with_rules(
        text: &str,
        known_patterns: HashSet<String>,
        verifier_only_pattern_ids: HashSet<String>,
        known_rule_names: HashSet<String>,
        active_identity_source: Option<&str>,
    ) -> Result<Self> {
        let mut known_pattern_names = known_patterns.iter().cloned().collect::<Vec<_>>();
        known_pattern_names.sort();
        Ok(Self {
            tokens: tokenize_condition(text)?,
            index: 0,
            known_patterns,
            known_pattern_names,
            verifier_only_pattern_ids,
            known_rule_names,
            active_identity_source: active_identity_source.map(str::to_ascii_lowercase),
        })
    }

    /// Returns the next token without consuming it.
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    /// Consumes one token and optionally validates that it matches the expected
    /// token kind.
    fn consume(&mut self, expected: Option<&Token>) -> Result<Token> {
        let Some(token) = self.tokens.get(self.index).cloned() else {
            return Err(SspryError::from("Unexpected end of condition."));
        };
        if let Some(expected_token) = expected {
            if &token != expected_token {
                return Err(SspryError::from(format!(
                    "Expected token {:?}, got {:?}.",
                    expected_token, token
                )));
            }
        }
        self.index += 1;
        Ok(token)
    }

    /// Parses the full condition expression and rejects any trailing tokens.
    fn parse(&mut self) -> Result<QueryNode> {
        if self.tokens.is_empty() {
            return Err(SspryError::from("Condition section is empty."));
        }
        let node = self.parse_or()?;
        if let Some(token) = self.peek() {
            return Err(SspryError::from(format!(
                "Unexpected trailing token in condition: {token:?}"
            )));
        }
        Ok(node)
    }

    /// Parses a left-associative OR chain into one query tree node.
    fn parse_or(&mut self) -> Result<QueryNode> {
        let mut nodes = vec![self.parse_and()?];
        while matches!(self.peek(), Some(Token::Or)) {
            self.consume(Some(&Token::Or))?;
            nodes.push(self.parse_and()?);
        }
        if nodes.len() == 1 {
            Ok(nodes.remove(0))
        } else {
            Ok(QueryNode {
                kind: "or".to_owned(),
                pattern_id: None,
                threshold: None,
                children: nodes,
            })
        }
    }

    /// Parses a left-associative AND chain into one query tree node.
    fn parse_and(&mut self) -> Result<QueryNode> {
        let mut nodes = vec![self.parse_factor()?];
        while matches!(self.peek(), Some(Token::And)) {
            self.consume(Some(&Token::And))?;
            nodes.push(self.parse_factor()?);
        }
        if nodes.len() == 1 {
            Ok(nodes.remove(0))
        } else {
            Ok(QueryNode {
                kind: "and".to_owned(),
                pattern_id: None,
                threshold: None,
                children: nodes,
            })
        }
    }

    /// Parses one atomic condition term, including grouped expressions,
    /// pattern references, metadata predicates, and verifier-only constructs.
    fn parse_factor(&mut self) -> Result<QueryNode> {
        match self.peek() {
            Some(Token::LParen) => {
                self.consume(Some(&Token::LParen))?;
                let node = self.parse_or()?;
                self.consume(Some(&Token::RParen))?;
                Ok(node)
            }
            Some(Token::Not) => {
                self.consume(Some(&Token::Not))?;
                Ok(QueryNode {
                    kind: "not".to_owned(),
                    pattern_id: None,
                    threshold: None,
                    children: vec![self.parse_factor()?],
                })
            }
            Some(Token::Id(_)) => {
                let Token::Id(raw_id) = self.consume(None)? else {
                    unreachable!();
                };
                if !self.known_patterns.contains(&raw_id) {
                    return Err(SspryError::from(format!(
                        "Condition references unknown string id: {raw_id}"
                    )));
                }
                if self.verifier_only_pattern_ids.contains(&raw_id)
                    && matches!(self.peek(), Some(Token::At | Token::In))
                {
                    return Err(SspryError::from(format!(
                        "Pattern {raw_id} requires an anchorable literal for at/in search use."
                    )));
                }
                if self.verifier_only_pattern_ids.contains(&raw_id)
                    && !matches!(self.peek(), Some(Token::At | Token::In))
                {
                    return Err(SspryError::from(format!(
                        "Pattern {raw_id} requires an anchorable literal for direct search use."
                    )));
                }
                if matches!(self.peek(), Some(Token::At)) {
                    self.consume(Some(&Token::At))?;
                    let offset = self.parse_at_offset_expr(&raw_id)?;
                    return Ok(QueryNode {
                        kind: "and".to_owned(),
                        pattern_id: None,
                        threshold: None,
                        children: vec![
                            QueryNode {
                                kind: "pattern".to_owned(),
                                pattern_id: Some(raw_id.clone()),
                                threshold: None,
                                children: Vec::new(),
                            },
                            QueryNode {
                                kind: "verifier_only_at".to_owned(),
                                pattern_id: Some(format!(
                                    "{raw_id}@{}",
                                    encode_at_offset_expr(&offset)
                                )),
                                threshold: None,
                                children: Vec::new(),
                            },
                        ],
                    });
                }
                if matches!(self.peek(), Some(Token::In)) {
                    self.consume(Some(&Token::In))?;
                    self.consume(Some(&Token::LParen))?;
                    let start = self.parse_range_bound_expr()?;
                    self.consume(Some(&Token::DotDot))?;
                    let end = self.parse_range_bound_expr()?;
                    self.consume(Some(&Token::RParen))?;
                    return Ok(QueryNode {
                        kind: "and".to_owned(),
                        pattern_id: None,
                        threshold: None,
                        children: vec![
                            QueryNode {
                                kind: "pattern".to_owned(),
                                pattern_id: Some(raw_id.clone()),
                                threshold: None,
                                children: Vec::new(),
                            },
                            QueryNode {
                                kind: "verifier_only_in_range".to_owned(),
                                pattern_id: Some(format!(
                                    "range:{raw_id}:{}:{}",
                                    encode_range_bound_expr(&start),
                                    encode_range_bound_expr(&end)
                                )),
                                threshold: None,
                                children: Vec::new(),
                            },
                        ],
                    });
                }
                Ok(QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some(raw_id),
                    threshold: None,
                    children: Vec::new(),
                })
            }
            Some(Token::Any) => {
                self.consume(Some(&Token::Any))?;
                self.consume(Some(&Token::Of))?;
                self.parse_n_of_expression(1)
            }
            Some(Token::All) => {
                self.consume(Some(&Token::All))?;
                self.consume(Some(&Token::Of))?;
                self.parse_n_of_expression(usize::MAX)
            }
            Some(Token::Name(_)) => {
                let Token::Name(field_name) = self.consume(None)? else {
                    unreachable!();
                };
                if field_name.starts_with(IGNORED_MODULE_PLACEHOLDER_PREFIX) {
                    return Ok(QueryNode {
                        kind: "ignored_module_predicate".to_owned(),
                        pattern_id: Some(field_name),
                        threshold: None,
                        children: Vec::new(),
                    });
                }
                if matches!(self.peek(), Some(Token::LParen)) {
                    self.consume(Some(&Token::LParen))?;
                    if field_name == "verifierloop" {
                        return self.parse_verifier_only_loop();
                    }
                    if field_name.starts_with("hash.") {
                        return self.parse_hash_identity_equality(&field_name);
                    }
                    if field_name == "math.entropy" {
                        return self.parse_math_entropy_comparison(&field_name);
                    }
                    let Token::Int(offset) = self.consume(None)? else {
                        return Err(SspryError::from(format!(
                            "{field_name} requires an integer byte offset."
                        )));
                    };
                    self.consume(Some(&Token::RParen))?;
                    self.consume(Some(&Token::EqEq))?;
                    let literal_token = self.consume(None)?;
                    if let Some(read_kind) = numeric_read_kind(&field_name) {
                        let literal_text = parse_numeric_read_literal(
                            self,
                            &field_name,
                            read_kind,
                            literal_token,
                        )?;
                        return Ok(QueryNode {
                            kind: "verifier_only_eq".to_owned(),
                            pattern_id: Some(format!("{field_name}({offset})=={literal_text}")),
                            threshold: None,
                            children: Vec::new(),
                        });
                    }
                    return Err(SspryError::from(format!(
                        "Unsupported condition field: {field_name}"
                    )));
                }
                if self.known_rule_names.contains(&field_name) {
                    return Ok(QueryNode {
                        kind: "rule_ref".to_owned(),
                        pattern_id: Some(field_name),
                        threshold: None,
                        children: Vec::new(),
                    });
                }
                let normalized = normalize_query_metadata_field(&field_name)
                    .or_else(|| {
                        if field_name == "filesize" {
                            Some("filesize")
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        if !field_name.contains('.') {
                            SspryError::from(format!(
                                "Condition references unknown rule: {field_name}"
                            ))
                        } else {
                            SspryError::from(format!("Unsupported condition field: {field_name}"))
                        }
                    })?;
                if let Some(op) = self.peek().and_then(comparison_op_from_token) {
                    self.consume(None)?;
                    let rhs = self.consume(None)?;
                    match rhs {
                        Token::Int(value) => {
                            let kind = if normalized == "filesize" {
                                comparison_kind("filesize", op)
                            } else if normalized == "time.now" {
                                comparison_kind("time_now", op)
                            } else if metadata_field_is_float(normalized) {
                                comparison_kind("metadata_float", op)
                            } else if metadata_field_is_boolean(normalized) {
                                if !matches!(op, ComparisonOp::Eq | ComparisonOp::Ne) {
                                    return Err(SspryError::from(format!(
                                        "Boolean metadata field {field_name} only supports == and !=."
                                    )));
                                }
                                comparison_kind("metadata", op)
                            } else if metadata_field_is_integer(normalized) {
                                comparison_kind("metadata", op)
                            } else {
                                return Err(SspryError::from(format!(
                                    "Condition field {field_name} requires == <literal>."
                                )));
                            };
                            Ok(QueryNode {
                                kind,
                                pattern_id: Some(normalized.to_owned()),
                                threshold: Some(value),
                                children: Vec::new(),
                            })
                        }
                        Token::Float(value) => {
                            if !metadata_field_is_float(normalized) {
                                return Err(SspryError::from(format!(
                                    "Expected integer literal after {field_name} comparison."
                                )));
                            }
                            Ok(QueryNode {
                                kind: comparison_kind("metadata_float", op),
                                pattern_id: Some(normalized.to_owned()),
                                threshold: Some((value as f32).to_bits() as usize),
                                children: Vec::new(),
                            })
                        }
                        Token::Bool(value) => {
                            if !metadata_field_is_boolean(normalized) {
                                return Err(SspryError::from(format!(
                                    "Expected integer literal after {field_name} comparison."
                                )));
                            }
                            if !matches!(op, ComparisonOp::Eq | ComparisonOp::Ne) {
                                return Err(SspryError::from(format!(
                                    "Boolean metadata field {field_name} only supports == and !=."
                                )));
                            }
                            Ok(QueryNode {
                                kind: comparison_kind("metadata", op),
                                pattern_id: Some(normalized.to_owned()),
                                threshold: Some(usize::from(value)),
                                children: Vec::new(),
                            })
                        }
                        Token::Name(rhs_name) => {
                            let rhs_normalized = normalize_query_metadata_field(&rhs_name)
                                .ok_or_else(|| {
                                    SspryError::from(format!(
                                        "Unsupported comparison target: {rhs_name}"
                                    ))
                                })?;
                            if normalized == "time.now" && rhs_normalized == "time.now" {
                                return Err(SspryError::from(
                                    "time.now comparisons against time.now are redundant.",
                                ));
                            }
                            if normalized == "time.now" && metadata_field_is_integer(rhs_normalized)
                            {
                                return Ok(QueryNode {
                                    kind: comparison_kind("metadata_time", op.reverse()),
                                    pattern_id: Some(rhs_normalized.to_owned()),
                                    threshold: None,
                                    children: Vec::new(),
                                });
                            }
                            if metadata_field_is_integer(normalized) && rhs_normalized == "time.now"
                            {
                                return Ok(QueryNode {
                                    kind: comparison_kind("metadata_time", op),
                                    pattern_id: Some(normalized.to_owned()),
                                    threshold: None,
                                    children: Vec::new(),
                                });
                            }
                            if metadata_field_is_integer(normalized)
                                && metadata_field_is_integer(rhs_normalized)
                            {
                                return Ok(QueryNode {
                                    kind: comparison_kind("metadata_field", op),
                                    pattern_id: Some(format!("{normalized}|{rhs_normalized}")),
                                    threshold: None,
                                    children: Vec::new(),
                                });
                            }
                            Err(SspryError::from(format!(
                                "Unsupported comparison target: {rhs_name}"
                            )))
                        }
                        _ => Err(SspryError::from(format!(
                            "Expected literal or comparable field after {field_name} comparison."
                        ))),
                    }
                } else if metadata_field_is_boolean(normalized) {
                    Ok(QueryNode {
                        kind: "metadata_eq".to_owned(),
                        pattern_id: Some(normalized.to_owned()),
                        threshold: Some(1),
                        children: Vec::new(),
                    })
                } else {
                    Err(SspryError::from(format!(
                        "Condition field {field_name} requires == <literal>."
                    )))
                }
            }
            Some(Token::Int(_)) => {
                let Token::Int(threshold) = self.consume(None)? else {
                    unreachable!();
                };
                if threshold == 0 {
                    return Err(SspryError::from("N-of threshold must be > 0."));
                }
                self.consume(Some(&Token::Of))?;
                self.parse_n_of_expression(threshold)
            }
            Some(Token::Hash) => {
                self.consume(Some(&Token::Hash))?;
                let Token::Id(raw_id) = self.consume(None)? else {
                    return Err(SspryError::from(
                        "Count conditions require a string id after '#'.",
                    ));
                };
                if !self.known_patterns.contains(&raw_id) {
                    return Err(SspryError::from(format!(
                        "Condition references unknown string id: {raw_id}"
                    )));
                }
                let (op, value) = match self.consume(None)? {
                    Token::EqEq => (
                        "eq",
                        match self.consume(None)? {
                            Token::Int(value) => value,
                            _ => {
                                return Err(SspryError::from(
                                    "Count conditions require an integer literal.",
                                ));
                            }
                        },
                    ),
                    Token::Gt => (
                        "gt",
                        match self.consume(None)? {
                            Token::Int(value) => value,
                            _ => {
                                return Err(SspryError::from(
                                    "Count conditions require an integer literal.",
                                ));
                            }
                        },
                    ),
                    Token::Ge => (
                        "ge",
                        match self.consume(None)? {
                            Token::Int(value) => value,
                            _ => {
                                return Err(SspryError::from(
                                    "Count conditions require an integer literal.",
                                ));
                            }
                        },
                    ),
                    Token::Lt => (
                        "lt",
                        match self.consume(None)? {
                            Token::Int(value) => value,
                            _ => {
                                return Err(SspryError::from(
                                    "Count conditions require an integer literal.",
                                ));
                            }
                        },
                    ),
                    Token::Le => (
                        "le",
                        match self.consume(None)? {
                            Token::Int(value) => value,
                            _ => {
                                return Err(SspryError::from(
                                    "Count conditions require an integer literal.",
                                ));
                            }
                        },
                    ),
                    token => {
                        return Err(SspryError::from(format!(
                            "Unsupported count comparison token: {token:?}"
                        )));
                    }
                };
                if let Some(simplified) = self.simplify_trivial_count_constraint(&raw_id, op, value)
                {
                    return Ok(simplified);
                }
                let mut children = Vec::new();
                if !self.verifier_only_pattern_ids.contains(&raw_id) {
                    children.push(QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some(raw_id.clone()),
                        threshold: None,
                        children: Vec::new(),
                    });
                }
                children.push(QueryNode {
                    kind: "verifier_only_count".to_owned(),
                    pattern_id: Some(format!("count:{raw_id}:{op}:{value}")),
                    threshold: None,
                    children: Vec::new(),
                });
                Ok(QueryNode {
                    kind: "and".to_owned(),
                    pattern_id: None,
                    threshold: None,
                    children,
                })
            }
            Some(token) => Err(SspryError::from(format!(
                "Unsupported condition token: {token:?}"
            ))),
            None => Err(SspryError::from("Unexpected end of condition.")),
        }
    }

    /// Parses the synthetic `verifierloop($id)` helper used to represent
    /// rewritten verifier-only iterator constructs.
    fn parse_verifier_only_loop(&mut self) -> Result<QueryNode> {
        let Token::Id(raw_id) = self.consume(None)? else {
            return Err(SspryError::from(
                "verifierloop requires a string id anchor argument.",
            ));
        };
        if !self.known_patterns.contains(&raw_id) {
            return Err(SspryError::from(format!(
                "Condition references unknown string id: {raw_id}"
            )));
        }
        if self.verifier_only_pattern_ids.contains(&raw_id) {
            return Err(SspryError::from(format!(
                "Pattern {raw_id} requires an anchorable literal for verifier-loop search use."
            )));
        }
        self.consume(Some(&Token::RParen))?;
        Ok(QueryNode {
            kind: "and".to_owned(),
            pattern_id: None,
            threshold: None,
            children: vec![
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some(raw_id.clone()),
                    threshold: None,
                    children: Vec::new(),
                },
                QueryNode {
                    kind: "verifier_only_loop".to_owned(),
                    pattern_id: Some(raw_id),
                    threshold: None,
                    children: Vec::new(),
                },
            ],
        })
    }

    /// Parses an `any/all of ...` expression into an `n_of` query node with a
    /// resolved threshold.
    fn parse_n_of_expression(&mut self, threshold: usize) -> Result<QueryNode> {
        let children = self.parse_n_of_targets()?;
        let resolved_threshold = if threshold == usize::MAX {
            children.len()
        } else {
            threshold
        };
        if resolved_threshold == 0 {
            return Err(SspryError::from(
                "N-of expression matched zero candidate patterns.",
            ));
        }
        Ok(QueryNode {
            kind: "n_of".to_owned(),
            pattern_id: None,
            threshold: Some(resolved_threshold),
            children,
        })
    }

    /// Parses one range-bound expression used by `in (start..end)` match
    /// constraints.
    fn parse_range_bound_expr(&mut self) -> Result<RangeBoundExpr> {
        match self.consume(None)? {
            Token::Int(value) => Ok(RangeBoundExpr::Literal(value)),
            Token::Name(name) if name == "filesize" => match self.peek() {
                Some(Token::Plus) => {
                    self.consume(Some(&Token::Plus))?;
                    let Token::Int(value) = self.consume(None)? else {
                        return Err(SspryError::from(
                            "filesize range arithmetic requires an integer literal.",
                        ));
                    };
                    Ok(RangeBoundExpr::FilesizePlus(value))
                }
                Some(Token::Minus) => {
                    self.consume(Some(&Token::Minus))?;
                    let Token::Int(value) = self.consume(None)? else {
                        return Err(SspryError::from(
                            "filesize range arithmetic requires an integer literal.",
                        ));
                    };
                    Ok(RangeBoundExpr::FilesizeMinus(value))
                }
                _ => Ok(RangeBoundExpr::Filesize),
            },
            Token::LParen => {
                let expr = self.parse_range_bound_expr()?;
                self.consume(Some(&Token::RParen))?;
                Ok(expr)
            }
            token => Err(SspryError::from(format!(
                "Expected range bound expression, got {token:?}"
            ))),
        }
    }

    /// Parses one byte-offset expression used by `$id at ...` constraints.
    fn parse_at_offset_expr(&mut self, raw_id: &str) -> Result<AtOffsetExpr> {
        match self.consume(None)? {
            Token::Int(value) => Ok(AtOffsetExpr::Literal(value)),
            Token::Name(name) => match self.peek() {
                Some(Token::Plus) => {
                    self.consume(Some(&Token::Plus))?;
                    let Token::Int(value) = self.consume(None)? else {
                        return Err(SspryError::from(format!(
                            "{raw_id} at requires integer arithmetic after {name}."
                        )));
                    };
                    Ok(AtOffsetExpr::FieldPlus(name, value))
                }
                Some(Token::Minus) => {
                    self.consume(Some(&Token::Minus))?;
                    let Token::Int(value) = self.consume(None)? else {
                        return Err(SspryError::from(format!(
                            "{raw_id} at requires integer arithmetic after {name}."
                        )));
                    };
                    Ok(AtOffsetExpr::FieldMinus(name, value))
                }
                _ => Ok(AtOffsetExpr::Field(name)),
            },
            Token::LParen => {
                let expr = self.parse_at_offset_expr(raw_id)?;
                self.consume(Some(&Token::RParen))?;
                Ok(expr)
            }
            _ => Err(SspryError::from(format!(
                "{raw_id} at requires an integer or field byte offset."
            ))),
        }
    }

    /// Parses searchable whole-file hash equality constraints such as
    /// `hash.sha256(0, filesize) == "..."`.
    fn parse_hash_identity_equality(&mut self, field_name: &str) -> Result<QueryNode> {
        let Some(hash_kind) = field_name.strip_prefix("hash.") else {
            return Err(SspryError::from(format!(
                "Unsupported condition field: {field_name}"
            )));
        };
        match hash_kind {
            "md5" | "sha1" | "sha256" => {}
            other => {
                return Err(SspryError::from(format!(
                    "Unsupported searchable hash function: {other}"
                )));
            }
        }
        let active_identity_source = self.active_identity_source.as_deref().ok_or_else(|| {
            SspryError::from("Whole-file hash equality search requires a known DB identity source.")
        })?;
        if active_identity_source != hash_kind {
            return Err(SspryError::from(format!(
                "hash.{hash_kind}(0, filesize) is only searchable when the DB identity source is {hash_kind}; current source is {active_identity_source}.",
            )));
        }

        let Token::Int(offset) = self.consume(None)? else {
            return Err(SspryError::from(format!(
                "{field_name} requires a literal start offset."
            )));
        };
        self.consume(Some(&Token::Comma))?;
        match self.consume(None)? {
            Token::Name(name) if name == "filesize" => {}
            _ => {
                return Err(SspryError::from(format!(
                    "Only whole-file {field_name}(0, filesize) equality is searchable.",
                )));
            }
        }
        self.consume(Some(&Token::RParen))?;
        if offset != 0 {
            return Err(SspryError::from(format!(
                "Only whole-file {field_name}(0, filesize) equality is searchable.",
            )));
        }
        self.consume(Some(&Token::EqEq))?;
        let Token::Quoted(literal) = self.consume(None)? else {
            return Err(SspryError::from(format!(
                "{field_name} equality requires a quoted hexadecimal digest.",
            )));
        };
        Ok(QueryNode {
            kind: "identity_eq".to_owned(),
            pattern_id: Some(normalize_identity_literal(hash_kind, &literal)?),
            threshold: None,
            children: Vec::new(),
        })
    }

    /// Parses searchable whole-file entropy comparisons.
    fn parse_math_entropy_comparison(&mut self, field_name: &str) -> Result<QueryNode> {
        let Token::Int(offset) = self.consume(None)? else {
            return Err(SspryError::from(format!(
                "{field_name} requires a literal start offset."
            )));
        };
        self.consume(Some(&Token::Comma))?;
        match self.consume(None)? {
            Token::Name(name) if name == "filesize" => {}
            _ => {
                return Err(SspryError::from(format!(
                    "Only whole-file {field_name}(0, filesize) comparisons are searchable.",
                )));
            }
        }
        self.consume(Some(&Token::RParen))?;
        if offset != 0 {
            return Err(SspryError::from(format!(
                "Only whole-file {field_name}(0, filesize) comparisons are searchable.",
            )));
        }
        let Some(op) = self.peek().and_then(comparison_op_from_token) else {
            return Err(SspryError::from(format!(
                "{field_name}(0, filesize) requires a comparison operator.",
            )));
        };
        self.consume(None)?;
        let rhs = self.consume(None)?;
        let value = match rhs {
            Token::Int(value) => value as f32,
            Token::Float(value) => value as f32,
            _ => {
                return Err(SspryError::from(format!(
                    "{field_name}(0, filesize) requires an integer or float literal.",
                )));
            }
        };
        if !value.is_finite() {
            return Err(SspryError::from(format!(
                "{field_name}(0, filesize) requires a finite numeric literal.",
            )));
        }
        Ok(QueryNode {
            kind: comparison_kind("metadata_float", op),
            pattern_id: Some("math.entropy".to_owned()),
            threshold: Some(value.to_bits() as usize),
            children: Vec::new(),
        })
    }

    /// Parses the selector portion of an `any/all of ...` expression and
    /// expands it into concrete pattern nodes.
    fn parse_n_of_targets(&mut self) -> Result<Vec<QueryNode>> {
        let pattern_ids = match self.peek() {
            Some(Token::LParen) => self.parse_n_of_target_list()?,
            Some(Token::Them) => {
                self.consume(Some(&Token::Them))?;
                self.known_pattern_names.clone()
            }
            Some(Token::Id(_)) => {
                let Token::Id(raw_id) = self.consume(None)? else {
                    unreachable!();
                };
                self.expand_pattern_selector(&raw_id)?
            }
            Some(token) => {
                return Err(SspryError::from(format!(
                    "Expected pattern selector after 'of', got {token:?}."
                )));
            }
            None => return Err(SspryError::from("Unexpected end of N-of expression.")),
        };
        if pattern_ids.is_empty() {
            return Err(SspryError::from(
                "N-of expression matched zero candidate patterns.",
            ));
        }
        Ok(pattern_ids
            .into_iter()
            .map(|pattern_id| {
                if self.verifier_only_pattern_ids.contains(&pattern_id) {
                    Err(SspryError::from(format!(
                        "Pattern {pattern_id} requires an anchorable literal for N-of search use."
                    )))
                } else {
                    Ok(QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some(pattern_id),
                        threshold: None,
                        children: Vec::new(),
                    })
                }
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .collect())
    }

    /// Parses a parenthesized selector list used by `any/all of (...)`.
    fn parse_n_of_target_list(&mut self) -> Result<Vec<String>> {
        self.consume(Some(&Token::LParen))?;
        let mut pattern_ids = Vec::<String>::new();
        let mut seen = HashSet::<String>::new();
        loop {
            let selector_matches = match self.consume(None)? {
                Token::Id(raw_id) => self.expand_pattern_selector(&raw_id)?,
                Token::Them => self.known_pattern_names.clone(),
                _ => return Err(SspryError::from("Expected pattern id in N-of expression.")),
            };
            for pattern_id in selector_matches {
                if seen.insert(pattern_id.clone()) {
                    pattern_ids.push(pattern_id);
                }
            }
            match self.peek() {
                Some(Token::Comma) => {
                    self.consume(Some(&Token::Comma))?;
                }
                Some(Token::RParen) => {
                    self.consume(Some(&Token::RParen))?;
                    break;
                }
                Some(token) => {
                    return Err(SspryError::from(format!(
                        "Expected ',' or ')' in N-of list, got {token:?}"
                    )));
                }
                None => return Err(SspryError::from("Unterminated N-of expression.")),
            }
        }
        Ok(pattern_ids)
    }

    /// Expands one exact or wildcard string selector into concrete pattern ids.
    fn expand_pattern_selector(&self, raw_id: &str) -> Result<Vec<String>> {
        if let Some(prefix) = raw_id.strip_suffix('*') {
            let matches = self
                .known_pattern_names
                .iter()
                .filter(|pattern_id| pattern_id.starts_with(prefix))
                .cloned()
                .collect::<Vec<_>>();
            if matches.is_empty() {
                return Err(SspryError::from(format!(
                    "Condition wildcard selector matched no string ids: {raw_id}"
                )));
            }
            return Ok(matches);
        }
        if !self.known_patterns.contains(raw_id) {
            return Err(SspryError::from(format!(
                "Condition references unknown string id: {raw_id}"
            )));
        }
        Ok(vec![raw_id.to_owned()])
    }

    /// Simplifies trivial `#id op value` count constraints into direct pattern
    /// or negated-pattern nodes when possible.
    fn simplify_trivial_count_constraint(
        &self,
        raw_id: &str,
        op: &str,
        value: usize,
    ) -> Option<QueryNode> {
        if self.verifier_only_pattern_ids.contains(raw_id) {
            return None;
        }
        let pattern_node = || QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some(raw_id.to_owned()),
            threshold: None,
            children: Vec::new(),
        };
        let not_pattern_node = || QueryNode {
            kind: "not".to_owned(),
            pattern_id: None,
            threshold: None,
            children: vec![pattern_node()],
        };
        match (op, value) {
            ("gt", 0) | ("ge", 1) => Some(pattern_node()),
            ("eq", 0) | ("le", 0) | ("lt", 1) => Some(not_pattern_node()),
            _ => None,
        }
    }
}

/// Tokenizes the normalized YARA condition text into the parser token stream.
fn tokenize_condition(text: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        if ch.is_whitespace() {
            index += 1;
            continue;
        }
        match ch {
            '(' => {
                tokens.push(Token::LParen);
                index += 1;
                continue;
            }
            ')' => {
                tokens.push(Token::RParen);
                index += 1;
                continue;
            }
            ',' => {
                tokens.push(Token::Comma);
                index += 1;
                continue;
            }
            '+' => {
                tokens.push(Token::Plus);
                index += 1;
                continue;
            }
            '-' => {
                tokens.push(Token::Minus);
                index += 1;
                continue;
            }
            '.' => {
                if chars.get(index + 1) == Some(&'.') {
                    tokens.push(Token::DotDot);
                    index += 2;
                    continue;
                }
            }
            '=' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::EqEq);
                    index += 2;
                    continue;
                }
                return Err(SspryError::from("Unsupported token in condition near: '='"));
            }
            '!' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::Ne);
                    index += 2;
                    continue;
                }
                return Err(SspryError::from("Unsupported token in condition near: '!'"));
            }
            '>' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::Ge);
                    index += 2;
                } else {
                    tokens.push(Token::Gt);
                    index += 1;
                }
                continue;
            }
            '<' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::Le);
                    index += 2;
                } else {
                    tokens.push(Token::Lt);
                    index += 1;
                }
                continue;
            }
            '#' => {
                tokens.push(Token::Hash);
                index += 1;
                let ident_start = index;
                while index < chars.len()
                    && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
                {
                    index += 1;
                }
                if index > ident_start {
                    let raw: String = chars[ident_start..index].iter().collect();
                    tokens.push(Token::Id(format!("${raw}")));
                }
                continue;
            }
            '$' => {
                let start = index;
                index += 1;
                while index < chars.len()
                    && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
                {
                    index += 1;
                }
                if index < chars.len() && chars[index] == '*' {
                    index += 1;
                }
                tokens.push(Token::Id(chars[start..index].iter().collect()));
                continue;
            }
            _ => {}
        }
        if ch == '"' {
            index += 1;
            let mut value = String::new();
            let mut escaped = false;
            while index < chars.len() {
                let current = chars[index];
                if escaped {
                    value.push(current);
                    escaped = false;
                    index += 1;
                    continue;
                }
                if current == '\\' {
                    escaped = true;
                    index += 1;
                    continue;
                }
                if current == '"' {
                    index += 1;
                    break;
                }
                value.push(current);
                index += 1;
            }
            if escaped || index > chars.len() || chars.get(index.saturating_sub(1)) != Some(&'"') {
                return Err(SspryError::from("Unterminated quoted string in condition."));
            }
            tokens.push(Token::Quoted(value));
            continue;
        }
        if ch.is_ascii_digit() {
            let start = index;
            index += 1;
            if ch == '0' && matches!(chars.get(index), Some('x' | 'X')) {
                index += 1;
                while index < chars.len() && chars[index].is_ascii_hexdigit() {
                    index += 1;
                }
                let raw: String = chars[start + 2..index].iter().collect();
                if raw.is_empty() {
                    return Err(SspryError::from("Invalid hexadecimal integer token: 0x"));
                }
                let value = usize::from_str_radix(&raw, 16).map_err(|_| {
                    SspryError::from(format!("Invalid hexadecimal integer token: 0x{raw}"))
                })?;
                tokens.push(Token::Int(value));
                continue;
            }
            while index < chars.len() && chars[index].is_ascii_digit() {
                index += 1;
            }
            if matches!(chars.get(index), Some('.')) && !matches!(chars.get(index + 1), Some('.')) {
                let dot = index;
                index += 1;
                let frac_start = index;
                while index < chars.len() && chars[index].is_ascii_digit() {
                    index += 1;
                }
                if frac_start == index {
                    let raw: String = chars[start..=dot].iter().collect();
                    return Err(SspryError::from(format!("Invalid float token: {raw}")));
                }
                let raw: String = chars[start..index].iter().collect();
                let value = raw
                    .parse::<f64>()
                    .map_err(|_| SspryError::from(format!("Invalid float token: {raw}")))?;
                tokens.push(Token::Float(value));
                continue;
            }
            let number_end = index;
            while index < chars.len() && chars[index].is_ascii_alphabetic() {
                index += 1;
            }
            let raw: String = chars[start..number_end].iter().collect();
            let mut value = raw
                .parse::<usize>()
                .map_err(|_| SspryError::from(format!("Invalid integer token: {raw}")))?;
            if number_end < index {
                let suffix: String = chars[number_end..index].iter().collect();
                let multiplier = match suffix.to_ascii_lowercase().as_str() {
                    "kb" => 1024usize,
                    "mb" => 1024usize * 1024usize,
                    "gb" => 1024usize * 1024usize * 1024usize,
                    _ => {
                        return Err(SspryError::from(format!(
                            "Unsupported numeric suffix in condition: {suffix}"
                        )));
                    }
                };
                value = value.saturating_mul(multiplier);
            }
            tokens.push(Token::Int(value));
            continue;
        }
        if ch.is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric()
                    || chars[index] == '_'
                    || chars[index] == '.')
            {
                index += 1;
            }
            let raw: String = chars[start..index].iter().collect();
            match raw.to_ascii_lowercase().as_str() {
                "and" => tokens.push(Token::And),
                "any" => tokens.push(Token::Any),
                "all" => tokens.push(Token::All),
                "at" => tokens.push(Token::At),
                "in" => tokens.push(Token::In),
                "not" => tokens.push(Token::Not),
                "or" => tokens.push(Token::Or),
                "of" => tokens.push(Token::Of),
                "them" => tokens.push(Token::Them),
                "true" => tokens.push(Token::Bool(true)),
                "false" => tokens.push(Token::Bool(false)),
                _ => tokens.push(Token::Name(raw.to_ascii_lowercase())),
            }
            continue;
        }
        return Err(SspryError::from(format!(
            "Unsupported token in condition near: {:?}",
            chars[index..chars.len().min(index + 24)]
                .iter()
                .collect::<String>()
        )));
    }
    Ok(tokens)
}

/// Encodes a parsed range-bound expression back into the compact string format
/// stored in verifier-only node payloads.
fn encode_range_bound_expr(expr: &RangeBoundExpr) -> String {
    match expr {
        RangeBoundExpr::Literal(value) => value.to_string(),
        RangeBoundExpr::Filesize => "filesize".to_owned(),
        RangeBoundExpr::FilesizePlus(value) => format!("filesize+{value}"),
        RangeBoundExpr::FilesizeMinus(value) => format!("filesize-{value}"),
    }
}

/// Encodes a parsed offset expression back into the compact string format
/// stored in verifier-only node payloads.
fn encode_at_offset_expr(expr: &AtOffsetExpr) -> String {
    match expr {
        AtOffsetExpr::Literal(value) => value.to_string(),
        AtOffsetExpr::Field(name) => name.clone(),
        AtOffsetExpr::FieldPlus(name, value) => format!("{name}+{value}"),
        AtOffsetExpr::FieldMinus(name, value) => format!("{name}-{value}"),
    }
}

/// Extracts distinct fixed-width grams from a byte slice.
fn grams_from_bytes(blob: &[u8], gram_size: usize) -> Vec<u64> {
    if blob.len() < gram_size {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for idx in 0..=(blob.len() - gram_size) {
        let gram = pack_exact_gram(&blob[idx..idx + gram_size]);
        if seen.insert(gram) {
            out.push(gram);
        }
    }
    out
}

/// Extracts distinct tier-1 grams from a byte slice.
fn grams_tier1_from_bytes(blob: &[u8], tier1_gram_size: usize) -> Vec<u64> {
    grams_from_bytes(blob, tier1_gram_size)
}

/// Extracts distinct tier-2 grams from a byte slice.
fn grams_tier2_from_bytes(blob: &[u8], tier2_gram_size: usize) -> Vec<u64> {
    grams_from_bytes(blob, tier2_gram_size)
}

/// Removes line and block comments from rule text while preserving offsets well
/// enough for subsequent structural parsing.
fn strip_rule_comments(rule_text: &str) -> String {
    let chars = rule_text.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(rule_text.len());
    let mut index = 0usize;
    let mut in_block_comment = false;
    let mut in_line_comment = false;
    let mut in_string = false;
    let mut in_regex = false;
    let mut regex_in_class = false;
    let mut escaped = false;
    let mut after_assignment = false;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();

        if in_block_comment {
            if ch == '\n' {
                out.push('\n');
            } else {
                out.push(' ');
                if ch == '*' && next == Some('/') {
                    in_block_comment = false;
                    out.push(' ');
                    index += 1;
                }
            }
            index += 1;
            continue;
        }
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                out.push('\n');
            } else {
                out.push(' ');
            }
            index += 1;
            continue;
        }
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if in_regex {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '[' {
                regex_in_class = true;
            } else if ch == ']' && regex_in_class {
                regex_in_class = false;
            } else if ch == '/' && !regex_in_class {
                in_regex = false;
            }
            index += 1;
            continue;
        }

        if ch == '/' && next == Some('*') {
            out.push(' ');
            out.push(' ');
            in_block_comment = true;
            index += 2;
            continue;
        }
        if ch == '/' && next == Some('/') {
            out.push(' ');
            out.push(' ');
            in_line_comment = true;
            index += 2;
            continue;
        }

        out.push(ch);
        if ch == '"' {
            in_string = true;
        } else if ch == '=' && next != Some('=') {
            after_assignment = true;
        } else if after_assignment {
            if ch.is_whitespace() {
                // Keep waiting for the first value token after assignment.
            } else {
                if ch == '/' {
                    in_regex = true;
                }
                after_assignment = false;
            }
        }
        if ch == '\n' {
            after_assignment = false;
        }
        index += 1;
    }

    out
}

/// Splits one rule block into its strings section, raw condition text, and the
/// rewritten searchable condition text.
fn parse_rule_sections(rule_text: &str) -> Result<(Vec<String>, String, String)> {
    let sanitized = strip_rule_comments(rule_text);
    let mut strings_lines = Vec::new();
    let mut condition_lines = Vec::new();
    let mut state = "none";
    for raw_line in sanitized.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if line.eq_ignore_ascii_case("strings:") {
            state = "strings";
            continue;
        }
        if line.eq_ignore_ascii_case("condition:") {
            state = "condition";
            continue;
        }
        if line == "}" {
            if state == "condition" {
                break;
            }
            continue;
        }
        match state {
            "strings" => strings_lines.push(raw_line.to_owned()),
            "condition" => condition_lines.push(raw_line.to_owned()),
            _ => {}
        }
    }
    if condition_lines.is_empty() {
        return Err(SspryError::from(
            "Rule does not contain a condition section.",
        ));
    }
    let raw_condition_text = condition_lines.join(" ");
    Ok((
        strings_lines,
        raw_condition_text.clone(),
        rewrite_verifier_only_for_any_loops(&rewrite_ignored_module_calls(&raw_condition_text)),
    ))
}

/// Finds the matching closing brace for a rule block while ignoring braces that
/// appear inside strings and regexes.
fn match_rule_brace_span(text: &str, open_idx: usize) -> Result<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut index = open_idx;
    let mut in_string = false;
    let mut in_regex = false;
    let mut regex_in_class = false;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        let next = bytes.get(index + 1).copied().map(char::from);
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if in_regex {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '[' {
                regex_in_class = true;
            } else if ch == ']' && regex_in_class {
                regex_in_class = false;
            } else if ch == '/' && !regex_in_class {
                in_regex = false;
            }
            index += 1;
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                index += 1;
            }
            '/' if next != Some('/') && next != Some('*') => {
                in_regex = true;
                regex_in_class = false;
                index += 1;
            }
            '{' => {
                depth += 1;
                index += 1;
            }
            '}' => {
                depth = depth.saturating_sub(1);
                index += 1;
                if depth == 0 {
                    return Ok(index);
                }
            }
            _ => {
                index += 1;
            }
        }
    }
    Err(SspryError::from("Unterminated rule block."))
}

/// Extracts every parseable rule block from a YARA source file.
fn parse_rule_blocks(rule_text: &str) -> Result<Vec<ParsedRuleBlock>> {
    let sanitized = strip_rule_comments(rule_text);
    let mut blocks = Vec::<ParsedRuleBlock>::new();
    let mut offset = 0usize;
    for line in sanitized.split_inclusive('\n') {
        let line_start = offset;
        offset += line.len();
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
        let Some(rule_idx) = tokens.iter().position(|token| *token == "rule") else {
            continue;
        };
        if rule_idx + 1 >= tokens.len() {
            continue;
        }
        if !tokens[..rule_idx]
            .iter()
            .all(|token| *token == "private" || *token == "global")
        {
            continue;
        }
        let name = tokens[rule_idx + 1].trim_end_matches('{').to_owned();
        if name.is_empty() {
            continue;
        }
        let open_idx = sanitized[line_start..]
            .find('{')
            .map(|value| line_start + value)
            .ok_or_else(|| SspryError::from(format!("Rule {name} is missing an opening brace.")))?;
        let end_idx = match_rule_brace_span(&sanitized, open_idx)?;
        let block_text = &sanitized[line_start..end_idx];
        let (strings_lines, raw_condition_text, condition_text) = parse_rule_sections(block_text)?;
        blocks.push(ParsedRuleBlock {
            name,
            is_private: tokens[..rule_idx].contains(&"private"),
            block_start_offset: line_start,
            block_text: block_text.to_owned(),
            strings_lines,
            raw_condition_text,
            condition_text,
        });
    }
    if blocks.is_empty() {
        return Err(SspryError::from(
            "Rule does not contain a parseable rule block.",
        ));
    }
    Ok(blocks)
}

/// Consumes a balanced parenthesized span from condition text, respecting
/// embedded strings and regexes.
fn consume_parenthesized_span(chars: &[char], open_idx: usize) -> Option<usize> {
    if chars.get(open_idx) != Some(&'(') {
        return None;
    }
    let mut index = open_idx;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut in_regex = false;
    let mut regex_in_class = false;
    let mut escaped = false;
    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if in_regex {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '[' {
                regex_in_class = true;
            } else if ch == ']' && regex_in_class {
                regex_in_class = false;
            } else if ch == '/' && !regex_in_class {
                in_regex = false;
            }
            index += 1;
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                index += 1;
            }
            '/' if next != Some('/') && next != Some('*') => {
                in_regex = true;
                regex_in_class = false;
                index += 1;
            }
            '(' => {
                depth += 1;
                index += 1;
            }
            ')' => {
                depth = depth.saturating_sub(1);
                index += 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {
                index += 1;
            }
        }
    }
    None
}

/// Rewrites ignored module calls into placeholder identifiers so the remaining
/// condition can still be parsed and analyzed.
fn rewrite_ignored_module_calls(condition_text: &str) -> String {
    let chars = condition_text.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(condition_text.len());
    let mut index = 0usize;
    let mut replacement_id = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        if ch.is_ascii_alphabetic() {
            let mut cursor = index + 1;
            while cursor < chars.len()
                && (chars[cursor].is_ascii_alphanumeric()
                    || chars[cursor] == '_'
                    || chars[cursor] == '.')
            {
                cursor += 1;
            }
            let name = chars[index..cursor].iter().collect::<String>();
            if ignored_search_module_name(&name) {
                let mut next = cursor;
                while next < chars.len() && chars[next].is_whitespace() {
                    next += 1;
                }
                if let Some(end) = consume_parenthesized_span(&chars, next) {
                    out.push_str(IGNORED_MODULE_PLACEHOLDER_PREFIX);
                    out.push_str(&replacement_id.to_string());
                    replacement_id += 1;
                    index = end;
                    continue;
                }
            }
        }
        out.push(ch);
        index += 1;
    }
    out
}

/// Rewrites certain verifier-only `for any` loops into synthetic parser forms
/// that preserve their searchable anchor.
fn rewrite_verifier_only_for_any_loops(condition_text: &str) -> String {
    let chars = condition_text.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(condition_text.len());
    let mut index = 0usize;
    while index < chars.len() {
        if let Some((end, pattern_id)) = consume_verifier_only_for_any_loop(&chars, index) {
            out.push_str("verifierloop(");
            out.push_str(&pattern_id);
            out.push(')');
            index = end;
            continue;
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// Recognizes verifier-only `for any/all of ... : ($ at pe.entry_point)` loops
/// so they can be expanded into explicit anchored pattern expressions.
fn consume_verifier_only_for_of_at_loop(
    chars: &[char],
    start: usize,
) -> Option<(usize, bool, String)> {
    let mut index = consume_condition_keyword(chars, start, "for")?;
    index = skip_condition_ws(chars, index);
    let any = if let Some(next) = consume_condition_keyword(chars, index, "any") {
        index = next;
        true
    } else if let Some(next) = consume_condition_keyword(chars, index, "all") {
        index = next;
        false
    } else {
        return None;
    };
    index = skip_condition_ws(chars, index);
    index = consume_condition_keyword(chars, index, "of")?;
    index = skip_condition_ws(chars, index);
    let selector_start = index;
    if chars.get(index) == Some(&'(') {
        index = consume_parenthesized_span(chars, index)?;
    } else {
        while index < chars.len() && !chars[index].is_whitespace() && chars[index] != ':' {
            index += 1;
        }
    }
    let selector = chars[selector_start..index].iter().collect::<String>();
    index = skip_condition_ws(chars, index);
    if chars.get(index) != Some(&':') {
        return None;
    }
    index += 1;
    index = skip_condition_ws(chars, index);
    let end = consume_parenthesized_span(chars, index)?;
    let body = chars[index..end].iter().collect::<String>();
    let normalized_body = body
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if normalized_body != "($atpe.entry_point)" {
        return None;
    }
    Some((end, any, selector))
}

/// Expands the selector inside a verifier-only `for ... of` loop into concrete
/// pattern ids.
fn expand_verifier_only_for_of_selector(
    selector: &str,
    known_pattern_names: &[String],
) -> Result<Vec<String>> {
    fn expand_item(item: &str, known_pattern_names: &[String]) -> Result<Vec<String>> {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        if trimmed.eq_ignore_ascii_case("them") {
            return Ok(known_pattern_names.to_vec());
        }
        if let Some(prefix) = trimmed.strip_suffix('*') {
            let matches = known_pattern_names
                .iter()
                .filter(|pattern_id| pattern_id.starts_with(prefix))
                .cloned()
                .collect::<Vec<_>>();
            if matches.is_empty() {
                return Err(SspryError::from(format!(
                    "Condition wildcard selector matched no string ids: {trimmed}"
                )));
            }
            return Ok(matches);
        }
        if known_pattern_names
            .iter()
            .any(|pattern_id| pattern_id == trimmed)
        {
            return Ok(vec![trimmed.to_owned()]);
        }
        Err(SspryError::from(format!(
            "Condition references unknown string id: {trimmed}"
        )))
    }

    let trimmed = selector.trim();
    let raw_items = if trimmed.starts_with('(') && trimmed.ends_with(')') {
        trimmed[1..trimmed.len() - 1].split(',').collect::<Vec<_>>()
    } else {
        vec![trimmed]
    };
    let mut out = Vec::<String>::new();
    let mut seen = HashSet::<String>::new();
    for item in raw_items {
        for pattern_id in expand_item(item, known_pattern_names)? {
            if seen.insert(pattern_id.clone()) {
                out.push(pattern_id);
            }
        }
    }
    if out.is_empty() {
        return Err(SspryError::from(
            "Verifier-only for-of expression matched zero candidate patterns.",
        ));
    }
    Ok(out)
}

/// Rewrites verifier-only `for any/all of ... at pe.entry_point` loops into
/// equivalent searchable boolean expressions.
fn rewrite_verifier_only_for_of_at_loops(
    condition_text: &str,
    known_pattern_names: &[String],
) -> Result<String> {
    let chars = condition_text.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(condition_text.len());
    let mut index = 0usize;
    while index < chars.len() {
        if let Some((end, any, selector)) = consume_verifier_only_for_of_at_loop(&chars, index) {
            let pattern_ids = expand_verifier_only_for_of_selector(&selector, known_pattern_names)?;
            let joiner = if any { " or " } else { " and " };
            out.push('(');
            for (idx, pattern_id) in pattern_ids.iter().enumerate() {
                if idx > 0 {
                    out.push_str(joiner);
                }
                out.push('(');
                out.push_str(pattern_id);
                out.push_str(" at pe.entry_point)");
            }
            out.push(')');
            index = end;
            continue;
        }
        out.push(chars[index]);
        index += 1;
    }
    Ok(out)
}

/// Advances past ASCII whitespace in condition text.
fn skip_condition_ws(chars: &[char], mut index: usize) -> usize {
    while index < chars.len() && chars[index].is_whitespace() {
        index += 1;
    }
    index
}

/// Consumes a case-insensitive condition keyword when it appears on identifier
/// boundaries.
fn consume_condition_keyword(chars: &[char], index: usize, keyword: &str) -> Option<usize> {
    let end = index.checked_add(keyword.len())?;
    if end > chars.len() {
        return None;
    }
    if !chars[index..end]
        .iter()
        .collect::<String>()
        .eq_ignore_ascii_case(keyword)
    {
        return None;
    }
    if index > 0
        && (chars[index - 1].is_ascii_alphanumeric()
            || chars[index - 1] == '_'
            || chars[index - 1] == '$')
    {
        return None;
    }
    if end < chars.len()
        && (chars[end].is_ascii_alphanumeric() || chars[end] == '_' || chars[end] == '$')
    {
        return None;
    }
    Some(end)
}

/// Consumes one plain identifier from condition text.
fn consume_condition_identifier(chars: &[char], index: usize) -> Option<(usize, String)> {
    if index >= chars.len() || !(chars[index].is_ascii_alphabetic() || chars[index] == '_') {
        return None;
    }
    let mut end = index + 1;
    while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
        end += 1;
    }
    Some((end, chars[index..end].iter().collect()))
}

/// Recognizes verifier-only `for any i in (1..#id) : (...)` loops so they can
/// be rewritten into the synthetic `verifierloop($id)` form.
fn consume_verifier_only_for_any_loop(chars: &[char], start: usize) -> Option<(usize, String)> {
    let mut index = consume_condition_keyword(chars, start, "for")?;
    index = skip_condition_ws(chars, index);
    index = consume_condition_keyword(chars, index, "any")?;
    index = skip_condition_ws(chars, index);
    let (next, _loop_var) = consume_condition_identifier(chars, index)?;
    index = skip_condition_ws(chars, next);
    index = consume_condition_keyword(chars, index, "in")?;
    index = skip_condition_ws(chars, index);
    if chars.get(index) != Some(&'(') {
        return None;
    }
    index += 1;
    index = skip_condition_ws(chars, index);
    if chars.get(index) != Some(&'1') {
        return None;
    }
    index += 1;
    index = skip_condition_ws(chars, index);
    if chars.get(index) != Some(&'.') || chars.get(index + 1) != Some(&'.') {
        return None;
    }
    index += 2;
    index = skip_condition_ws(chars, index);
    if chars.get(index) != Some(&'#') {
        return None;
    }
    index += 1;
    let (next, pattern_name) = consume_condition_identifier(chars, index)?;
    index = skip_condition_ws(chars, next);
    if chars.get(index) != Some(&')') {
        return None;
    }
    index += 1;
    index = skip_condition_ws(chars, index);
    if chars.get(index) != Some(&':') {
        return None;
    }
    index += 1;
    index = skip_condition_ws(chars, index);
    let end = consume_parenthesized_span(chars, index)?;
    Some((end, format!("${pattern_name}")))
}

/// Removes ignored-module placeholder predicates from the parsed query tree.
fn prune_ignored_module_predicates(node: QueryNode) -> Option<QueryNode> {
    match node.kind.as_str() {
        "ignored_module_predicate" => None,
        "pattern"
        | "metadata_eq"
        | "metadata_ne"
        | "metadata_lt"
        | "metadata_le"
        | "metadata_gt"
        | "metadata_ge"
        | "metadata_float_eq"
        | "metadata_float_ne"
        | "metadata_float_lt"
        | "metadata_float_le"
        | "metadata_float_gt"
        | "metadata_float_ge"
        | "metadata_time_eq"
        | "metadata_time_ne"
        | "metadata_time_lt"
        | "metadata_time_le"
        | "metadata_time_gt"
        | "metadata_time_ge"
        | "metadata_field_eq"
        | "metadata_field_ne"
        | "metadata_field_lt"
        | "metadata_field_le"
        | "metadata_field_gt"
        | "metadata_field_ge"
        | "filesize_eq"
        | "filesize_ne"
        | "filesize_gt"
        | "filesize_ge"
        | "filesize_lt"
        | "filesize_le"
        | "time_now_eq"
        | "time_now_ne"
        | "time_now_lt"
        | "time_now_le"
        | "time_now_gt"
        | "time_now_ge"
        | "verifier_only_eq"
        | "verifier_only_at"
        | "verifier_only_count"
        | "verifier_only_in_range"
        | "verifier_only_loop" => Some(node),
        "not" => node
            .children
            .into_iter()
            .next()
            .and_then(prune_ignored_module_predicates)
            .map(|child| QueryNode {
                kind: "not".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![child],
            }),
        "and" | "or" => {
            let children = node
                .children
                .into_iter()
                .filter_map(prune_ignored_module_predicates)
                .collect::<Vec<_>>();
            match children.len() {
                0 => None,
                1 => children.into_iter().next(),
                _ => Some(QueryNode {
                    kind: node.kind,
                    pattern_id: None,
                    threshold: None,
                    children,
                }),
            }
        }
        "n_of" => {
            let children = node
                .children
                .into_iter()
                .filter_map(prune_ignored_module_predicates)
                .collect::<Vec<_>>();
            if children.is_empty() {
                return None;
            }
            let original = node.threshold.unwrap_or(children.len());
            let threshold = original.min(children.len());
            if threshold == 0 {
                return None;
            }
            if threshold == 1 && children.len() == 1 {
                return children.into_iter().next();
            }
            Some(QueryNode {
                kind: "n_of".to_owned(),
                pattern_id: None,
                threshold: Some(threshold),
                children,
            })
        }
        _ => Some(node),
    }
}

/// Parses one quoted literal string definition from a rule strings section.
fn parse_literal_line(line: &str) -> Result<Option<PatternDef>> {
    let trimmed = line.trim();
    let Some(eq_idx) = trimmed.find('=') else {
        return Ok(None);
    };
    let pattern_id = trimmed[..eq_idx].trim();
    if !pattern_id.starts_with('$') {
        return Ok(None);
    }
    let rest = trimmed[eq_idx + 1..].trim();
    if !rest.starts_with('"') {
        return Ok(None);
    }

    let mut escaped = false;
    let mut end_quote = None;
    for (idx, ch) in rest.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            end_quote = Some(idx);
            break;
        }
    }
    let Some(end_idx) = end_quote else {
        return Err(SspryError::from(format!(
            "Invalid literal string: {trimmed:?}"
        )));
    };
    let literal_raw = &rest[1..end_idx];
    let flags_raw = rest[end_idx + 1..].trim();
    let mut flags: HashSet<String> = if flags_raw.is_empty() {
        HashSet::from(["ascii".to_owned()])
    } else {
        flags_raw
            .split_whitespace()
            .map(|item| item.to_ascii_lowercase())
            .collect()
    };
    for flag in &flags {
        if flag != "ascii" && flag != "wide" && flag != "fullword" && flag != "nocase" {
            return Err(SspryError::from(format!(
                "Unsupported literal flag(s) for {pattern_id}: {flag}"
            )));
        }
    }
    if !flags.contains("ascii") && !flags.contains("wide") {
        flags.insert("ascii".to_owned());
    }
    let literal_text: String = serde_json::from_str(&format!("\"{literal_raw}\""))
        .map_err(|_| SspryError::from(format!("Invalid literal string: {literal_raw:?}")))?;

    let mut alternatives = Vec::new();
    let mut wide_flags = Vec::new();
    let mut fullword_flags = Vec::new();
    let mut nocase_flags = Vec::new();
    if flags.contains("ascii") {
        alternatives.push(literal_text.as_bytes().to_vec());
        wide_flags.push(false);
        fullword_flags.push(flags.contains("fullword"));
        nocase_flags.push(flags.contains("nocase"));
    }
    if flags.contains("wide") {
        let mut wide = Vec::with_capacity(literal_text.len() * 2);
        for unit in literal_text.encode_utf16() {
            wide.extend_from_slice(&unit.to_le_bytes());
        }
        alternatives.push(wide);
        wide_flags.push(true);
        fullword_flags.push(flags.contains("fullword"));
        nocase_flags.push(flags.contains("nocase"));
    }

    Ok(Some(PatternDef {
        pattern_id: pattern_id.to_owned(),
        alternatives,
        wide_flags,
        fullword_flags,
        nocase_flags,
        exact_literals: !flags.contains("nocase"),
    }))
}

/// Returns the pattern id when a strings line appears to define a regex.
fn parse_regex_pattern_id(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let eq_idx = trimmed.find('=')?;
    let pattern_id = trimmed[..eq_idx].trim();
    let rest = trimmed[eq_idx + 1..].trim();
    if pattern_id.starts_with('$') && rest.starts_with('/') {
        Some(pattern_id.to_owned())
    } else {
        None
    }
}

/// Parses one regex definition and extracts the mandatory literal windows that
/// can anchor search.
fn parse_regex_line(line: &str, gram_sizes: GramSizes) -> Result<Option<PatternDef>> {
    let trimmed = line.trim();
    let Some(eq_idx) = trimmed.find('=') else {
        return Ok(None);
    };
    let pattern_id = trimmed[..eq_idx].trim();
    if !pattern_id.starts_with('$') {
        return Ok(None);
    }
    let rest = trimmed[eq_idx + 1..].trim();
    if !rest.starts_with('/') {
        return Ok(None);
    }

    let mut escaped = false;
    let mut in_class = false;
    let mut end_slash = None;
    for (idx, ch) in rest.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '[' {
            in_class = true;
            continue;
        }
        if ch == ']' && in_class {
            in_class = false;
            continue;
        }
        if ch == '/' && !in_class {
            end_slash = Some(idx);
            break;
        }
    }
    let Some(end_idx) = end_slash else {
        return Err(SspryError::from(format!(
            "Invalid regex string: {trimmed:?}"
        )));
    };
    let regex_raw = &rest[1..end_idx];
    let flags_raw = rest[end_idx + 1..].trim();
    let mut flags: HashSet<String> = if flags_raw.is_empty() {
        HashSet::from(["ascii".to_owned()])
    } else {
        flags_raw
            .split_whitespace()
            .map(|item| item.to_ascii_lowercase())
            .collect()
    };
    for flag in &flags {
        if flag != "ascii" && flag != "wide" && flag != "fullword" {
            return Err(SspryError::from(format!(
                "Unsupported regex flag(s) for {pattern_id}: {flag}"
            )));
        }
    }
    if !flags.contains("ascii") && !flags.contains("wide") {
        flags.insert("ascii".to_owned());
    }

    let literal = extract_regex_mandatory_literal(regex_raw)?;

    let mut alternatives = Vec::new();
    let mut wide_flags = Vec::new();
    let mut fullword_flags = Vec::new();
    if flags.contains("ascii") {
        if literal.len() >= gram_sizes.tier2 {
            alternatives.push(literal.clone());
            wide_flags.push(false);
            fullword_flags.push(flags.contains("fullword"));
        }
    }
    if flags.contains("wide") {
        let mut wide = Vec::with_capacity(literal.len() * 2);
        for byte in &literal {
            wide.push(*byte);
            wide.push(0);
        }
        if wide.len() >= gram_sizes.tier2 {
            alternatives.push(wide);
            wide_flags.push(true);
            fullword_flags.push(flags.contains("fullword"));
        }
    }
    if alternatives.is_empty() {
        return Err(SspryError::from(format!(
            "Regex {pattern_id} does not contain an anchorable mandatory literal for the active gram sizes."
        )));
    }
    let alt_count = alternatives.len();

    Ok(Some(PatternDef {
        pattern_id: pattern_id.to_owned(),
        alternatives,
        wide_flags,
        fullword_flags,
        nocase_flags: vec![false; alt_count],
        exact_literals: false,
    }))
}

/// Extracts the strongest mandatory literal that can safely anchor a searchable
/// regex pattern.
fn extract_regex_mandatory_literal(regex_raw: &str) -> Result<Vec<u8>> {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RegexAtom {
        Literal(u8),
        Variable,
        Candidate,
        Anchor,
    }

    fn parse_quantifier(chars: &[char], index: usize) -> Result<(usize, usize)> {
        if index >= chars.len() {
            return Ok((1, 0));
        }
        match chars[index] {
            '?' => Ok((0, 1)),
            '*' => Ok((0, 1)),
            '+' => Ok((1, 1)),
            '{' => {
                let mut end = index + 1;
                while end < chars.len() && chars[end] != '}' {
                    end += 1;
                }
                if end >= chars.len() {
                    return Err(SspryError::from(
                        "Unsupported regex quantifier: missing closing '}'",
                    ));
                }
                let body = chars[index + 1..end].iter().collect::<String>();
                let Some((left, _right)) = body
                    .split_once(',')
                    .or_else(|| Some((body.as_str(), body.as_str())))
                else {
                    return Err(SspryError::from("Unsupported regex quantifier body."));
                };
                let min = left
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| SspryError::from("Unsupported regex quantifier body."))?;
                Ok((min, end - index + 1))
            }
            _ => Ok((1, 0)),
        }
    }

    fn split_top_level_alternation(regex_raw: &str) -> Result<Vec<&str>> {
        let mut parts = Vec::<&str>::new();
        let mut start = 0usize;
        let mut escaped = false;
        let mut in_class = false;
        let mut depth = 0usize;
        for (idx, ch) in regex_raw.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => {
                    escaped = true;
                }
                '[' => {
                    in_class = true;
                }
                ']' if in_class => {
                    in_class = false;
                }
                '(' if !in_class => {
                    depth += 1;
                }
                ')' if !in_class => {
                    if depth == 0 {
                        return Err(SspryError::from("Unbalanced ')' in regex string."));
                    }
                    depth -= 1;
                }
                '|' if !in_class && depth == 0 => {
                    parts.push(&regex_raw[start..idx]);
                    start = idx + 1;
                }
                _ => {}
            }
        }
        if depth != 0 || in_class || escaped {
            return Err(SspryError::from(
                "Unterminated group or character class in regex.",
            ));
        }
        parts.push(&regex_raw[start..]);
        Ok(parts)
    }

    fn longest_common_substring(branch_runs: &[Vec<Vec<u8>>]) -> Vec<u8> {
        let Some(first_runs) = branch_runs.first() else {
            return Vec::new();
        };
        let mut first_candidates = first_runs
            .iter()
            .filter(|run| !run.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        first_candidates.sort_by_key(|run| std::cmp::Reverse(run.len()));
        for candidate in first_candidates {
            for len in (1..=candidate.len()).rev() {
                for start in 0..=(candidate.len() - len) {
                    let needle = &candidate[start..start + len];
                    if branch_runs[1..]
                        .iter()
                        .all(|runs| runs.iter().any(|run| run.windows(len).any(|w| w == needle)))
                    {
                        return needle.to_vec();
                    }
                }
            }
        }
        Vec::new()
    }

    fn extract_regex_branch_mandatory_runs(regex_raw: &str) -> Result<Vec<Vec<u8>>> {
        fn flush_current(current: &mut Vec<u8>, runs: &mut Vec<Vec<u8>>) {
            if !current.is_empty() {
                runs.push(current.clone());
                current.clear();
            }
        }

        fn parse_group(chars: &[char], start: usize) -> Result<(String, usize)> {
            let mut depth = 1usize;
            let mut escaped = false;
            let mut in_class = false;
            let mut index = start + 1;
            while index < chars.len() {
                let ch = chars[index];
                if escaped {
                    escaped = false;
                    index += 1;
                    continue;
                }
                match ch {
                    '\\' => {
                        escaped = true;
                    }
                    '[' => {
                        in_class = true;
                    }
                    ']' if in_class => {
                        in_class = false;
                    }
                    '(' if !in_class => {
                        depth += 1;
                    }
                    ')' if !in_class => {
                        depth -= 1;
                        if depth == 0 {
                            let inner = chars[start + 1..index].iter().collect::<String>();
                            return Ok((inner, index + 1));
                        }
                    }
                    _ => {}
                }
                index += 1;
            }
            Err(SspryError::from("Unterminated regex group."))
        }

        let chars = regex_raw.chars().collect::<Vec<_>>();
        let mut runs = Vec::<Vec<u8>>::new();
        let mut current = Vec::<u8>::new();
        let mut index = 0usize;
        while index < chars.len() {
            let mut candidate_bytes = Vec::<u8>::new();
            let atom = match chars[index] {
                '^' | '$' => {
                    index += 1;
                    RegexAtom::Anchor
                }
                '(' => {
                    let (mut inner, next_index) = parse_group(&chars, index)?;
                    index = next_index;
                    if let Some(stripped) = inner.strip_prefix("?:") {
                        inner = stripped.to_owned();
                    } else if inner.starts_with('?') {
                        return Err(SspryError::from(
                            "Unsupported regex group extension in searchable regex.",
                        ));
                    }
                    if let Ok(group_literal) = extract_regex_mandatory_literal(&inner) {
                        if !group_literal.is_empty() {
                            candidate_bytes = group_literal;
                            RegexAtom::Candidate
                        } else {
                            RegexAtom::Variable
                        }
                    } else {
                        RegexAtom::Variable
                    }
                }
                '[' => {
                    index += 1;
                    let mut escaped = false;
                    while index < chars.len() {
                        let ch = chars[index];
                        index += 1;
                        if escaped {
                            escaped = false;
                            continue;
                        }
                        if ch == '\\' {
                            escaped = true;
                            continue;
                        }
                        if ch == ']' {
                            break;
                        }
                    }
                    RegexAtom::Variable
                }
                '.' => {
                    index += 1;
                    RegexAtom::Variable
                }
                '\\' => {
                    index += 1;
                    if index >= chars.len() {
                        return Err(SspryError::from("Invalid regex escape."));
                    }
                    let escaped = chars[index];
                    index += 1;
                    match escaped {
                        'b' | 'B' | 'A' | 'z' | 'Z' => RegexAtom::Anchor,
                        'd' | 'D' | 's' | 'S' | 'w' | 'W' => RegexAtom::Variable,
                        'n' => {
                            candidate_bytes.push(b'\n');
                            RegexAtom::Literal(b'\n')
                        }
                        'r' => {
                            candidate_bytes.push(b'\r');
                            RegexAtom::Literal(b'\r')
                        }
                        't' => {
                            candidate_bytes.push(b'\t');
                            RegexAtom::Literal(b'\t')
                        }
                        'x' => {
                            let hi = chars.get(index).copied();
                            let lo = chars.get(index + 1).copied();
                            let (Some(hi), Some(lo)) = (hi, lo) else {
                                return Err(SspryError::from("Invalid regex hex escape."));
                            };
                            if !(hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit()) {
                                return Err(SspryError::from("Invalid regex hex escape."));
                            }
                            index += 2;
                            let text = [hi, lo].iter().collect::<String>();
                            let value = u8::from_str_radix(&text, 16)
                                .map_err(|_| SspryError::from("Invalid regex hex escape."))?;
                            candidate_bytes.push(value);
                            RegexAtom::Literal(value)
                        }
                        other if other.is_ascii() => {
                            candidate_bytes.push(other as u8);
                            RegexAtom::Literal(other as u8)
                        }
                        _ => {
                            return Err(SspryError::from(
                                "Unsupported non-ASCII regex escape in searchable regex.",
                            ));
                        }
                    }
                }
                '|' | ')' => {
                    return Err(SspryError::from(
                        "Unexpected alternation or group terminator in regex branch.",
                    ));
                }
                ch if ch.is_ascii() => {
                    index += 1;
                    candidate_bytes.push(ch as u8);
                    RegexAtom::Literal(ch as u8)
                }
                _ => {
                    return Err(SspryError::from(
                        "Unsupported non-ASCII regex string in searchable regex.",
                    ));
                }
            };

            let (min_repeat, quantifier_len) = parse_quantifier(&chars, index)?;
            if quantifier_len > 0 {
                index += quantifier_len;
                if index < chars.len() && chars[index] == '?' {
                    index += 1;
                }
            }

            match atom {
                RegexAtom::Anchor => {}
                RegexAtom::Literal(byte) if min_repeat > 0 => {
                    for _ in 0..min_repeat {
                        current.push(byte);
                    }
                }
                RegexAtom::Candidate if min_repeat > 0 => {
                    flush_current(&mut current, &mut runs);
                    let mut repeated = Vec::with_capacity(candidate_bytes.len() * min_repeat);
                    for _ in 0..min_repeat {
                        repeated.extend_from_slice(&candidate_bytes);
                    }
                    runs.push(repeated);
                }
                RegexAtom::Literal(_) | RegexAtom::Variable | RegexAtom::Candidate => {
                    flush_current(&mut current, &mut runs);
                }
            }
        }
        flush_current(&mut current, &mut runs);
        Ok(runs)
    }

    let branches = split_top_level_alternation(regex_raw)?;
    if branches.len() == 1 {
        let runs = extract_regex_branch_mandatory_runs(regex_raw)?;
        let best = runs
            .into_iter()
            .max_by_key(|run| run.len())
            .unwrap_or_default();
        if best.is_empty() {
            return Err(SspryError::from(
                "Regex string does not contain a searchable mandatory literal.",
            ));
        }
        return Ok(best);
    }

    let branch_runs = branches
        .into_iter()
        .map(extract_regex_branch_mandatory_runs)
        .collect::<Result<Vec<_>>>()?;
    let best = longest_common_substring(&branch_runs);
    if best.is_empty() {
        return Err(SspryError::from(
            "Regex string does not contain a searchable mandatory literal.",
        ));
    }
    Ok(best)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HexToken {
    Bytes(Vec<u8>),
    Gap,
    Group(Vec<Vec<u8>>),
}

/// Returns the byte positions whose ASCII case can vary in a nocase literal.
fn nocase_toggle_positions(bytes: &[u8]) -> Vec<usize> {
    bytes
        .iter()
        .enumerate()
        .filter_map(|(idx, byte)| byte.is_ascii_alphabetic().then_some(idx))
        .collect()
}

/// Expands one ASCII nocase literal window into every distinct case variant.
fn expand_ascii_nocase_variants(bytes: &[u8]) -> Vec<Vec<u8>> {
    let positions = nocase_toggle_positions(bytes);
    if positions.is_empty() {
        return vec![bytes.to_vec()];
    }
    let mut out = Vec::with_capacity(1usize << positions.len().min(12));
    let total = 1usize << positions.len();
    for mask in 0..total {
        let mut variant = bytes.to_vec();
        for (bit, pos) in positions.iter().enumerate() {
            variant[*pos] = if (mask >> bit) & 1 == 1 {
                variant[*pos].to_ascii_uppercase()
            } else {
                variant[*pos].to_ascii_lowercase()
            };
        }
        out.push(variant);
    }
    out.sort();
    out.dedup();
    out
}

/// Assigns a rough selectivity hint to one byte when ranking candidate anchor
/// windows.
fn anchor_hint_for_byte(byte: u8) -> u128 {
    match byte {
        0 => 0,
        b'\\' | b'/' | b'.' | b'_' | b'-' | b':' | b'@' => 24,
        b'0'..=b'9' => 18,
        b'A'..=b'Z' | b'a'..=b'z' => 4,
        b' ' | b'\t' | b'\r' | b'\n' => 2,
        _ if byte.is_ascii_punctuation() => 16,
        _ if byte.is_ascii() => 8,
        _ => 12,
    }
}

/// Scores a literal window by byte stability and distinct gram content to help
/// choose stronger anchors.
fn bytes_anchor_hint(bytes: &[u8], gram_sizes: GramSizes) -> u128 {
    if bytes.is_empty() {
        return 0;
    }
    let stable_hint = bytes
        .iter()
        .map(|byte| anchor_hint_for_byte(*byte))
        .sum::<u128>();
    let distinct_bytes = bytes.iter().copied().collect::<HashSet<_>>().len() as u128;
    let unique_tier1 = grams_tier1_from_bytes(bytes, gram_sizes.tier1)
        .into_iter()
        .collect::<HashSet<_>>()
        .len() as u128;
    let unique_tier2 = grams_tier2_from_bytes(bytes, gram_sizes.tier2)
        .into_iter()
        .collect::<HashSet<_>>()
        .len() as u128;
    stable_hint
        .saturating_mul(32)
        .saturating_add(distinct_bytes.saturating_mul(8))
        .saturating_add(unique_tier1.saturating_mul(24))
        .saturating_add(unique_tier2.saturating_mul(8))
}

/// Scores one fixed gram as an anchor candidate.
fn exact_gram_anchor_hint(gram: u64, gram_size: usize) -> u128 {
    bytes_anchor_hint(&gram.to_le_bytes()[..gram_size], GramSizes::default())
}

/// Chooses a bounded-size literal window for `nocase` search and expands it
/// into concrete case variants.
fn derive_nocase_search_alternatives(
    literal: &[u8],
    wide: bool,
    gram_sizes: GramSizes,
) -> Result<Vec<Vec<u8>>> {
    fn gram_count_for_len(len: usize, gram_size: usize) -> usize {
        if len < gram_size {
            0
        } else {
            len - gram_size + 1
        }
    }

    let min_search_len = [gram_sizes.tier2, gram_sizes.tier1]
        .into_iter()
        .filter(|size| !wide || size % 2 == 0)
        .min()
        .unwrap_or(gram_sizes.tier1);
    if literal.len() < min_search_len {
        return Err(SspryError::from(
            "nocase literal does not contain an anchorable window for the active gram sizes",
        ));
    }
    if nocase_toggle_positions(literal).is_empty() {
        return Ok(vec![literal.to_vec()]);
    }
    let step = if wide { 2 } else { 1 };
    let mut best: Option<(u128, u128, u128, usize, usize, usize)> = None;
    for start in (0..=literal.len() - min_search_len).step_by(step) {
        let mut end = start + min_search_len;
        while end <= literal.len() {
            if wide && (end - start) % 2 != 0 {
                end += 1;
                continue;
            }
            let slice = &literal[start..end];
            let alpha_count = nocase_toggle_positions(slice).len();
            let variant_count = 1usize << alpha_count.min(usize::BITS as usize - 1);
            if variant_count <= MAX_NOCASE_LITERAL_VARIANTS {
                let tier1_grams = gram_count_for_len(slice.len(), gram_sizes.tier1);
                let tier2_grams = gram_count_for_len(slice.len(), gram_sizes.tier2);
                let search_weight = (tier1_grams as u128) * 8 + tier2_grams as u128;
                let anchor_hint = bytes_anchor_hint(slice, gram_sizes);
                let weighted_score = search_weight
                    .saturating_mul(search_weight)
                    .saturating_mul(search_weight)
                    .saturating_mul(anchor_hint.saturating_add(1))
                    / variant_count.max(1) as u128;
                let score = (
                    weighted_score,
                    anchor_hint,
                    search_weight,
                    usize::MAX - variant_count,
                    slice.len(),
                    start,
                );
                if best.map(|current| score > current).unwrap_or(true) {
                    best = Some(score);
                }
            }
            end += step;
        }
    }
    let Some((
        _weighted_score,
        _anchor_hint,
        _search_weight,
        _inverse_variants,
        best_len,
        best_start,
    )) = best
    else {
        return Err(SspryError::from(
            "nocase literal expands too broadly for the active gram sizes",
        ));
    };
    let window = &literal[best_start..best_start + best_len];
    Ok(expand_ascii_nocase_variants(window))
}

/// Parses one packed concrete-byte token from a hex string.
fn parse_hex_bytes_token(token: &str) -> Result<Vec<u8>> {
    let compact = token
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    if compact.is_empty()
        || compact.len() % 2 != 0
        || !compact.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(SspryError::from(format!("Invalid hex byte token: {token}")));
    }
    let mut out = Vec::with_capacity(compact.len() / 2);
    for index in (0..compact.len()).step_by(2) {
        out.push(
            u8::from_str_radix(&compact[index..index + 2], 16)
                .map_err(|_| SspryError::from(format!("Invalid hex byte token: {token}")))?,
        );
    }
    Ok(out)
}

/// Tokenizes a hex-string body into whitespace-delimited structural tokens.
fn tokenize_hex_body(body: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for ch in body.chars() {
        match ch {
            '(' => {
                paren_depth += 1;
                current.push(ch);
            }
            ')' => {
                if paren_depth == 0 {
                    return Err(SspryError::from("Unbalanced ')' in hex string."));
                }
                paren_depth -= 1;
                current.push(ch);
            }
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                if bracket_depth == 0 {
                    return Err(SspryError::from("Unbalanced ']' in hex string."));
                }
                bracket_depth -= 1;
                current.push(ch);
            }
            _ if ch.is_whitespace() && paren_depth == 0 && bracket_depth == 0 => {
                if !current.trim().is_empty() {
                    out.push(current.trim().to_owned());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if paren_depth != 0 || bracket_depth != 0 {
        return Err(SspryError::from(
            "Unterminated group or gap token in hex string.",
        ));
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_owned());
    }
    Ok(out)
}

/// Parses one simple alternation group inside a hex string.
fn parse_hex_group_token(token: &str) -> Result<Vec<Vec<u8>>> {
    let inner = token
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| SspryError::from(format!("Invalid hex group token: {token}")))?;
    if inner.contains('(') || inner.contains(')') {
        return Err(SspryError::from(format!(
            "Nested hex groups are unsupported: {token}"
        )));
    }
    let mut branches = Vec::new();
    for branch in inner.split('|') {
        let branch = branch.trim();
        if branch.is_empty() {
            return Err(SspryError::from(format!(
                "Empty branch in hex group token: {token}"
            )));
        }
        if branch.contains("??") || branch.contains('[') || branch.contains(']') {
            return Err(SspryError::from(format!(
                "Unsupported hex group branch for {token:?}. Supported: same-length concrete byte branches."
            )));
        }
        branches.push(parse_hex_bytes_token(branch)?);
    }
    let expected_len = branches
        .first()
        .map(Vec::len)
        .ok_or_else(|| SspryError::from(format!("Invalid hex group token: {token}")))?;
    if expected_len == 0 || branches.iter().any(|branch| branch.len() != expected_len) {
        return Err(SspryError::from(format!(
            "Hex group branches must be the same non-zero byte length: {token}"
        )));
    }
    Ok(branches)
}

/// Converts a hex-string body into normalized token types used by the gram
/// extractor.
fn parse_hex_body_tokens(body: &str) -> Result<Vec<HexToken>> {
    let mut out = Vec::new();
    for token in tokenize_hex_body(body)? {
        if token == "??" || is_gap_token(&token) {
            out.push(HexToken::Gap);
            continue;
        }
        if token.len() == 2
            && token.chars().all(|ch| ch == '?' || ch.is_ascii_hexdigit())
            && token != "??"
            && token.contains('?')
        {
            out.push(HexToken::Gap);
            continue;
        }
        if token.starts_with('(') && token.ends_with(')') {
            out.push(HexToken::Group(parse_hex_group_token(&token)?));
            continue;
        }
        if token.chars().all(|ch| ch.is_ascii_hexdigit()) && token.len() % 2 == 0 {
            out.push(HexToken::Bytes(parse_hex_bytes_token(&token)?));
            continue;
        }
        return Err(SspryError::from(format!(
            "Unsupported hex token: {token:?}. Supported: concrete bytes, packed concrete bytes, ??, [n], [n-m], simple same-length groups."
        )));
    }
    Ok(out)
}

/// Parses one hex-string definition into tier-1/tier-2 gram alternatives and
/// optional fixed literals.
fn parse_hex_line_to_grams(
    line: &str,
    gram_sizes: GramSizes,
) -> Result<Option<(String, Vec<Vec<u64>>, Vec<Vec<u64>>, Vec<Vec<u8>>)>> {
    let trimmed = line.trim();
    let Some(eq_idx) = trimmed.find('=') else {
        return Ok(None);
    };
    let pattern_id = trimmed[..eq_idx].trim();
    if !pattern_id.starts_with('$') {
        return Ok(None);
    }
    let rest = trimmed[eq_idx + 1..].trim();
    if !(rest.starts_with('{') && rest.ends_with('}')) {
        return Ok(None);
    }
    let body = rest[1..rest.len() - 1].trim();
    if body.is_empty() {
        return Err(SspryError::from(format!(
            "Hex pattern {pattern_id} is empty."
        )));
    }

    let tokens = parse_hex_body_tokens(body).map_err(|err| {
        SspryError::from(format!("Unsupported hex token for {pattern_id}: {}", err))
    })?;

    let mut variants = vec![Vec::<HexToken>::new()];
    for token in tokens {
        match token {
            HexToken::Group(branches) => {
                if variants.len().saturating_mul(branches.len()) > MAX_HEX_GROUP_ALTERNATIVES {
                    return Err(SspryError::from(format!(
                        "Hex pattern {pattern_id} expands to too many alternation branches."
                    )));
                }
                let mut next = Vec::with_capacity(variants.len().saturating_mul(branches.len()));
                for variant in &variants {
                    for branch in &branches {
                        let mut expanded = variant.clone();
                        expanded.push(HexToken::Bytes(branch.clone()));
                        next.push(expanded);
                    }
                }
                variants = next;
            }
            other => {
                for variant in &mut variants {
                    variant.push(other.clone());
                }
            }
        }
    }

    let mut all_alts = Vec::with_capacity(variants.len());
    let mut all_tier2_alts = Vec::with_capacity(variants.len());
    let mut all_fixed_literals = Vec::with_capacity(variants.len());
    for variant in variants {
        let mut runs = Vec::<Vec<u8>>::new();
        let mut current = Vec::<u8>::new();
        let mut saw_gap = false;
        for token in variant {
            match token {
                HexToken::Bytes(bytes) => current.extend(bytes),
                HexToken::Gap => {
                    saw_gap = true;
                    if !current.is_empty() {
                        runs.push(std::mem::take(&mut current));
                    }
                }
                HexToken::Group(_) => unreachable!("groups should be expanded"),
            }
        }
        if !current.is_empty() {
            runs.push(current);
        }
        let fixed_literal = if !saw_gap && runs.len() == 1 {
            runs[0].clone()
        } else {
            Vec::new()
        };
        let mut seen = HashSet::new();
        let mut seen_tier2 = HashSet::new();
        let mut grams = Vec::new();
        let mut tier2_grams = Vec::new();
        for run in runs {
            for gram in grams_tier1_from_bytes(&run, gram_sizes.tier1) {
                if seen.insert(gram) {
                    grams.push(gram);
                }
            }
            for gram in grams_tier2_from_bytes(&run, gram_sizes.tier2) {
                if seen_tier2.insert(gram) {
                    tier2_grams.push(gram);
                }
            }
        }
        all_alts.push(grams);
        all_tier2_alts.push(tier2_grams);
        all_fixed_literals.push(fixed_literal);
    }
    Ok(Some((
        pattern_id.to_owned(),
        all_alts,
        all_tier2_alts,
        all_fixed_literals,
    )))
}

/// Returns true when a token represents a variable-length hex gap.
fn is_gap_token(token: &str) -> bool {
    if !(token.starts_with('[') && token.ends_with(']')) {
        return false;
    }
    let inner = &token[1..token.len() - 1];
    let Some((left, right)) = inner.split_once('-').or_else(|| Some((inner, inner))) else {
        return false;
    };
    !left.is_empty()
        && !right.is_empty()
        && left.chars().all(|ch| ch.is_ascii_digit())
        && right.chars().all(|ch| ch.is_ascii_digit())
}

/// Ranks and trims grams for one alternative so large literals do not produce
/// an excessive number of anchors.
fn optimize_grams(
    grams: &[u64],
    fixed_literal: &[u8],
    gram_size: usize,
    max_anchors_per_alt: usize,
) -> Vec<u64> {
    if grams.is_empty() || max_anchors_per_alt == 0 || grams.len() <= max_anchors_per_alt {
        return grams.to_vec();
    }
    let has_positions = !fixed_literal.is_empty() && fixed_literal.len() >= gram_size;
    if !has_positions {
        let mut ranked = grams.to_vec();
        ranked.sort_by(|left, right| {
            exact_gram_anchor_hint(*right, gram_size)
                .cmp(&exact_gram_anchor_hint(*left, gram_size))
                .then_with(|| left.cmp(right))
        });
        ranked.truncate(max_anchors_per_alt);
        return ranked;
    }

    let mut positions_by_gram = HashMap::<u64, Vec<usize>>::new();
    for idx in 0..=(fixed_literal.len() - gram_size) {
        let gram = pack_exact_gram(&fixed_literal[idx..idx + gram_size]);
        positions_by_gram.entry(gram).or_default().push(idx);
    }

    let mut remaining = grams.to_vec();
    remaining.sort_unstable();
    let mut selected = Vec::<u64>::new();
    let mut selected_positions = Vec::<usize>::new();
    let max_start = fixed_literal.len().saturating_sub(gram_size);
    while selected.len() < max_anchors_per_alt && !remaining.is_empty() {
        let mut best_idx = 0usize;
        let mut best_spread = 0usize;
        let mut best_hint = 0u128;
        let mut best_gram = u64::MAX;
        for (idx, gram) in remaining.iter().enumerate() {
            let spread = positions_by_gram
                .get(gram)
                .map(|positions| {
                    if selected_positions.is_empty() {
                        positions
                            .iter()
                            .map(|pos| usize::min(*pos, max_start.saturating_sub(*pos)))
                            .max()
                            .unwrap_or(0)
                    } else {
                        positions
                            .iter()
                            .map(|pos| {
                                selected_positions
                                    .iter()
                                    .map(|other| pos.abs_diff(*other))
                                    .min()
                                    .unwrap_or(0)
                            })
                            .max()
                            .unwrap_or(0)
                    }
                })
                .unwrap_or(0);
            let hint = exact_gram_anchor_hint(*gram, gram_size);
            let better = (spread, hint, std::cmp::Reverse(*gram))
                > (best_spread, best_hint, std::cmp::Reverse(best_gram));
            if better {
                best_idx = idx;
                best_spread = spread;
                best_hint = hint;
                best_gram = *gram;
            }
        }
        let chosen = remaining.remove(best_idx);
        if let Some(pos) = positions_by_gram
            .get(&chosen)
            .and_then(|positions| positions.first())
            .copied()
        {
            selected_positions.push(pos);
        }
        selected.push(chosen);
    }
    selected
}

/// Estimates how selective a pattern looks from its shortest alternative.
fn pattern_selectivity_score(pattern_id: &str, patterns: &BTreeMap<String, Vec<Vec<u64>>>) -> u128 {
    let Some(alternatives) = patterns.get(pattern_id) else {
        return u128::MAX;
    };
    alternatives
        .iter()
        .map(|alternative| {
            if alternative.is_empty() {
                return u128::MAX / 4;
            }
            alternative.len() as u128
        })
        .min()
        .unwrap_or(u128::MAX)
}

/// Reorders OR branches so more selective subtrees evaluate first.
fn reorder_or_nodes_for_selectivity(
    node: &mut QueryNode,
    patterns: &BTreeMap<String, Vec<Vec<u64>>>,
) {
    for child in &mut node.children {
        reorder_or_nodes_for_selectivity(child, patterns);
    }
    if node.kind != "or" {
        return;
    }
    node.children
        .sort_by_key(|child| node_selectivity_score(child, patterns));
}

/// Collects every pattern id referenced under one query subtree.
fn collect_patterns(node: &QueryNode, out: &mut HashSet<String>) {
    if node.kind == "pattern" {
        if let Some(pattern_id) = &node.pattern_id {
            out.insert(pattern_id.clone());
        }
        return;
    }
    for child in &node.children {
        collect_patterns(child, out);
    }
}

/// Assigns tighter anchor budgets to patterns that appear under wide OR
/// branches.
fn collect_or_branch_budgets(
    node: &QueryNode,
    base_budget: usize,
    out: &mut HashMap<String, usize>,
) {
    if node.kind == "or" && node.children.len() > 1 {
        let penalty = node
            .children
            .len()
            .saturating_sub(1)
            .min(base_budget.saturating_sub(1));
        let branch_budget = base_budget.saturating_sub(penalty).max(1);
        for child in &node.children {
            let mut patterns = HashSet::new();
            collect_patterns(child, &mut patterns);
            for pattern in patterns {
                out.entry(pattern)
                    .and_modify(|existing| *existing = (*existing).min(branch_budget))
                    .or_insert(branch_budget);
            }
        }
    }
    for child in &node.children {
        collect_or_branch_budgets(child, base_budget, out);
    }
}

/// Removes duplicate children from OR nodes after planning rewrites.
fn dedupe_or_nodes(node: &mut QueryNode) {
    for child in &mut node.children {
        dedupe_or_nodes(child);
    }
    if node.kind != "or" || node.children.len() <= 1 {
        return;
    }
    let mut seen = HashSet::new();
    node.children.retain(|child| seen.insert(child.clone()));
}

/// Deduplicates pattern alternatives while preserving the aligned fixed-literal
/// side tables.
fn dedupe_pattern_alternatives(
    alternatives: Vec<Vec<u64>>,
    tier2_alternatives: Vec<Vec<u64>>,
    anchor_literals: Vec<Vec<u8>>,
    fixed_literals: Vec<Vec<u8>>,
    fixed_literal_wide: Vec<bool>,
    fixed_literal_fullword: Vec<bool>,
) -> (
    Vec<Vec<u64>>,
    Vec<Vec<u64>>,
    Vec<Vec<u8>>,
    Vec<Vec<u8>>,
    Vec<bool>,
    Vec<bool>,
) {
    let mut seen = HashSet::<(Vec<u64>, Vec<u64>, Vec<u8>, Vec<u8>, bool, bool)>::new();
    let mut kept_tier1 = Vec::new();
    let mut kept_tier2 = Vec::new();
    let mut kept_anchor_literals = Vec::new();
    let mut kept_literals = Vec::new();
    let mut kept_wide = Vec::new();
    let mut kept_fullword = Vec::new();
    let max_len = alternatives
        .len()
        .max(tier2_alternatives.len())
        .max(anchor_literals.len())
        .max(fixed_literals.len())
        .max(fixed_literal_wide.len())
        .max(fixed_literal_fullword.len());
    for index in 0..max_len {
        let tier1 = alternatives.get(index).cloned().unwrap_or_default();
        let tier2 = tier2_alternatives.get(index).cloned().unwrap_or_default();
        let anchor_literal = anchor_literals.get(index).cloned().unwrap_or_default();
        let literal = fixed_literals.get(index).cloned().unwrap_or_default();
        let wide = fixed_literal_wide.get(index).copied().unwrap_or(false);
        let fullword = fixed_literal_fullword.get(index).copied().unwrap_or(false);
        if !seen.insert((
            tier1.clone(),
            tier2.clone(),
            anchor_literal.clone(),
            literal.clone(),
            wide,
            fullword,
        )) {
            continue;
        }
        kept_tier1.push(tier1);
        kept_tier2.push(tier2);
        kept_anchor_literals.push(anchor_literal);
        kept_literals.push(literal);
        kept_wide.push(wide);
        kept_fullword.push(fullword);
    }
    (
        kept_tier1,
        kept_tier2,
        kept_anchor_literals,
        kept_literals,
        kept_wide,
        kept_fullword,
    )
}

/// Classifies numeric-read functions by the literal type they accept.
fn numeric_read_kind(name: &str) -> Option<NumericReadKind> {
    match name {
        "int16" | "uint16" | "int16be" | "uint16be" | "int32" | "uint32" | "int32be"
        | "uint32be" | "int64" | "uint64" | "int64be" | "uint64be" => {
            Some(NumericReadKind::Integer)
        }
        "float32" | "float64" | "float32be" | "float64be" => Some(NumericReadKind::Float),
        _ => None,
    }
}

/// Parses the right-hand literal for an indexed numeric-read equality.
fn parse_numeric_read_literal(
    parser: &mut ConditionParser,
    field_name: &str,
    read_kind: NumericReadKind,
    first_token: Token,
) -> Result<String> {
    match read_kind {
        NumericReadKind::Float => match first_token {
            Token::Int(value) => Ok(value.to_string()),
            Token::Float(value) => Ok(value.to_string()),
            _ => Err(SspryError::from(format!(
                "{field_name} requires equality against a literal constant."
            ))),
        },
        NumericReadKind::Integer => match first_token {
            Token::Int(value) => Ok(value.to_string()),
            Token::Minus if field_name.starts_with("int") => match parser.consume(None)? {
                Token::Int(value) => Ok(format!("-{value}")),
                _ => Err(SspryError::from(format!(
                    "{field_name} requires equality against a literal constant."
                ))),
            },
            _ => Err(SspryError::from(format!(
                "{field_name} requires equality against a literal constant."
            ))),
        },
    }
}

/// Splits a serialized numeric-read verifier expression back into function
/// name, byte offset, and literal text.
fn parse_numeric_read_expression(expr: &str) -> Result<(&str, usize, &str)> {
    let Some((name, rest)) = expr.split_once('(') else {
        return Err(SspryError::from(format!(
            "Invalid numeric read expression: {expr}"
        )));
    };
    let Some((offset_text, literal_text)) = rest.split_once(")==") else {
        return Err(SspryError::from(format!(
            "Invalid numeric read expression: {expr}"
        )));
    };
    let offset = offset_text
        .parse::<usize>()
        .map_err(|_| SspryError::from(format!("Invalid numeric read expression offset: {expr}")))?;
    Ok((name, offset, literal_text))
}

/// Encodes a numeric-read literal into the byte sequence used for exact anchor
/// matching.
fn numeric_read_anchor_bytes(name: &str, literal_text: &str) -> Result<Vec<u8>> {
    match name {
        "int16" => {
            let value = literal_text.parse::<i16>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_le_bytes().to_vec())
        }
        "uint16" => {
            let value = literal_text.parse::<u16>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_le_bytes().to_vec())
        }
        "int16be" => {
            let value = literal_text.parse::<i16>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_be_bytes().to_vec())
        }
        "uint16be" => {
            let value = literal_text.parse::<u16>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_be_bytes().to_vec())
        }
        "int32" => {
            let value = literal_text.parse::<i32>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_le_bytes().to_vec())
        }
        "uint32" => {
            let value = literal_text.parse::<u32>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_le_bytes().to_vec())
        }
        "int32be" => {
            let value = literal_text.parse::<i32>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_be_bytes().to_vec())
        }
        "uint32be" => {
            let value = literal_text.parse::<u32>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_be_bytes().to_vec())
        }
        "int64" => {
            let value = literal_text.parse::<i64>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_le_bytes().to_vec())
        }
        "uint64" => {
            let value = literal_text.parse::<u64>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_le_bytes().to_vec())
        }
        "int64be" => {
            let value = literal_text.parse::<i64>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_be_bytes().to_vec())
        }
        "uint64be" => {
            let value = literal_text.parse::<u64>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_be_bytes().to_vec())
        }
        "float32" => {
            let value = literal_text.parse::<f32>().map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?;
            Ok(value.to_bits().to_le_bytes().to_vec())
        }
        "float32be" => {
            let value = literal_text.parse::<f32>().map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?;
            Ok(value.to_bits().to_be_bytes().to_vec())
        }
        "float64" => {
            let value = literal_text.parse::<f64>().map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?;
            Ok(value.to_bits().to_le_bytes().to_vec())
        }
        "float64be" => {
            let value = literal_text.parse::<f64>().map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?;
            Ok(value.to_bits().to_be_bytes().to_vec())
        }
        _ => Err(SspryError::from(format!(
            "Unsupported numeric read anchor function: {name}"
        ))),
    }
}

/// Injects synthetic pattern anchors for exact numeric-read equality nodes so
/// they can participate in indexed search.
fn inject_numeric_read_anchor_patterns(
    node: &mut QueryNode,
    pattern_alternatives: &mut BTreeMap<String, Vec<Vec<u64>>>,
    pattern_tier2_alternatives: &mut BTreeMap<String, Vec<Vec<u64>>>,
    pattern_anchor_literals: &mut BTreeMap<String, Vec<Vec<u8>>>,
    pattern_fixed_literals: &mut BTreeMap<String, Vec<Vec<u8>>>,
    pattern_fixed_literal_wide: &mut BTreeMap<String, Vec<bool>>,
    pattern_fixed_literal_fullword: &mut BTreeMap<String, Vec<bool>>,
    gram_sizes: GramSizes,
    next_anchor_id: &mut usize,
) -> Result<()> {
    for child in &mut node.children {
        inject_numeric_read_anchor_patterns(
            child,
            pattern_alternatives,
            pattern_tier2_alternatives,
            pattern_anchor_literals,
            pattern_fixed_literals,
            pattern_fixed_literal_wide,
            pattern_fixed_literal_fullword,
            gram_sizes,
            next_anchor_id,
        )?;
    }
    if node.kind != "verifier_only_eq" {
        return Ok(());
    }
    let expr = node
        .pattern_id
        .as_ref()
        .ok_or_else(|| SspryError::from("verifier_only_eq node requires pattern_id"))?
        .clone();
    let (name, _offset, literal_text) = parse_numeric_read_expression(&expr)?;
    let anchor_bytes = numeric_read_anchor_bytes(name, literal_text)?;
    if anchor_bytes.len() < gram_sizes.tier1 {
        return Ok(());
    }
    let synthetic_pattern_id = format!("{NUMERIC_READ_ANCHOR_PREFIX}{next_anchor_id}");
    *next_anchor_id += 1;
    pattern_alternatives.insert(
        synthetic_pattern_id.clone(),
        vec![grams_tier1_from_bytes(&anchor_bytes, gram_sizes.tier1)],
    );
    pattern_tier2_alternatives.insert(
        synthetic_pattern_id.clone(),
        vec![grams_tier2_from_bytes(&anchor_bytes, gram_sizes.tier2)],
    );
    pattern_anchor_literals.insert(synthetic_pattern_id.clone(), vec![anchor_bytes.clone()]);
    pattern_fixed_literals.insert(synthetic_pattern_id.clone(), vec![anchor_bytes]);
    pattern_fixed_literal_wide.insert(synthetic_pattern_id.clone(), vec![false]);
    pattern_fixed_literal_fullword.insert(synthetic_pattern_id.clone(), vec![false]);
    let verifier_node = node.clone();
    *node = QueryNode {
        kind: "and".to_owned(),
        pattern_id: None,
        threshold: None,
        children: vec![
            QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some(synthetic_pattern_id),
                threshold: None,
                children: Vec::new(),
            },
            verifier_node,
        ],
    };
    Ok(())
}

/// Returns true when the query tree still contains any verifier-only nodes.
fn contains_verifier_only_node(node: &QueryNode) -> bool {
    matches!(
        node.kind.as_str(),
        "verifier_only_eq"
            | "verifier_only_at"
            | "verifier_only_count"
            | "verifier_only_in_range"
            | "verifier_only_loop"
    ) || node.children.iter().any(contains_verifier_only_node)
}

const FILE_PREFIX_8_BYTES: usize = 8;

/// Resolves verifier-only offset expressions that can be proven from indexed
/// prefix windows.
fn verifier_only_at_prefix_offset(offset_text: &str) -> Option<(usize, usize)> {
    if offset_text == "0" {
        Some((0, FILE_PREFIX_8_BYTES))
    } else if offset_text == "pe.entry_point" {
        Some((0, PE_ENTRY_POINT_PREFIX_BYTES))
    } else {
        offset_text
            .strip_prefix("pe.entry_point+")?
            .parse::<usize>()
            .ok()
            .map(|offset| (offset, PE_ENTRY_POINT_PREFIX_BYTES))
    }
}

/// Returns true when every fixed literal for a pattern can be proven within the
/// indexed prefix window at the requested offset.
fn pattern_supports_exact_prefix_window(
    pattern: &PatternPlan,
    offset: usize,
    max_window_bytes: usize,
) -> bool {
    let mut saw_supported = false;
    let mut all_supported = true;
    for idx in 0..pattern.alternatives.len() {
        let Some(literal) = pattern.fixed_literals.get(idx) else {
            return false;
        };
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
    }
    saw_supported && all_supported
}

/// Returns true when a serialized numeric-read verifier expression is exact
/// within the indexed file prefix.
fn verifier_only_eq_is_index_exact(expr: &str) -> bool {
    let Ok((name, offset, literal_text)) = parse_numeric_read_expression(expr) else {
        return false;
    };
    let Ok(expected) = numeric_read_anchor_bytes(name, literal_text) else {
        return false;
    };
    offset.saturating_add(expected.len()) <= FILE_PREFIX_8_BYTES
}

/// Returns true when one verifier-only node can be proven exactly from indexed
/// prefix data alone.
fn verifier_only_node_is_index_exact(
    node: &QueryNode,
    pattern_map: &HashMap<String, &PatternPlan>,
) -> bool {
    match node.kind.as_str() {
        "verifier_only_eq" => node
            .pattern_id
            .as_deref()
            .is_some_and(verifier_only_eq_is_index_exact),
        "verifier_only_at" => {
            let Some(expr) = node.pattern_id.as_deref() else {
                return false;
            };
            let Some((pattern_id, offset_text)) = expr.split_once('@') else {
                return false;
            };
            let Some((offset, max_window_bytes)) = verifier_only_at_prefix_offset(offset_text)
            else {
                return false;
            };
            let Some(pattern) = pattern_map.get(pattern_id).copied() else {
                return false;
            };
            pattern_supports_exact_prefix_window(pattern, offset, max_window_bytes)
        }
        _ => false,
    }
}

/// Collects verifier-only node kinds that still require local verification.
fn collect_unresolved_verifier_only_kinds(
    node: &QueryNode,
    pattern_map: &HashMap<String, &PatternPlan>,
    out: &mut BTreeSet<String>,
) {
    if matches!(
        node.kind.as_str(),
        "verifier_only_eq"
            | "verifier_only_at"
            | "verifier_only_count"
            | "verifier_only_in_range"
            | "verifier_only_loop"
    ) && !verifier_only_node_is_index_exact(node, pattern_map)
    {
        out.insert(node.kind.clone());
    }
    for child in &node.children {
        collect_unresolved_verifier_only_kinds(child, pattern_map, out);
    }
}

/// Returns a human-readable label for one verifier-only node kind.
fn verifier_only_kind_label(kind: &str) -> &'static str {
    match kind {
        "verifier_only_eq" => "byte-equality constraints around a match",
        "verifier_only_at" => "fixed or computed match offsets",
        "verifier_only_count" => "match-count constraints",
        "verifier_only_in_range" => "match range constraints",
        "verifier_only_loop" => "loop or iterator constraints",
        _ => "verifier-only constraints",
    }
}

/// Returns the stable rule-check issue code for one verifier-only node kind.
fn verifier_only_issue_code(kind: &str) -> &'static str {
    match kind {
        "verifier_only_eq" => "verifier-only-byte-equality",
        "verifier_only_at" => "verifier-only-offset",
        "verifier_only_count" => "verifier-only-count",
        "verifier_only_in_range" => "verifier-only-range",
        "verifier_only_loop" => "verifier-only-loop",
        _ => "verifier-only-constraint",
    }
}

/// Builds the user-facing rule-check message for a verifier-only node kind.
fn verifier_only_issue_message(kind: &str) -> String {
    match kind {
        "verifier_only_eq" => "This rule uses byte-read equality outside sspry's exact indexed prefix window. sspry can narrow candidates, but exact evaluation requires local verification with --verify.".to_owned(),
        "verifier_only_at" => "This rule constrains a string match to a specific offset that sspry cannot prove exactly from indexed prefix metadata alone. sspry can anchor candidate search, but exact evaluation requires local verification with --verify.".to_owned(),
        "verifier_only_count" => "This rule constrains the number of string matches. sspry can narrow candidates, but exact match-count evaluation requires local verification with --verify.".to_owned(),
        "verifier_only_in_range" => "This rule constrains matches to a byte range. sspry can narrow candidates, but exact range evaluation requires local verification with --verify.".to_owned(),
        "verifier_only_loop" => "This rule uses a for-any or for-all iterator over match conditions. sspry can narrow candidates, but exact iterator evaluation requires local verification with --verify.".to_owned(),
        _ => format!(
            "This rule uses {}. sspry can anchor it for candidate search, but exact evaluation requires local verification with --verify.",
            verifier_only_kind_label(kind)
        ),
    }
}

// Rule-check diagnostics and source mapping helpers live in a sibling file to keep
// the core query-plan compiler readable.
include!("query_plan/rule_check.rs");

/// Builds a verifier-only execution plan when every pattern can be reduced to
/// fixed-literal checks.
pub fn fixed_literal_match_plan(plan: &CompiledQueryPlan) -> Option<FixedLiteralMatchPlan> {
    if contains_identity_node(&plan.root) {
        return None;
    }
    let mut literals = HashMap::<String, Vec<Vec<u8>>>::new();
    let mut literal_wide = HashMap::<String, Vec<bool>>::new();
    let mut literal_fullword = HashMap::<String, Vec<bool>>::new();
    for pattern in &plan.patterns {
        if pattern.fixed_literals.is_empty() {
            return None;
        }
        if pattern.alternatives.len() != pattern.fixed_literals.len() {
            return None;
        }
        if pattern.alternatives.len() != pattern.fixed_literal_wide.len()
            || pattern.alternatives.len() != pattern.fixed_literal_fullword.len()
        {
            return None;
        }
        if pattern
            .fixed_literals
            .iter()
            .any(|literal| literal.is_empty())
        {
            return None;
        }
        literals.insert(pattern.pattern_id.clone(), pattern.fixed_literals.clone());
        literal_wide.insert(
            pattern.pattern_id.clone(),
            pattern.fixed_literal_wide.clone(),
        );
        literal_fullword.insert(
            pattern.pattern_id.clone(),
            pattern.fixed_literal_fullword.clone(),
        );
    }
    Some(FixedLiteralMatchPlan {
        literals,
        literal_wide,
        literal_fullword,
        root: plan.root.clone(),
    })
}

/// Evaluates a fixed-literal match map against the boolean query tree produced
/// by the normal planner.
pub fn evaluate_fixed_literal_match(
    node: &QueryNode,
    matches: &HashMap<String, bool>,
) -> Result<bool> {
    match node.kind.as_str() {
        "pattern" => {
            let pattern_id = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| SspryError::from("pattern node requires pattern_id"))?;
            Ok(matches.get(pattern_id).copied().unwrap_or(false))
        }
        "not" => {
            let child = node
                .children
                .first()
                .ok_or_else(|| SspryError::from("not node requires one child"))?;
            Ok(!evaluate_fixed_literal_match(child, matches)?)
        }
        "filesize_eq" => Err(SspryError::from(
            "filesize_eq requires file metadata and cannot use the fixed-literal fast path",
        )),
        "filesize_ne" | "filesize_lt" | "filesize_le" | "filesize_gt" | "filesize_ge" => {
            Err(SspryError::from(
                "filesize comparison requires file metadata and cannot use the fixed-literal fast path",
            ))
        }
        "verifier_only_eq" => Err(SspryError::from(
            "verifier_only_eq requires file verification and cannot use the fixed-literal fast path",
        )),
        "verifier_only_at" => Err(SspryError::from(
            "verifier_only_at requires file verification and cannot use the fixed-literal fast path",
        )),
        "verifier_only_count" => Err(SspryError::from(
            "verifier_only_count requires file verification and cannot use the fixed-literal fast path",
        )),
        "verifier_only_in_range" => Err(SspryError::from(
            "verifier_only_in_range requires file verification and cannot use the fixed-literal fast path",
        )),
        "verifier_only_loop" => Err(SspryError::from(
            "verifier_only_loop requires file verification and cannot use the fixed-literal fast path",
        )),
        "identity_eq" => Err(SspryError::from(
            "identity_eq requires DB identity lookup and cannot use the fixed-literal fast path",
        )),
        "metadata_eq" | "metadata_ne" | "metadata_lt" | "metadata_le" | "metadata_gt"
        | "metadata_ge" | "metadata_float_eq" | "metadata_float_ne" | "metadata_float_lt"
        | "metadata_float_le" | "metadata_float_gt" | "metadata_float_ge" | "metadata_time_eq"
        | "metadata_time_ne" | "metadata_time_lt" | "metadata_time_le" | "metadata_time_gt"
        | "metadata_time_ge" | "metadata_field_eq" | "metadata_field_ne" | "metadata_field_lt"
        | "metadata_field_le" | "metadata_field_gt" | "metadata_field_ge" => Err(SspryError::from(
            "metadata comparison requires stored metadata and cannot use the fixed-literal fast path",
        )),
        "time_now_eq" | "time_now_ne" | "time_now_lt" | "time_now_le" | "time_now_gt"
        | "time_now_ge" => Err(SspryError::from(
            "time_now comparison requires runtime evaluation and cannot use the fixed-literal fast path",
        )),
        "and" => {
            for child in &node.children {
                if !evaluate_fixed_literal_match(child, matches)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        "or" => {
            for child in &node.children {
                if evaluate_fixed_literal_match(child, matches)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        "n_of" => {
            let threshold = node
                .threshold
                .ok_or_else(|| SspryError::from("n_of node requires threshold"))?;
            let mut matched = 0usize;
            for child in &node.children {
                if evaluate_fixed_literal_match(child, matches)? {
                    matched += 1;
                    if matched >= threshold {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        other => Err(SspryError::from(format!(
            "Unsupported ast node kind: {other}"
        ))),
    }
}

fn node_selectivity_score(node: &QueryNode, patterns: &BTreeMap<String, Vec<Vec<u64>>>) -> u128 {
    match node.kind.as_str() {
        "pattern" => node
            .pattern_id
            .as_deref()
            .map(|pattern_id| pattern_selectivity_score(pattern_id, patterns))
            .unwrap_or(u128::MAX),
        "and" => node
            .children
            .iter()
            .map(|child| node_selectivity_score(child, patterns))
            .min()
            .unwrap_or(u128::MAX),
        "not" => u128::MAX / 2,
        "filesize_eq"
        | "filesize_ne"
        | "filesize_lt"
        | "filesize_le"
        | "filesize_gt"
        | "filesize_ge"
        | "identity_eq"
        | "metadata_eq"
        | "metadata_ne"
        | "metadata_lt"
        | "metadata_le"
        | "metadata_gt"
        | "metadata_ge"
        | "metadata_float_eq"
        | "metadata_float_ne"
        | "metadata_float_lt"
        | "metadata_float_le"
        | "metadata_float_gt"
        | "metadata_float_ge"
        | "metadata_time_eq"
        | "metadata_time_ne"
        | "metadata_time_lt"
        | "metadata_time_le"
        | "metadata_time_gt"
        | "metadata_time_ge"
        | "metadata_field_eq"
        | "metadata_field_ne"
        | "metadata_field_lt"
        | "metadata_field_le"
        | "metadata_field_gt"
        | "metadata_field_ge"
        | "time_now_eq"
        | "time_now_ne"
        | "time_now_lt"
        | "time_now_le"
        | "time_now_gt"
        | "time_now_ge"
        | "verifier_only_eq"
        | "verifier_only_at"
        | "verifier_only_count"
        | "verifier_only_in_range"
        | "verifier_only_loop" => u128::MAX / 2,
        "or" => node
            .children
            .iter()
            .map(|child| node_selectivity_score(child, patterns))
            .min()
            .unwrap_or(u128::MAX),
        "n_of" => node
            .children
            .iter()
            .map(|child| node_selectivity_score(child, patterns))
            .min()
            .unwrap_or(u128::MAX),
        _ => u128::MAX,
    }
}

// Rule compilation and public entry points live in a sibling file so the parser
// and plan-shaping logic stay easier to navigate.
include!("query_plan/compile.rs");

#[cfg(test)]
mod tests;
