use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::candidate::{
    DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes, pack_exact_gram,
};
use crate::{Result, TgsError};

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
    pub fixed_literals: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledQueryPlan {
    pub patterns: Vec<PatternPlan>,
    pub root: QueryNode,
    pub force_tier1_only: bool,
    pub allow_tier2_fallback: bool,
    pub max_candidates: usize,
    pub tier2_gram_size: usize,
    pub tier1_gram_size: usize,
}

pub fn normalize_max_candidates(max_candidates: usize) -> usize {
    if max_candidates == 0 {
        usize::MAX
    } else {
        max_candidates
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedLiteralMatchPlan {
    pub literals: HashMap<String, Vec<Vec<u8>>>,
    pub root: QueryNode,
}

#[derive(Clone, Debug)]
struct PatternDef {
    pattern_id: String,
    alternatives: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    Comma,
    And,
    Or,
    Of,
    Int(usize),
    Id(String),
}

struct ConditionParser {
    tokens: Vec<Token>,
    index: usize,
    known_patterns: HashSet<String>,
}

impl ConditionParser {
    fn new(text: &str, known_patterns: HashSet<String>) -> Result<Self> {
        Ok(Self {
            tokens: tokenize_condition(text)?,
            index: 0,
            known_patterns,
        })
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn consume(&mut self, expected: Option<&Token>) -> Result<Token> {
        let Some(token) = self.tokens.get(self.index).cloned() else {
            return Err(TgsError::from("Unexpected end of condition."));
        };
        if let Some(expected_token) = expected {
            if &token != expected_token {
                return Err(TgsError::from(format!(
                    "Expected token {:?}, got {:?}.",
                    expected_token, token
                )));
            }
        }
        self.index += 1;
        Ok(token)
    }

    fn parse(&mut self) -> Result<QueryNode> {
        if self.tokens.is_empty() {
            return Err(TgsError::from("Condition section is empty."));
        }
        let node = self.parse_or()?;
        if let Some(token) = self.peek() {
            return Err(TgsError::from(format!(
                "Unexpected trailing token in condition: {token:?}"
            )));
        }
        Ok(node)
    }

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

    fn parse_factor(&mut self) -> Result<QueryNode> {
        match self.peek() {
            Some(Token::LParen) => {
                self.consume(Some(&Token::LParen))?;
                let node = self.parse_or()?;
                self.consume(Some(&Token::RParen))?;
                Ok(node)
            }
            Some(Token::Id(_)) => {
                let Token::Id(raw_id) = self.consume(None)? else {
                    unreachable!();
                };
                if !self.known_patterns.contains(&raw_id) {
                    return Err(TgsError::from(format!(
                        "Condition references unknown string id: {raw_id}"
                    )));
                }
                Ok(QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some(raw_id),
                    threshold: None,
                    children: Vec::new(),
                })
            }
            Some(Token::Int(_)) => {
                let Token::Int(threshold) = self.consume(None)? else {
                    unreachable!();
                };
                if threshold == 0 {
                    return Err(TgsError::from("N-of threshold must be > 0."));
                }
                self.consume(Some(&Token::Of))?;
                self.consume(Some(&Token::LParen))?;
                let mut children = Vec::new();
                loop {
                    let Token::Id(raw_id) = self.consume(None)? else {
                        return Err(TgsError::from("Expected pattern id in N-of expression."));
                    };
                    if !self.known_patterns.contains(&raw_id) {
                        return Err(TgsError::from(format!(
                            "Condition references unknown string id: {raw_id}"
                        )));
                    }
                    children.push(QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some(raw_id),
                        threshold: None,
                        children: Vec::new(),
                    });
                    match self.peek() {
                        Some(Token::Comma) => {
                            self.consume(Some(&Token::Comma))?;
                        }
                        Some(Token::RParen) => {
                            self.consume(Some(&Token::RParen))?;
                            break;
                        }
                        Some(token) => {
                            return Err(TgsError::from(format!(
                                "Expected ',' or ')' in N-of list, got {token:?}"
                            )));
                        }
                        None => return Err(TgsError::from("Unterminated N-of expression.")),
                    }
                }
                Ok(QueryNode {
                    kind: "n_of".to_owned(),
                    pattern_id: None,
                    threshold: Some(threshold),
                    children,
                })
            }
            Some(token) => Err(TgsError::from(format!(
                "Unsupported condition token: {token:?}"
            ))),
            None => Err(TgsError::from("Unexpected end of condition.")),
        }
    }
}

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
            '$' => {
                let start = index;
                index += 1;
                while index < chars.len()
                    && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
                {
                    index += 1;
                }
                tokens.push(Token::Id(chars[start..index].iter().collect()));
                continue;
            }
            _ => {}
        }
        if ch.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < chars.len() && chars[index].is_ascii_digit() {
                index += 1;
            }
            let raw: String = chars[start..index].iter().collect();
            let value = raw
                .parse::<usize>()
                .map_err(|_| TgsError::from(format!("Invalid integer token: {raw}")))?;
            tokens.push(Token::Int(value));
            continue;
        }
        if ch.is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < chars.len() && chars[index].is_ascii_alphabetic() {
                index += 1;
            }
            let raw: String = chars[start..index].iter().collect();
            match raw.to_ascii_lowercase().as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "of" => tokens.push(Token::Of),
                _ => {
                    return Err(TgsError::from(format!(
                        "Unsupported token in condition near: {raw:?}"
                    )));
                }
            }
            continue;
        }
        return Err(TgsError::from(format!(
            "Unsupported token in condition near: {:?}",
            chars[index..chars.len().min(index + 24)]
                .iter()
                .collect::<String>()
        )));
    }
    Ok(tokens)
}

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

fn grams_tier1_from_bytes(blob: &[u8], tier1_gram_size: usize) -> Vec<u64> {
    grams_from_bytes(blob, tier1_gram_size)
}

fn grams_tier2_from_bytes(blob: &[u8], tier2_gram_size: usize) -> Vec<u64> {
    grams_from_bytes(blob, tier2_gram_size)
}

fn parse_rule_sections(rule_text: &str) -> Result<(Vec<String>, String)> {
    let mut strings_lines = Vec::new();
    let mut condition_lines = Vec::new();
    let mut state = "none";
    for raw_line in rule_text.lines() {
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
    if strings_lines.is_empty() {
        return Err(TgsError::from(
            "Rule does not contain a strings section with supported entries.",
        ));
    }
    if condition_lines.is_empty() {
        return Err(TgsError::from("Rule does not contain a condition section."));
    }
    Ok((strings_lines, condition_lines.join(" ")))
}

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
        return Err(TgsError::from(format!(
            "Invalid literal string: {trimmed:?}"
        )));
    };
    let literal_raw = &rest[1..end_idx];
    let flags_raw = rest[end_idx + 1..].trim();
    let flags: HashSet<String> = if flags_raw.is_empty() {
        HashSet::from(["ascii".to_owned()])
    } else {
        flags_raw
            .split_whitespace()
            .map(|item| item.to_ascii_lowercase())
            .collect()
    };
    for flag in &flags {
        if flag != "ascii" && flag != "wide" {
            return Err(TgsError::from(format!(
                "Unsupported literal flag(s) for {pattern_id}: {flag}"
            )));
        }
    }
    let literal_text: String = serde_json::from_str(&format!("\"{literal_raw}\""))
        .map_err(|_| TgsError::from(format!("Invalid literal string: {literal_raw:?}")))?;

    let mut alternatives = Vec::new();
    if flags.contains("ascii") {
        alternatives.push(literal_text.as_bytes().to_vec());
    }
    if flags.contains("wide") {
        let mut wide = Vec::with_capacity(literal_text.len() * 2);
        for unit in literal_text.encode_utf16() {
            wide.extend_from_slice(&unit.to_le_bytes());
        }
        alternatives.push(wide);
    }

    Ok(Some(PatternDef {
        pattern_id: pattern_id.to_owned(),
        alternatives,
    }))
}

fn parse_hex_line_to_grams(
    line: &str,
    gram_sizes: GramSizes,
) -> Result<Option<(String, Vec<u64>, Vec<u64>, Vec<u8>)>> {
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
        return Err(TgsError::from(format!(
            "Hex pattern {pattern_id} is empty."
        )));
    }

    let mut runs = Vec::<Vec<u8>>::new();
    let mut current = Vec::<u8>::new();
    let mut saw_gap = false;
    for token in body.split_whitespace() {
        if token.len() == 2 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
            current.push(
                u8::from_str_radix(token, 16)
                    .map_err(|_| TgsError::from(format!("Invalid hex byte: {token}")))?,
            );
            continue;
        }
        if token == "??" || is_gap_token(token) {
            saw_gap = true;
            if !current.is_empty() {
                runs.push(current.clone());
                current.clear();
            }
            continue;
        }
        return Err(TgsError::from(format!(
            "Unsupported hex token for {pattern_id}: {token:?}. Supported: concrete bytes, ??, [n], [n-m]."
        )));
    }
    if !current.is_empty() {
        runs.push(current);
    }

    let mut seen = HashSet::new();
    let mut seen5 = HashSet::new();
    let mut grams = Vec::new();
    let mut grams5 = Vec::new();
    let fixed_literal = if !saw_gap && runs.len() == 1 {
        runs[0].clone()
    } else {
        Vec::new()
    };
    for run in runs {
        for gram in grams_tier1_from_bytes(&run, gram_sizes.tier1) {
            if seen.insert(gram) {
                grams.push(gram);
            }
        }
        for gram in grams_tier2_from_bytes(&run, gram_sizes.tier2) {
            if seen5.insert(gram) {
                grams5.push(gram);
            }
        }
    }
    Ok(Some((pattern_id.to_owned(), grams, grams5, fixed_literal)))
}

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

fn optimize_grams(
    grams: &[u64],
    fixed_literal: &[u8],
    gram_size: usize,
    df_counts: Option<&HashMap<u64, usize>>,
    max_anchors_per_alt: usize,
) -> Vec<u64> {
    if grams.is_empty() || max_anchors_per_alt == 0 || grams.len() <= max_anchors_per_alt {
        return grams.to_vec();
    }
    let df_for = |gram: &u64| {
        df_counts
            .and_then(|counts| counts.get(gram).copied())
            .unwrap_or(usize::MAX / 2)
    };
    let has_positions = !fixed_literal.is_empty() && fixed_literal.len() >= gram_size;
    if !has_positions {
        let mut ranked = grams.to_vec();
        ranked.sort_unstable_by_key(|gram| (df_for(gram), *gram));
        ranked.truncate(max_anchors_per_alt);
        return ranked;
    }

    let mut positions_by_gram = HashMap::<u64, Vec<usize>>::new();
    for idx in 0..=(fixed_literal.len() - gram_size) {
        let gram = pack_exact_gram(&fixed_literal[idx..idx + gram_size]);
        positions_by_gram.entry(gram).or_default().push(idx);
    }

    let mut remaining = grams.to_vec();
    remaining.sort_unstable_by_key(|gram| (df_for(gram), *gram));
    let mut selected = Vec::<u64>::new();
    let mut selected_positions = Vec::<usize>::new();
    let max_start = fixed_literal.len().saturating_sub(gram_size);
    while selected.len() < max_anchors_per_alt && !remaining.is_empty() {
        let mut best_idx = 0usize;
        let mut best_df = usize::MAX;
        let mut best_spread = 0usize;
        let mut best_gram = u64::MAX;
        for (idx, gram) in remaining.iter().enumerate() {
            let df = df_for(gram);
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
            let better =
                (df, usize::MAX - spread, *gram) < (best_df, usize::MAX - best_spread, best_gram);
            if better {
                best_idx = idx;
                best_df = df;
                best_spread = spread;
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

fn pattern_selectivity_score(
    pattern_id: &str,
    patterns: &BTreeMap<String, Vec<Vec<u64>>>,
    df_counts: Option<&HashMap<u64, usize>>,
) -> u128 {
    let Some(alternatives) = patterns.get(pattern_id) else {
        return u128::MAX;
    };
    alternatives
        .iter()
        .map(|alternative| {
            if alternative.is_empty() {
                return u128::MAX / 4;
            }
            alternative.iter().fold(0u128, |acc, gram| {
                let df = df_counts
                    .and_then(|counts| counts.get(gram).copied())
                    .unwrap_or(usize::MAX / 2);
                acc.saturating_add(df as u128)
            })
        })
        .min()
        .unwrap_or(u128::MAX)
}

fn reorder_or_nodes_for_selectivity(
    node: &mut QueryNode,
    patterns: &BTreeMap<String, Vec<Vec<u64>>>,
    df_counts: Option<&HashMap<u64, usize>>,
) {
    for child in &mut node.children {
        reorder_or_nodes_for_selectivity(child, patterns, df_counts);
    }
    if node.kind != "or" {
        return;
    }
    node.children
        .sort_by_key(|child| node_selectivity_score(child, patterns, df_counts));
}

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

fn dedupe_pattern_alternatives(
    alternatives: Vec<Vec<u64>>,
    tier2_alternatives: Vec<Vec<u64>>,
    fixed_literals: Vec<Vec<u8>>,
) -> (Vec<Vec<u64>>, Vec<Vec<u64>>, Vec<Vec<u8>>) {
    let mut seen = HashSet::<(Vec<u64>, Vec<u64>, Vec<u8>)>::new();
    let mut kept_tier1 = Vec::new();
    let mut kept_tier2 = Vec::new();
    let mut kept_literals = Vec::new();
    let max_len = alternatives
        .len()
        .max(tier2_alternatives.len())
        .max(fixed_literals.len());
    for index in 0..max_len {
        let tier1 = alternatives.get(index).cloned().unwrap_or_default();
        let tier2 = tier2_alternatives.get(index).cloned().unwrap_or_default();
        let literal = fixed_literals.get(index).cloned().unwrap_or_default();
        if !seen.insert((tier1.clone(), tier2.clone(), literal.clone())) {
            continue;
        }
        kept_tier1.push(tier1);
        kept_tier2.push(tier2);
        kept_literals.push(literal);
    }
    (kept_tier1, kept_tier2, kept_literals)
}

pub fn fixed_literal_match_plan(plan: &CompiledQueryPlan) -> Option<FixedLiteralMatchPlan> {
    let mut literals = HashMap::<String, Vec<Vec<u8>>>::new();
    for pattern in &plan.patterns {
        if pattern.fixed_literals.is_empty() {
            return None;
        }
        if pattern.alternatives.len() != pattern.fixed_literals.len() {
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
    }
    Some(FixedLiteralMatchPlan {
        literals,
        root: plan.root.clone(),
    })
}

pub fn evaluate_fixed_literal_match(
    node: &QueryNode,
    matches: &HashMap<String, bool>,
) -> Result<bool> {
    match node.kind.as_str() {
        "pattern" => {
            let pattern_id = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| TgsError::from("pattern node requires pattern_id"))?;
            Ok(matches.get(pattern_id).copied().unwrap_or(false))
        }
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
                .ok_or_else(|| TgsError::from("n_of node requires threshold"))?;
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
        other => Err(TgsError::from(format!(
            "Unsupported ast node kind: {other}"
        ))),
    }
}

fn node_selectivity_score(
    node: &QueryNode,
    patterns: &BTreeMap<String, Vec<Vec<u64>>>,
    df_counts: Option<&HashMap<u64, usize>>,
) -> u128 {
    match node.kind.as_str() {
        "pattern" => node
            .pattern_id
            .as_deref()
            .map(|pattern_id| pattern_selectivity_score(pattern_id, patterns, df_counts))
            .unwrap_or(u128::MAX),
        "and" => node
            .children
            .iter()
            .map(|child| node_selectivity_score(child, patterns, df_counts))
            .min()
            .unwrap_or(u128::MAX),
        "or" => node
            .children
            .iter()
            .map(|child| node_selectivity_score(child, patterns, df_counts))
            .min()
            .unwrap_or(u128::MAX),
        "n_of" => node
            .children
            .iter()
            .map(|child| node_selectivity_score(child, patterns, df_counts))
            .min()
            .unwrap_or(u128::MAX),
        _ => u128::MAX,
    }
}

pub fn compile_query_plan(
    rule_text: &str,
    df_counts: Option<&HashMap<u64, usize>>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: usize,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_with_gram_sizes(
        rule_text,
        GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)?,
        df_counts,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

pub fn compile_query_plan_with_gram_sizes(
    rule_text: &str,
    gram_sizes: GramSizes,
    df_counts: Option<&HashMap<u64, usize>>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: usize,
) -> Result<CompiledQueryPlan> {
    let max_candidates = normalize_max_candidates(max_candidates);
    let (strings_lines, condition_text) = parse_rule_sections(rule_text)?;
    let mut pattern_alternatives = BTreeMap::<String, Vec<Vec<u64>>>::new();
    let mut pattern_tier2_alternatives = BTreeMap::<String, Vec<Vec<u64>>>::new();
    let mut pattern_fixed_literals = BTreeMap::<String, Vec<Vec<u8>>>::new();
    for line in strings_lines {
        if let Some(def) = parse_literal_line(&line)? {
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
            let fixed_literals = def.alternatives.clone();
            pattern_alternatives.insert(def.pattern_id.clone(), alternatives);
            pattern_tier2_alternatives.insert(def.pattern_id.clone(), tier2_alternatives);
            pattern_fixed_literals.insert(def.pattern_id, fixed_literals);
            continue;
        }
        if let Some((pattern_id, grams, grams5, fixed_literal)) =
            parse_hex_line_to_grams(&line, gram_sizes)?
        {
            pattern_alternatives.insert(pattern_id.clone(), vec![grams]);
            pattern_tier2_alternatives.insert(pattern_id.clone(), vec![grams5]);
            pattern_fixed_literals.insert(pattern_id, vec![fixed_literal]);
            continue;
        }
        return Err(TgsError::from(format!(
            "Unsupported strings declaration: {:?}. Supported forms: $id = \"...\" [ascii|wide], $id = {{ ... }}",
            line.trim()
        )));
    }

    let mut parser = ConditionParser::new(
        &condition_text,
        pattern_alternatives.keys().cloned().collect(),
    )?;
    let mut root = parser.parse()?;
    reorder_or_nodes_for_selectivity(&mut root, &pattern_alternatives, df_counts);
    dedupe_or_nodes(&mut root);
    let mut branch_budgets = HashMap::<String, usize>::new();
    collect_or_branch_budgets(&root, max_anchors_per_alt, &mut branch_budgets);

    let mut patterns = Vec::new();
    for (pattern_id, alternatives) in pattern_alternatives {
        let tier2_alternatives = pattern_tier2_alternatives
            .remove(&pattern_id)
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let fixed_literals = pattern_fixed_literals
            .remove(&pattern_id)
            .unwrap_or_else(|| vec![Vec::new(); alternatives.len()]);
        let (alternatives, tier2_alternatives, fixed_literals) =
            dedupe_pattern_alternatives(alternatives, tier2_alternatives, fixed_literals);
        let per_pattern_budget = branch_budgets
            .get(&pattern_id)
            .copied()
            .unwrap_or(max_anchors_per_alt);
        let optimized = alternatives
            .iter()
            .zip(fixed_literals.iter())
            .map(|(alt, fixed_literal)| {
                optimize_grams(
                    alt,
                    fixed_literal,
                    gram_sizes.tier1,
                    df_counts,
                    per_pattern_budget,
                )
            })
            .collect();
        patterns.push(PatternPlan {
            pattern_id,
            alternatives: optimized,
            tier2_alternatives,
            fixed_literals,
        });
    }

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

pub fn compile_query_plan_from_file(
    rule_path: impl AsRef<Path>,
    df_counts: Option<&HashMap<u64, usize>>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: usize,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_from_file_with_gram_sizes(
        rule_path,
        GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)?,
        df_counts,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

pub fn compile_query_plan_from_file_with_gram_sizes(
    rule_path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    df_counts: Option<&HashMap<u64, usize>>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: usize,
) -> Result<CompiledQueryPlan> {
    let text = fs::read_to_string(rule_path)?;
    compile_query_plan_with_gram_sizes(
        &text,
        gram_sizes,
        df_counts,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

pub fn compile_query_plan_with_tier2_gram_size(
    rule_text: &str,
    tier2_gram_size: usize,
    df_counts: Option<&HashMap<u64, usize>>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: usize,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_with_gram_sizes(
        rule_text,
        GramSizes::new(tier2_gram_size, DEFAULT_TIER1_GRAM_SIZE)?,
        df_counts,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

pub fn compile_query_plan_from_file_with_tier2_gram_size(
    rule_path: impl AsRef<Path>,
    tier2_gram_size: usize,
    df_counts: Option<&HashMap<u64, usize>>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: usize,
) -> Result<CompiledQueryPlan> {
    compile_query_plan_from_file_with_gram_sizes(
        rule_path,
        GramSizes::new(tier2_gram_size, DEFAULT_TIER1_GRAM_SIZE)?,
        df_counts,
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::fs;

    use tempfile::tempdir;

    use super::*;

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
        let plan = compile_query_plan(rule, None, 16, false, true, 100_000).expect("plan");
        assert!(matches!(plan, CompiledQueryPlan { .. }));
        let patterns = plan
            .patterns
            .iter()
            .map(|item| (item.pattern_id.as_str(), item))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(patterns["$a"].alternatives.len(), 1);
        assert_eq!(patterns["$a"].alternatives[0].len(), 1);
        assert_eq!(patterns["$b"].alternatives.len(), 1);
        assert_eq!(patterns["$b"].alternatives[0].len(), 1);
        assert_eq!(patterns["$c"].alternatives, vec![vec![0x0908_0706]]);
    }

    #[test]
    fn unsupported_construct_raises() {
        let rule = r#"
rule bad {
  strings:
    $a = /abc.*/
  condition:
    $a
}
"#;
        assert!(compile_query_plan(rule, None, 8, false, true, 100_000).is_err());
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
            tokenize_condition("@")
                .expect_err("unsupported token")
                .to_string()
                .contains("Unsupported token in condition")
        );

        let mut parser = ConditionParser::new("", HashSet::new()).expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("empty condition")
                .to_string()
                .contains("Condition section is empty")
        );

        let mut parser =
            ConditionParser::new("$a $b", HashSet::from(["$a".to_owned(), "$b".to_owned()]))
                .expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("trailing token")
                .to_string()
                .contains("Unexpected trailing token")
        );

        let mut parser =
            ConditionParser::new("$missing", HashSet::from(["$a".to_owned()])).expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("unknown pattern")
                .to_string()
                .contains("unknown string id")
        );

        let mut parser =
            ConditionParser::new("0 of ($a)", HashSet::from(["$a".to_owned()])).expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("zero threshold")
                .to_string()
                .contains("threshold must be > 0")
        );

        let mut parser = ConditionParser::new(
            "1 of ($a $b)",
            HashSet::from(["$a".to_owned(), "$b".to_owned()]),
        )
        .expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("missing comma")
                .to_string()
                .contains("Expected ',' or ')'")
        );

        let mut parser =
            ConditionParser::new("( $a ", HashSet::from(["$a".to_owned()])).expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("unterminated paren")
                .to_string()
                .contains("Unexpected end of condition")
        );

        let (strings, condition) = parse_rule_sections(
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
        assert!(
            parse_rule_sections("rule empty { condition: true }")
                .expect_err("missing strings")
                .to_string()
                .contains("strings section")
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
        assert!(
            parse_literal_line(r#"$a = "Ab" nocase"#)
                .expect_err("unsupported flag")
                .to_string()
                .contains("Unsupported literal flag")
        );
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

        let (pattern_id, grams, grams5, fixed_literal) = parse_hex_line_to_grams(
            "$h = { 41 42 43 44 ?? 45 46 47 48 [2-4] 49 4A 4B 4C }",
            GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
                .expect("default gram sizes"),
        )
        .expect("hex line")
        .expect("parsed hex");
        assert_eq!(pattern_id, "$h");
        assert_eq!(grams.len(), 3);
        assert_eq!(grams5.len(), 6);
        assert!(fixed_literal.is_empty());
        assert!(is_gap_token("[3]"));
        assert!(is_gap_token("[1-9]"));
        assert!(!is_gap_token("[a-b]"));
        assert!(
            parse_hex_line_to_grams(
                "$h = { }",
                GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
                    .expect("default gram sizes"),
            )
            .expect_err("empty hex body")
            .to_string()
            .contains("is empty")
        );
        assert!(
            parse_hex_line_to_grams(
                "$h = { GG }",
                GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
                    .expect("default gram sizes"),
            )
            .expect_err("bad hex token")
            .to_string()
            .contains("Unsupported hex token")
        );
        assert!(
            parse_hex_line_to_grams(
                "$h = \"ABCD\"",
                GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
                    .expect("default gram sizes"),
            )
            .expect("literal line should be ignored")
            .is_none()
        );

        let grams = grams_from_bytes(b"ABCDEABCDE", 4);
        assert_eq!(grams.len(), 5);
        let ranked = optimize_grams(
            &grams,
            b"ABCDEABCDE",
            4,
            Some(&HashMap::from([(grams[1], 1usize)])),
            2,
        );
        assert_eq!(ranked.len(), 2);
        assert!(ranked.contains(&grams[1]));
        assert_eq!(optimize_grams(&grams, b"", 4, None, 0), grams);
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
        let df = HashMap::from([
            (u64::from(u32::from_le_bytes(*b"ABCD")), 9usize),
            (u64::from(u32::from_le_bytes([1, 2, 3, 4])), 1usize),
        ]);
        let plan = compile_query_plan(rule, Some(&df), 1, true, false, 9).expect("compile");
        assert!(plan.force_tier1_only);
        assert!(!plan.allow_tier2_fallback);
        assert_eq!(plan.max_candidates, 9);
        assert_eq!(plan.patterns.len(), 3);
        assert!(matches!(plan.root.kind.as_str(), "and"));
        assert!(plan.patterns.iter().all(|pattern| {
            pattern
                .alternatives
                .iter()
                .all(|alternative| alternative.len() <= 1)
        }));

        assert_eq!(
            compile_query_plan(rule, None, 1, false, true, 0)
                .expect("zero means unlimited")
                .max_candidates,
            usize::MAX
        );
        assert!(
            compile_query_plan(
                r#"
rule bad {
  strings:
    $a = "ABCD"
  condition:
    1 of ($a, $missing)
}
"#,
                None,
                8,
                false,
                true,
                100,
            )
            .expect_err("unknown pattern in condition")
            .to_string()
            .contains("unknown string id")
        );
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
        let plan = compile_query_plan(rule, None, 16, false, true, 100_000).expect("plan");
        let literal_plan = fixed_literal_match_plan(&plan).expect("fixed literal plan");
        assert_eq!(literal_plan.literals["$a"], vec![b"ABCD".to_vec()]);
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
    $a = "AB" ascii wide
  condition:
    $a
}
"#;
        let plan = compile_query_plan(rule, None, 16, false, true, 100_000).expect("plan");
        let literal_plan = fixed_literal_match_plan(&plan).expect("fixed literal plan");
        let literals = literal_plan.literals.get("$a").expect("literals");
        assert_eq!(literals.len(), 2);
        assert_eq!(literals[0], b"AB".to_vec());
        assert_eq!(literals[1], vec![b'A', 0, b'B', 0]);
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
        let plan = compile_query_plan(rule, None, 4, false, true, 100_000).expect("plan");
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
        let plan = compile_query_plan_from_file(&rule_path, None, 8, false, true, 100)
            .expect("plan from file");
        assert_eq!(plan.patterns.len(), 1);
    }

    #[test]
    fn parser_and_helper_edge_cases_cover_remaining_branches() {
        let mut parser =
            ConditionParser::new("$a", HashSet::from(["$a".to_owned()])).expect("parser");
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
            ConditionParser::new("1 of ($a,", HashSet::from(["$a".to_owned()])).expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("unterminated n-of")
                .to_string()
                .contains("Unexpected end of condition")
        );

        let mut parser =
            ConditionParser::new("and", HashSet::from(["$a".to_owned()])).expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("unsupported condition token")
                .to_string()
                .contains("Unsupported condition token")
        );

        assert!(
            tokenize_condition("xor")
                .expect_err("unsupported alpha token")
                .to_string()
                .contains("Unsupported token in condition")
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
        assert_eq!(fixed.3, b"ABCDE".to_vec());
        assert_eq!(fixed.1.len(), 2);
        assert_eq!(fixed.2.len(), 3);
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
        let df_counts = HashMap::from([(1u64, 100usize), (2u64, 50usize), (3u64, 1usize)]);
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
        reorder_or_nodes_for_selectivity(&mut root, &patterns, Some(&df_counts));
        assert_eq!(root.children[0].pattern_id.as_deref(), Some("$b"));
        assert_eq!(
            pattern_selectivity_score("$missing", &patterns, Some(&df_counts)),
            u128::MAX
        );
        assert_eq!(
            node_selectivity_score(
                &QueryNode {
                    kind: "bogus".to_owned(),
                    pattern_id: None,
                    threshold: None,
                    children: Vec::new(),
                },
                &patterns,
                Some(&df_counts)
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
        let plan = compile_query_plan_with_tier2_gram_size(rule, 3, None, 8, false, true, 50)
            .expect("plan");
        assert_eq!(plan.tier2_gram_size, 3);
        assert_eq!(plan.tier1_gram_size, DEFAULT_TIER1_GRAM_SIZE);

        let tmp = tempdir().expect("tmp");
        let rule_path = tmp.path().join("rule.yar");
        fs::write(&rule_path, rule).expect("rule");
        let plan = compile_query_plan_from_file_with_tier2_gram_size(
            &rule_path, 3, None, 8, false, true, 50,
        )
        .expect("plan from file");
        assert_eq!(plan.tier2_gram_size, 3);
        assert_eq!(plan.max_candidates, 50);
    }

    #[test]
    fn fixed_literal_helpers_cover_invalid_shapes_and_ast_variants() {
        let mut patterns = BTreeMap::new();
        patterns.insert("$a".to_owned(), vec![vec![1_u64, 2, 3]]);
        patterns.insert("$b".to_owned(), vec![vec![4_u64, 5]]);
        let df_counts = HashMap::from([
            (1_u64, 10_usize),
            (2_u64, 9_usize),
            (3_u64, 8_usize),
            (4_u64, 3_usize),
            (5_u64, 4_usize),
        ]);

        assert_eq!(
            node_selectivity_score(
                &QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: None,
                    threshold: None,
                    children: Vec::new(),
                },
                &patterns,
                Some(&df_counts),
            ),
            u128::MAX
        );
        let pattern_b_score = pattern_selectivity_score("$b", &patterns, Some(&df_counts));
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
                Some(&df_counts),
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
                Some(&df_counts),
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
                Some(&df_counts),
            ),
            pattern_b_score
        );

        let invalid_empty = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$bad".to_owned(),
                alternatives: vec![vec![1_u64]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$bad".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 1,
            tier2_gram_size: 3,
            tier1_gram_size: 4,
        };
        assert!(fixed_literal_match_plan(&invalid_empty).is_none());

        let invalid_alternatives = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$bad".to_owned(),
                alternatives: vec![vec![1_u64], vec![2_u64]],
                tier2_alternatives: vec![Vec::new(), Vec::new()],
                fixed_literals: vec![vec![0x41]],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$bad".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 1,
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

        let (alts, alts5, literals) = dedupe_pattern_alternatives(
            vec![vec![1_u64, 2], vec![1_u64, 2], vec![3_u64]],
            vec![vec![7_u64], vec![7_u64], vec![8_u64]],
            vec![b"AB".to_vec(), b"AB".to_vec(), b"CD".to_vec()],
        );
        assert_eq!(alts, vec![vec![1_u64, 2], vec![3_u64]]);
        assert_eq!(alts5, vec![vec![7_u64], vec![8_u64]]);
        assert_eq!(literals, vec![b"AB".to_vec(), b"CD".to_vec()]);
    }
}
