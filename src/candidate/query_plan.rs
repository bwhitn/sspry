use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::candidate::{
    GramSizes, metadata_field_is_boolean, normalize_query_metadata_field, pack_exact_gram,
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
    pub fixed_literals: Vec<Vec<u8>>,
    #[serde(default)]
    pub fixed_literal_wide: Vec<bool>,
    #[serde(default)]
    pub fixed_literal_fullword: Vec<bool>,
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
    exact_literals: bool,
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    LParen,
    RParen,
    Comma,
    EqEq,
    And,
    Any,
    All,
    Or,
    Of,
    Them,
    Int(usize),
    Float(f64),
    Bool(bool),
    Id(String),
    Name(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NumericReadKind {
    Integer,
    Float,
}

const NUMERIC_READ_ANCHOR_PREFIX: &str = "__numeric_eq_anchor_";

struct ConditionParser {
    tokens: Vec<Token>,
    index: usize,
    known_patterns: HashSet<String>,
    known_pattern_names: Vec<String>,
}

fn magic_numeric_eq_rewrite(name: &str, offset: usize, value: usize) -> Option<&'static str> {
    match (name, offset, value) {
        ("uint16", 0, 0x5a4d) | ("uint16be", 0, 0x4d5a) => Some("pe.is_pe"),
        ("uint16", 0, 0x457f)
        | ("uint16be", 0, 0x7f45)
        | ("uint32", 0, 0x464c457f)
        | ("uint32be", 0, 0x7f454c46) => Some("elf.is_elf"),
        ("uint32", 0, 0x04034b50) | ("uint32be", 0, 0x504b0304) => Some("zip.is_zip"),
        _ => None,
    }
}

impl ConditionParser {
    fn new(text: &str, known_patterns: HashSet<String>) -> Result<Self> {
        let mut known_pattern_names = known_patterns.iter().cloned().collect::<Vec<_>>();
        known_pattern_names.sort();
        Ok(Self {
            tokens: tokenize_condition(text)?,
            index: 0,
            known_patterns,
            known_pattern_names,
        })
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

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
                    return Err(SspryError::from(format!(
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
                if matches!(self.peek(), Some(Token::LParen)) {
                    self.consume(Some(&Token::LParen))?;
                    let Token::Int(offset) = self.consume(None)? else {
                        return Err(SspryError::from(format!(
                            "{field_name} requires an integer byte offset."
                        )));
                    };
                    self.consume(Some(&Token::RParen))?;
                    self.consume(Some(&Token::EqEq))?;
                    let literal_token = self.consume(None)?;
                    if let Token::Int(value) = literal_token
                        && let Some(metadata_field) =
                            magic_numeric_eq_rewrite(&field_name, offset, value)
                    {
                        return Ok(QueryNode {
                            kind: "metadata_eq".to_owned(),
                            pattern_id: Some(metadata_field.to_owned()),
                            threshold: Some(1),
                            children: Vec::new(),
                        });
                    }
                    if let Some(read_kind) = numeric_read_kind(&field_name) {
                        let literal_text = match (read_kind, literal_token) {
                            (NumericReadKind::Integer, Token::Int(value)) => value.to_string(),
                            (NumericReadKind::Float, Token::Int(value)) => value.to_string(),
                            (NumericReadKind::Float, Token::Float(value)) => value.to_string(),
                            _ => {
                                return Err(SspryError::from(format!(
                                    "{field_name} requires equality against a literal constant."
                                )));
                            }
                        };
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
                let normalized = normalize_query_metadata_field(&field_name)
                    .or_else(|| {
                        if field_name == "filesize" {
                            Some("filesize")
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        SspryError::from(format!("Unsupported condition field: {field_name}"))
                    })?;
                if matches!(self.peek(), Some(Token::EqEq)) {
                    self.consume(Some(&Token::EqEq))?;
                    let threshold = match self.consume(None)? {
                        Token::Int(value) => value,
                        Token::Bool(value) if metadata_field_is_boolean(normalized) => {
                            usize::from(value)
                        }
                        _ => {
                            return Err(SspryError::from(format!(
                                "Expected literal equality value after {field_name} ==."
                            )));
                        }
                    };
                    let kind = match normalized {
                        "filesize" => "filesize_eq",
                        "time.now" => "time_now_eq",
                        _ => "metadata_eq",
                    };
                    Ok(QueryNode {
                        kind: kind.to_owned(),
                        pattern_id: Some(normalized.to_owned()),
                        threshold: Some(threshold),
                        children: Vec::new(),
                    })
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
            Some(token) => Err(SspryError::from(format!(
                "Unsupported condition token: {token:?}"
            ))),
            None => Err(SspryError::from("Unexpected end of condition.")),
        }
    }

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
            .map(|pattern_id| QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some(pattern_id),
                threshold: None,
                children: Vec::new(),
            })
            .collect())
    }

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
            '=' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::EqEq);
                    index += 2;
                    continue;
                }
                return Err(SspryError::from("Unsupported token in condition near: '='"));
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
            if matches!(chars.get(index), Some('.')) {
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
            let raw: String = chars[start..index].iter().collect();
            let value = raw
                .parse::<usize>()
                .map_err(|_| SspryError::from(format!("Invalid integer token: {raw}")))?;
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
        return Err(SspryError::from(
            "Rule does not contain a strings section with supported entries.",
        ));
    }
    if condition_lines.is_empty() {
        return Err(SspryError::from(
            "Rule does not contain a condition section.",
        ));
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
        if flag != "ascii" && flag != "wide" && flag != "fullword" {
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
    if flags.contains("ascii") {
        alternatives.push(literal_text.as_bytes().to_vec());
        wide_flags.push(false);
        fullword_flags.push(flags.contains("fullword"));
    }
    if flags.contains("wide") {
        let mut wide = Vec::with_capacity(literal_text.len() * 2);
        for unit in literal_text.encode_utf16() {
            wide.extend_from_slice(&unit.to_le_bytes());
        }
        alternatives.push(wide);
        wide_flags.push(true);
        fullword_flags.push(flags.contains("fullword"));
    }

    Ok(Some(PatternDef {
        pattern_id: pattern_id.to_owned(),
        alternatives,
        wide_flags,
        fullword_flags,
        exact_literals: true,
    }))
}

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
    if literal.len() < gram_sizes.tier1 {
        return Err(SspryError::from(format!(
            "Regex {pattern_id} does not contain a mandatory literal long enough for tier1 grams."
        )));
    }

    let mut alternatives = Vec::new();
    let mut wide_flags = Vec::new();
    let mut fullword_flags = Vec::new();
    if flags.contains("ascii") {
        alternatives.push(literal.clone());
        wide_flags.push(false);
        fullword_flags.push(flags.contains("fullword"));
    }
    if flags.contains("wide") {
        let mut wide = Vec::with_capacity(literal.len() * 2);
        for byte in &literal {
            wide.push(*byte);
            wide.push(0);
        }
        if wide.len() >= gram_sizes.tier1 {
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

    Ok(Some(PatternDef {
        pattern_id: pattern_id.to_owned(),
        alternatives,
        wide_flags,
        fullword_flags,
        exact_literals: false,
    }))
}

fn extract_regex_mandatory_literal(regex_raw: &str) -> Result<Vec<u8>> {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RegexAtom {
        Literal(u8),
        Variable,
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

    let chars = regex_raw.chars().collect::<Vec<_>>();
    let mut best = Vec::<u8>::new();
    let mut current = Vec::<u8>::new();
    let mut index = 0usize;
    while index < chars.len() {
        let atom = match chars[index] {
            '^' | '$' => {
                index += 1;
                RegexAtom::Anchor
            }
            '(' | ')' | '|' => {
                return Err(SspryError::from(
                    "Unsupported regex string: groups and alternation are not searchable yet.",
                ));
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
                    'n' => RegexAtom::Literal(b'\n'),
                    'r' => RegexAtom::Literal(b'\r'),
                    't' => RegexAtom::Literal(b'\t'),
                    'x' => {
                        if index + 1 > chars.len() {
                            return Err(SspryError::from("Invalid regex hex escape."));
                        }
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
                        RegexAtom::Literal(value)
                    }
                    other if other.is_ascii() => RegexAtom::Literal(other as u8),
                    _ => {
                        return Err(SspryError::from(
                            "Unsupported non-ASCII regex escape in searchable regex.",
                        ));
                    }
                }
            }
            ch if ch.is_ascii() => {
                index += 1;
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
            RegexAtom::Literal(_) | RegexAtom::Variable => {
                if current.len() > best.len() {
                    best = current.clone();
                }
                current.clear();
            }
        }
    }
    if current.len() > best.len() {
        best = current;
    }
    if best.is_empty() {
        return Err(SspryError::from(
            "Regex string does not contain a searchable mandatory literal.",
        ));
    }
    Ok(best)
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
        return Err(SspryError::from(format!(
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
                    .map_err(|_| SspryError::from(format!("Invalid hex byte: {token}")))?,
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
        return Err(SspryError::from(format!(
            "Unsupported hex token for {pattern_id}: {token:?}. Supported: concrete bytes, ??, [n], [n-m]."
        )));
    }
    if !current.is_empty() {
        runs.push(current);
    }

    let mut seen = HashSet::new();
    let mut seen_tier2 = HashSet::new();
    let mut grams = Vec::new();
    let mut tier2_grams = Vec::new();
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
            if seen_tier2.insert(gram) {
                tier2_grams.push(gram);
            }
        }
    }
    Ok(Some((
        pattern_id.to_owned(),
        grams,
        tier2_grams,
        fixed_literal,
    )))
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
    max_anchors_per_alt: usize,
) -> Vec<u64> {
    if grams.is_empty() || max_anchors_per_alt == 0 || grams.len() <= max_anchors_per_alt {
        return grams.to_vec();
    }
    let has_positions = !fixed_literal.is_empty() && fixed_literal.len() >= gram_size;
    if !has_positions {
        let mut ranked = grams.to_vec();
        ranked.sort_unstable();
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
            let better = (usize::MAX - spread, *gram) < (usize::MAX - best_spread, best_gram);
            if better {
                best_idx = idx;
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
    fixed_literal_wide: Vec<bool>,
    fixed_literal_fullword: Vec<bool>,
) -> (Vec<Vec<u64>>, Vec<Vec<u64>>, Vec<Vec<u8>>, Vec<bool>, Vec<bool>) {
    let mut seen = HashSet::<(Vec<u64>, Vec<u64>, Vec<u8>, bool, bool)>::new();
    let mut kept_tier1 = Vec::new();
    let mut kept_tier2 = Vec::new();
    let mut kept_literals = Vec::new();
    let mut kept_wide = Vec::new();
    let mut kept_fullword = Vec::new();
    let max_len = alternatives
        .len()
        .max(tier2_alternatives.len())
        .max(fixed_literals.len())
        .max(fixed_literal_wide.len())
        .max(fixed_literal_fullword.len());
    for index in 0..max_len {
        let tier1 = alternatives.get(index).cloned().unwrap_or_default();
        let tier2 = tier2_alternatives.get(index).cloned().unwrap_or_default();
        let literal = fixed_literals.get(index).cloned().unwrap_or_default();
        let wide = fixed_literal_wide.get(index).copied().unwrap_or(false);
        let fullword = fixed_literal_fullword.get(index).copied().unwrap_or(false);
        if !seen.insert((tier1.clone(), tier2.clone(), literal.clone(), wide, fullword)) {
            continue;
        }
        kept_tier1.push(tier1);
        kept_tier2.push(tier2);
        kept_literals.push(literal);
        kept_wide.push(wide);
        kept_fullword.push(fullword);
    }
    (
        kept_tier1,
        kept_tier2,
        kept_literals,
        kept_wide,
        kept_fullword,
    )
}

fn numeric_read_kind(name: &str) -> Option<NumericReadKind> {
    match name {
        "int32" | "uint32" | "int32be" | "uint32be" => Some(NumericReadKind::Integer),
        "float32" | "float64" | "float32be" | "float64be" => Some(NumericReadKind::Float),
        _ => None,
    }
}

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

fn numeric_read_anchor_bytes(name: &str, literal_text: &str) -> Result<Vec<u8>> {
    match name {
        "int32" | "uint32" => {
            let value = literal_text.parse::<u32>().map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?;
            Ok(value.to_le_bytes().to_vec())
        }
        "int32be" | "uint32be" => {
            let value = literal_text.parse::<u32>().map_err(|_| {
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

fn inject_numeric_read_anchor_patterns(
    node: &mut QueryNode,
    pattern_alternatives: &mut BTreeMap<String, Vec<Vec<u64>>>,
    pattern_tier2_alternatives: &mut BTreeMap<String, Vec<Vec<u64>>>,
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

fn contains_verifier_only_eq(node: &QueryNode) -> bool {
    node.kind == "verifier_only_eq" || node.children.iter().any(contains_verifier_only_eq)
}

fn contains_pattern_node(node: &QueryNode) -> bool {
    node.kind == "pattern" || node.children.iter().any(contains_pattern_node)
}

pub fn fixed_literal_match_plan(plan: &CompiledQueryPlan) -> Option<FixedLiteralMatchPlan> {
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
        literal_wide.insert(pattern.pattern_id.clone(), pattern.fixed_literal_wide.clone());
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
        "filesize_eq" => Err(SspryError::from(
            "filesize_eq requires file metadata and cannot use the fixed-literal fast path",
        )),
        "verifier_only_eq" => Err(SspryError::from(
            "verifier_only_eq requires file verification and cannot use the fixed-literal fast path",
        )),
        "metadata_eq" => Err(SspryError::from(
            "metadata_eq requires stored metadata and cannot use the fixed-literal fast path",
        )),
        "time_now_eq" => Err(SspryError::from(
            "time_now_eq requires runtime evaluation and cannot use the fixed-literal fast path",
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
        "filesize_eq" | "metadata_eq" | "time_now_eq" | "verifier_only_eq" => u128::MAX / 2,
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

pub fn compile_query_plan_with_gram_sizes(
    rule_text: &str,
    gram_sizes: GramSizes,
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
    let mut pattern_fixed_literal_wide = BTreeMap::<String, Vec<bool>>::new();
    let mut pattern_fixed_literal_fullword = BTreeMap::<String, Vec<bool>>::new();
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
            let fixed_literals = if def.exact_literals {
                def.alternatives.clone()
            } else {
                vec![Vec::new(); def.alternatives.len()]
            };
            pattern_alternatives.insert(def.pattern_id.clone(), alternatives);
            pattern_tier2_alternatives.insert(def.pattern_id.clone(), tier2_alternatives);
            pattern_fixed_literals.insert(def.pattern_id.clone(), fixed_literals);
            pattern_fixed_literal_wide.insert(def.pattern_id.clone(), def.wide_flags);
            pattern_fixed_literal_fullword.insert(def.pattern_id, def.fullword_flags);
            continue;
        }
        if let Some(def) = parse_regex_line(&line, gram_sizes)? {
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
            pattern_alternatives.insert(def.pattern_id.clone(), alternatives);
            pattern_tier2_alternatives.insert(def.pattern_id.clone(), tier2_alternatives);
            pattern_fixed_literals.insert(def.pattern_id.clone(), fixed_literals);
            pattern_fixed_literal_wide.insert(def.pattern_id.clone(), def.wide_flags);
            pattern_fixed_literal_fullword.insert(def.pattern_id, def.fullword_flags);
            continue;
        }
        if let Some((pattern_id, grams, tier2_grams, fixed_literal)) =
            parse_hex_line_to_grams(&line, gram_sizes)?
        {
            pattern_alternatives.insert(pattern_id.clone(), vec![grams]);
            pattern_tier2_alternatives.insert(pattern_id.clone(), vec![tier2_grams]);
            pattern_fixed_literals.insert(pattern_id.clone(), vec![fixed_literal]);
            pattern_fixed_literal_wide.insert(pattern_id.clone(), vec![false]);
            pattern_fixed_literal_fullword.insert(pattern_id, vec![false]);
            continue;
        }
        return Err(SspryError::from(format!(
            "Unsupported strings declaration: {:?}. Supported forms: $id = \"...\" [ascii|wide|fullword], $id = /.../ [ascii|wide|fullword], $id = {{ ... }}",
            line.trim()
        )));
    }

    let mut parser = ConditionParser::new(
        &condition_text,
        pattern_alternatives.keys().cloned().collect(),
    )?;
    let mut root = parser.parse()?;
    let mut next_numeric_anchor_id = 0usize;
    inject_numeric_read_anchor_patterns(
        &mut root,
        &mut pattern_alternatives,
        &mut pattern_tier2_alternatives,
        &mut pattern_fixed_literals,
        &mut pattern_fixed_literal_wide,
        &mut pattern_fixed_literal_fullword,
        gram_sizes,
        &mut next_numeric_anchor_id,
    )?;
    if !contains_pattern_node(&root) && contains_verifier_only_eq(&root) {
        return Err(SspryError::from(
            "Numeric read equality in indexed search requires an anchorable literal for the current gram sizes or another string/hex anchor.",
        ));
    }
    reorder_or_nodes_for_selectivity(&mut root, &pattern_alternatives);
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
        let fixed_literal_wide = pattern_fixed_literal_wide
            .remove(&pattern_id)
            .unwrap_or_else(|| vec![false; alternatives.len()]);
        let fixed_literal_fullword = pattern_fixed_literal_fullword
            .remove(&pattern_id)
            .unwrap_or_else(|| vec![false; alternatives.len()]);
        let (
            alternatives,
            tier2_alternatives,
            fixed_literals,
            fixed_literal_wide,
            fixed_literal_fullword,
        ) = dedupe_pattern_alternatives(
            alternatives,
            tier2_alternatives,
            fixed_literals,
            fixed_literal_wide,
            fixed_literal_fullword,
        );
        let per_pattern_budget = branch_budgets
            .get(&pattern_id)
            .copied()
            .unwrap_or(max_anchors_per_alt);
        let optimized = alternatives
            .iter()
            .zip(fixed_literals.iter())
            .map(|(alt, fixed_literal)| {
                optimize_grams(alt, fixed_literal, gram_sizes.tier1, per_pattern_budget)
            })
            .collect();
        patterns.push(PatternPlan {
            pattern_id,
            alternatives: optimized,
            tier2_alternatives,
            fixed_literals,
            fixed_literal_wide,
            fixed_literal_fullword,
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

pub fn compile_query_plan_from_file_with_gram_sizes(
    rule_path: impl AsRef<Path>,
    gram_sizes: GramSizes,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: usize,
) -> Result<CompiledQueryPlan> {
    let text = fs::read_to_string(rule_path)?;
    compile_query_plan_with_gram_sizes(
        &text,
        gram_sizes,
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

    use crate::candidate::{DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE};

    use super::*;

    fn default_gram_sizes() -> GramSizes {
        GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
            .expect("default gram sizes")
    }

    fn compile_query_plan_default(
        rule_text: &str,
        max_anchors_per_alt: usize,
        force_tier1_only: bool,
        allow_tier2_fallback: bool,
        max_candidates: usize,
    ) -> Result<CompiledQueryPlan> {
        compile_query_plan_with_gram_sizes(
            rule_text,
            default_gram_sizes(),
            max_anchors_per_alt,
            force_tier1_only,
            allow_tier2_fallback,
            max_candidates,
        )
    }

    fn compile_query_plan_from_file_default(
        rule_path: impl AsRef<Path>,
        max_anchors_per_alt: usize,
        force_tier1_only: bool,
        allow_tier2_fallback: bool,
        max_candidates: usize,
    ) -> Result<CompiledQueryPlan> {
        compile_query_plan_from_file_with_gram_sizes(
            rule_path,
            default_gram_sizes(),
            max_anchors_per_alt,
            force_tier1_only,
            allow_tier2_fallback,
            max_candidates,
        )
    }

    fn compile_query_plan_with_tier2_default_tier1(
        rule_text: &str,
        tier2_gram_size: usize,
        max_anchors_per_alt: usize,
        force_tier1_only: bool,
        allow_tier2_fallback: bool,
        max_candidates: usize,
    ) -> Result<CompiledQueryPlan> {
        compile_query_plan_with_gram_sizes(
            rule_text,
            GramSizes::new(tier2_gram_size, DEFAULT_TIER1_GRAM_SIZE)?,
            max_anchors_per_alt,
            force_tier1_only,
            allow_tier2_fallback,
            max_candidates,
        )
    }

    fn compile_query_plan_from_file_with_tier2_default_tier1(
        rule_path: impl AsRef<Path>,
        tier2_gram_size: usize,
        max_anchors_per_alt: usize,
        force_tier1_only: bool,
        allow_tier2_fallback: bool,
        max_candidates: usize,
    ) -> Result<CompiledQueryPlan> {
        compile_query_plan_from_file_with_gram_sizes(
            rule_path,
            GramSizes::new(tier2_gram_size, DEFAULT_TIER1_GRAM_SIZE)?,
            max_anchors_per_alt,
            force_tier1_only,
            allow_tier2_fallback,
            max_candidates,
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
        assert!(compile_query_plan_default(rule, 8, false, true, 100_000).is_err());
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
    fn compile_rule_rewrites_header_magic_numeric_reads_to_metadata() {
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
        assert!(plan.root.children.iter().any(|child| {
            child.kind == "metadata_eq"
                && child.pattern_id.as_deref() == Some("pe.is_pe")
                && child.threshold == Some(1)
        }));
        assert!(plan.root.children.iter().any(|child| {
            child.kind == "metadata_eq"
                && child.pattern_id.as_deref() == Some("elf.is_elf")
                && child.threshold == Some(1)
        }));
        assert!(plan.root.children.iter().any(|child| {
            child.kind == "metadata_eq"
                && child.pattern_id.as_deref() == Some("zip.is_zip")
                && child.threshold == Some(1)
        }));
        assert!(plan.root.children.iter().any(|child| {
            child.kind == "and"
                && child.children.iter().any(|grandchild| grandchild.kind == "verifier_only_eq")
        }));
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
                    grandchild.kind == "verifier_only_eq"
                        && grandchild.pattern_id.as_deref().is_some()
                }));
                verifier_children += 1;
            }
        }
        assert_eq!(verifier_children, 2);
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
            child.kind == "verifier_only_eq"
                && child.pattern_id.as_deref() == Some("uint32(0)==16384")
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
        let err = compile_query_plan_with_gram_sizes(
            rule,
            GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, 5).expect("gram sizes"),
            8,
            false,
            true,
            100_000,
        )
        .expect_err("unanchorable numeric-only condition should fail");
        assert!(
            err.to_string()
                .contains("requires an anchorable literal for the current gram sizes")
        );
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
            "pe.machine",
            HashSet::from(["$a".to_owned(), "$b".to_owned()]),
        )
        .expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("missing metadata equality")
                .to_string()
                .contains("requires == <literal>")
        );

        let mut parser = ConditionParser::new("uint32(x) == 1", HashSet::from(["$a".to_owned()]))
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
            HashSet::from([
                "$a1".to_owned(),
                "$a2".to_owned(),
                "$b1".to_owned(),
            ]),
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
        )
        .expect("parser");
        let them = parser.parse().expect("them parse");
        assert_eq!(them.kind, "n_of");
        assert_eq!(them.threshold, Some(1));
        assert_eq!(them.children.len(), 2);

        let mut parser = ConditionParser::new(
            "1 of $missing*",
            HashSet::from(["$a".to_owned(), "$b".to_owned()]),
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
        let fullword = parse_literal_line(r#"$a = "Ab" fullword"#)
            .expect("literal")
            .expect("pattern");
        assert_eq!(fullword.fullword_flags, vec![true]);
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

        let (pattern_id, grams, tier2_grams, fixed_literal) = parse_hex_line_to_grams(
            "$h = { 41 42 43 44 ?? 45 46 47 48 [2-4] 49 4A 4B 4C }",
            GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
                .expect("default gram sizes"),
        )
        .expect("hex line")
        .expect("parsed hex");
        assert_eq!(pattern_id, "$h");
        assert_eq!(grams.len(), 3);
        assert_eq!(tier2_grams.len(), 6);
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
        let ranked = optimize_grams(&grams, b"ABCDEABCDE", 4, 2);
        assert_eq!(ranked.len(), 2);
        assert_eq!(optimize_grams(&grams, b"", 4, 0), grams);

        let regex = parse_regex_line(
            r#"$r = /[A-Z]+applesause[0-9]+/"#,
            GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
                .expect("default gram sizes"),
        )
        .expect("regex parse")
        .expect("regex pattern");
        assert_eq!(regex.alternatives, vec![b"applesause".to_vec()]);
        assert!(!regex.exact_literals);

        let regex_escaped = parse_regex_line(
            r#"$r = /https?:\/\/evil\.com/"#,
            GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
                .expect("default gram sizes"),
        )
        .expect("regex parse")
        .expect("regex pattern");
        assert_eq!(regex_escaped.alternatives, vec![b"://evil.com".to_vec()]);
        assert!(
            parse_regex_line(
                r#"$r = /(apple|orange)/"#,
                GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
                    .expect("default gram sizes"),
            )
            .expect_err("alternation unsupported")
            .to_string()
            .contains("groups and alternation")
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
            compile_query_plan_default(rule, 1, false, true, 0)
                .expect("zero means unlimited")
                .max_candidates,
            usize::MAX
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
        assert!(wildcard_sets.root.children.iter().all(|child| child.kind == "n_of"));

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
            .expect_err("numeric-only indexed search without anchorable grams")
            .to_string()
            .contains("requires an anchorable literal")
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

        let mut parser = ConditionParser::new("xor == 7", HashSet::new()).expect("parser");
        assert!(
            parser
                .parse()
                .expect_err("unsupported condition field")
                .to_string()
                .contains("Unsupported condition field")
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
            compile_query_plan_with_tier2_default_tier1(rule, 3, 8, false, true, 50).expect("plan");
        assert_eq!(plan.tier2_gram_size, 3);
        assert_eq!(plan.tier1_gram_size, DEFAULT_TIER1_GRAM_SIZE);

        let tmp = tempdir().expect("tmp");
        let rule_path = tmp.path().join("rule.yar");
        fs::write(&rule_path, rule).expect("rule");
        let plan = compile_query_plan_from_file_with_tier2_default_tier1(
            &rule_path, 3, 8, false, true, 50,
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

        let (alts, alts5, literals, wide, fullword) = dedupe_pattern_alternatives(
            vec![vec![1_u64, 2], vec![1_u64, 2], vec![3_u64]],
            vec![vec![7_u64], vec![7_u64], vec![8_u64]],
            vec![b"AB".to_vec(), b"AB".to_vec(), b"CD".to_vec()],
            vec![false, false, true],
            vec![false, false, true],
        );
        assert_eq!(alts, vec![vec![1_u64, 2], vec![3_u64]]);
        assert_eq!(alts5, vec![vec![7_u64], vec![8_u64]]);
        assert_eq!(literals, vec![b"AB".to_vec(), b"CD".to_vec()]);
        assert_eq!(wide, vec![false, true]);
        assert_eq!(fullword, vec![false, true]);
    }
}
