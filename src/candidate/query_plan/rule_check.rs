#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RuleSourceLocation {
    line: usize,
    column: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuleSourceMatch {
    location: RuleSourceLocation,
    snippet: String,
}

struct RuleSourceContext<'a> {
    full_text: &'a str,
    block_text: &'a str,
    block_start_offset: usize,
}

/// Converts a byte offset in the full rule text into a 1-based line and column
/// location.
fn source_location_for_offset(rule_text: &str, offset: usize) -> RuleSourceLocation {
    let mut line = 1usize;
    let mut column = 1usize;
    for ch in rule_text[..offset.min(rule_text.len())].chars() {
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    RuleSourceLocation { line, column }
}

/// Returns the trimmed source line that contains `offset`.
fn source_snippet_for_offset(rule_text: &str, offset: usize) -> String {
    let bounded_offset = offset.min(rule_text.len());
    let line_start = rule_text[..bounded_offset]
        .rfind('\n')
        .map(|value| value + 1)
        .unwrap_or(0);
    let line_end = rule_text[bounded_offset..]
        .find('\n')
        .map(|value| bounded_offset + value)
        .unwrap_or(rule_text.len());
    rule_text[line_start..line_end].trim().to_owned()
}

/// Builds a source match from a block-relative offset using the surrounding
/// rule source context.
fn source_match_for_offset(context: &RuleSourceContext<'_>, offset: usize) -> RuleSourceMatch {
    RuleSourceMatch {
        location: source_location_for_offset(
            context.full_text,
            context.block_start_offset.saturating_add(offset),
        ),
        snippet: source_snippet_for_offset(context.block_text, offset),
    }
}

/// Finds the first occurrence of a literal anywhere in the current rule block.
fn source_match_for_literal(
    context: &RuleSourceContext<'_>,
    literal: &str,
) -> Option<RuleSourceMatch> {
    context
        .block_text
        .find(literal)
        .map(|offset| source_match_for_offset(context, offset))
}

/// Finds the first occurrence of a literal in the condition section, falling
/// back to a whole-block search when needed.
fn source_match_for_condition_literal(
    context: &RuleSourceContext<'_>,
    literal: &str,
) -> Option<RuleSourceMatch> {
    if let Some(condition_offset) = context.block_text.find("condition:")
        && let Some(relative_offset) = context.block_text[condition_offset..].find(literal)
    {
        return Some(source_match_for_offset(
            context,
            condition_offset + relative_offset,
        ));
    }
    source_match_for_literal(context, literal)
}

/// Finds a pattern identifier inside the condition section.
fn source_match_for_condition_pattern_id(
    context: &RuleSourceContext<'_>,
    pattern_id: &str,
) -> Option<RuleSourceMatch> {
    source_match_for_condition_literal(context, pattern_id)
}

/// Finds a literal inside the strings section of the current rule block.
fn source_match_for_strings_literal(
    context: &RuleSourceContext<'_>,
    literal: &str,
) -> Option<RuleSourceMatch> {
    let strings_offset = context.block_text.find("strings:")?;
    let section_end = context.block_text[strings_offset..]
        .find("condition:")
        .map(|offset| strings_offset + offset)
        .unwrap_or(context.block_text.len());
    let strings_section = &context.block_text[strings_offset..section_end];
    strings_section
        .find(literal)
        .map(|relative_offset| source_match_for_offset(context, strings_offset + relative_offset))
}

/// Returns the first non-whitespace source location inside the strings section.
fn source_match_for_first_strings_line(context: &RuleSourceContext<'_>) -> Option<RuleSourceMatch> {
    let strings_offset = context.block_text.find("strings:")?;
    let tail = &context.block_text[strings_offset..];
    let newline_offset = tail.find('\n')?;
    let body_start = strings_offset + newline_offset + 1;
    let section_end = context.block_text[body_start..]
        .find("condition:")
        .map(|offset| body_start + offset)
        .unwrap_or(context.block_text.len());
    let remaining = &context.block_text[body_start..section_end];
    let first_non_ws = remaining
        .char_indices()
        .find_map(|(idx, ch)| (!ch.is_whitespace()).then_some(idx))?;
    Some(source_match_for_offset(context, body_start + first_non_ws))
}

/// Extracts the quoted message fragment that follows a known error prefix.
fn extract_message_fragment(message: &str, prefix: &str) -> Option<String> {
    let suffix = message.strip_prefix(prefix)?.trim();
    let quoted = suffix.strip_prefix('"')?.strip_suffix('"')?;
    Some(quoted.to_owned())
}

/// Locates the first source position that likely triggered an anchorless
/// verifier-only condition.
fn source_match_for_anchorless_verifier_only_condition(
    context: &RuleSourceContext<'_>,
) -> Option<RuleSourceMatch> {
    for candidate in [
        "uint8(", "uint16(", "uint32(", "uint64(", "int8(", "int16(", "int32(", "int64(",
        "float32(", "float64(", " at ", " in (", "#", "for any", "for all",
    ] {
        if let Some(found) = source_match_for_condition_literal(context, candidate) {
            return Some(found);
        }
    }
    source_match_for_first_condition_line(context)
}

/// Returns the first non-whitespace source location inside the condition
/// section.
fn source_match_for_first_condition_line(
    context: &RuleSourceContext<'_>,
) -> Option<RuleSourceMatch> {
    let condition_offset = context.block_text.find("condition:")?;
    let tail = &context.block_text[condition_offset..];
    let newline_offset = tail.find('\n')?;
    let body_start = condition_offset + newline_offset + 1;
    let remaining = &context.block_text[body_start..];
    let first_non_ws = remaining
        .char_indices()
        .find_map(|(idx, ch)| (!ch.is_whitespace()).then_some(idx))?;
    Some(source_match_for_offset(context, body_start + first_non_ws))
}

/// Locates the most representative source token for a specific verifier-only
/// issue kind.
fn verifier_only_kind_match(
    context: &RuleSourceContext<'_>,
    kind: &str,
) -> Option<RuleSourceMatch> {
    let candidates: &[&str] = match kind {
        "verifier_only_at" => &[" at ", " at\t", " at\r", " at\n"],
        "verifier_only_count" => &["#", " of ("],
        "verifier_only_in_range" => &[" in ("],
        "verifier_only_loop" => &["for any", "for all"],
        "verifier_only_eq" => &[
            "uint8(", "uint16(", "uint32(", "uint64(", "int8(", "int16(", "int32(", "int64(",
        ],
        _ => &[],
    };
    candidates
        .iter()
        .find_map(|candidate| source_match_for_literal(context, candidate))
}

/// Builds one structured rule-check issue with optional source location and
/// remediation text.
fn rule_check_issue(
    rule_name: Option<&str>,
    code: &str,
    severity: RuleCheckSeverity,
    message: impl Into<String>,
    source_match: Option<RuleSourceMatch>,
    remediation: Option<String>,
) -> RuleCheckIssue {
    RuleCheckIssue {
        code: code.to_owned(),
        severity,
        message: message.into(),
        rule: rule_name.map(str::to_owned),
        line: source_match.as_ref().map(|value| value.location.line),
        column: source_match.as_ref().map(|value| value.location.column),
        snippet: source_match.map(|value| value.snippet),
        remediation,
    }
}

/// Returns canned remediation guidance for a known rule-check issue code.
fn remediation_for_issue_code(code: &str) -> Option<String> {
    match code {
        "verifier-only-constraint" => Some(
            "Run `search --verify` for exact results, or rewrite the rule around searchable anchored literals only."
                .to_owned(),
        ),
        "verifier-only-byte-equality" => Some(
            "Run `search --verify` for exact numeric or byte-read checks, or keep the full read inside the stored 8-byte file prefix."
                .to_owned(),
        ),
        "verifier-only-offset" => Some(
            "Run `search --verify` for exact offset checks, or rewrite the rule so the match fits inside an exact indexed prefix window such as `at 0` or `at pe.entry_point`."
                .to_owned(),
        ),
        "verifier-only-count" => Some(
            "Run `search --verify` for exact match counts, or rewrite the rule to avoid `#` count constraints."
                .to_owned(),
        ),
        "verifier-only-range" => Some(
            "Run `search --verify` for exact range checks, or rewrite the rule to avoid `in (...)` range constraints."
                .to_owned(),
        ),
        "verifier-only-loop" => Some(
            "Run `search --verify` for exact `for any` or `for all` evaluation, or rewrite the iterator into directly searchable anchored literals."
                .to_owned(),
        ),
        "verifier-only-negation" => Some(
            "Run `search --verify` for exact negative conditions, or rewrite the rule so the excluded terms become positive searchable anchors in separate filtering steps."
                .to_owned(),
        ),
        "negated-search-unbounded" => Some(
            "Add a positive searchable anchor outside the negated condition, or use direct/local YARA verification instead of sspry's indexed candidate search for this rule."
                .to_owned(),
        ),
        "no-parseable-rule-block" => Some(
            "Point `rule-check` at a real YARA rule file rather than an index/include list, or expand the include file before checking it."
                .to_owned(),
        ),
        "no-condition-section" => Some(
            "Add a `condition:` section to the rule so sspry can analyze the searchable logic."
                .to_owned(),
        ),
        "ignored-module-no-anchor" => Some(
            "Add a searchable string or hex anchor that survives after module predicates are pruned, or use `search --verify` on a positively anchored companion rule."
                .to_owned(),
        ),
        "unsupported-regex-flags" => Some(
            "Remove unsupported regex flags such as `nocase`, or rewrite the regex as anchored literals or hex that sspry can index."
                .to_owned(),
        ),
        "unsupported-literal-flags" => Some(
            "Remove unsupported literal flags such as `base64`, or pre-expand the transformed strings into ordinary searchable literals."
                .to_owned(),
        ),
        "unsupported-hex-syntax" => Some(
            "Rewrite the hex string to use sspry's supported syntax: concrete bytes, `??`, bounded gaps like `[n]` or `[n-m]`, and simple same-length groups."
                .to_owned(),
        ),
        "regex-no-mandatory-literal" => Some(
            "Rewrite the regex so it contains a stable mandatory literal anchor, or add a separate mandatory string/hex anchor alongside it."
                .to_owned(),
        ),
        "unsupported-regex-syntax" => Some(
            "Rewrite the regex to avoid unsupported regex syntax, or replace it with anchored literals or hex that sspry can index."
                .to_owned(),
        ),
        "nocase-no-anchorable-window" => Some(
            "Use a longer `nocase` literal, remove `nocase`, or add a separate mandatory anchorable literal so sspry can derive searchable grams."
                .to_owned(),
        ),
        "unsupported-strings-declaration" => Some(
            "Rewrite the string declaration into one of the supported forms: plain literal, regex, or hex with sspry's supported syntax."
                .to_owned(),
        ),
        "unsupported-condition-field" => Some(
            "Rewrite the rule around supported metadata or anchored literals, or reserve this predicate for local verification instead of indexed search."
                .to_owned(),
        ),
        "nonliteral-byte-offset" => Some(
            "Rewrite the byte-read offset to a literal constant that fits an indexed exact window, or move this condition behind `search --verify`."
                .to_owned(),
        ),
        "count-requires-integer-literal" => Some(
            "Rewrite the count comparison to use an integer literal, or verify the rule locally if it depends on dynamic count expressions."
                .to_owned(),
        ),
        "numeric-read-literal-out-of-range" => Some(
            "Use a literal constant that fits the numeric read width, or rewrite the comparison to avoid out-of-range values."
                .to_owned(),
        ),
        "invalid-literal-string" => Some(
            "Fix the string escaping so the literal is valid YARA text, then rerun `rule-check`."
                .to_owned(),
        ),
        "unknown-rule-reference" => Some(
            "Include or inline the referenced helper rule before checking, or fix the rule name reference."
                .to_owned(),
        ),
        "unsupported-condition-syntax" => Some(
            "Rewrite the condition into sspry's supported searchable subset; complex array indexing, bitwise expressions, and iterator-heavy module access are not currently indexed."
                .to_owned(),
        ),
        "unsupported-comparison-operator" => Some(
            "Rewrite the comparison into a supported searchable form such as equality or a positively anchored verify-only rule."
                .to_owned(),
        ),
        "ignored-module-predicate" => Some(
            "Use `search --verify` if these module predicates matter, or rewrite the rule to rely on indexed literals or metadata that sspry can evaluate directly."
                .to_owned(),
        ),
        "hash-identity-mismatch" => Some(
            "Point the check at a DB or server with the matching `--id-source`, or rewrite the rule to use the identity source that DB was built with."
                .to_owned(),
        ),
        "hash-identity-source-unknown" => Some(
            "Run `rule-check` with `--addr`, `--root`, or an explicit `--id-source` so whole-file hash rules can be evaluated against a real DB identity policy."
                .to_owned(),
        ),
        "overbroad-union" => Some(
            "Add a stable mandatory anchor that every matching branch must satisfy, or split the rule so the union fanout stays selective."
                .to_owned(),
        ),
        "low-information-entrypoint-stub" => Some(
            "Add a longer mandatory literal at the entry point, or rewrite the rule around a stronger PE-specific anchor."
                .to_owned(),
        ),
        "low-information-range-rule" => Some(
            "Add a longer mandatory literal outside the suffix/range constraint, or split the rule into a stronger searchable prefilter plus verification."
                .to_owned(),
        ),
        "low-information-single-pattern" => Some(
            "Use a longer literal or combine the pattern with another mandatory searchable condition."
                .to_owned(),
        ),
        "requires-anchorable-literal-direct" => Some(
            "Add a sufficiently specific literal anchor to the direct search condition, or simplify the pattern so sspry can derive searchable grams from it."
                .to_owned(),
        ),
        "requires-anchorable-literal-at-in" => Some(
            "Add a sufficiently specific literal anchor to the `at` or `in` condition, or simplify the pattern so sspry can derive searchable grams from it."
                .to_owned(),
        ),
        "requires-anchorable-literal-loop" => Some(
            "Add a sufficiently specific literal anchor before the iterator, or simplify the looped pattern so sspry can derive searchable grams from it."
                .to_owned(),
        ),
        "requires-anchorable-literal-n-of" => Some(
            "Add a sufficiently specific literal anchor to each `any of` or `all of` branch, or reduce the rule to a smaller searchable subset."
                .to_owned(),
        ),
        "verifier-only-no-anchor" => Some(
            "Add a searchable string or hex anchor so sspry can narrow candidates before verification."
                .to_owned(),
        ),
        "unsupported-hash-function" => Some(
            "Use one of the searchable whole-file hash forms: `hash.md5(0, filesize)`, `hash.sha1(0, filesize)`, or `hash.sha256(0, filesize)`."
                .to_owned(),
        ),
        "whole-file-only" => Some(
            "Rewrite the rule to the searchable whole-file form, or expect it to be unsupported for sspry candidate search."
                .to_owned(),
        ),
        "requires-anchorable-literal" => Some(
            "Add a sufficiently specific literal anchor to the rule, or simplify the pattern so sspry can derive searchable grams from it."
                .to_owned(),
        ),
        "unsupported" => Some(
            "Rewrite the rule into sspry's searchable subset, or use direct/local YARA verification for exact evaluation."
                .to_owned(),
        ),
        _ => None,
    }
}

fn classify_unsupported_issue_code(message: &str) -> &'static str {
    if message == "Rule does not contain a parseable rule block." {
        "no-parseable-rule-block"
    } else if message == "Rule does not contain a condition section." {
        "no-condition-section"
    } else if message.contains("after pruning ignored module predicates") {
        "ignored-module-no-anchor"
    } else if message.starts_with("Unsupported regex flag(s) for ") {
        "unsupported-regex-flags"
    } else if message.starts_with("Unsupported literal flag(s) for ") {
        "unsupported-literal-flags"
    } else if message.starts_with("Unsupported hex token for ") {
        "unsupported-hex-syntax"
    } else if message == "Regex string does not contain a searchable mandatory literal." {
        "regex-no-mandatory-literal"
    } else if message.starts_with("Unsupported regex quantifier")
        || message == "Unsupported regex quantifier body."
        || message == "Unsupported regex group extension in searchable regex."
    {
        "unsupported-regex-syntax"
    } else if message
        == "nocase literal does not contain an anchorable window for the active gram sizes"
    {
        "nocase-no-anchorable-window"
    } else if message.starts_with("Unsupported strings declaration: ") {
        "unsupported-strings-declaration"
    } else if message.starts_with("Unsupported condition field: ") {
        "unsupported-condition-field"
    } else if message.ends_with("requires an integer byte offset.") {
        "nonliteral-byte-offset"
    } else if message == "Count conditions require an integer literal." {
        "count-requires-integer-literal"
    } else if message.starts_with("Numeric read literal is out of range for ") {
        "numeric-read-literal-out-of-range"
    } else if message.starts_with("Invalid literal string: ") {
        "invalid-literal-string"
    } else if message.starts_with("Condition references unknown rule: ") {
        "unknown-rule-reference"
    } else if message.starts_with("Unsupported token in condition near: ")
        || message.starts_with("Unexpected trailing token in condition:")
    {
        "unsupported-condition-syntax"
    } else if message.starts_with("Unsupported count comparison token: ")
        || message.starts_with("Expected token EqEq, got ")
    {
        "unsupported-comparison-operator"
    } else if message.contains("current source is") && message.starts_with("hash.") {
        "hash-identity-mismatch"
    } else if message.contains("requires a known DB identity source") {
        "hash-identity-source-unknown"
    } else if message.contains("no mandatory anchorable pattern and union fanout") {
        "overbroad-union"
    } else if message.contains("entry-point stub provides only low-information gram anchors") {
        "low-information-entrypoint-stub"
    } else if message.contains("short range/suffix anchors are too weak at scale") {
        "low-information-range-rule"
    } else if message.contains("single-pattern rule provides only tiny gram anchors") {
        "low-information-single-pattern"
    } else if message.contains("requires an anchorable literal for direct search use") {
        "requires-anchorable-literal-direct"
    } else if message.contains("requires an anchorable literal for at/in search use") {
        "requires-anchorable-literal-at-in"
    } else if message.contains("requires an anchorable literal for verifier-loop search use") {
        "requires-anchorable-literal-loop"
    } else if message.contains("requires an anchorable literal for N-of search use") {
        "requires-anchorable-literal-n-of"
    } else if message.contains("Verifier-only indexed conditions require an anchorable literal") {
        "verifier-only-no-anchor"
    } else if message.contains("Unsupported searchable hash function") {
        "unsupported-hash-function"
    } else if message.contains("Only whole-file") {
        "whole-file-only"
    } else if message.contains("requires an anchorable literal") {
        "requires-anchorable-literal"
    } else {
        "unsupported"
    }
}

fn unsupported_issue_match(
    context: &RuleSourceContext<'_>,
    message: &str,
) -> Option<RuleSourceMatch> {
    let code = classify_unsupported_issue_code(message);
    if let Some(hash_start) = message.find("hash.") {
        let suffix = &message[hash_start..];
        let end = suffix.find('(').unwrap_or(suffix.len());
        let literal = &suffix[..end];
        if !literal.is_empty() {
            return source_match_for_literal(context, literal);
        }
    }
    if message.contains("math.entropy") {
        return source_match_for_literal(context, "math.entropy(");
    }
    match code {
        "no-condition-section" => source_match_for_literal(context, "strings:")
            .or_else(|| source_match_for_first_strings_line(context)),
        "ignored-module-no-anchor" => {
            for candidate in ["androguard.", "console.", "cuckoo."] {
                if let Some(found) = source_match_for_condition_literal(context, candidate) {
                    return Some(found);
                }
            }
            source_match_for_first_condition_line(context)
        }
        "unsupported-regex-flags" | "unsupported-literal-flags" => message
            .split_once(" for ")
            .and_then(|(_, suffix)| suffix.split_once(':'))
            .and_then(|(pattern_id, _)| source_match_for_strings_literal(context, pattern_id))
            .or_else(|| source_match_for_first_strings_line(context)),
        "unsupported-hex-syntax" => message
            .split_once(" for ")
            .and_then(|(_, suffix)| suffix.split_once(':'))
            .and_then(|(pattern_id, _)| source_match_for_strings_literal(context, pattern_id))
            .or_else(|| source_match_for_first_strings_line(context)),
        "regex-no-mandatory-literal" => source_match_for_first_strings_line(context),
        "unsupported-regex-syntax" | "nocase-no-anchorable-window" => {
            source_match_for_first_strings_line(context)
        }
        "unsupported-strings-declaration" => {
            extract_message_fragment(message, "Unsupported strings declaration: ")
                .and_then(|fragment| source_match_for_strings_literal(context, &fragment))
                .or_else(|| source_match_for_first_strings_line(context))
        }
        "unsupported-condition-field" => message
            .strip_prefix("Unsupported condition field: ")
            .and_then(|field| source_match_for_condition_literal(context, field))
            .or_else(|| source_match_for_first_condition_line(context)),
        "nonliteral-byte-offset" => message
            .strip_suffix(" requires an integer byte offset.")
            .and_then(|name| source_match_for_condition_literal(context, &format!("{name}(")))
            .or_else(|| source_match_for_first_condition_line(context)),
        "count-requires-integer-literal" => source_match_for_condition_literal(context, "#")
            .or_else(|| source_match_for_condition_literal(context, " of ("))
            .or_else(|| source_match_for_first_condition_line(context)),
        "numeric-read-literal-out-of-range" => message
            .strip_prefix("Numeric read literal is out of range for ")
            .and_then(|suffix| suffix.split_once(':').map(|(name, _)| name))
            .and_then(|name| source_match_for_condition_literal(context, &format!("{name}(")))
            .or_else(|| source_match_for_first_condition_line(context)),
        "invalid-literal-string" => source_match_for_first_strings_line(context),
        "unknown-rule-reference" => message
            .strip_prefix("Condition references unknown rule: ")
            .and_then(|rule_name| source_match_for_condition_literal(context, rule_name))
            .or_else(|| source_match_for_first_condition_line(context)),
        "unsupported-condition-syntax" => {
            extract_message_fragment(message, "Unsupported token in condition near: ")
                .and_then(|fragment| source_match_for_condition_literal(context, &fragment))
                .or_else(|| source_match_for_first_condition_line(context))
        }
        "unsupported-comparison-operator" => source_match_for_condition_literal(context, "!=")
            .or_else(|| source_match_for_condition_literal(context, "#"))
            .or_else(|| source_match_for_first_condition_line(context)),
        "overbroad-union" => {
            for candidate in ["any of", "or", "1 of", "2 of"] {
                if let Some(found) = source_match_for_condition_literal(context, candidate) {
                    return Some(found);
                }
            }
            source_match_for_first_condition_line(context)
        }
        "low-information-entrypoint-stub" => {
            source_match_for_condition_literal(context, "at pe.entry_point")
        }
        "low-information-range-rule" => source_match_for_condition_literal(context, " in ("),
        "low-information-single-pattern" => source_match_for_first_condition_line(context),
        "requires-anchorable-literal-direct" => extract_pattern_id_from_anchor_error(message)
            .and_then(|pattern_id| source_match_for_condition_pattern_id(context, &pattern_id))
            .or_else(|| source_match_for_first_condition_line(context)),
        "requires-anchorable-literal-at-in" => extract_pattern_id_from_anchor_error(message)
            .and_then(|pattern_id| {
                source_match_for_condition_literal(context, &format!("{pattern_id} at"))
                    .or_else(|| {
                        source_match_for_condition_literal(context, &format!("{pattern_id} in"))
                    })
                    .or_else(|| source_match_for_condition_pattern_id(context, &pattern_id))
            })
            .or_else(|| source_match_for_condition_literal(context, " at "))
            .or_else(|| source_match_for_condition_literal(context, " in (")),
        "requires-anchorable-literal-loop" => {
            source_match_for_condition_literal(context, "verifierloop(")
                .or_else(|| source_match_for_condition_literal(context, "for any"))
                .or_else(|| source_match_for_condition_literal(context, "for all"))
        }
        "requires-anchorable-literal-n-of" => {
            if let Some(pattern_id) = extract_pattern_id_from_anchor_error(message)
                && let Some(found) = source_match_for_condition_pattern_id(context, &pattern_id)
            {
                return Some(found);
            }
            for candidate in ["any of", "all of", "1 of", "2 of"] {
                if let Some(found) = source_match_for_condition_literal(context, candidate) {
                    return Some(found);
                }
            }
            source_match_for_first_condition_line(context)
        }
        "verifier-only-no-anchor" => source_match_for_anchorless_verifier_only_condition(context),
        _ => None,
    }
}

/// Extracts the pattern id from an "anchorable literal required" compiler error
/// so diagnostics can highlight the most relevant source location.
///
/// Inputs:
/// - `message`: Compiler error text emitted during rule compilation.
///
/// Returns:
/// - The offending pattern id when the message matches the expected format.
fn extract_pattern_id_from_anchor_error(message: &str) -> Option<String> {
    let suffix = message.strip_prefix("Pattern ")?;
    let end = suffix.find(" requires an anchorable literal")?;
    Some(suffix[..end].to_owned())
}

/// Converts either a successful compiled plan or a compilation error into the
/// user-facing rule-check report for one rule.
///
/// How it works:
/// - Successful plans are scanned for verifier-only and negated-search risks.
/// - Compilation failures are classified into stable issue codes and anchored
///   back to the most relevant source location when possible.
///
/// Inputs:
/// - `source_context`: Source text and offsets used to compute locations/snippets.
/// - `rule_name`: Optional rule name for per-rule reports.
/// - `plan_result`: Either the compiled query plan or the compilation error.
/// - `ignored_module_calls`: Module predicates that are pruned during search.
///
/// Returns:
/// - The `RuleCheckReport` consumed by CLI and JSON output paths.
fn build_rule_check_report(
    source_context: &RuleSourceContext<'_>,
    rule_name: Option<&str>,
    plan_result: Result<CompiledQueryPlan>,
    ignored_module_calls: Vec<String>,
) -> RuleCheckReport {
    match plan_result {
        Ok(plan) => {
            let pattern_map = plan
                .patterns
                .iter()
                .map(|pattern| (pattern.pattern_id.clone(), pattern))
                .collect::<HashMap<_, _>>();
            let mut verifier_only_kinds = BTreeSet::<String>::new();
            collect_unresolved_verifier_only_kinds(
                &plan.root,
                &pattern_map,
                &mut verifier_only_kinds,
            );
            let verifier_only_kinds = verifier_only_kinds.into_iter().collect::<Vec<_>>();
            let mut issues = Vec::<RuleCheckIssue>::new();
            let negated_search_match =
                first_negated_search_condition_match(&plan.root, source_context);
            let negated_search_unbounded =
                negated_search_condition_makes_candidate_branch_unbounded(&plan.root);
            for kind in &verifier_only_kinds {
                let code = verifier_only_issue_code(kind);
                issues.push(rule_check_issue(
                    rule_name,
                    code,
                    RuleCheckSeverity::Warning,
                    verifier_only_issue_message(kind),
                    verifier_only_kind_match(source_context, kind),
                    remediation_for_issue_code(code),
                ));
            }
            if negated_search_unbounded {
                issues.push(rule_check_issue(
                    rule_name,
                    "negated-search-unbounded",
                    RuleCheckSeverity::Error,
                    "This rule negates searchable string, hex, or verifier-only conditions without any exact positive prefilter. sspry's indexed candidate stage would treat that negated branch as always true, so the rule is not suitable for scalable indexed search as written.",
                    negated_search_match.clone(),
                    remediation_for_issue_code("negated-search-unbounded"),
                ));
            } else if let Some(source_match) = negated_search_match {
                issues.push(rule_check_issue(
                    rule_name,
                    "verifier-only-negation",
                    RuleCheckSeverity::Warning,
                    "This rule negates searchable string, hex, or verifier-only conditions. sspry can keep the positive prefilter, but exact negative evaluation requires local verification with --verify.",
                    Some(source_match),
                    remediation_for_issue_code("verifier-only-negation"),
                ));
            }
            for module_call in &ignored_module_calls {
                issues.push(rule_check_issue(
                    rule_name,
                    "ignored-module-predicate",
                    RuleCheckSeverity::Warning,
                    format!(
                        "Indexed candidate search prunes the module predicate `{module_call}`. Use --verify if you need exact module-aware results."
                    ),
                    source_match_for_literal(source_context, module_call),
                    remediation_for_issue_code("ignored-module-predicate"),
                ));
            }
            RuleCheckReport {
                status: if negated_search_unbounded {
                    RuleCheckStatus::Unsupported
                } else if issues.is_empty() {
                    RuleCheckStatus::Searchable
                } else {
                    RuleCheckStatus::SearchableNeedsVerify
                },
                issues,
                verifier_only_kinds,
                ignored_module_calls,
            }
        }
        Err(err) => {
            let error_message = err.to_string();
            let error_code = classify_unsupported_issue_code(&error_message);
            let mut issues = vec![rule_check_issue(
                rule_name,
                error_code,
                RuleCheckSeverity::Error,
                error_message.clone(),
                unsupported_issue_match(source_context, &error_message),
                remediation_for_issue_code(error_code),
            )];
            for module_call in &ignored_module_calls {
                issues.push(rule_check_issue(
                    rule_name,
                    "ignored-module-predicate",
                    RuleCheckSeverity::Warning,
                    format!(
                        "The rule also references the ignored module predicate `{module_call}`."
                    ),
                    source_match_for_literal(source_context, module_call),
                    remediation_for_issue_code("ignored-module-predicate"),
                ));
            }
            RuleCheckReport {
                status: RuleCheckStatus::Unsupported,
                issues,
                verifier_only_kinds: Vec::new(),
                ignored_module_calls,
            }
        }
    }
}

fn contains_identity_node(node: &QueryNode) -> bool {
    node.kind == "identity_eq" || node.children.iter().any(contains_identity_node)
}

fn contains_pattern_node(node: &QueryNode) -> bool {
    node.kind == "pattern" || node.children.iter().any(contains_pattern_node)
}

fn contains_pattern_or_verifier_only_node(node: &QueryNode) -> bool {
    contains_pattern_node(node) || contains_verifier_only_node(node)
}

fn first_negated_search_condition_match(
    node: &QueryNode,
    context: &RuleSourceContext<'_>,
) -> Option<RuleSourceMatch> {
    if node.kind == "not"
        && node
            .children
            .first()
            .is_some_and(contains_pattern_or_verifier_only_node)
    {
        return source_match_for_condition_literal(context, "not ")
            .or_else(|| source_match_for_first_condition_line(context));
    }
    node.children
        .iter()
        .find_map(|child| first_negated_search_condition_match(child, context))
}

/// Combines per-rule reports into the file-level rule-check summary.
///
/// How it works:
/// - Ignores private helper rules when a public rule is present.
/// - Merges statuses, issues, verifier-only kinds, and ignored module calls.
///
/// Inputs:
/// - `rules`: Per-rule reports for every parsed rule block.
///
/// Returns:
/// - The aggregated file-level report.
fn summarize_rule_check_rules(rules: Vec<RuleCheckRuleReport>) -> RuleCheckFileReport {
    let considered_rules = if rules.iter().any(|rule| !rule.is_private) {
        rules
            .iter()
            .filter(|rule| !rule.is_private)
            .collect::<Vec<_>>()
    } else {
        rules.iter().collect::<Vec<_>>()
    };
    let mut status = RuleCheckStatus::Searchable;
    let mut issues = Vec::<RuleCheckIssue>::new();
    let mut verifier_only_kinds = BTreeSet::<String>::new();
    let mut ignored_module_calls = BTreeSet::<String>::new();
    for rule in considered_rules {
        status = status.combine(rule.status);
        issues.extend(rule.issues.iter().cloned());
        verifier_only_kinds.extend(rule.verifier_only_kinds.iter().cloned());
        ignored_module_calls.extend(rule.ignored_module_calls.iter().cloned());
    }
    RuleCheckFileReport {
        status,
        issues,
        verifier_only_kinds: verifier_only_kinds.into_iter().collect(),
        ignored_module_calls: ignored_module_calls.into_iter().collect(),
        rules,
    }
}

fn negated_search_condition_makes_candidate_branch_unbounded(node: &QueryNode) -> bool {
    match node.kind.as_str() {
        "not" => node
            .children
            .first()
            .is_some_and(contains_pattern_or_verifier_only_node),
        "and" => {
            !node.children.is_empty()
                && node
                    .children
                    .iter()
                    .all(negated_search_condition_makes_candidate_branch_unbounded)
        }
        "or" => node
            .children
            .iter()
            .any(negated_search_condition_makes_candidate_branch_unbounded),
        "n_of" => {
            let threshold = node.threshold.unwrap_or(1);
            node.children
                .iter()
                .filter(|child| negated_search_condition_makes_candidate_branch_unbounded(child))
                .count()
                >= threshold
        }
        _ => false,
    }
}

const OVERBROAD_UNION_FANOUT_LIMIT: usize = 160;
const MANDATORY_PATTERN_COMBINATION_LIMIT: usize = 4096;
const LOW_INFORMATION_EP_STUB_PATTERN_LIMIT: usize = 2;
const LOW_INFORMATION_EP_STUB_MAX_TIER1_GRAMS: usize = 2;
const LOW_INFORMATION_EP_STUB_MAX_TIER2_GRAMS: usize = 3;
const LOW_INFORMATION_RANGE_RULE_PATTERN_LIMIT: usize = 3;
const LOW_INFORMATION_RANGE_RULE_MAX_TIER1_GRAMS: usize = 1;
const LOW_INFORMATION_RANGE_RULE_MAX_TIER2_GRAMS: usize = 2;
const LOW_INFORMATION_RANGE_RULE_MAX_ANCHOR_LEN: usize = 4;
const LOW_INFORMATION_SINGLE_PATTERN_MAX_TIER1_GRAMS: usize = 1;
const LOW_INFORMATION_SINGLE_PATTERN_MAX_TIER2_GRAMS: usize = 4;

fn pattern_is_anchorable(pattern: &PatternPlan) -> bool {
    pattern.alternatives.iter().any(|alt| !alt.is_empty())
        || pattern.tier2_alternatives.iter().any(|alt| !alt.is_empty())
        || pattern
            .anchor_literals
            .iter()
            .any(|literal| !literal.is_empty())
}

fn pattern_has_anchor_literals(pattern: &PatternPlan) -> bool {
    pattern
        .anchor_literals
        .iter()
        .any(|literal| !literal.is_empty())
}

fn pattern_max_anchor_literal_len(pattern: &PatternPlan) -> usize {
    pattern
        .anchor_literals
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(0)
}

fn pattern_max_tier1_grams(pattern: &PatternPlan) -> usize {
    pattern.alternatives.iter().map(Vec::len).max().unwrap_or(0)
}

fn pattern_max_tier2_grams(pattern: &PatternPlan) -> usize {
    pattern
        .tier2_alternatives
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(0)
}

fn choose_bounded(n: usize, k: usize, limit: usize) -> Option<usize> {
    if k > n {
        return Some(0);
    }
    let k = k.min(n.saturating_sub(k));
    let mut value = 1usize;
    for i in 0..k {
        let numerator = n.saturating_sub(i);
        let denominator = i.saturating_add(1);
        value = value.checked_mul(numerator)?;
        value /= denominator;
        if value > limit {
            return None;
        }
    }
    Some(value)
}

fn combinations_intersection_of_unions(
    child_sets: &[HashSet<String>],
    threshold: usize,
) -> HashSet<String> {
    fn visit(
        child_sets: &[HashSet<String>],
        threshold: usize,
        start: usize,
        current: &mut Vec<usize>,
        intersection: &mut Option<HashSet<String>>,
    ) {
        if current.len() == threshold {
            let union = current
                .iter()
                .flat_map(|idx| child_sets[*idx].iter().cloned())
                .collect::<HashSet<_>>();
            if let Some(existing) = intersection {
                existing.retain(|pattern_id| union.contains(pattern_id));
            } else {
                *intersection = Some(union);
            }
            return;
        }
        let remaining = threshold.saturating_sub(current.len());
        let max_start = child_sets.len().saturating_sub(remaining);
        for idx in start..=max_start {
            current.push(idx);
            visit(child_sets, threshold, idx + 1, current, intersection);
            current.pop();
            if intersection.as_ref().is_some_and(HashSet::is_empty) {
                return;
            }
        }
    }

    let mut intersection = None;
    visit(
        child_sets,
        threshold,
        0,
        &mut Vec::with_capacity(threshold),
        &mut intersection,
    );
    intersection.unwrap_or_default()
}

fn mandatory_pattern_ids(node: &QueryNode) -> HashSet<String> {
    match node.kind.as_str() {
        "pattern" => node.pattern_id.iter().cloned().collect::<HashSet<_>>(),
        "and" => node
            .children
            .iter()
            .flat_map(mandatory_pattern_ids)
            .collect::<HashSet<_>>(),
        "or" => {
            let mut children = node.children.iter();
            let Some(first) = children.next() else {
                return HashSet::new();
            };
            let mut mandatory = mandatory_pattern_ids(first);
            for child in children {
                mandatory.retain(|pattern_id| mandatory_pattern_ids(child).contains(pattern_id));
                if mandatory.is_empty() {
                    break;
                }
            }
            mandatory
        }
        "n_of" => {
            let threshold = node.threshold.unwrap_or(0);
            if threshold == 0 || node.children.is_empty() || threshold > node.children.len() {
                return HashSet::new();
            }
            if threshold == node.children.len() {
                return node
                    .children
                    .iter()
                    .flat_map(mandatory_pattern_ids)
                    .collect::<HashSet<_>>();
            }
            let Some(combo_count) = choose_bounded(
                node.children.len(),
                threshold,
                MANDATORY_PATTERN_COMBINATION_LIMIT,
            ) else {
                return HashSet::new();
            };
            if combo_count == 0 {
                return HashSet::new();
            }
            let child_sets = node
                .children
                .iter()
                .map(mandatory_pattern_ids)
                .collect::<Vec<_>>();
            combinations_intersection_of_unions(&child_sets, threshold)
        }
        _ => HashSet::new(),
    }
}

fn node_has_branching_pattern_union(node: &QueryNode) -> bool {
    match node.kind.as_str() {
        "or" => {
            node.children.len() > 1 || node.children.iter().any(node_has_branching_pattern_union)
        }
        "n_of" => {
            let threshold = node.threshold.unwrap_or(0);
            (threshold > 0 && threshold < node.children.len())
                || node.children.iter().any(node_has_branching_pattern_union)
        }
        _ => node.children.iter().any(node_has_branching_pattern_union),
    }
}

fn node_contains_kind(node: &QueryNode, kind: &str) -> bool {
    node.kind == kind
        || node
            .children
            .iter()
            .any(|child| node_contains_kind(child, kind))
}

fn total_pattern_anchor_fanout(patterns: &[PatternPlan]) -> usize {
    patterns
        .iter()
        .map(|pattern| {
            pattern
                .anchor_literals
                .iter()
                .filter(|literal| !literal.is_empty())
                .count()
                .max(
                    pattern
                        .alternatives
                        .iter()
                        .filter(|alt| !alt.is_empty())
                        .count()
                        .max(
                            pattern
                                .tier2_alternatives
                                .iter()
                                .filter(|alt| !alt.is_empty())
                                .count(),
                        ),
                )
                .max(1)
        })
        .sum()
}

/// Rejects rules whose unions are too broad to prefilter safely at scale.
///
/// Inputs:
/// - `root`: Compiled query tree.
/// - `patterns`: Patterns referenced by the compiled rule.
///
/// Returns:
/// - `Ok(())` when the rule keeps a strong mandatory anchor.
/// - An error when union fanout is too large without one.
fn reject_overbroad_pattern_union(root: &QueryNode, patterns: &[PatternPlan]) -> Result<()> {
    if patterns.is_empty() || !node_has_branching_pattern_union(root) {
        return Ok(());
    }
    let pattern_map = patterns
        .iter()
        .map(|pattern| (pattern.pattern_id.clone(), pattern))
        .collect::<HashMap<_, _>>();
    let mandatory_anchorable = mandatory_pattern_ids(root)
        .into_iter()
        .filter(|pattern_id| {
            pattern_map
                .get(pattern_id)
                .copied()
                .is_some_and(pattern_is_anchorable)
        })
        .count();
    if mandatory_anchorable > 0 {
        return Ok(());
    }
    let fanout = total_pattern_anchor_fanout(patterns);
    if fanout < OVERBROAD_UNION_FANOUT_LIMIT {
        return Ok(());
    }
    Err(SspryError::from(format!(
        "Rule is overbroad for scalable search: no mandatory anchorable pattern and union fanout {fanout} exceeds {OVERBROAD_UNION_FANOUT_LIMIT}. Add a stable mandatory anchor or split the rule."
    )))
}

/// Rejects very small entry-point stub rules whose anchors are too weak for
/// scalable search.
///
/// Inputs:
/// - `root`: Compiled query tree.
/// - `patterns`: Patterns referenced by the compiled rule.
///
/// Returns:
/// - An error when the rule is effectively an overbroad entry-point stub.
fn reject_low_information_entrypoint_stub(
    root: &QueryNode,
    patterns: &[PatternPlan],
) -> Result<()> {
    if patterns.is_empty()
        || !node_contains_kind(root, "verifier_only_at")
        || patterns.len() > LOW_INFORMATION_EP_STUB_PATTERN_LIMIT
    {
        return Ok(());
    }
    if patterns.iter().any(pattern_has_anchor_literals) {
        return Ok(());
    }
    let max_tier1 = patterns
        .iter()
        .map(pattern_max_tier1_grams)
        .max()
        .unwrap_or(0);
    let max_tier2 = patterns
        .iter()
        .map(pattern_max_tier2_grams)
        .max()
        .unwrap_or(0);
    if max_tier1 > LOW_INFORMATION_EP_STUB_MAX_TIER1_GRAMS
        || max_tier2 > LOW_INFORMATION_EP_STUB_MAX_TIER2_GRAMS
    {
        return Ok(());
    }
    Err(SspryError::from(
        "Rule is overbroad for scalable search: entry-point stub provides only low-information gram anchors. Add a longer mandatory literal or split the rule.",
    ))
}

/// Rejects range or suffix rules whose anchors stay too small once range logic
/// is accounted for.
///
/// Inputs:
/// - `root`: Compiled query tree.
/// - `patterns`: Patterns referenced by the compiled rule.
///
/// Returns:
/// - An error when the rule is too low-information for scalable search.
fn reject_low_information_range_rule(root: &QueryNode, patterns: &[PatternPlan]) -> Result<()> {
    if patterns.is_empty()
        || !node_contains_kind(root, "verifier_only_in_range")
        || patterns.len() > LOW_INFORMATION_RANGE_RULE_PATTERN_LIMIT
        || patterns.len() < 2
        || !node_contains_kind(root, "verifier_only_at")
    {
        return Ok(());
    }
    let max_anchor_len = patterns
        .iter()
        .map(pattern_max_anchor_literal_len)
        .max()
        .unwrap_or(0);
    let max_tier1 = patterns
        .iter()
        .map(pattern_max_tier1_grams)
        .max()
        .unwrap_or(0);
    let max_tier2 = patterns
        .iter()
        .map(pattern_max_tier2_grams)
        .max()
        .unwrap_or(0);
    if max_anchor_len > LOW_INFORMATION_RANGE_RULE_MAX_ANCHOR_LEN
        || max_tier1 > LOW_INFORMATION_RANGE_RULE_MAX_TIER1_GRAMS
        || max_tier2 > LOW_INFORMATION_RANGE_RULE_MAX_TIER2_GRAMS
    {
        return Ok(());
    }
    Err(SspryError::from(
        "Rule is overbroad for scalable search: short range/suffix anchors are too weak at scale. Add a longer mandatory literal or split the rule.",
    ))
}

/// Rejects single-pattern rules whose only anchors are too small to be useful
/// at scale.
///
/// Inputs:
/// - `root`: Compiled query tree.
/// - `patterns`: Patterns referenced by the compiled rule.
///
/// Returns:
/// - An error when a lone pattern contributes only tiny gram anchors.
fn reject_low_information_single_pattern(root: &QueryNode, patterns: &[PatternPlan]) -> Result<()> {
    if patterns.len() != 1 || node_has_branching_pattern_union(root) {
        return Ok(());
    }
    let pattern = &patterns[0];
    if pattern_has_anchor_literals(pattern) {
        return Ok(());
    }
    let max_tier1 = pattern_max_tier1_grams(pattern);
    let max_tier2 = pattern_max_tier2_grams(pattern);
    if max_tier1 > LOW_INFORMATION_SINGLE_PATTERN_MAX_TIER1_GRAMS
        || max_tier2 > LOW_INFORMATION_SINGLE_PATTERN_MAX_TIER2_GRAMS
    {
        return Ok(());
    }
    Err(SspryError::from(
        "Rule is overbroad for scalable search: single-pattern rule provides only tiny gram anchors. Add a longer literal or combine it with a stronger mandatory condition.",
    ))
}
