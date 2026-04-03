use std::env;
use std::fs;
use std::path::PathBuf;

use serde::Serialize;
use sspry::candidate::{GramSizes, compile_query_plan_with_gram_sizes_and_identity_source};

#[derive(Serialize)]
struct PatternSummary {
    pattern_id: String,
    alt_count: usize,
    tier1_grams_per_alt: Vec<usize>,
    tier1_gram_hex_per_alt: Vec<Vec<String>>,
    tier2_grams_per_alt: Vec<usize>,
    anchor_literals_hex: Vec<String>,
    fixed_literals_hex: Vec<String>,
    fixed_literal_wide: Vec<bool>,
    fixed_literal_fullword: Vec<bool>,
}

#[derive(Serialize)]
struct Dump {
    root: sspry::candidate::QueryNode,
    patterns: Vec<PatternSummary>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let rule_path = PathBuf::from(args.next().ok_or("missing rule path")?);
    let max_candidates = args
        .next()
        .map(|value| value.parse::<f64>())
        .transpose()?
        .unwrap_or(7.5);
    let rule = fs::read_to_string(&rule_path)?;
    let plan = compile_query_plan_with_gram_sizes_and_identity_source(
        &rule,
        GramSizes { tier2: 3, tier1: 4 },
        Some("sha256"),
        8,
        false,
        true,
        max_candidates,
    )?;
    let dump = Dump {
        root: plan.root.clone(),
        patterns: plan
            .patterns
            .iter()
            .map(|pattern| PatternSummary {
                pattern_id: pattern.pattern_id.clone(),
                alt_count: pattern.alternatives.len(),
                tier1_grams_per_alt: pattern.alternatives.iter().map(Vec::len).collect(),
                tier1_gram_hex_per_alt: pattern
                    .alternatives
                    .iter()
                    .map(|alt| {
                        alt.iter()
                            .map(|gram| {
                                let bytes = gram.to_be_bytes();
                                hex::encode(&bytes[4..])
                            })
                            .collect()
                    })
                    .collect(),
                tier2_grams_per_alt: pattern.tier2_alternatives.iter().map(Vec::len).collect(),
                anchor_literals_hex: pattern.anchor_literals.iter().map(hex::encode).collect(),
                fixed_literals_hex: pattern.fixed_literals.iter().map(hex::encode).collect(),
                fixed_literal_wide: pattern.fixed_literal_wide.clone(),
                fixed_literal_fullword: pattern.fixed_literal_fullword.clone(),
            })
            .collect(),
    };
    println!("{}", serde_json::to_string_pretty(&dump)?);
    Ok(())
}
