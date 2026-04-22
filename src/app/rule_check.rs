/// Resolves a rule-check policy from a local root by inspecting the forest or
/// direct store configuration already on disk.
///
/// Inputs:
/// - `root`: Root directory that contains the candidate store layout to inspect.
///
/// Returns:
/// - The gram sizes and identity source that rule-check should use for that
///   local store.
fn rule_check_policy_from_root(root: &Path) -> Result<RuleCheckPolicy> {
    let tree_groups = open_forest_tree_groups(root)?;
    let (gram_sizes, active_identity_source, _summary_cap_bytes) =
        validate_forest_search_policy(&tree_groups)?;
    let id_source =
        CandidateIdSource::parse_config_value(active_identity_source.as_deref().ok_or_else(
            || SspryError::from("candidate stores do not expose an identity source"),
        )?)?;
    Ok(RuleCheckPolicy {
        source: RuleCheckPolicySource::LocalRoot,
        id_source,
        gram_sizes,
    })
}

/// Resolves the effective rule-check policy for a CLI invocation.
///
/// How it works:
/// - Prefers an explicit local root when provided.
/// - Otherwise asks a live server for its policy when `--addr` is set.
/// - Falls back to explicit CLI overrides or the built-in defaults.
///
/// Inputs:
/// - `args`: CLI arguments that may provide a root, server address, or explicit
///   policy overrides.
///
/// Returns:
/// - A fully resolved policy used to compile and classify the rule file.
fn rule_check_policy(args: &RuleCheckArgs) -> Result<RuleCheckPolicy> {
    if let Some(root) = &args.root {
        return rule_check_policy_from_root(Path::new(root));
    }
    if let Some(addr) = &args.addr {
        let server_policy = server_scan_policy(&ClientConnectionArgs {
            addr: addr.clone(),
            timeout: DEFAULT_RPC_TIMEOUT,
            max_message_bytes: DEFAULT_MAX_REQUEST_BYTES,
            ignore_offline: false,
        })?;
        return Ok(RuleCheckPolicy {
            source: RuleCheckPolicySource::Server,
            id_source: server_policy.id_source,
            gram_sizes: server_policy.gram_sizes,
        });
    }
    let source = if args.id_source.is_some() || args.gram_sizes.is_some() {
        RuleCheckPolicySource::Explicit
    } else {
        RuleCheckPolicySource::Defaults
    };
    Ok(RuleCheckPolicy {
        source,
        id_source: args.id_source.unwrap_or(CandidateIdSource::Sha256),
        gram_sizes: GramSizes::parse(args.gram_sizes.as_deref().unwrap_or("3,4"))?,
    })
}

/// Combines the resolved policy metadata with the rule-check report so the CLI
/// can print either JSON or human-readable output from one structure.
///
/// Inputs:
/// - `policy`: The policy that was actually used for compilation and analysis.
/// - `report`: The per-file rule-check report returned by the candidate module.
///
/// Returns:
/// - A CLI-oriented `RuleCheckOutput` that includes both policy and report data.
fn rule_check_output(
    policy: RuleCheckPolicy,
    report: crate::candidate::RuleCheckFileReport,
) -> RuleCheckOutput {
    RuleCheckOutput {
        status: report.status,
        policy: RuleCheckPolicyOutput {
            source: policy.source.as_str().to_owned(),
            id_source: policy.id_source.as_str().to_owned(),
            gram_sizes: format!("{},{}", policy.gram_sizes.tier1, policy.gram_sizes.tier2),
        },
        issues: report.issues,
        verifier_only_kinds: report.verifier_only_kinds,
        ignored_module_calls: report.ignored_module_calls,
        rules: report.rules,
    }
}

/// Prints each individual rule-check issue in the plain-text format used by the
/// CLI.
///
/// Inputs:
/// - `issues`: The issues to print, each with optional rule, location, snippet,
///   and remediation data.
///
/// Output:
/// - Writes one human-readable block per issue to stdout.
fn print_rule_check_issues(issues: &[crate::candidate::RuleCheckIssue]) {
    for issue in issues {
        match (&issue.rule, issue.line, issue.column) {
            (Some(rule), Some(line), Some(column)) => {
                println!(
                    "{} in {} at {}:{}: {}",
                    issue.severity.as_str(),
                    rule,
                    line,
                    column,
                    issue.message
                );
            }
            (Some(rule), _, _) => {
                println!("{} in {}: {}", issue.severity.as_str(), rule, issue.message);
            }
            (_, Some(line), Some(column)) => {
                println!(
                    "{} at {}:{}: {}",
                    issue.severity.as_str(),
                    line,
                    column,
                    issue.message
                );
            }
            _ => {
                println!("{}: {}", issue.severity.as_str(), issue.message);
            }
        }
        if let Some(snippet) = &issue.snippet {
            println!("source: {snippet}");
        }
        if let Some(remediation) = &issue.remediation {
            println!("remediation: {remediation}");
        }
    }
}

/// Prints the plain-text rule-check summary shown when `--json` is not used.
///
/// How it works:
/// - Prints top-level policy data first.
/// - Expands per-rule detail when a file contains multiple rules.
/// - Falls back to a success summary when no issues were reported.
///
/// Inputs:
/// - `output`: Fully assembled rule-check output including policy and issues.
///
/// Output:
/// - Writes the formatted summary to stdout.
fn print_rule_check_output(output: &RuleCheckOutput) {
    println!("status: {}", output.status.as_str());
    println!("policy_source: {}", output.policy.source);
    println!("id_source: {}", output.policy.id_source);
    println!("gram_sizes: {}", output.policy.gram_sizes);
    if output.rules.len() > 1 {
        println!("rules: {}", output.rules.len());
        for rule in &output.rules {
            println!();
            println!("rule: {}", rule.rule);
            if rule.is_private {
                println!("private: true");
            }
            println!("status: {}", rule.status.as_str());
            if rule.issues.is_empty() {
                println!(
                    "summary: rule is compatible with sspry candidate search under this policy."
                );
            } else {
                print_rule_check_issues(&rule.issues);
            }
        }
        return;
    }
    if output.issues.is_empty() {
        println!("summary: rule is compatible with sspry candidate search under this policy.");
        return;
    }
    print_rule_check_issues(&output.issues);
}
