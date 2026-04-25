use std::fs;
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

mod common;

use common::*;

#[test]
fn init_validation_errors_are_reported() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("candidate_db");

    let err = run_fail(&[
        "init",
        "--root",
        candidate_root.to_str().expect("root"),
        "--tier1-set-fp",
        "1.0",
    ]);
    assert!(err.contains("tier1_filter_target_fp"));
}

#[test]
fn info_over_tcp_returns_json_after_explicit_init() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();

    init_root(&root, "workspace", &[]);
    let mut child = spawn_serve_tcp(port, &root, &[]);
    let addr = tcp_addr(port);
    wait_for_info_quick(&addr);

    let stats = run_ok(&["info", "--addr", &addr]);
    let parsed: Value = serde_json::from_str(&stats).expect("stats json");
    assert_eq!(
        parsed.get("active_doc_count").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        parsed.get("deleted_doc_count").and_then(Value::as_u64),
        Some(0)
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn multi_server_remote_commands_cover_info_index_search_and_delete() {
    let tmp = tempdir().expect("tmp");
    let root_a = tmp.path().join("candidate_a");
    let root_b = tmp.path().join("candidate_b");
    let port_a = reserve_tcp_port();
    let port_b = reserve_tcp_port();
    let addr_a = tcp_addr(port_a);
    let addr_b = tcp_addr(port_b);
    let addrs = format!("{addr_a},{addr_b}");

    init_root(&root_a, "workspace", &[]);
    init_root(&root_b, "workspace", &[]);
    let mut child_a = spawn_serve_tcp(port_a, &root_a, &[]);
    let mut child_b = spawn_serve_tcp(port_b, &root_b, &[]);
    wait_for_info_quick(&addr_a);
    wait_for_info_quick(&addr_b);

    let multi_info = run_ok(&["info", "--addr", &addrs]);
    let parsed: Value = serde_json::from_str(&multi_info).expect("multi info json");
    let servers = parsed.as_array().expect("multi info array");
    assert_eq!(servers.len(), 2);
    assert!(servers.iter().any(|server| {
        server
            .get("addr")
            .and_then(Value::as_str)
            .is_some_and(|addr| addr == addr_a)
    }));
    assert!(servers.iter().any(|server| {
        server
            .get("addr")
            .and_then(Value::as_str)
            .is_some_and(|addr| addr == addr_b)
    }));
    let offline_addr = tcp_addr(reserve_tcp_port());
    let ignore_addr = format!("{addr_a},{offline_addr}");
    let (ignore_stdout, ignore_stderr) =
        run_ok_capture(&["info", "--addr", &ignore_addr, "--ignore-offline"]);
    let parsed: Value = serde_json::from_str(&ignore_stdout).expect("ignore-offline info json");
    assert_eq!(
        parsed.as_array().expect("ignore-offline info array").len(),
        1
    );
    assert!(
        ignore_stderr.contains("warning.info.offline_server"),
        "{ignore_stderr}"
    );

    let mut sample_paths = Vec::new();
    for index in 0..34 {
        let path = tmp.path().join(format!("sample_{index:02}.bin"));
        let body = if index == 0 {
            "alpha distributed sample unique 00".to_string()
        } else {
            format!("distributed sample unique {index:02}")
        };
        fs::write(&path, body).expect("write sample");
        sample_paths.push(path);
    }
    let alpha = sample_paths[0].clone();
    let mut index_args = vec![
        "index".to_owned(),
        "--addr".to_owned(),
        addrs.clone(),
        "--workers".to_owned(),
        "1".to_owned(),
    ];
    index_args.extend(
        sample_paths
            .iter()
            .map(|path| path.to_str().expect("sample path").to_owned()),
    );
    let index_stdout = run_ok_owned(&index_args);
    assert!(
        index_stdout.contains("multi_server_submitted_documents: 34"),
        "{index_stdout}"
    );
    assert!(
        index_stdout.contains("multi_server_processed_documents: 34"),
        "{index_stdout}"
    );
    wait_for_published_doc_count_quick(&addr_a, 18, 1);
    wait_for_published_doc_count_quick(&addr_b, 16, 1);

    let alpha_rule = tmp.path().join("alpha.yar");
    fs::write(
        &alpha_rule,
        r#"
rule alpha_hit {
  strings:
    $a = "alpha"
  condition:
    $a
}
"#,
    )
    .expect("write alpha rule");
    wait_for_search_candidates(&addrs, &alpha_rule, 1);

    run_ok(&["delete", "--addr", &addrs, alpha.to_str().expect("alpha")]);
    wait_for_search_candidates(&addrs, &alpha_rule, 0);

    let _ = child_a.kill();
    let _ = child_a.wait();
    let _ = child_b.kill();
    let _ = child_b.wait();
}

#[test]
fn serve_requires_explicit_init() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();
    let output = Command::new(bin_path())
        .args([
            "serve",
            "--addr",
            &tcp_addr(port),
            "--root",
            root.to_str().expect("root"),
        ])
        .output()
        .expect("run serve");
    assert!(!output.status.success(), "serve should fail without init");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("is not initialized"), "{text}");
    assert!(text.contains("sspry init --root"), "{text}");
}

#[test]
fn local_index_requires_explicit_init() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("local_db");
    let sample = tmp.path().join("sample.bin");
    fs::write(&sample, b"sample local index").expect("write sample");

    let err = run_fail(&[
        "local",
        "index",
        "--root",
        root.to_str().expect("root"),
        sample.to_str().expect("sample"),
    ]);
    assert!(err.contains("is not initialized"), "{err}");
    assert!(err.contains("--mode local"), "{err}");
    assert!(err.contains("sspry init --root"), "{err}");
}

#[test]
fn rule_check_reports_unsupported_hash_mismatch_with_explicit_policy() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("rule.yar");
    fs::write(
        &rule_path,
        r#"
rule mismatched_hash {
  condition:
    hash.md5(0, filesize) == "0123456789abcdef0123456789abcdef"
}
"#,
    )
    .expect("write rule");

    let output = Command::new(bin_path())
        .args([
            "rule-check",
            "--rule",
            rule_path.to_str().expect("rule"),
            "--id-source",
            "sha256",
            "--json",
        ])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should fail for unsupported rule"
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("rule-check json");
    assert_eq!(
        parsed.get("status").and_then(Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        parsed
            .get("policy")
            .and_then(|value| value.get("source"))
            .and_then(Value::as_str),
        Some("explicit")
    );
    let issue = parsed
        .get("issues")
        .and_then(Value::as_array)
        .and_then(|issues| issues.first())
        .expect("issue");
    assert_eq!(
        issue.get("code").and_then(Value::as_str),
        Some("hash-identity-mismatch")
    );
    assert_eq!(
        issue.get("rule").and_then(Value::as_str),
        Some("mismatched_hash")
    );
    assert_eq!(issue.get("line").and_then(Value::as_u64), Some(4));
    assert!(issue.get("column").and_then(Value::as_u64).is_some());
    assert!(
        issue
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("current source is sha256")
    );
    assert!(
        issue
            .get("remediation")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("--id-source")
    );
    assert_eq!(
        issue.get("snippet").and_then(Value::as_str),
        Some("hash.md5(0, filesize) == \"0123456789abcdef0123456789abcdef\"")
    );
}

#[test]
fn rule_check_uses_server_policy_from_live_addr() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();
    let addr = tcp_addr(port);
    init_root(&root, "workspace", &["--id-source", "md5"]);
    let mut child = spawn_serve_tcp(port, &root, &[]);
    wait_for_info_quick(&addr);

    let rule_path = tmp.path().join("rule.yar");
    fs::write(
        &rule_path,
        r#"
rule mismatched_hash {
  condition:
    hash.sha256(0, filesize) == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args([
            "rule-check",
            "--addr",
            &addr,
            "--rule",
            rule_path.to_str().expect("rule"),
            "--json",
        ])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should fail for unsupported rule"
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("rule-check json");
    assert_eq!(
        parsed.get("status").and_then(Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        parsed
            .get("policy")
            .and_then(|value| value.get("source"))
            .and_then(Value::as_str),
        Some("server")
    );
    assert_eq!(
        parsed
            .get("policy")
            .and_then(|value| value.get("id_source"))
            .and_then(Value::as_str),
        Some("md5")
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn rule_check_uses_local_root_policy() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("local_db");
    let sample = tmp.path().join("sample.bin");
    fs::write(&sample, b"sample local root rule check").expect("write sample");
    init_root(&root, "local", &[]);
    let _ = run_ok(&[
        "local",
        "index",
        "--root",
        root.to_str().expect("root"),
        sample.to_str().expect("sample"),
    ]);

    let rule_path = tmp.path().join("rule.yar");
    fs::write(
        &rule_path,
        r#"
rule mismatched_hash {
  condition:
    hash.md5(0, filesize) == "0123456789abcdef0123456789abcdef"
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args([
            "rule-check",
            "--root",
            root.to_str().expect("root"),
            "--rule",
            rule_path.to_str().expect("rule"),
            "--json",
        ])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should fail for unsupported rule"
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("rule-check json");
    assert_eq!(
        parsed.get("status").and_then(Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        parsed
            .get("policy")
            .and_then(|value| value.get("source"))
            .and_then(Value::as_str),
        Some("local-root")
    );
    assert_eq!(
        parsed
            .get("policy")
            .and_then(|value| value.get("id_source"))
            .and_then(Value::as_str),
        Some("sha256")
    );
}

#[test]
fn rule_check_plain_text_prints_location_and_remediation() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("rule.yar");
    fs::write(
        &rule_path,
        r#"
rule verifier_rule {
  strings:
    $a = "ABCDEFGHIJKLMNOPQ"
  condition:
    $a at pe.entry_point
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        output.status.success(),
        "rule-check should succeed with warning"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: searchable-needs-verify"));
    assert!(stdout.contains("warning in verifier_rule at 6:"));
    assert!(stdout.contains("source: $a at pe.entry_point"));
    assert!(stdout.contains("remediation: Run `search --verify`"));
}

#[test]
fn rule_check_plain_text_omits_warning_for_exact_entrypoint_prefix_rule() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("exact-rule.yar");
    fs::write(
        &rule_path,
        r#"
rule exact_entrypoint_rule {
  strings:
    $a = "ABCD"
  condition:
    $a at pe.entry_point
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        output.status.success(),
        "rule-check should accept exact entry-point literal rules"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: searchable"));
    assert!(!stdout.contains("warning"));
    assert!(!stdout.contains("remediation:"));
}

#[test]
fn rule_check_plain_text_omits_warning_for_exact_prefix_numeric_rule() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("numeric-exact.yar");
    fs::write(
        &rule_path,
        r#"
rule exact_prefix_numeric_rule {
  condition:
    uint32(0) == 16909060
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        output.status.success(),
        "rule-check should accept exact prefix numeric rules"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: searchable"));
    assert!(!stdout.contains("warning"));
}

#[test]
fn rule_check_plain_text_omits_warning_for_in_prefix_numeric_rule() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("numeric-in-prefix.yar");
    fs::write(
        &rule_path,
        r#"
rule in_prefix_numeric_rule {
  condition:
    uint32(4) == 16909060
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        output.status.success(),
        "rule-check should accept exact in-prefix numeric rules"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: searchable"));
    assert!(!stdout.contains("warning"));
}

#[test]
fn rule_check_plain_text_reports_specific_count_constraint_details() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("count-rule.yar");
    fs::write(
        &rule_path,
        r#"
rule count_rule {
  strings:
    $a = "ABCD"
  condition:
    #a > 1
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        output.status.success(),
        "rule-check should warn rather than fail for count constraints"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: searchable-needs-verify"));
    assert!(stdout.contains("warning in count_rule"));
    assert!(stdout.contains("number of string matches"));
    assert!(stdout.contains("source: #a > 1"));
    assert!(stdout.contains("count constraints"));
}

#[test]
fn rule_check_plain_text_reports_negated_search_constraints() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("negated-search-rule.yar");
    fs::write(
        &rule_path,
        r#"
rule negated_search_rule {
  strings:
    $a = "ABCD"
    $b = "WXYZ"
  condition:
    $a and not $b and filesize >= 8 and filesize < 9
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        output.status.success(),
        "rule-check should warn rather than fail for negated searchable constraints"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: searchable-needs-verify"));
    assert!(stdout.contains("warning in negated_search_rule"));
    assert!(stdout.contains("negates searchable string"));
    assert!(stdout.contains("source: $a and not $b and filesize >= 8 and filesize < 9"));
    assert!(stdout.contains("search --verify"));
}

#[test]
fn rule_check_plain_text_omits_warning_for_trivial_positive_count_rule() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("count-exists-rule.yar");
    fs::write(
        &rule_path,
        r#"
rule trivial_count_exists_rule {
  strings:
    $a = "ABCD"
  condition:
    #a > 0
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        output.status.success(),
        "rule-check should accept trivial positive count rules"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: searchable"));
    assert!(!stdout.contains("warning"));
}

#[test]
fn rule_check_plain_text_reports_trivial_zero_count_rule_as_unsupported() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("count-zero-rule.yar");
    fs::write(
        &rule_path,
        r#"
rule trivial_count_zero_rule {
  strings:
    $a = "ABCD"
  condition:
    #a == 0
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should reject trivial zero-count rules because they simplify to unbounded negation"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: unsupported"));
    assert!(stdout.contains("always true"));
    assert!(stdout.contains("source: #a == 0"));
}

#[test]
fn rule_check_plain_text_reports_specific_overbroad_union_details() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("overbroad-rule.yar");
    fs::write(
        &rule_path,
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
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should fail unsupported overbroad unions"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: unsupported"));
    assert!(stdout.contains("error in overbroad_iron_tiger_style"));
    assert!(stdout.contains("union fanout"));
    assert!(stdout.contains("source: uint16(0) == 0x5a4d and any of them"));
    assert!(stdout.contains("mandatory anchor"));
}

#[test]
fn rule_check_plain_text_reports_nonliteral_byte_offset_details() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("dynamic-offset-rule.yar");
    fs::write(
        &rule_path,
        r#"
rule dynamic_offset_rule {
  condition:
    uint32(filesize) == 1
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should fail unsupported nonliteral byte offsets"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: unsupported"));
    assert!(stdout.contains("error in dynamic_offset_rule"));
    assert!(stdout.contains("integer byte offset"));
    assert!(stdout.contains("source: uint32(filesize) == 1"));
    assert!(stdout.contains("literal constant"));
}

#[test]
fn rule_check_plain_text_reports_unbounded_negated_search_as_unsupported() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("negated-only-rule.yar");
    fs::write(
        &rule_path,
        r#"
rule negated_only_rule {
  strings:
    $a = "ABCD"
  condition:
    not $a
}
"#,
    )
    .expect("write rule");
    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should fail unsupported unbounded negated-search rules"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: unsupported"));
    assert!(stdout.contains("error in negated_only_rule"));
    assert!(stdout.contains("always true"));
    assert!(stdout.contains("source: not $a"));
    assert!(stdout.contains("positive searchable anchor"));
}

#[test]
fn rule_check_json_reports_each_rule_in_multi_rule_file() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("multi.yar");
    fs::write(
        &rule_path,
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
    )
    .expect("write rule");

    let output = Command::new(bin_path())
        .args([
            "rule-check",
            "--rule",
            rule_path.to_str().expect("rule"),
            "--json",
        ])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should fail when any rule in the file is unsupported"
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("rule-check json");
    assert_eq!(
        parsed.get("status").and_then(Value::as_str),
        Some("unsupported")
    );
    let rules = parsed
        .get("rules")
        .and_then(Value::as_array)
        .expect("rules array");
    assert_eq!(rules.len(), 2);
    assert_eq!(
        rules[0].get("rule").and_then(Value::as_str),
        Some("searchable_rule")
    );
    assert_eq!(
        rules[0].get("status").and_then(Value::as_str),
        Some("searchable")
    );
    assert_eq!(
        rules[1].get("rule").and_then(Value::as_str),
        Some("unsupported_rule")
    );
    assert_eq!(
        rules[1].get("status").and_then(Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        rules[1]
            .get("issues")
            .and_then(Value::as_array)
            .and_then(|issues| issues.first())
            .and_then(|issue| issue.get("snippet"))
            .and_then(Value::as_str),
        Some("not $b")
    );
}

#[test]
fn rule_check_plain_text_reports_each_rule_in_multi_rule_file() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("multi.txt.yar");
    fs::write(
        &rule_path,
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
    )
    .expect("write rule");

    let output = Command::new(bin_path())
        .args(["rule-check", "--rule", rule_path.to_str().expect("rule")])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should fail when any rule in the file is unsupported"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("status: unsupported"));
    assert!(stdout.contains("rules: 2"));
    assert!(stdout.contains("rule: searchable_rule"));
    assert!(stdout.contains("rule: unsupported_rule"));
    assert!(stdout.contains("status: searchable"));
    assert!(stdout.contains("status: unsupported"));
    assert!(stdout.contains("source: not $b"));
}

#[test]
fn rule_check_json_ignores_private_helper_rule_in_top_level_status() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("private-helper.yar");
    fs::write(
        &rule_path,
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
    )
    .expect("write rule");

    let output = Command::new(bin_path())
        .args([
            "rule-check",
            "--rule",
            rule_path.to_str().expect("rule"),
            "--json",
        ])
        .output()
        .expect("run rule-check");
    assert!(
        output.status.success(),
        "rule-check should succeed when only private helper rules are unsupported"
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("rule-check json");
    assert_eq!(
        parsed.get("status").and_then(Value::as_str),
        Some("searchable")
    );
    assert!(
        parsed
            .get("issues")
            .and_then(Value::as_array)
            .is_some_and(|issues| issues.is_empty())
    );
    let rules = parsed
        .get("rules")
        .and_then(Value::as_array)
        .expect("rules array");
    assert_eq!(rules.len(), 2);
    assert_eq!(
        rules[0].get("is_private").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        rules[0].get("status").and_then(Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        rules[1].get("status").and_then(Value::as_str),
        Some("searchable")
    );
}

#[test]
fn rule_check_json_preserves_locations_with_comments_before_later_rules() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("commented-multi.yar");
    fs::write(
        &rule_path,
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
    )
    .expect("write rule");

    let output = Command::new(bin_path())
        .args([
            "rule-check",
            "--rule",
            rule_path.to_str().expect("rule"),
            "--json",
        ])
        .output()
        .expect("run rule-check");
    assert!(
        !output.status.success(),
        "rule-check should fail because rule two is unsupported"
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("rule-check json");
    let rules = parsed
        .get("rules")
        .and_then(Value::as_array)
        .expect("rules array");
    let issue = rules[1]
        .get("issues")
        .and_then(Value::as_array)
        .and_then(|issues| issues.first())
        .expect("issue");
    assert_eq!(issue.get("rule").and_then(Value::as_str), Some("two"));
    assert_eq!(issue.get("line").and_then(Value::as_u64), Some(15));
    assert_eq!(issue.get("column").and_then(Value::as_u64), Some(5));
    assert_eq!(issue.get("snippet").and_then(Value::as_str), Some("not $b"));
}

#[test]
fn serve_persists_candidate_shards() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();

    init_root(&root, "workspace", &["--shards", "2"]);
    let mut child = spawn_serve_tcp(port, &root, &[]);
    let addr = tcp_addr(port);
    wait_for_info_quick(&addr);

    let stats = run_ok(&["info", "--addr", &addr]);
    let parsed: Value = serde_json::from_str(&stats).expect("stats json");
    assert_eq!(
        parsed.get("candidate_shards").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        parsed.get("workspace_mode").and_then(Value::as_bool),
        Some(true)
    );
    assert!(root.join("current").join("tree_00").join("meta.json").exists());
    assert!(
        root.join("current")
            .join("tree_00")
            .join("shard_000")
            .join("store_meta.json")
            .exists()
    );
    assert!(
        root.join("current")
            .join("tree_00")
            .join("shard_001")
            .join("store_meta.json")
            .exists()
    );
    assert!(!root.join("work_a").exists());
    assert!(!root.join("work_b").exists());

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn serve_reuses_initialized_policy() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");

    init_root(
        &root,
        "workspace",
        &[
            "--shards",
            "2",
            "--tier1-set-fp",
            "0.31",
            "--tier2-set-fp",
            "0.17",
            "--id-source",
            "md5",
            "--gram-sizes",
            "4,5",
        ],
    );

    let restart_port = reserve_tcp_port();
    let restart_addr = tcp_addr(restart_port);
    let mut restart_child = spawn_serve_tcp_capture_stderr(restart_port, &root, &[]);
    wait_for_info_quick(&restart_addr);

    let info = run_ok(&["info", "--addr", &restart_addr]);
    let parsed: Value = serde_json::from_str(&info).expect("stats json");
    assert_eq!(
        parsed.get("candidate_shards").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(parsed.get("id_source").and_then(Value::as_str), Some("md5"));
    assert_eq!(
        parsed.get("store_path").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        parsed.get("tier1_filter_target_fp").and_then(Value::as_f64),
        Some(0.31)
    );
    assert_eq!(
        parsed.get("tier2_filter_target_fp").and_then(Value::as_f64),
        Some(0.17)
    );
    assert_eq!(
        parsed.get("tier1_gram_size").and_then(Value::as_u64),
        Some(4)
    );
    assert_eq!(
        parsed.get("tier2_gram_size").and_then(Value::as_u64),
        Some(5)
    );

    let _ = restart_child.kill();
    let output = restart_child.wait_with_output().expect("restart output");
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(!stderr.contains("ignoring serve initialization options"));
}

#[test]
fn serve_reuses_initialized_store_path() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");

    init_root(
        &root,
        "workspace",
        &[
            "--shards",
            "2",
            "--tier1-set-fp",
            "0.31",
            "--tier2-set-fp",
            "0.17",
            "--id-source",
            "md5",
            "--store-path",
            "--gram-sizes",
            "4,5",
        ],
    );

    let restart_port = reserve_tcp_port();
    let restart_addr = tcp_addr(restart_port);
    let mut restart_child = spawn_serve_tcp_capture_stderr(restart_port, &root, &[]);
    wait_for_info_quick(&restart_addr);

    let info = run_ok(&["info", "--addr", &restart_addr]);
    let parsed: Value = serde_json::from_str(&info).expect("stats json");
    assert_eq!(parsed.get("id_source").and_then(Value::as_str), Some("md5"));
    assert_eq!(
        parsed.get("store_path").and_then(Value::as_bool),
        Some(true)
    );

    let _ = restart_child.kill();
    let output = restart_child.wait_with_output().expect("restart output");
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(!stderr.contains("ignoring serve initialization options"));
}

#[test]
fn yara_reports_match_and_tags() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("rule.yar");
    let hit_path = tmp.path().join("hit.bin");
    fs::write(
        &rule_path,
        "rule TestLiteral : tag_a { strings: $a = \"hello\" condition: $a }\n",
    )
    .expect("rule");
    fs::write(&hit_path, b"well hello there").expect("hit");

    let out = run_ok(&[
        "--rule",
        rule_path.to_str().expect("rule"),
        "--show-tags",
        hit_path.to_str().expect("hit"),
    ]);
    assert!(out.contains("matched: yes"));
    assert!(out.contains("match_rule: TestLiteral"));
    assert!(out.contains("match_tags: tag_a"));
}

#[test]
fn yara_reports_missing_inputs() {
    let tmp = tempdir().expect("tmp");
    let hit_path = tmp.path().join("hit.bin");
    fs::write(&hit_path, b"hello").expect("hit");

    let rule_err = run_fail(&[
        "--rule",
        tmp.path().join("missing.yar").to_str().expect("rule"),
        hit_path.to_str().expect("hit"),
    ]);
    assert!(rule_err.contains("Rule file not found"));

    let file_err = run_fail(&[
        "--rule",
        hit_path.to_str().expect("rule"),
        tmp.path().join("missing.bin").to_str().expect("file"),
    ]);
    assert!(file_err.contains("Target file not found"));
}

#[test]
fn yara_supports_numeric_reads_and_filesize_conditions() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("numeric.yar");
    let hit_path = tmp.path().join("numeric.bin");

    let mut payload = Vec::new();
    payload.extend_from_slice(&0x0102_0304u32.to_le_bytes());
    payload.extend_from_slice(&0x0102_0304u32.to_be_bytes());
    payload.extend_from_slice(&1.5f32.to_le_bytes());
    payload.extend_from_slice(&2.5f32.to_be_bytes());
    payload.extend_from_slice(&3.5f64.to_le_bytes());
    payload.extend_from_slice(&4.5f64.to_be_bytes());
    assert_eq!(payload.len(), 32);
    fs::write(&hit_path, payload).expect("write payload");

    fs::write(
        &rule_path,
        r#"
rule NumericReads {
  condition:
    filesize == 32 and
    uint32(0) == 16909060 and
    int32(0) == 16909060 and
    uint32be(4) == 16909060 and
    int32be(4) == 16909060 and
    float32(8) == 1.5 and
    float32be(12) == 2.5 and
    float64(16) == 3.5 and
    float64be(24) == 4.5
}
"#,
    )
    .expect("write rule");

    let out = run_ok(&[
        "--rule",
        rule_path.to_str().expect("rule"),
        hit_path.to_str().expect("hit"),
    ]);
    assert!(out.contains("matched: yes"));
    assert!(out.contains("match_rule: NumericReads"));
}

#[test]
fn tcp_cli_index_publish_search_roundtrip_verifies_match() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let dataset = tmp.path().join("dataset");
    fs::create_dir_all(&dataset).expect("dataset dir");
    let hit_path = dataset.join("hit.bin");
    let miss_path = dataset.join("miss.bin");
    let hit_bytes = b"xxABCDyy";
    let miss_bytes = b"zzzzzzzz";
    fs::write(&hit_path, hit_bytes).expect("hit");
    fs::write(&miss_path, miss_bytes).expect("miss");
    let expected_hit_sha = hex::encode(Sha256::digest(hit_bytes));
    let expected_miss_sha = hex::encode(Sha256::digest(miss_bytes));

    let rule_path = tmp.path().join("rule.yar");
    fs::write(
        &rule_path,
        r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
    )
    .expect("rule");

    let port = reserve_tcp_port();
    let addr = tcp_addr(port);
    init_root(&root, "workspace", &["--store-path"]);
    let mut child = spawn_serve_tcp(port, &root, &[]);
    wait_for_info_quick(&addr);

    let index_output = Command::new(bin_path())
        .args(["index", "--addr", &addr, dataset.to_str().expect("dataset")])
        .output()
        .expect("run index");
    assert!(
        index_output.status.success(),
        "index failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&index_output.stdout),
        String::from_utf8_lossy(&index_output.stderr)
    );

    wait_for_published_doc_count_quick(&addr, 2, 1);

    let info = run_ok(&["info", "--addr", &addr]);
    let parsed: Value = serde_json::from_str(&info).expect("stats json");
    assert_eq!(parsed.get("doc_count").and_then(Value::as_u64), Some(2));
    assert_eq!(
        parsed
            .get("publish")
            .and_then(|value| value.get("publish_runs_total"))
            .and_then(Value::as_u64),
        Some(1)
    );

    let search_output = Command::new(bin_path())
        .args([
            "search",
            "--addr",
            &addr,
            "--rule",
            rule_path.to_str().expect("rule"),
            "--verify",
        ])
        .output()
        .expect("run search");
    assert!(
        search_output.status.success(),
        "search failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&search_output.stdout),
        String::from_utf8_lossy(&search_output.stderr)
    );
    let stdout = String::from_utf8(search_output.stdout).expect("utf8 search stdout");
    assert!(stdout.contains("tier_used:"));
    assert!(stdout.contains("verified_matched: 1"));
    assert!(stdout.contains("verified_skipped: 0"));
    assert!(stdout.contains(&expected_hit_sha));
    assert!(!stdout.contains(&expected_miss_sha));

    let delete_output = Command::new(bin_path())
        .args([
            "delete",
            "--addr",
            &addr,
            hit_path.to_str().expect("hit path"),
        ])
        .output()
        .expect("run delete");
    assert!(
        delete_output.status.success(),
        "delete failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&delete_output.stdout),
        String::from_utf8_lossy(&delete_output.stderr)
    );
    let delete_stdout = String::from_utf8(delete_output.stdout).expect("utf8 delete stdout");
    assert!(delete_stdout.contains("status: deleted"));
    assert!(delete_stdout.contains(&expected_hit_sha));

    let info = run_ok(&["info", "--addr", &addr]);
    let parsed: Value = serde_json::from_str(&info).expect("stats json");
    assert_eq!(
        parsed.get("active_doc_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        parsed.get("deleted_doc_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        parsed
            .get("publish")
            .and_then(|value| value.get("publish_runs_total"))
            .and_then(Value::as_u64),
        Some(1)
    );

    let post_delete_search_output = Command::new(bin_path())
        .args([
            "search",
            "--addr",
            &addr,
            "--rule",
            rule_path.to_str().expect("rule"),
            "--verify",
        ])
        .output()
        .expect("run post-delete search");
    assert!(
        post_delete_search_output.status.success(),
        "post-delete search failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&post_delete_search_output.stdout),
        String::from_utf8_lossy(&post_delete_search_output.stderr)
    );
    let post_delete_stdout =
        String::from_utf8(post_delete_search_output.stdout).expect("utf8 post-delete stdout");
    assert!(post_delete_stdout.contains("tier_used:"));
    assert!(post_delete_stdout.contains("verified_matched: 0"));
    assert!(post_delete_stdout.contains("verified_skipped: 0"));
    assert!(!post_delete_stdout.contains(&expected_hit_sha));
    assert!(!post_delete_stdout.contains(&expected_miss_sha));

    let _ = child.kill();
    let _ = child.wait();
}
