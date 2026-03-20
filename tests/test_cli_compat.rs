use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tempfile::tempdir;

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sspry"))
}

fn run_ok(args: &[&str]) -> String {
    let output = Command::new(bin_path())
        .args(args)
        .output()
        .expect("run command");
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout={}\nstderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn run_ok_capture(args: &[&str]) -> (String, String) {
    let output = Command::new(bin_path())
        .args(args)
        .output()
        .expect("run command");
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout={}\nstderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        String::from_utf8(output.stderr).expect("utf8 stderr"),
    )
}

fn run_ok_env(args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut command = Command::new(bin_path());
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout={}\nstderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn reserve_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn tcp_addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

fn wait_for_info(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let output = Command::new(bin_path())
            .args(["info", "--addr", addr])
            .output()
            .expect("run info");
        if output.status.success() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not become ready on {addr}");
}

fn wait_for_search_candidates(addr: &str, rule: &Path, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let output = Command::new(bin_path())
            .args([
                "search",
                "--addr",
                addr,
                "--rule",
                rule.to_str().expect("rule path"),
            ])
            .output()
            .expect("run search");
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains(&format!("candidates: {expected}")) {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("search did not reach {expected} candidates on {addr}");
}

fn wait_for_verified_matches(
    addr: &str,
    rule: &Path,
    expected_checked: usize,
    expected_matched: usize,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let output = Command::new(bin_path())
            .args([
                "search",
                "--addr",
                addr,
                "--rule",
                rule.to_str().expect("rule path"),
                "--verify",
            ])
            .output()
            .expect("run verified search");
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains(&format!("verified_checked: {expected_checked}"))
                && stdout.contains(&format!("verified_matched: {expected_matched}"))
            {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "verified search did not reach checked={expected_checked} matched={expected_matched} on {addr}"
    );
}

fn spawn_serve_tcp(port: u16, candidate_root: &Path, extra_args: &[&str]) -> Child {
    let addr = tcp_addr(port);
    let mut command = Command::new(bin_path());
    command
        .arg("serve")
        .arg("--addr")
        .arg(&addr)
        .arg("--root")
        .arg(candidate_root)
        .args(extra_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.spawn().expect("spawn serve")
}

fn write_minimal_pe64_dotnet(path: &Path, anchor: &[u8]) {
    write_minimal_pe(
        path,
        0x14c,
        0x1234_5678,
        3,
        0x20b,
        false,
        true,
        true,
        anchor,
    );
}

fn write_minimal_pe(
    path: &Path,
    machine: u16,
    timestamp: u32,
    subsystem: u16,
    magic: u16,
    is_dll: bool,
    is_signed: bool,
    is_dotnet: bool,
    anchor: &[u8],
) {
    let mut pe = vec![0u8; 512];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    pe[0x88..0x8c].copy_from_slice(&timestamp.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    pe[0x96..0x98].copy_from_slice(&(if is_dll { 0x2000u16 } else { 0u16 }).to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&magic.to_le_bytes());
    pe[0x98 + 68..0x98 + 70].copy_from_slice(&subsystem.to_le_bytes());
    let data_dir_base = if magic == 0x10b { 96usize } else { 112usize };
    if is_signed {
        pe[0x98 + data_dir_base + 32..0x98 + data_dir_base + 40]
            .copy_from_slice(&[1, 0, 0, 0, 8, 0, 0, 0]);
    }
    if is_dotnet {
        pe[0x98 + data_dir_base + 112..0x98 + data_dir_base + 120]
            .copy_from_slice(&[1, 0, 0, 0, 8, 0, 0, 0]);
    }
    pe.extend_from_slice(anchor);
    fs::write(path, pe).expect("write pe");
}

fn write_minimal_crx(path: &Path, anchor: &[u8]) {
    let mut crx = b"Cr24".to_vec();
    crx.resize(32, 0);
    crx.extend_from_slice(anchor);
    fs::write(path, crx).expect("write crx");
}

fn write_minimal_zip(path: &Path, anchor: &[u8]) {
    let mut zip = b"PK\x03\x04".to_vec();
    zip.resize(32, 0);
    zip.extend_from_slice(anchor);
    fs::write(path, zip).expect("write zip");
}

fn write_minimal_elf64(path: &Path, anchor: &[u8]) {
    let mut elf = vec![0u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[7] = 3;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf.extend_from_slice(anchor);
    fs::write(path, elf).expect("write elf");
}

fn write_minimal_dex(path: &Path, version: &str, anchor: &[u8]) {
    let mut dex = format!("dex\n{version}\0").into_bytes();
    dex.resize(64, 0);
    dex.extend_from_slice(anchor);
    fs::write(path, dex).expect("write dex");
}

fn write_minimal_thin_macho(path: &Path, cpu_type: u32, device_type: u32, anchor: &[u8]) {
    let mut macho = vec![0u8; 64];
    macho[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    macho[4..8].copy_from_slice(&cpu_type.to_le_bytes());
    macho[16..20].copy_from_slice(&1u32.to_le_bytes());
    macho[20..24].copy_from_slice(&8u32.to_le_bytes());
    macho[32..36].copy_from_slice(&device_type.to_le_bytes());
    macho[36..40].copy_from_slice(&8u32.to_le_bytes());
    macho.extend_from_slice(anchor);
    fs::write(path, macho).expect("write macho");
}

fn unix_to_filetime(unix_seconds: u64) -> u64 {
    (unix_seconds + 11_644_473_600) * 10_000_000
}

fn write_minimal_lnk(
    path: &Path,
    creation_unix: u64,
    access_unix: u64,
    write_unix: u64,
    anchor: &[u8],
) {
    let mut lnk = vec![0u8; 128];
    lnk[0..4].copy_from_slice(&0x4cu32.to_le_bytes());
    lnk[4..12].copy_from_slice(&0x0000_0000_0002_1401u64.to_le_bytes());
    lnk[12..20].copy_from_slice(&0x4600_0000_0000_00c0u64.to_le_bytes());
    lnk[28..36].copy_from_slice(&unix_to_filetime(creation_unix).to_le_bytes());
    lnk[36..44].copy_from_slice(&unix_to_filetime(access_unix).to_le_bytes());
    lnk[44..52].copy_from_slice(&unix_to_filetime(write_unix).to_le_bytes());
    lnk[96..96 + anchor.len()].copy_from_slice(anchor);
    fs::write(path, lnk).expect("write lnk");
}

#[test]
fn public_cli_roundtrip_over_tcp() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let rule = base.join("rule.yar");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    let sample_a = sample_dir.join("a.bin");
    let sample_b = sample_dir.join("b.bin");
    fs::write(&sample_a, b"xxABCDyy").expect("write a");
    fs::write(&sample_b, b"zzABCDqq").expect("write b");
    fs::write(
        &rule,
        r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
    )
    .expect("write rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &["--store-path"]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("submitted_documents: 2"));
    assert!(ingest.contains("processed_documents: 2"));

    wait_for_search_candidates(&addr, &rule, 2);

    let search = run_ok(&[
        "search",
        "--addr",
        &addr,
        "--rule",
        rule.to_str().expect("rule"),
    ]);
    assert!(search.contains("tier_used:"));
    assert!(search.contains("candidates: 2"));

    let deleted = run_ok(&[
        "delete",
        "--addr",
        &addr,
        sample_a.to_str().expect("sample a"),
    ]);
    assert!(deleted.contains("status: deleted"));

    let info = run_ok(&["info", "--addr", &addr]);
    let parsed: Value = serde_json::from_str(&info).expect("info json");
    assert_eq!(parsed.get("doc_count").and_then(Value::as_u64), Some(2));
    assert_eq!(
        parsed.get("active_doc_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        parsed.get("deleted_doc_count").and_then(Value::as_u64),
        Some(1)
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn help_surface_has_only_public_commands() {
    let out = run_ok(&["--help"]);
    assert!(out.contains("Scalable Screening and Prefiltering of Rules for YARA"));
    assert!(out.contains("serve"));
    assert!(out.contains("index"));
    assert!(out.contains("delete"));
    assert!(out.contains("search"));
    assert!(out.contains("info"));
    assert!(out.contains("shutdown"));
    assert!(out.contains("yara"));
    assert!(!out.contains("publish"));
    assert!(!out.contains("candidate-init"));
    assert!(!out.contains("candidate-ingest"));
    assert!(!out.contains("candidate-query"));
    assert!(!out.contains("candidate-stats"));
    assert!(!out.contains("init\n"));
}

#[test]
fn info_uses_sspry_addr_env() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();
    let addr = tcp_addr(port);

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    wait_for_info(&addr);

    let info = run_ok_env(&["info"], &[("SSPRY_ADDR", &addr)]);
    let parsed: Value = serde_json::from_str(&info).expect("info json");
    assert_eq!(
        parsed.get("candidate_shards").and_then(Value::as_u64),
        Some(256)
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn serve_help_uses_sspry_env() {
    let out = run_ok(&["serve", "--help"]);
    assert!(out.contains("SSPRY_ADDR"));
}

#[test]
fn info_light_exposes_adaptive_publish_status() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();
    let addr = tcp_addr(port);

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    wait_for_info(&addr);

    let info = run_ok(&["info", "--addr", &addr, "--light"]);
    let parsed: Value = serde_json::from_str(&info).expect("info json");
    let adaptive_publish = parsed
        .get("adaptive_publish")
        .and_then(Value::as_object)
        .expect("adaptive publish object");
    assert!(adaptive_publish.contains_key("current_idle_ms"));
    assert!(adaptive_publish.contains_key("mode"));
    assert!(adaptive_publish.contains_key("reason"));
    assert!(adaptive_publish.contains_key("storage_class"));
    assert!(
        parsed
            .get("published_tier2_snapshot_seal")
            .and_then(Value::as_object)
            .is_some()
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_verify_uses_stored_paths_when_available() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let rule = base.join("rule.yar");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    let hit = sample_dir.join("hit.bin");
    let miss = sample_dir.join("miss.bin");
    fs::write(&hit, b"prefix NEEDLE suffix").expect("write hit");
    fs::write(&miss, b"prefix nothing suffix").expect("write miss");
    fs::write(
        &rule,
        r#"
rule q {
  strings:
    $a = "NEEDLE"
  condition:
    $a
}
"#,
    )
    .expect("write rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &["--store-path"]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 2"));

    wait_for_search_candidates(&addr, &rule, 1);
    wait_for_verified_matches(&addr, &rule, 1, 1);

    let search = run_ok(&[
        "search",
        "--addr",
        &addr,
        "--rule",
        rule.to_str().expect("rule"),
        "--verify",
    ]);
    assert!(search.contains("candidates: 1"));
    assert!(search.contains("verified_checked: 1"));
    assert!(search.contains("verified_matched: 1"));
    assert!(search.contains("verified_skipped: 0"));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_verify_skips_candidates_without_stored_paths() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let rule = base.join("rule.yar");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    let hit = sample_dir.join("hit.bin");
    fs::write(&hit, b"prefix NEEDLE suffix").expect("write hit");
    fs::write(
        &rule,
        r#"
rule q {
  strings:
    $a = "NEEDLE"
  condition:
    $a
}
"#,
    )
    .expect("write rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 1"));

    wait_for_search_candidates(&addr, &rule, 1);

    let search = run_ok(&[
        "search",
        "--addr",
        &addr,
        "--rule",
        rule.to_str().expect("rule"),
        "--verify",
    ]);
    assert!(search.contains("candidates: 1"));
    assert!(search.contains("verified_checked: 0"));
    assert!(search.contains("verified_matched: 0"));
    assert!(search.contains("verified_skipped: 1"));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_supports_filesize_equality_conditions() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let rule = base.join("rule.yar");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    let small = sample_dir.join("small.bin");
    let large = sample_dir.join("large.bin");
    fs::write(&small, b"ABCD1234").expect("write small");
    fs::write(&large, b"ABCD12345").expect("write large");
    fs::write(
        &rule,
        r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a and filesize == 8
}
"#,
    )
    .expect("write rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 2"));

    wait_for_search_candidates(&addr, &rule, 1);

    let search = run_ok(&[
        "search",
        "--addr",
        &addr,
        "--rule",
        rule.to_str().expect("rule"),
    ]);
    assert!(search.contains("candidates: 1"));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_supports_module_metadata_conditions() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let pe_rule = base.join("pe_rule.yar");
    let elf_rule = base.join("elf_rule.yar");
    let dex_rule = base.join("dex_rule.yar");
    let lnk_rule = base.join("lnk_rule.yar");
    let port = reserve_tcp_port();
    let anchor = b"ANCHOR";
    let creation_time = 1_700_000_000u64;
    let access_time = creation_time + 1;
    let write_time = creation_time + 2;
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    write_minimal_pe64_dotnet(&sample_dir.join("dotnet_pe.bin"), anchor);
    write_minimal_elf64(&sample_dir.join("linux.elf"), anchor);
    write_minimal_dex(&sample_dir.join("classes.dex"), "035", anchor);
    write_minimal_lnk(
        &sample_dir.join("shortcut.lnk"),
        creation_time,
        access_time,
        write_time,
        anchor,
    );
    fs::write(
        sample_dir.join("decoy.bin"),
        [anchor.as_slice(), b"-not-a-module"].concat(),
    )
    .expect("write decoy");

    fs::write(
        &pe_rule,
        r#"
rule ModulePe {
  strings:
    $a = "ANCHOR"
  condition:
    $a and pe.is_pe and PE.Machine == 0x14c and pe.is_64bit == true and dotnet.is_dotnet == true
}
"#,
    )
    .expect("write pe rule");
    fs::write(
        &elf_rule,
        r#"
rule ModuleElf {
  strings:
    $a = "ANCHOR"
  condition:
    $a and elf.machine == 62 and elf.type == 2 and ELF.OSABI == 3
}
"#,
    )
    .expect("write elf rule");
    fs::write(
        &dex_rule,
        r#"
rule ModuleDex {
  strings:
    $a = "ANCHOR"
  condition:
    $a and dex.is_dex and dex.version == 35
}
"#,
    )
    .expect("write dex rule");
    fs::write(
        &lnk_rule,
        format!(
            r#"
rule ModuleLnk {{
  strings:
    $a = "ANCHOR"
  condition:
    $a and lnk.is_lnk and lnk.creation_time == {creation_time} and lnk.access_time == {access_time} and lnk.write_time == {write_time}
}}
"#
        ),
    )
    .expect("write lnk rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 5"));

    for rule in [&pe_rule, &elf_rule, &dex_rule, &lnk_rule] {
        wait_for_search_candidates(&addr, rule, 1);
        let search = run_ok(&[
            "search",
            "--addr",
            &addr,
            "--rule",
            rule.to_str().expect("rule"),
        ]);
        assert!(search.contains("candidates: 1"), "{rule:?}: {search}");
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_supports_additional_module_metadata_conditions() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let pe_rule = base.join("pe_extra_rule.yar");
    let crx_rule = base.join("crx_rule.yar");
    let macho_rule = base.join("macho_rule.yar");
    let port = reserve_tcp_port();
    let anchor = b"EXTRA-ANCHOR";
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    write_minimal_pe(
        &sample_dir.join("signed32.dll"),
        0x14c,
        0x2233_4455,
        2,
        0x10b,
        true,
        true,
        false,
        anchor,
    );
    write_minimal_crx(&sample_dir.join("sample.crx"), anchor);
    write_minimal_thin_macho(&sample_dir.join("sample.macho"), 0x0100_0007, 0x24, anchor);
    fs::write(
        sample_dir.join("decoy.bin"),
        [anchor.as_slice(), b"-not-a-module"].concat(),
    )
    .expect("write decoy");

    fs::write(
        &pe_rule,
        r#"
rule ModulePeExtra {
  strings:
    $a = "EXTRA-ANCHOR"
  condition:
    $a and pe.is_pe and pe.is_32bit and pe.is_64bit == false and pe.is_dll and pe.is_signed and dotnet.is_dotnet == false and pe.subsystem == 2 and pe.timestamp == 0x22334455
}
"#,
    )
    .expect("write pe rule");
    fs::write(
        &crx_rule,
        r#"
rule ModuleCrx {
  strings:
    $a = "EXTRA-ANCHOR"
  condition:
    $a and crx.is_crx
}
"#,
    )
    .expect("write crx rule");
    fs::write(
        &macho_rule,
        r#"
rule ModuleMacho {
  strings:
    $a = "EXTRA-ANCHOR"
  condition:
    $a and macho.cputype == 0x01000007 and macho.devicetype == 0x24
}
"#,
    )
    .expect("write macho rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 4"));

    for rule in [&pe_rule, &crx_rule, &macho_rule] {
        wait_for_search_candidates(&addr, rule, 1);
        let search = run_ok(&[
            "search",
            "--addr",
            &addr,
            "--rule",
            rule.to_str().expect("rule"),
        ]);
        assert!(search.contains("candidates: 1"), "{rule:?}: {search}");
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_rewrites_header_magic_numeric_conditions_to_metadata() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let pe_rule = base.join("pe_magic_rule.yar");
    let pe_be_rule = base.join("pe_magic_be_rule.yar");
    let elf_rule = base.join("elf_magic_rule.yar");
    let zip_rule = base.join("zip_magic_rule.yar");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    write_minimal_pe64_dotnet(&sample_dir.join("sample.exe"), b"pe-hit");
    write_minimal_elf64(&sample_dir.join("sample.elf"), b"elf-hit");
    write_minimal_zip(&sample_dir.join("sample.zip"), b"zip-hit");
    fs::write(sample_dir.join("decoy.bin"), b"not-a-magic-hit").expect("write decoy");

    fs::write(
        &pe_rule,
        r#"
rule MagicPeLe {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or uint16(0) == 0x5A4D
}
"#,
    )
    .expect("write pe rule");
    fs::write(
        &pe_be_rule,
        r#"
rule MagicPeBe {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or uint16be(0) == 0x4D5A
}
"#,
    )
    .expect("write pe be rule");
    fs::write(
        &elf_rule,
        r#"
rule MagicElf {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or uint32(0) == 0x464C457F
}
"#,
    )
    .expect("write elf rule");
    fs::write(
        &zip_rule,
        r#"
rule MagicZip {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or uint32(0) == 0x04034B50
}
"#,
    )
    .expect("write zip rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 4"));

    for rule in [&pe_rule, &pe_be_rule, &elf_rule, &zip_rule] {
        wait_for_search_candidates(&addr, rule, 1);
        let search = run_ok(&[
            "search",
            "--addr",
            &addr,
            "--rule",
            rule.to_str().expect("rule"),
        ]);
        assert!(search.contains("candidates: 1"), "{rule:?}: {search}");
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn index_verbose_emits_server_telemetry() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");
    fs::write(sample_dir.join("a.bin"), b"alpha NEEDLE").expect("write a");
    fs::write(sample_dir.join("b.bin"), b"beta NEEDLE").expect("write b");

    let mut child = spawn_serve_tcp(port, &candidate_root, &["--store-path"]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let (stdout, stderr) = run_ok_capture(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
        "--verbose",
    ]);
    assert!(stdout.contains("submitted_documents: 2"));
    assert!(stdout.contains("processed_documents: 2"));
    assert!(stderr.contains("verbose.index.total_ms:"));
    assert!(stderr.contains("verbose.index.submit_ms:"));
    assert!(stderr.contains("verbose.index.server_disk_usage_bytes:"));
    assert!(stderr.contains("verbose.index.server_publish_adaptive_idle_ms:"));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_verbose_verify_emits_telemetry() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let rule = base.join("rule.yar");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    fs::write(sample_dir.join("hit.bin"), b"prefix NEEDLE suffix").expect("write hit");
    fs::write(sample_dir.join("miss.bin"), b"prefix nothing suffix").expect("write miss");
    fs::write(
        &rule,
        r#"
rule q {
  strings:
    $a = "NEEDLE"
  condition:
    $a
}
"#,
    )
    .expect("write rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &["--store-path"]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 2"));
    wait_for_search_candidates(&addr, &rule, 1);

    let (stdout, stderr) = run_ok_capture(&[
        "search",
        "--addr",
        &addr,
        "--rule",
        rule.to_str().expect("rule"),
        "--verify",
        "--verbose",
    ]);
    assert!(stdout.contains("candidates: 1"));
    assert!(stdout.contains("verified_checked: 1"));
    assert!(stdout.contains("verified_matched: 1"));
    assert!(stderr.contains("verbose.search.total_ms:"));
    assert!(stderr.contains("verbose.search.query_ms:"));
    assert!(stderr.contains("verbose.search.verify_ms:"));
    assert!(stderr.contains("verbose.search.verify_enabled: true"));
    assert!(stderr.contains("verbose.search.verified_checked: 1"));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_verify_supports_numeric_read_equality_conditions() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let rule = base.join("numeric_rule.yar");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    let mut hit = 0x0000_4000u32.to_le_bytes().to_vec();
    hit.extend_from_slice(b"rest-of-hit");
    fs::write(sample_dir.join("hit.bin"), hit).expect("write hit");

    let mut miss = 0x0000_4001u32.to_le_bytes().to_vec();
    miss.extend_from_slice(b"rest-of-miss");
    fs::write(sample_dir.join("miss.bin"), miss).expect("write miss");

    fs::write(
        &rule,
        r#"
rule NumericSearch {
  strings:
    $unused = "ANCHOR"
  condition:
    $unused or uint32(0) == 0x4000
}
"#,
    )
    .expect("write rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &["--store-path"]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 2"));

    wait_for_search_candidates(&addr, &rule, 1);

    let search = run_ok(&[
        "search",
        "--addr",
        &addr,
        "--rule",
        rule.to_str().expect("rule"),
        "--verify",
    ]);
    assert!(search.contains("candidates: 1"));
    assert!(search.contains("verified_checked: 1"));
    assert!(search.contains("verified_matched: 1"));
    assert!(search.contains("verified_skipped: 0"));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_verify_supports_numeric_read_equality_variants() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    fs::write(
        sample_dir.join("u32le_hit.bin"),
        [0x0000_4000u32.to_le_bytes().as_slice(), b"u32le-hit"].concat(),
    )
    .expect("write u32le hit");
    fs::write(
        sample_dir.join("u32le_miss.bin"),
        [0x0000_4001u32.to_le_bytes().as_slice(), b"u32le-miss"].concat(),
    )
    .expect("write u32le miss");
    fs::write(
        sample_dir.join("u32be_hit.bin"),
        [0x0000_4000u32.to_be_bytes().as_slice(), b"u32be-hit"].concat(),
    )
    .expect("write u32be hit");
    fs::write(
        sample_dir.join("u32be_miss.bin"),
        [0x0000_4001u32.to_be_bytes().as_slice(), b"u32be-miss"].concat(),
    )
    .expect("write u32be miss");
    fs::write(
        sample_dir.join("f32le_hit.bin"),
        [1.5f32.to_bits().to_le_bytes().as_slice(), b"f32le-hit"].concat(),
    )
    .expect("write f32le hit");
    fs::write(
        sample_dir.join("f32le_miss.bin"),
        [1.25f32.to_bits().to_le_bytes().as_slice(), b"f32le-miss"].concat(),
    )
    .expect("write f32le miss");
    fs::write(
        sample_dir.join("f32be_hit.bin"),
        [1.5f32.to_bits().to_be_bytes().as_slice(), b"f32be-hit"].concat(),
    )
    .expect("write f32be hit");
    fs::write(
        sample_dir.join("f32be_miss.bin"),
        [1.25f32.to_bits().to_be_bytes().as_slice(), b"f32be-miss"].concat(),
    )
    .expect("write f32be miss");
    fs::write(
        sample_dir.join("f64le_hit.bin"),
        [3.25f64.to_bits().to_le_bytes().as_slice(), b"f64le-hit"].concat(),
    )
    .expect("write f64le hit");
    fs::write(
        sample_dir.join("f64le_miss.bin"),
        [3.5f64.to_bits().to_le_bytes().as_slice(), b"f64le-miss"].concat(),
    )
    .expect("write f64le miss");
    fs::write(
        sample_dir.join("f64be_hit.bin"),
        [3.25f64.to_bits().to_be_bytes().as_slice(), b"f64be-hit"].concat(),
    )
    .expect("write f64be hit");
    fs::write(
        sample_dir.join("f64be_miss.bin"),
        [3.5f64.to_bits().to_be_bytes().as_slice(), b"f64be-miss"].concat(),
    )
    .expect("write f64be miss");

    let mut child = spawn_serve_tcp(port, &candidate_root, &["--store-path"]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 12"));

    let rules = [
        (
            "uint32_le.yar",
            r#"
rule NumericU32Le {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or uint32(0) == 0x4000
}
"#,
        ),
        (
            "int32_le.yar",
            r#"
rule NumericI32Le {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or int32(0) == 0x4000
}
"#,
        ),
        (
            "uint32_be.yar",
            r#"
rule NumericU32Be {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or uint32be(0) == 0x4000
}
"#,
        ),
        (
            "int32_be.yar",
            r#"
rule NumericI32Be {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or int32be(0) == 0x4000
}
"#,
        ),
        (
            "float32_le.yar",
            r#"
rule NumericF32Le {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or float32(0) == 1.5
}
"#,
        ),
        (
            "float32_be.yar",
            r#"
rule NumericF32Be {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or float32be(0) == 1.5
}
"#,
        ),
        (
            "float64_le.yar",
            r#"
rule NumericF64Le {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or float64(0) == 3.25
}
"#,
        ),
        (
            "float64_be.yar",
            r#"
rule NumericF64Be {
  strings:
    $unused = "UNUSED-ANCHOR"
  condition:
    $unused or float64be(0) == 3.25
}
"#,
        ),
    ];

    for (file_name, rule_text) in rules {
        let rule_path = base.join(file_name);
        fs::write(&rule_path, rule_text).expect("write numeric rule");
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut last_output = String::new();
        while Instant::now() < deadline {
            let output = Command::new(bin_path())
                .args([
                    "search",
                    "--addr",
                    &addr,
                    "--rule",
                    rule_path.to_str().expect("rule"),
                    "--verify",
                ])
                .output()
                .expect("run verified numeric search");
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                if stdout.contains("verified_checked: 1") && stdout.contains("verified_matched: 1")
                {
                    last_output = stdout;
                    break;
                }
                last_output = stdout;
            } else {
                last_output = format!(
                    "stdout={}\nstderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert!(
            last_output.contains("verified_checked: 1")
                && last_output.contains("verified_matched: 1"),
            "{file_name}: {last_output}"
        );
        let search = run_ok(&[
            "search",
            "--addr",
            &addr,
            "--rule",
            rule_path.to_str().expect("rule"),
            "--verify",
        ]);
        assert!(search.contains("candidates: 1"), "{file_name}: {search}");
        assert!(
            search.contains("verified_checked: 1"),
            "{file_name}: {search}"
        );
        assert!(
            search.contains("verified_matched: 1"),
            "{file_name}: {search}"
        );
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn search_supports_time_now_and_wide_literal_conditions() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let time_rule = base.join("time_rule.yar");
    let wide_rule = base.join("wide_rule.yar");
    let ascii_rule = base.join("ascii_rule.yar");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    fs::write(sample_dir.join("clock.bin"), b"CLOCK-ANCHOR").expect("write clock");

    let mut wide_bytes = Vec::new();
    for unit in "WIDE-ANCHOR".encode_utf16() {
        wide_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    fs::write(sample_dir.join("wide.bin"), &wide_bytes).expect("write wide");
    fs::write(sample_dir.join("ascii.bin"), b"ASCII-ANCHOR").expect("write ascii");

    fs::write(
        &wide_rule,
        r#"
rule WideLiteral {
  strings:
    $a = "WIDE-ANCHOR" wide
  condition:
    $a
}
"#,
    )
    .expect("write wide rule");
    fs::write(
        &ascii_rule,
        r#"
rule AsciiLiteral {
  strings:
    $a = "ASCII-ANCHOR" ascii
  condition:
    $a
}
"#,
    )
    .expect("write ascii rule");

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 3"));

    for rule in [&wide_rule, &ascii_rule] {
        wait_for_search_candidates(&addr, rule, 1);
        let search = run_ok(&[
            "search",
            "--addr",
            &addr,
            "--rule",
            rule.to_str().expect("rule"),
        ]);
        assert!(search.contains("candidates: 1"), "{rule:?}: {search}");
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut matched = false;
    while Instant::now() < deadline {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix time")
            .as_secs();
        fs::write(
            &time_rule,
            format!(
                r#"
rule TimeNow {{
  strings:
    $a = "CLOCK-ANCHOR"
  condition:
    $a and time.now == {now}
}}
"#
            ),
        )
        .expect("write time rule");
        let search = run_ok(&[
            "search",
            "--addr",
            &addr,
            "--rule",
            time_rule.to_str().expect("rule"),
        ]);
        if search.contains("candidates: 1") {
            matched = true;
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(matched, "time.now rule did not match within deadline");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn shutdown_command_drains_server() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();
    let addr = tcp_addr(port);

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    wait_for_info(&addr);

    let out = run_ok(&["shutdown", "--addr", &addr]);
    assert!(out.contains("shutdown requested"));

    for _ in 0..80 {
        if child.try_wait().expect("wait").is_some() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("server did not exit after shutdown");
}
