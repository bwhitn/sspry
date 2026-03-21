use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use yara_x::{Compiler as YaraCompiler, Scanner as YaraScanner};

#[derive(Debug, Parser)]
#[command(about = "Generate ground-truth per-rule matches from original YARA files.")]
struct Args {
    #[arg(long = "manifest")]
    manifest: PathBuf,
    #[arg(long = "files-json")]
    files_json: PathBuf,
    #[arg(long = "output-json")]
    output_json: PathBuf,
    #[arg(long = "workers", default_value_t = default_workers())]
    workers: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct InputRuleFile {
    path: String,
    #[serde(default)]
    rule_file: String,
}

#[derive(Debug, Serialize)]
struct OutputRuleFile {
    path: String,
    rule_file: String,
    compile_error: Option<String>,
    scan_errors: Vec<String>,
    matches: BTreeMap<String, Vec<String>>,
}

fn default_workers() -> usize {
    thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1)
        .max(1)
        .min(8)
}

fn first_64_hex(name: &str) -> Option<String> {
    let mut current = String::new();
    for ch in name.chars() {
        if ch.is_ascii_hexdigit() {
            current.push(ch.to_ascii_lowercase());
            if current.len() == 64 {
                return Some(current);
            }
        } else {
            current.clear();
        }
    }
    None
}

fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("read {}: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn file_identity_hex(path: &Path) -> Result<String, String> {
    if let Some(hex) = path
        .file_name()
        .and_then(|value| value.to_str())
        .and_then(first_64_hex)
    {
        return Ok(hex);
    }
    sha256_file_hex(path)
}

fn load_manifest(path: &Path) -> Result<Vec<(PathBuf, String)>, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("read manifest {}: {err}", path.display()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let file_path = PathBuf::from(trimmed);
        let identity = file_identity_hex(&file_path)?;
        out.push((file_path, identity));
    }
    Ok(out)
}

fn process_rule_file(file: &InputRuleFile, manifest: &[(PathBuf, String)]) -> OutputRuleFile {
    let source = match fs::read_to_string(&file.path) {
        Ok(value) => value,
        Err(err) => {
            return OutputRuleFile {
                path: file.path.clone(),
                rule_file: file.rule_file.clone(),
                compile_error: Some(format!("read error: {err}")),
                scan_errors: Vec::new(),
                matches: BTreeMap::new(),
            };
        }
    };
    let mut compiler = YaraCompiler::new();
    if let Err(err) = compiler.add_source(source.as_str()) {
        return OutputRuleFile {
            path: file.path.clone(),
            rule_file: file.rule_file.clone(),
            compile_error: Some(err.to_string()),
            scan_errors: Vec::new(),
            matches: BTreeMap::new(),
        };
    }
    let rules = compiler.build();
    let mut scanner = YaraScanner::new(&rules);
    let mut matches = BTreeMap::<String, Vec<String>>::new();
    let mut scan_errors = Vec::new();
    for (scan_path, identity_hex) in manifest {
        match scanner.scan_file(scan_path) {
            Ok(scan) => {
                for rule in scan.matching_rules() {
                    matches
                        .entry(rule.identifier().to_owned())
                        .or_default()
                        .push(identity_hex.clone());
                }
            }
            Err(err) => {
                scan_errors.push(format!("{}: {}", scan_path.display(), err));
            }
        }
    }
    for values in matches.values_mut() {
        values.sort();
        values.dedup();
    }
    OutputRuleFile {
        path: file.path.clone(),
        rule_file: file.rule_file.clone(),
        compile_error: None,
        scan_errors,
        matches,
    }
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    let inputs: Vec<InputRuleFile> = serde_json::from_str(
        &fs::read_to_string(&args.files_json)
            .map_err(|err| format!("read files json {}: {err}", args.files_json.display()))?,
    )
    .map_err(|err| format!("decode files json {}: {err}", args.files_json.display()))?;
    let manifest = Arc::new(load_manifest(&args.manifest)?);
    let queue = Arc::new(Mutex::new(inputs));
    let (tx, rx) = mpsc::channel::<OutputRuleFile>();
    let worker_count = args.workers.max(1);
    let mut workers = Vec::new();
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let manifest = Arc::clone(&manifest);
        let tx = tx.clone();
        workers.push(thread::spawn(move || {
            loop {
                let next = {
                    let mut guard = queue.lock().expect("queue lock");
                    guard.pop()
                };
                let Some(file) = next else {
                    break;
                };
                let result = process_rule_file(&file, &manifest);
                if tx.send(result).is_err() {
                    break;
                }
            }
        }));
    }
    drop(tx);

    let mut results = Vec::new();
    while let Ok(record) = rx.recv() {
        results.push(record);
    }
    for worker in workers {
        worker.join().map_err(|_| "worker panicked".to_owned())?;
    }
    results.sort_by(|left, right| left.path.cmp(&right.path));
    fs::write(
        &args.output_json,
        serde_json::to_vec_pretty(&results)
            .map_err(|err| format!("encode output {}: {err}", args.output_json.display()))?,
    )
    .map_err(|err| format!("write output {}: {err}", args.output_json.display()))?;
    Ok(())
}
