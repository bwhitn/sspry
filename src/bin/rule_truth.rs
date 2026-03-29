use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use yara_x::{Compiler as YaraCompiler, Scanner as YaraScanner, SourceCode};

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

fn compile_rule_files(
    files: &[InputRuleFile],
) -> (
    Vec<OutputRuleFile>,
    Option<Arc<yara_x::Rules>>,
    BTreeMap<String, usize>,
) {
    let mut outputs = Vec::with_capacity(files.len());
    let mut compiler = YaraCompiler::new();
    let mut namespace_to_output = BTreeMap::new();
    let mut compiled_any = false;

    for (index, file) in files.iter().enumerate() {
        outputs.push(OutputRuleFile {
            path: file.path.clone(),
            rule_file: file.rule_file.clone(),
            compile_error: None,
            scan_errors: Vec::new(),
            matches: BTreeMap::new(),
        });

        let source = match fs::read_to_string(&file.path) {
            Ok(value) => value,
            Err(err) => {
                outputs[index].compile_error = Some(format!("read error: {err}"));
                continue;
            }
        };

        let namespace = format!("rule_file_{index:04}");
        compiler.new_namespace(&namespace);
        let source = SourceCode::from(source.as_str()).with_origin(&file.path);
        if let Err(err) = compiler.add_source(source) {
            outputs[index].compile_error = Some(err.to_string());
            continue;
        }

        namespace_to_output.insert(namespace, index);
        compiled_any = true;
    }

    let rules = if compiled_any {
        Some(Arc::new(compiler.build()))
    } else {
        None
    };

    (outputs, rules, namespace_to_output)
}

#[derive(Default)]
struct WorkerAccum {
    matches: Vec<BTreeMap<String, Vec<String>>>,
    scan_errors: Vec<String>,
}

fn scan_manifest_chunk(
    manifest: &[(PathBuf, String)],
    rules: &yara_x::Rules,
    namespace_to_output: &BTreeMap<String, usize>,
    output_count: usize,
    progress: &AtomicUsize,
    total_files: usize,
) -> WorkerAccum {
    let mut scanner = YaraScanner::new(rules);
    let mut matches = vec![BTreeMap::<String, Vec<String>>::new(); output_count];
    let mut scan_errors = Vec::new();

    for (scan_path, identity_hex) in manifest {
        match scanner.scan_file(scan_path) {
            Ok(scan) => {
                for rule in scan.matching_rules() {
                    if let Some(output_index) = namespace_to_output.get(rule.namespace()) {
                        matches[*output_index]
                            .entry(rule.identifier().to_owned())
                            .or_default()
                            .push(identity_hex.clone());
                    }
                }
            }
            Err(err) => {
                scan_errors.push(format!("{}: {}", scan_path.display(), err));
            }
        }

        let processed = progress.fetch_add(1, Ordering::Relaxed) + 1;
        if processed == total_files || processed % 1000 == 0 {
            eprintln!(
                "progress.truth: {processed}/{total_files} ({:.1}%)",
                (processed as f64 / total_files.max(1) as f64) * 100.0
            );
        }
    }

    WorkerAccum {
        matches,
        scan_errors,
    }
}

fn dedup_output_matches(output: &mut OutputRuleFile) {
    for values in output.matches.values_mut() {
        values.sort();
        values.dedup();
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
    let (mut results, rules, namespace_to_output) = compile_rule_files(&inputs);

    if let Some(rules) = rules {
        let output_count = results.len();
        let total_files = manifest.len();
        let worker_count = args.workers.max(1).min(total_files.max(1));
        let progress = Arc::new(AtomicUsize::new(0));
        let mut scan_errors = Vec::new();

        thread::scope(|scope| -> Result<(), String> {
            let mut handles = Vec::new();
            if total_files > 0 {
                let chunk_size = total_files.div_ceil(worker_count);
                for chunk in manifest.chunks(chunk_size) {
                    let progress = Arc::clone(&progress);
                    let rules = Arc::clone(&rules);
                    let namespace_to_output = &namespace_to_output;
                    handles.push(scope.spawn(move || {
                        scan_manifest_chunk(
                            chunk,
                            rules.as_ref(),
                            namespace_to_output,
                            output_count,
                            progress.as_ref(),
                            total_files,
                        )
                    }));
                }
            }

            for handle in handles {
                let accum = handle
                    .join()
                    .map_err(|_| "rule_truth worker panicked".to_owned())?;
                scan_errors.extend(accum.scan_errors);
                for (output, local_matches) in results.iter_mut().zip(accum.matches.into_iter()) {
                    for (rule_name, mut identities) in local_matches {
                        output
                            .matches
                            .entry(rule_name)
                            .or_default()
                            .append(&mut identities);
                    }
                }
            }

            Ok(())
        })?;

        scan_errors.sort();
        scan_errors.dedup();
        for output in &mut results {
            if output.compile_error.is_none() {
                output.scan_errors = scan_errors.clone();
            }
            dedup_output_matches(output);
        }
    } else {
        for output in &mut results {
            dedup_output_matches(output);
        }
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
