#[derive(Debug, Parser)]
#[command(
    name = "sspry",
    about = "Scalable Screening and Prefiltering of Rules for YARA.",
    after_help = "Default scan mode: sspry --rule <RULE> <FILE>"
)]
struct Cli {
    #[arg(
        long = "perf-report",
        global = true,
        help = "Write JSON performance report to this path."
    )]
    perf_report: Option<String>,
    #[arg(long = "perf-stdout", global = true, action = ArgAction::SetTrue, help = "Print JSON performance report on exit.")]
    perf_stdout: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Init(InitArgs),
    Serve(ServeArgs),
    Index(IndexArgs),
    Delete(DeleteArgs),
    RuleCheck(RuleCheckArgs),
    Search(SearchCommandArgs),
    Info(InfoCommandArgs),
    Local(LocalArgs),
    Shutdown(ShutdownArgs),
    #[command(hide = true)]
    Yara(YaraArgs),
}

fn rewrite_default_yara_argv(argv: Vec<String>) -> Vec<String> {
    if argv.len() <= 1 {
        return argv;
    }
    let mut scan = 1usize;
    while scan < argv.len() {
        let token = &argv[scan];
        match token.as_str() {
            "--perf-report" => {
                scan += 2;
                continue;
            }
            "--perf-stdout" => {
                scan += 1;
                continue;
            }
            value if value.starts_with("--perf-report=") => {
                scan += 1;
                continue;
            }
            _ => break,
        }
    }
    if scan >= argv.len() {
        return argv;
    }
    let token = &argv[scan];
    if matches!(token.as_str(), "-h" | "--help") {
        return argv;
    }
    let is_named_command = matches!(
        token.as_str(),
        "init"
            | "serve"
            | "index"
            | "delete"
            | "rule-check"
            | "search"
            | "info"
            | "local"
            | "shutdown"
            | "help"
            | "yara"
    );
    if is_named_command {
        return argv;
    }

    let mut rewritten = Vec::with_capacity(argv.len() + 1);
    rewritten.extend_from_slice(&argv[..scan]);
    rewritten.push("yara".to_owned());
    rewritten.extend_from_slice(&argv[scan..]);
    rewritten
}

#[derive(Debug, clap::Args)]
struct LocalArgs {
    #[command(subcommand)]
    command: LocalCommands,
}

#[derive(Debug, Subcommand)]
enum LocalCommands {
    Index(LocalIndexArgs),
    Delete(LocalDeleteArgs),
    Search(LocalSearchArgs),
    Info(LocalInfoArgs),
}

#[derive(Debug, clap::Args)]
struct IndexArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(required = true, help = "File or directory paths.")]
    paths: Vec<String>,
    #[arg(
        long = "path-list",
        action = ArgAction::SetTrue,
        help = "Treat each input path as a newline-delimited manifest of file paths."
    )]
    path_list: bool,
    #[arg(
        long = "batch-bytes",
        default_value_t = REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
        help = "Client-side soft payload cap in bytes for remote insert_batch requests."
    )]
    batch_bytes: usize,
    #[arg(
        long = "insert-chunk-bytes",
        default_value_t = grpc::DEFAULT_GRPC_INSERT_CHUNK_BYTES,
        help = "Per-frame remote insert chunk size in bytes."
    )]
    grpc_insert_chunk_bytes: usize,
    #[arg(
        long = "workers",
        help = "Process workers for recursive file scan/feature extraction before batched inserts. Default is auto: CPU-based on solid-state input, capped conservatively on rotational storage."
    )]
    workers: Option<usize>,
    #[arg(
        long = "verbose",
        action = ArgAction::SetTrue,
        help = "Print timing details to stderr."
    )]
    verbose: bool,
}

#[derive(Debug, clap::Args)]
struct LocalIndexArgs {
    #[arg(
        long = "root",
        required = true,
        help = "Direct local store root directory."
    )]
    root: String,
    #[arg(required = true, help = "File or directory paths.")]
    paths: Vec<String>,
    #[arg(
        long = "path-list",
        action = ArgAction::SetTrue,
        help = "Treat each input path as a newline-delimited manifest of file paths."
    )]
    path_list: bool,
    #[arg(
        long = "batch-docs",
        default_value_t = 64,
        help = "Documents per local insert batch."
    )]
    batch_docs: usize,
    #[arg(
        long = "workers",
        help = "Process workers for recursive file scan/feature extraction before local batched inserts. Default is auto: CPU-based on solid-state input, capped conservatively on rotational storage."
    )]
    workers: Option<usize>,
    #[arg(
        long = "verbose",
        action = ArgAction::SetTrue,
        help = "Print timing details to stderr."
    )]
    verbose: bool,
}

#[derive(Debug, clap::Args)]
struct DeleteArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(
        required = true,
        help = "Existing file paths or hex digests in the server's configured identity format."
    )]
    values: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct LocalDeleteArgs {
    #[arg(
        long = "root",
        required = true,
        help = "Direct local store root directory."
    )]
    root: String,
    #[arg(
        required = true,
        help = "Existing file paths or hex digests in the store's identity format."
    )]
    values: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct RuleCheckArgs {
    #[arg(long = "rule", required = true, help = "Path to YARA rule file.")]
    rule: String,
    #[arg(
        long = "addr",
        conflicts_with = "root",
        help = "Use the active scan policy from a live server at host:port."
    )]
    addr: Option<String>,
    #[arg(
        long = "root",
        conflicts_with = "addr",
        help = "Use the active scan policy from a local store or forest root."
    )]
    root: Option<String>,
    #[arg(
        long = "id-source",
        value_enum,
        conflicts_with_all = ["addr", "root"],
        help = "Assumed DB identity source when no live server or local root is provided."
    )]
    id_source: Option<CandidateIdSource>,
    #[arg(
        long = "gram-sizes",
        conflicts_with_all = ["addr", "root"],
        help = "Assumed DB gram-size pair as tier1,tier2 when no live server or local root is provided."
    )]
    gram_sizes: Option<String>,
    #[arg(
        long = "max-anchors-per-pattern",
        default_value_t = 16,
        help = "Keep at most this many anchors per pattern alternative while checking."
    )]
    max_anchors_per_pattern: usize,
    #[arg(
        long = "json",
        action = ArgAction::SetTrue,
        help = "Emit structured JSON instead of text."
    )]
    json: bool,
}

#[derive(Debug, clap::Args)]
struct SearchCommandArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(long = "rule", required = true, help = "Path to YARA rule file.")]
    rule: String,
    #[arg(
        long = "max-anchors-per-pattern",
        default_value_t = 16,
        help = "Keep at most this many anchors per pattern alternative."
    )]
    max_anchors_per_pattern: usize,
    #[arg(
        long = "max-candidates",
        default_value_t = 10.0,
        value_parser = parse_max_candidates_percent,
        help = "Server-side candidate cap as a percentage of searchable documents; 0 means unlimited."
    )]
    max_candidates: f64,
    #[arg(
        long = "verify",
        action = ArgAction::SetTrue,
        default_value_t = false,
        help = "Enable local YARA verification over candidate file paths."
    )]
    verify_yara_files: bool,
    #[arg(long = "verbose", action = ArgAction::SetTrue, help = "Print timing details to stderr.")]
    verbose: bool,
}

#[derive(Debug, clap::Args)]
struct LocalSearchArgs {
    #[arg(
        long = "root",
        required = true,
        help = "Direct local store or forest root for in-process search."
    )]
    root: String,
    #[arg(long = "rule", required = true, help = "Path to YARA rule file.")]
    rule: String,
    #[arg(
        long = "search-workers",
        default_value_t = 0,
        help = "Local search workers. 0 means auto up to the tree count."
    )]
    search_workers: usize,
    #[arg(
        long = "max-anchors-per-pattern",
        default_value_t = 16,
        help = "Keep at most this many anchors per pattern alternative."
    )]
    max_anchors_per_pattern: usize,
    #[arg(
        long = "max-candidates",
        default_value_t = 10.0,
        value_parser = parse_max_candidates_percent,
        help = "Candidate cap as a percentage of searchable documents; 0 means unlimited."
    )]
    max_candidates: f64,
    #[arg(
        long = "verify",
        action = ArgAction::SetTrue,
        default_value_t = false,
        help = "Enable local YARA verification over candidate file paths."
    )]
    verify_yara_files: bool,
    #[arg(long = "verbose", action = ArgAction::SetTrue, help = "Print timing details to stderr.")]
    verbose: bool,
}

#[derive(Debug, clap::Args)]
struct InfoConnectionArgs {
    #[arg(
        long = "addr",
        env = "SSPRY_ADDR",
        default_value = DEFAULT_RPC_ADDR,
        help = "Server address as host:port."
    )]
    addr: String,
    #[arg(
        long = "timeout",
        default_value_t = DEFAULT_RPC_TIMEOUT,
        help = "Connection/read timeout in seconds."
    )]
    timeout: f64,
    #[arg(
        long = "ignore-offline",
        action = ArgAction::SetTrue,
        help = "Skip unreachable servers when --addr contains multiple comma-separated addresses."
    )]
    ignore_offline: bool,
}

#[derive(Debug, clap::Args)]
struct InfoCommandArgs {
    #[command(flatten)]
    connection: InfoConnectionArgs,
    #[arg(
        long = "light",
        action = ArgAction::SetTrue,
        help = "Return lightweight server status without walking shard stats."
    )]
    light: bool,
}

#[derive(Debug, clap::Args)]
struct LocalInfoArgs {
    #[arg(
        long = "root",
        required = true,
        help = "Direct local store or forest root directory."
    )]
    root: String,
}

#[derive(Debug, clap::Args)]
struct ShutdownArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
}

#[derive(Debug, clap::Args)]
struct YaraArgs {
    #[arg(long = "rule", required = true, help = "Path to YARA rule file.")]
    rule: String,
    #[arg(help = "Path to the file to scan.")]
    file_path: String,
    #[arg(
        long = "scan-timeout",
        default_value_t = 60,
        help = "YARA scan timeout in seconds (default: 60)."
    )]
    scan_timeout: u64,
    #[arg(
        long = "show-tags",
        action = ArgAction::SetTrue,
        help = "Print matched rule tags."
    )]
    show_tags: bool,
}

#[derive(Debug, Clone, clap::Args)]
struct ServeCommonArgs {
    #[arg(
        long = "addr",
        env = "SSPRY_ADDR",
        default_value = DEFAULT_RPC_ADDR,
        help = "Bind address as host:port."
    )]
    addr: String,
    #[arg(
        long = "search-workers",
        default_value_t = default_search_workers(),
        help = "Server-side search workers per search. Direct/workspace mode fans out across shards; forest mode fans out across shard/tree work units. Default is max(1, cpus/4)."
    )]
    search_workers: usize,
    #[arg(
        long = "root",
        default_value = DEFAULT_CANDIDATE_ROOT,
        help = "Workspace root, direct local store root, or forest root directory."
    )]
    root: String,
}

#[derive(Debug, clap::Args)]
struct ServeArgs {
    #[command(flatten)]
    common: ServeCommonArgs,
    #[arg(
        long = "max-message-bytes",
        default_value_t = DEFAULT_MAX_REQUEST_BYTES,
        help = "Maximum accepted remote message size in bytes."
    )]
    max_message_bytes: usize,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum InitMode {
    Workspace,
    Local,
}

#[derive(Debug, clap::Args)]
struct InitArgs {
    #[arg(
        long = "root",
        default_value = DEFAULT_CANDIDATE_ROOT,
        help = "Workspace root or direct local store root to initialize."
    )]
    root: String,
    #[arg(
        long = "mode",
        value_enum,
        default_value_t = InitMode::Workspace,
        help = "Initialization target. `workspace` creates/uses <root>/current for serve. `local` creates a direct store at <root> for local index/search/info."
    )]
    mode: InitMode,
    #[arg(
        long = "shards",
        help = "Number of independent candidate shards (lock stripes) to initialize. Defaults to 8 for workspace mode and 1 for local mode."
    )]
    shards: Option<usize>,
    #[arg(long = "force", action = ArgAction::SetTrue, help = "Overwrite an existing candidate store.")]
    force: bool,
    #[arg(
        long = "tier1-set-fp",
        help = "Tier1 Bloom false-positive rate. Defaults to 0.38 when omitted."
    )]
    tier1_filter_target_fp: Option<f64>,
    #[arg(
        long = "tier2-set-fp",
        help = "Tier2 Bloom false-positive rate. Defaults to 0.18 when omitted."
    )]
    tier2_filter_target_fp: Option<f64>,
    #[arg(
        long = "id-source",
        value_enum,
        default_value_t = CandidateIdSource::Sha256,
        help = "DB-wide document identity source used by ingest and delete."
    )]
    id_source: CandidateIdSource,
    #[arg(
        long = "store-path",
        action = ArgAction::SetTrue,
        help = "Store the canonical file path as external_id for each inserted document."
    )]
    store_path: bool,
    #[arg(
        long = "gram-sizes",
        default_value = "3,4",
        help = "DB-wide gram-size pair as tier1,tier2. Supported pairs: 3,4 4,5 5,6 7,8."
    )]
    gram_sizes: String,
    #[arg(
        long = "compaction-idle-cooldown-s",
        default_value_t = 5.0,
        help = "Minimum idle time after writes before compaction is allowed to run."
    )]
    compaction_idle_cooldown_s: f64,
    #[arg(
        long = "dedup-min-docs",
        default_value_t = 1_000_u64,
        help = "Minimum new inserts before tree source-ref rebuilds and forest-wide source-id dedup maintenance can run."
    )]
    source_dedup_min_new_docs: u64,
}

#[cfg(test)]
#[derive(Debug, clap::Args)]
struct InternalIndexArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    file_path: String,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
    #[arg(
        long = "external-id",
        help = "Optional external identifier to associate with the document."
    )]
    external_id: Option<String>,
    #[arg(long = "chunk-size", default_value_t = 1024 * 1024, help = "File read chunk size in bytes.")]
    chunk_size: usize,
}

#[derive(Debug, clap::Args)]
struct InternalIndexBatchArgs {
    paths: Vec<String>,
    #[arg(long = "path-list", action = ArgAction::SetTrue, help = "Treat input paths as newline-delimited file manifests.")]
    path_list: bool,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
    #[arg(
        long = "batch-docs",
        default_value_t = 64,
        help = "Documents per batch request."
    )]
    batch_docs: usize,
    #[arg(
        long = "workers",
        default_value_t = default_ingest_workers(),
        help = "Workers for recursive file scan before batched inserts."
    )]
    workers: usize,
    #[arg(long = "chunk-size", default_value_t = 1024 * 1024, help = "Client read chunk size in bytes.")]
    chunk_size: usize,
    #[arg(long = "verbose", action = ArgAction::SetTrue, help = "Print timing details to stderr.")]
    verbose: bool,
}

#[derive(Debug, clap::Args)]
struct InternalDeleteArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
    values: Vec<String>,
}

#[cfg(test)]
#[derive(Debug, clap::Args)]
struct InternalQueryArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
    #[arg(long = "rule", help = "Path to a restricted-YARA rule file.")]
    rule: String,
    #[arg(long = "cursor", default_value_t = 0, help = "Result cursor offset.")]
    cursor: usize,
    #[arg(long = "chunk-size", default_value_t = 128, help = "Page size.")]
    chunk_size: usize,
    #[arg(
        long = "max-anchors-per-pattern",
        alias = "max-anchors-per-alt",
        default_value_t = 16,
        help = "Maximum anchor grams kept per pattern alternative after planner reduction."
    )]
    max_anchors_per_pattern: usize,
    #[arg(long = "force-tier1-only", action = ArgAction::SetTrue, help = "Disable tier2 fallback for complete documents.")]
    force_tier1_only: bool,
    #[arg(long = "no-tier2-fallback", action = ArgAction::SetTrue, help = "Disable optional tier2 fallback on complete documents.")]
    no_tier2_fallback: bool,
    #[arg(
        long = "max-candidates",
        default_value_t = 10.0,
        value_parser = parse_max_candidates_percent,
        help = "Maximum candidate percentage returned before paging; 0 means unlimited."
    )]
    max_candidates: f64,
}

#[cfg(test)]
#[derive(Debug, clap::Args)]
#[cfg(test)]
struct InternalStatsArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
}
