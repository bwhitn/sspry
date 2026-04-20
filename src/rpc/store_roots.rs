/// Merges one candidate-store open profile into the aggregate startup metrics
/// for a root.
///
/// Inputs:
/// - `aggregate`: Running totals for a direct/work/current root.
/// - `profile`: Timing and count data produced while opening one shard.
///
/// Output:
/// - Updates `aggregate` in place by saturating each counter.
fn apply_store_open_profile(
    aggregate: &mut StoreRootStartupProfile,
    profile: &CandidateStoreOpenProfile,
) {
    aggregate.doc_count = aggregate.doc_count.saturating_add(profile.doc_count as u64);
    aggregate.store_open_total_ms = aggregate
        .store_open_total_ms
        .saturating_add(profile.total_ms);
    aggregate.store_open_manifest_ms = aggregate
        .store_open_manifest_ms
        .saturating_add(profile.manifest_ms);
    aggregate.store_open_meta_ms = aggregate.store_open_meta_ms.saturating_add(profile.meta_ms);
    aggregate.store_open_load_state_ms = aggregate
        .store_open_load_state_ms
        .saturating_add(profile.load_state_ms);
    aggregate.store_open_sidecars_ms = aggregate
        .store_open_sidecars_ms
        .saturating_add(profile.sidecars_ms);
    aggregate.store_open_rebuild_indexes_ms = aggregate
        .store_open_rebuild_indexes_ms
        .saturating_add(profile.rebuild_indexes_ms);
    aggregate.store_open_rebuild_identity_index_ms = aggregate
        .store_open_rebuild_identity_index_ms
        .saturating_add(profile.rebuild_identity_index_ms);
}

/// Opens an existing candidate store or initializes a new one while capturing
/// a startup profile.
///
/// Inputs:
/// - `config`: Fully resolved candidate-store configuration for a single root.
///
/// Returns:
/// - The opened store.
/// - Whether the store had to be initialized from scratch.
/// - The open/init timing profile for startup reporting.
fn ensure_candidate_store_profiled(
    config: CandidateConfig,
) -> Result<(CandidateStore, bool, CandidateStoreOpenProfile)> {
    let has_store_meta =
        config.root.join("store_meta.json").exists() || config.root.join("meta.json").exists();
    if !has_store_meta {
        let started = Instant::now();
        let store = CandidateStore::init(config, false)?;
        return Ok((
            store,
            true,
            CandidateStoreOpenProfile {
                total_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                ..CandidateStoreOpenProfile::default()
            },
        ));
    }
    let (store, profile) = CandidateStore::open_profiled(&config.root)?;
    Ok((store, false, profile))
}

/// Returns the canonical workspace path that serves published data.
fn workspace_current_root(root: &Path) -> PathBuf {
    root.join("current")
}

/// Returns the first candidate workspace path used for staging writes.
fn workspace_work_root_a(root: &Path) -> PathBuf {
    root.join("work_a")
}

/// Returns the second candidate workspace path used for staging writes.
fn workspace_work_root_b(root: &Path) -> PathBuf {
    root.join("work_b")
}

/// Chooses the preferred staging root when the caller needs a default work
/// target.
///
/// Inputs:
/// - `root`: Top-level workspace root.
///
/// Returns:
/// - `work_a` or `work_b`, preferring the one that already exists exclusively.
fn preferred_workspace_work_root(root: &Path) -> PathBuf {
    let work_root_a = workspace_work_root_a(root);
    let work_root_b = workspace_work_root_b(root);
    if work_root_a.exists() && !work_root_b.exists() {
        work_root_a
    } else if work_root_b.exists() && !work_root_a.exists() {
        work_root_b
    } else {
        work_root_a
    }
}

/// Returns the staging root opposite the currently active one.
///
/// Inputs:
/// - `root`: Top-level workspace root.
/// - `active_root`: The work root currently in use.
///
/// Returns:
/// - The alternate work root that can be prepared next.
fn alternate_workspace_work_root(root: &Path, active_root: &Path) -> PathBuf {
    if active_root == workspace_work_root_a(root) {
        workspace_work_root_b(root)
    } else {
        workspace_work_root_a(root)
    }
}

/// Returns the directory that stores retired published workspace generations.
fn workspace_retired_root(root: &Path) -> PathBuf {
    root.join("retired")
}

/// Lists retired published workspace roots in stable order.
///
/// Inputs:
/// - `root`: Directory that should contain `published_*` generations.
///
/// Returns:
/// - Sorted retired-generation paths, newest last.
fn workspace_retired_roots(root: &Path) -> Vec<PathBuf> {
    let mut retired = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return retired,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if name.starts_with("published_") {
            retired.push(path);
        }
    }
    retired.sort_unstable();
    retired
}

/// Computes the number and total on-disk size of retired workspace roots for
/// tests.
///
/// Inputs:
/// - `root`: Retired workspace root directory.
///
/// Returns:
/// - `(count, bytes)` for the currently visible retired generations.
#[cfg(test)]
fn workspace_retired_stats(root: &Path) -> (u64, u64) {
    let retired = workspace_retired_roots(root);
    let bytes = retired.iter().map(|path| disk_usage_under(path)).sum();
    (retired.len() as u64, bytes)
}

/// Discovers forest tree roots beneath a top-level root.
///
/// How it works:
/// - Walks one directory level.
/// - Treats `tree_*/current` as the live tree root when present.
/// - Filters out anything that does not match the expected tree layout.
///
/// Inputs:
/// - `root`: Top-level forest directory.
///
/// Returns:
/// - Sorted live tree roots that should participate in search/open.
fn forest_tree_roots(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut tree_roots = fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .map(|entry| {
            let path = entry.path();
            let current = path.join("current");
            if current.is_dir() { current } else { path }
        })
        .filter(|path| {
            path.is_dir()
                && path
                    .parent()
                    .and_then(|value| value.file_name().or_else(|| path.file_name()))
                    .and_then(|value| value.to_str())
                    .map(|name| name.starts_with("tree_"))
                    .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    tree_roots.sort();
    Ok(tree_roots)
}

/// Merges one root's startup profile into a larger startup aggregate.
///
/// Inputs:
/// - `dst`: Aggregate profile being accumulated.
/// - `src`: Newly collected profile for one root.
///
/// Output:
/// - Updates `dst` in place using saturating arithmetic.
fn merge_store_root_startup_profile(
    dst: &mut StoreRootStartupProfile,
    src: &StoreRootStartupProfile,
) {
    dst.total_ms = dst.total_ms.saturating_add(src.total_ms);
    dst.opened_existing_shards = dst
        .opened_existing_shards
        .saturating_add(src.opened_existing_shards);
    dst.initialized_new_shards = dst
        .initialized_new_shards
        .saturating_add(src.initialized_new_shards);
    dst.doc_count = dst.doc_count.saturating_add(src.doc_count);
    dst.store_open_total_ms = dst
        .store_open_total_ms
        .saturating_add(src.store_open_total_ms);
    dst.store_open_manifest_ms = dst
        .store_open_manifest_ms
        .saturating_add(src.store_open_manifest_ms);
    dst.store_open_meta_ms = dst
        .store_open_meta_ms
        .saturating_add(src.store_open_meta_ms);
    dst.store_open_load_state_ms = dst
        .store_open_load_state_ms
        .saturating_add(src.store_open_load_state_ms);
    dst.store_open_sidecars_ms = dst
        .store_open_sidecars_ms
        .saturating_add(src.store_open_sidecars_ms);
    dst.store_open_rebuild_indexes_ms = dst
        .store_open_rebuild_indexes_ms
        .saturating_add(src.store_open_rebuild_indexes_ms);
    dst.store_open_rebuild_identity_index_ms = dst
        .store_open_rebuild_identity_index_ms
        .saturating_add(src.store_open_rebuild_identity_index_ms);
}

/// Produces a unique path for the next retired published root.
///
/// Inputs:
/// - `root`: The retired-root directory that will contain published generations.
///
/// Returns:
/// - A path using the current timestamp, with a PID fallback if needed.
fn next_workspace_retired_root_path(root: &Path) -> PathBuf {
    let base = current_unix_ms();
    for offset in 0..1024u64 {
        let candidate = root.join(format!("published_{}", base.saturating_add(offset)));
        if !candidate.exists() {
            return candidate;
        }
    }
    root.join(format!("published_{}_{}", base, std::process::id()))
}

/// Deletes the oldest retired workspace roots beyond the configured retention
/// count.
///
/// Inputs:
/// - `root`: Directory containing retired published roots.
/// - `keep`: Number of newest roots to retain.
///
/// Returns:
/// - The number of retired roots removed.
fn prune_workspace_retired_roots(root: &Path, keep: usize) -> Result<usize> {
    let retired = workspace_retired_roots(root);
    let prune_count = retired.len().saturating_sub(keep);
    let mut removed = 0usize;
    for path in retired.into_iter().take(prune_count) {
        match fs::remove_dir_all(&path) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                removed = removed.saturating_add(1);
            }
            Err(err) => {
                return Err(SspryError::from(format!(
                    "Failed to remove retired workspace root {}: {err}",
                    path.display()
                )));
            }
        }
    }
    Ok(removed)
}

/// Ensures all candidate stores under one logical root exist and are open with
/// runtime limits applied.
///
/// How it works:
/// - Validates the requested shard count against any existing manifest.
/// - Opens or initializes each shard.
/// - Applies runtime memory limits to each opened store.
///
/// Inputs:
/// - `config`: Server configuration that provides shard count and memory budget.
/// - `root`: Direct/work/current root whose shard set should be materialized.
///
/// Returns:
/// - The opened stores for this root.
/// - The number of abandoned compaction roots removed during startup.
/// - Startup timing/profile data for this root.
fn ensure_candidate_stores_at_root(
    config: &ServerConfig,
    root: &Path,
) -> Result<(Vec<CandidateStore>, usize, StoreRootStartupProfile)> {
    let started_total = Instant::now();
    let shard_count = config.candidate_shards.max(1);
    let single_meta = root.join("meta.json");
    let sharded_meta = root.join("shard_000").join("meta.json");
    if let Some(existing) = read_candidate_shard_count(root)? {
        if existing != shard_count {
            return Err(SspryError::from(format!(
                "{} contains a candidate shard manifest for {existing} shard(s); re-run init with matching --shards.",
                root.display()
            )));
        }
    } else {
        if shard_count > 1 && single_meta.exists() {
            return Err(SspryError::from(format!(
                "{} contains a single-shard store; re-run init with --shards 1 or re-init.",
                root.display()
            )));
        }
        if shard_count == 1 && sharded_meta.exists() {
            return Err(SspryError::from(format!(
                "{} contains a sharded store; re-run init with matching --shards.",
                root.display()
            )));
        }
    }

    let mut stores = Vec::with_capacity(shard_count);
    let mut cleanup_removed_roots = 0usize;
    let mut startup_profile = StoreRootStartupProfile::default();
    fs::create_dir_all(root)?;
    for shard_idx in 0..shard_count {
        let mut shard_config = config.candidate_config.clone();
        shard_config.root = candidate_shard_root(root, shard_count, shard_idx);
        cleanup_removed_roots = cleanup_removed_roots
            .saturating_add(cleanup_abandoned_compaction_roots(&shard_config.root)?);
        let (mut store, created_new, open_profile) = ensure_candidate_store_profiled(shard_config)?;
        if created_new {
            startup_profile.initialized_new_shards =
                startup_profile.initialized_new_shards.saturating_add(1);
        } else {
            startup_profile.opened_existing_shards =
                startup_profile.opened_existing_shards.saturating_add(1);
        }
        apply_store_open_profile(&mut startup_profile, &open_profile);
        store.apply_runtime_limits(config.memory_budget_bytes, shard_count)?;
        stores.push(store);
    }
    write_candidate_shard_count(root, shard_count)?;
    startup_profile.total_ms = started_total
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    Ok((stores, cleanup_removed_roots, startup_profile))
}

/// Resolves the store layout the server should open at startup.
///
/// How it works:
/// - Chooses forest mode when multiple `tree_*` roots are present.
/// - Chooses direct mode for a single plain root.
/// - Chooses workspace mode when the current/work layout is enabled.
///
/// Inputs:
/// - `config`: Full server configuration including root path and workspace mode.
///
/// Returns:
/// - The opened store mode.
/// - The number of cleanup roots removed during startup.
/// - The startup profile covering all roots opened for this server.
fn ensure_candidate_stores(config: &ServerConfig) -> Result<(StoreMode, usize, StartupProfile)> {
    let root = &config.candidate_config.root;
    if !config.workspace_mode {
        let forest_roots = forest_tree_roots(root)?;
        if !forest_roots.is_empty() && !root.join("current").is_dir() {
            let mut trees = Vec::with_capacity(forest_roots.len());
            let mut removed_roots = 0usize;
            let mut current_profile = StoreRootStartupProfile::default();
            for tree_root in forest_roots {
                let (stores, tree_removed_roots, tree_profile) =
                    ensure_candidate_stores_at_root(config, &tree_root)?;
                removed_roots = removed_roots.saturating_add(tree_removed_roots);
                merge_store_root_startup_profile(&mut current_profile, &tree_profile);
                trees.push(Arc::new(StoreSet::new(tree_root, stores)));
            }
            return Ok((
                StoreMode::Forest {
                    _root: root.clone(),
                    trees,
                },
                removed_roots,
                StartupProfile {
                    current: current_profile,
                    ..StartupProfile::default()
                },
            ));
        }
        let (stores, removed_roots, current_profile) =
            ensure_candidate_stores_at_root(config, root)?;
        return Ok((
            StoreMode::Direct {
                stores: Arc::new(StoreSet::new(root.clone(), stores)),
            },
            removed_roots,
            StartupProfile {
                current: current_profile,
                ..StartupProfile::default()
            },
        ));
    }

    let has_workspace_layout = root.join("current").is_dir()
        || root.join("work_a").is_dir()
        || root.join("work_b").is_dir();
    if !has_workspace_layout
        && (root.join("meta.json").exists() || root.join("shard_000").join("meta.json").exists())
    {
        return Err(SspryError::from(format!(
            "{} contains a direct store; move it under {}/current or use a fresh workspace root.",
            root.display(),
            root.display()
        )));
    }

    let current_root = workspace_current_root(root);
    if root.join("work").exists() {
        return Err(SspryError::from(format!(
            "{} contains the retired workspace work/ root; move or remove it before restarting.",
            root.display()
        )));
    }
    let retired_root = workspace_retired_root(root);
    let removed_retired =
        prune_workspace_retired_roots(&retired_root, DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP)?;
    let (published, removed_current, current_profile) =
        ensure_candidate_stores_at_root(config, &current_root)?;
    Ok((
        StoreMode::Workspace {
            root: root.clone(),
            published: Arc::new(StoreSet::new(current_root, published)),
            work_active: None,
        },
        removed_current.saturating_add(removed_retired),
        StartupProfile {
            current: current_profile,
            ..StartupProfile::default()
        },
    ))
}

/// Returns the raw identity width implied by one configured id_source label.
fn identity_bytes_for_source(id_source: &str) -> Result<usize> {
    match id_source {
        "md5" => Ok(16),
        "sha1" => Ok(20),
        "sha256" => Ok(32),
        "sha512" => Ok(64),
        other => Err(SspryError::from(format!(
            "invalid candidate id_source `{other}`; expected one of sha256, md5, sha1, sha512"
        ))),
    }
}

/// Decodes a normalized identity string into its raw binary form.
///
/// Inputs:
/// - `value`: User-provided hexadecimal digest string.
/// - `id_source`: Configured forest identity source.
///
/// Returns:
/// - The decoded digest bytes.
fn decode_identity(value: &str, id_source: &str) -> Result<Vec<u8>> {
    let normalized = normalize_identity_hex(value, id_source)?;
    let mut out = vec![0u8; identity_bytes_for_source(id_source)?];
    hex::decode_to_slice(normalized, &mut out)?;
    Ok(out)
}

/// Validates and normalizes a user-provided identity string.
///
/// Inputs:
/// - `value`: Candidate hexadecimal digest text.
/// - `id_source`: Configured forest identity source.
///
/// Returns:
/// - The lowercase hexadecimal digest string.
fn normalize_identity_hex(value: &str, id_source: &str) -> Result<String> {
    let text = value.trim().to_ascii_lowercase();
    let expected_hex_len = identity_bytes_for_source(id_source)?.saturating_mul(2);
    if text.len() != expected_hex_len || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(SspryError::from(format!(
            "{id_source} must be exactly {expected_hex_len} hexadecimal characters.",
        )));
    }
    Ok(text)
}

/// Recursively sums file sizes beneath a root for status reporting.
///
/// Inputs:
/// - `root`: Directory or file whose disk footprint should be measured.
///
/// Returns:
/// - Total bytes visible under `root`, skipping entries that cannot be read.
fn disk_usage_under(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.is_file() {
            total += metadata.len();
            continue;
        }
        if !metadata.is_dir() {
            continue;
        }
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            stack.push(entry.path());
        }
    }
    total
}
