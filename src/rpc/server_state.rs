type StreamStoreHits = (Vec<String>, Option<Vec<Option<String>>>);
type StreamStoreQueryResult = (
    SearchWorkUnit,
    StreamStoreHits,
    Vec<String>,
    CandidateQueryProfile,
);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SearchWorkUnit {
    store_set_idx: usize,
    store_idx: usize,
}

#[derive(Default)]
struct BundledQueryAccumulator {
    tier_used: Vec<String>,
    query_profile: CandidateQueryProfile,
    eval_nanos: u128,
}

impl BundledQueryAccumulator {
    /// Merges one store-set-local terminal summary into the final per-rule totals.
    fn merge_from_partial(&mut self, partial: &BundledQueryPartial) {
        self.tier_used.push(partial.tier_used.clone());
        self.query_profile.merge_from(&partial.query_profile);
        self.eval_nanos = self.eval_nanos.saturating_add(partial.eval_nanos);
    }
}

#[derive(Default)]
struct BundledQueryPartial {
    hashes: Vec<String>,
    external_ids: Option<Vec<Option<String>>>,
    tier_used: String,
    query_profile: CandidateQueryProfile,
    eval_nanos: u128,
}

type BundledStoreQueryResult = (SearchWorkUnit, Vec<BundledQueryPartial>);

impl ServerState {
    /// Initializes server state, opens or creates the underlying store layout,
    /// and seeds all runtime counters and caches.
    fn new(config: ServerConfig, shutdown: Arc<AtomicBool>) -> Result<Self> {
        let started = Instant::now();
        let (store_mode, startup_cleanup_removed_roots, mut startup_profile) =
            ensure_candidate_stores(&config)?;
        startup_profile.total_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let startup_work_documents = match &store_mode {
            StoreMode::Workspace { .. } => startup_profile.work.doc_count,
            StoreMode::Direct { .. } | StoreMode::Forest { .. } => 0,
        };
        let auto_publish_storage_class = config.auto_publish_storage_class.clone();
        let auto_publish_initial_idle_ms = config.auto_publish_initial_idle_ms;
        let candidate_shards = config.candidate_shards;
        Ok(Self {
            config,
            shutdown,
            operation_gate: RwLock::new(()),
            store_mode: Mutex::new(store_mode),
            publish_requested: AtomicBool::new(false),
            mutations_paused: AtomicBool::new(false),
            publish_in_progress: AtomicBool::new(false),
            active_mutations: AtomicUsize::new(0),
            active_index_clients: AtomicUsize::new(0),
            next_index_client_id: AtomicU64::new(1),
            index_client_leases: Mutex::new(HashMap::new()),
            publish_after_index_clients: AtomicBool::new(false),
            active_index_sessions: AtomicUsize::new(0),
            work_dirty: AtomicBool::new(false),
            work_active_estimated_documents: AtomicU64::new(startup_work_documents),
            work_active_estimated_input_bytes: AtomicU64::new(0),
            index_backpressure_events_total: AtomicU64::new(0),
            index_backpressure_sleep_ms_total: AtomicU64::new(0),
            last_index_backpressure_delay_ms: AtomicU64::new(0),
            last_work_mutation_unix_ms: AtomicU64::new(0),
            index_session_total_documents: AtomicU64::new(0),
            index_session_submitted_documents: AtomicU64::new(0),
            index_session_processed_documents: AtomicU64::new(0),
            index_session_started_unix_ms: AtomicU64::new(0),
            index_session_last_update_unix_ms: AtomicU64::new(0),
            index_session_server_insert_batch_count: AtomicU64::new(0),
            index_session_server_insert_batch_documents: AtomicU64::new(0),
            index_session_server_insert_batch_shards_touched: AtomicU64::new(0),
            index_session_server_insert_batch_total_us: AtomicU64::new(0),
            index_session_server_insert_batch_parse_us: AtomicU64::new(0),
            index_session_server_insert_batch_group_us: AtomicU64::new(0),
            index_session_server_insert_batch_build_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_us: AtomicU64::new(0),
            index_session_server_insert_batch_finalize_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_resolve_doc_state_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_sidecars_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_sidecar_payloads_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_bloom_payload_assemble_us:
                AtomicU64::new(0),
            index_session_server_insert_batch_store_append_bloom_payload_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_metadata_payload_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_external_id_payload_us: AtomicU64::new(
                0,
            ),
            index_session_server_insert_batch_store_append_tier2_bloom_payload_us: AtomicU64::new(
                0,
            ),
            index_session_server_insert_batch_store_append_doc_row_build_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_bloom_payload_bytes: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_metadata_payload_bytes: AtomicU64::new(
                0,
            ),
            index_session_server_insert_batch_store_append_external_id_payload_bytes:
                AtomicU64::new(0),
            index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes:
                AtomicU64::new(0),
            index_session_server_insert_batch_store_append_doc_records_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_write_existing_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_install_docs_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_tier2_update_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_persist_meta_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_rebalance_tier2_us: AtomicU64::new(0),
            last_publish_started_unix_ms: AtomicU64::new(0),
            last_publish_completed_unix_ms: AtomicU64::new(0),
            last_publish_duration_ms: AtomicU64::new(0),
            last_publish_lock_wait_ms: AtomicU64::new(0),
            last_publish_swap_ms: AtomicU64::new(0),
            last_publish_promote_work_ms: AtomicU64::new(0),
            last_publish_promote_work_export_ms: AtomicU64::new(0),
            last_publish_promote_work_import_ms: AtomicU64::new(0),
            last_publish_promote_work_import_resolve_doc_state_ms: AtomicU64::new(0),
            last_publish_promote_work_import_build_payloads_ms: AtomicU64::new(0),
            last_publish_promote_work_import_append_sidecars_ms: AtomicU64::new(0),
            last_publish_promote_work_import_install_docs_ms: AtomicU64::new(0),
            last_publish_promote_work_import_tier2_update_ms: AtomicU64::new(0),
            last_publish_promote_work_import_persist_meta_ms: AtomicU64::new(0),
            last_publish_promote_work_import_rebalance_tier2_ms: AtomicU64::new(0),
            last_publish_promote_work_remove_work_root_ms: AtomicU64::new(0),
            last_publish_promote_work_other_ms: AtomicU64::new(0),
            last_publish_promote_work_imported_docs: AtomicU64::new(0),
            last_publish_promote_work_imported_shards: AtomicU64::new(0),
            last_publish_init_work_ms: AtomicU64::new(0),
            last_publish_tier2_snapshot_persist_failures: AtomicU64::new(0),
            last_publish_persisted_snapshot_shards: AtomicU64::new(0),
            last_publish_reused_work_stores: AtomicBool::new(false),
            publish_runs_total: AtomicU64::new(0),
            pending_published_tier2_snapshot_shards: Mutex::new(HashSet::new()),
            published_tier2_snapshot_seal_in_progress: AtomicBool::new(false),
            published_tier2_snapshot_seal_runs_total: AtomicU64::new(0),
            last_published_tier2_snapshot_seal_duration_ms: AtomicU64::new(0),
            last_published_tier2_snapshot_seal_persisted_shards: AtomicU64::new(0),
            last_published_tier2_snapshot_seal_failures: AtomicU64::new(0),
            last_published_tier2_snapshot_seal_completed_unix_ms: AtomicU64::new(0),
            adaptive_publish: Mutex::new(AdaptivePublishState::new(
                auto_publish_storage_class,
                auto_publish_initial_idle_ms,
                candidate_shards,
            )),
            #[cfg(test)]
            normalized_plan_cache: Mutex::new(BoundedCache::new(NORMALIZED_PLAN_CACHE_CAPACITY)),
            query_artifact_cache: Mutex::new(BoundedCache::new(QUERY_ARTIFACT_CACHE_CAPACITY)),
            #[cfg(test)]
            query_cache: Mutex::new(BoundedCache::new(QUERY_CACHE_CAPACITY)),
            search_admission: Mutex::new(SearchAdmissionState::default()),
            search_admission_cv: Condvar::new(),
            compaction_runtime: Mutex::new(CompactionRuntime::default()),
            next_compaction_shard: AtomicUsize::new(0),
            active_connections: AtomicUsize::new(0),
            maintenance_epoch: Mutex::new(1),
            maintenance_cv: Condvar::new(),
            startup_cleanup_removed_roots,
            startup_profile,
        })
    }

    /// Returns true when shutdown has been requested by process signals or RPC.
    fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Wakes background maintenance workers by advancing the shared epoch and
    /// notifying the condition variable.
    fn notify_maintenance_workers(&self) {
        if let Ok(mut epoch) = self.maintenance_epoch.lock() {
            *epoch = epoch.wrapping_add(1);
            self.maintenance_cv.notify_all();
        }
    }

    /// Returns the current maintenance epoch observed by background workers.
    fn current_maintenance_epoch(&self) -> u64 {
        self.maintenance_epoch
            .lock()
            .map(|epoch| *epoch)
            .unwrap_or(0)
    }

    /// Waits for a maintenance wake-up, shutdown, or optional timeout while
    /// tracking the last-seen epoch.
    fn wait_for_maintenance_event(&self, last_seen: &mut u64, timeout: Option<Duration>) {
        let Ok(mut epoch) = self.maintenance_epoch.lock() else {
            return;
        };
        if *epoch != *last_seen {
            *last_seen = *epoch;
            return;
        }
        if self.is_shutting_down() {
            return;
        }
        epoch = match timeout {
            Some(timeout) => match self.maintenance_cv.wait_timeout(epoch, timeout) {
                Ok((epoch, _)) => epoch,
                Err(_) => return,
            },
            None => match self.maintenance_cv.wait(epoch) {
                Ok(epoch) => epoch,
                Err(_) => return,
            },
        };
        *last_seen = *epoch;
    }

    /// Serializes search execution so only one admitted search request runs at
    /// a time.
    fn begin_search_request(&self) -> Result<ActiveSearchRequestGuard<'_>> {
        let mut admission = self
            .search_admission
            .lock()
            .map_err(|_| SspryError::from("Search admission lock poisoned."))?;
        let ticket = admission.next_ticket;
        admission.next_ticket = admission.next_ticket.wrapping_add(1);
        admission.waiting = admission.waiting.saturating_add(1);
        loop {
            if !admission.active && ticket == admission.serving_ticket {
                admission.active = true;
                admission.waiting = admission.waiting.saturating_sub(1);
                return Ok(ActiveSearchRequestGuard { state: self });
            }
            admission = self
                .search_admission_cv
                .wait(admission)
                .map_err(|_| SspryError::from("Search admission lock poisoned."))?;
        }
    }

    /// Removes expired index-client leases and resets session state when the
    /// last client disappears unexpectedly.
    fn prune_expired_index_clients(&self, now_unix_ms: u64) -> Result<usize> {
        let mut leases = self
            .index_client_leases
            .lock()
            .map_err(|_| SspryError::from("Index client lease lock poisoned."))?;
        let before = leases.len();
        leases.retain(|_, lease| {
            now_unix_ms.saturating_sub(lease.last_heartbeat_unix_ms) <= lease.lease_timeout_ms
        });
        let after = leases.len();
        self.active_index_clients.store(after, Ordering::SeqCst);
        let cleared_orphaned_session =
            before > 0 && after == 0 && self.active_index_sessions.swap(0, Ordering::SeqCst) > 0;
        if before > 0 && after == 0 {
            self.publish_after_index_clients
                .store(true, Ordering::SeqCst);
        }
        if cleared_orphaned_session {
            self.index_session_last_update_unix_ms
                .store(now_unix_ms, Ordering::SeqCst);
            let _ = self.update_adaptive_publish_from_index_session();
        }
        drop(leases);
        if before != after {
            self.notify_maintenance_workers();
        }
        if before > 0 && after == 0 {
            let _ = self.maybe_force_publish_after_index_clients();
        }
        Ok(after)
    }

    /// Forces a publish after index clients drain when workspace-mode state
    /// indicates the published view is stale.
    fn maybe_force_publish_after_index_clients(&self) -> Result<()> {
        if !self.publish_after_index_clients.load(Ordering::Acquire)
            || !self.config.workspace_mode
            || !self.work_dirty.load(Ordering::Acquire)
            || self.publish_requested.load(Ordering::Acquire)
            || self.publish_in_progress.load(Ordering::Acquire)
            || self.mutations_paused.load(Ordering::Acquire)
            || self.active_mutations.load(Ordering::Acquire) > 0
            || self.active_index_sessions.load(Ordering::Acquire) > 0
            || self.active_index_clients.load(Ordering::Acquire) > 0
        {
            return Ok(());
        }
        let _ = self.handle_publish()?;
        Ok(())
    }

    /// Returns the currently published store set for modes that expose a single
    /// queryable published view.
    fn published_store_set(&self) -> Result<Arc<StoreSet>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { stores } => stores.clone(),
            StoreMode::Forest { .. } => {
                return Err(SspryError::from(
                    "forest-root server has no single published store set; use candidate_query against the forest.",
                ));
            }
            StoreMode::Workspace { published, .. } => published.clone(),
        })
    }

    /// Returns the writable store set, lazily creating the workspace work set
    /// when needed.
    fn work_store_set(&self) -> Result<Arc<StoreSet>> {
        let mut mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(match &mut *mode {
            StoreMode::Direct { stores } => stores.clone(),
            StoreMode::Forest { .. } => {
                return Err(SspryError::from(
                    "forest-root server is read-only; work store is unavailable.",
                ));
            }
            StoreMode::Workspace {
                root, work_active, ..
            } => {
                if let Some(work_active) = work_active.as_ref() {
                    work_active.clone()
                } else {
                    let work_root = preferred_workspace_work_root(root);
                    let (stores, _, _) = ensure_candidate_stores_at_root(&self.config, &work_root)?;
                    let work_set = Arc::new(StoreSet::new(work_root, stores));
                    *work_active = Some(work_set.clone());
                    work_set
                }
            }
        })
    }

    /// Returns the writable store set when it already exists without forcing
    /// workspace activation.
    fn work_store_set_if_present(&self) -> Result<Option<Arc<StoreSet>>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { stores } => Some(stores.clone()),
            StoreMode::Forest { .. } => None,
            StoreMode::Workspace { work_active, .. } => work_active.clone(),
        })
    }

    /// Returns every store set that should participate in published-query
    /// execution for the current server mode.
    fn published_query_store_sets(&self) -> Result<Vec<Arc<StoreSet>>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { stores } => vec![stores.clone()],
            StoreMode::Forest { trees, .. } => trees.clone(),
            StoreMode::Workspace { published, .. } => vec![published.clone()],
        })
    }

    /// Reads the active gram sizes and identity source from the published query
    /// stores so new query plans compile against live settings.
    fn active_query_compile_policy(&self) -> Result<(GramSizes, String)> {
        let store_sets = self.published_query_store_sets()?;
        let first_store_lock = store_sets
            .first()
            .and_then(|store_set| store_set.stores.first())
            .ok_or_else(|| SspryError::from("Candidate store is not initialized."))?;
        let store = lock_candidate_store_blocking(first_store_lock)?;
        let config = store.config();
        let gram_sizes = GramSizes::new(config.tier1_gram_size, config.tier2_gram_size)?;
        Ok((gram_sizes, config.id_source.clone()))
    }

    /// Compiles one or more search plans directly from the YARA source
    /// embedded in a gRPC search request.
    fn compile_search_plans_from_yara_source(
        &self,
        request: &SearchRequest,
    ) -> Result<Vec<(String, CompiledQueryPlan)>> {
        if request.yara_rule_source.trim().is_empty() {
            return Err(SspryError::from(
                "Search request is missing yara_rule_source.",
            ));
        }
        let (gram_sizes, id_source) = self.active_query_compile_policy()?;
        let max_anchors_per_pattern = (request.max_anchors_per_pattern as usize).max(1);
        if request.target_rule_name.trim().is_empty() {
            let rule_names = search_target_rule_names(&request.yara_rule_source)?;
            if rule_names.is_empty() {
                return Err(SspryError::from(
                    "Search request does not contain a searchable rule.",
                ));
            }
            let plans = rule_names
                .iter()
                .map(|rule_name| {
                    compile_query_plan_for_rule_name_with_gram_sizes_and_identity_source(
                        &request.yara_rule_source,
                        rule_name,
                        gram_sizes,
                        Some(id_source.as_str()),
                        max_anchors_per_pattern,
                        request.force_tier1_only,
                        request.allow_tier2_fallback,
                        request.max_candidates_percent,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(rule_names.into_iter().zip(plans.into_iter()).collect())
        } else {
            Ok(vec![(
                request.target_rule_name.clone(),
                compile_query_plan_for_rule_name_with_gram_sizes_and_identity_source(
                    &request.yara_rule_source,
                    &request.target_rule_name,
                    gram_sizes,
                    Some(id_source.as_str()),
                    max_anchors_per_pattern,
                    request.force_tier1_only,
                    request.allow_tier2_fallback,
                    request.max_candidates_percent,
                )?,
            )])
        }
    }

    /// Reports the current forest root and tree count when the server is
    /// serving a forest layout.
    fn forest_mode_info(&self) -> Result<Option<(PathBuf, usize)>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Forest { _root, trees } => Some((_root.clone(), trees.len())),
            _ => None,
        })
    }

    /// Flushes any dirty store metadata across all active store sets before
    /// process shutdown or test assertions.
    fn flush_store_meta_if_dirty(&self) -> Result<()> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        match &*mode {
            StoreMode::Direct { stores } => {
                for (shard_idx, store_lock) in stores.stores.iter().enumerate() {
                    let mut store =
                        lock_candidate_store_with_timeout(store_lock, shard_idx, "flush meta")?;
                    let _ = store.persist_meta_if_dirty()?;
                }
            }
            StoreMode::Forest { trees, .. } => {
                for stores in trees {
                    for (shard_idx, store_lock) in stores.stores.iter().enumerate() {
                        let mut store = lock_candidate_store_with_timeout(
                            store_lock,
                            shard_idx,
                            "flush forest meta",
                        )?;
                        let _ = store.persist_meta_if_dirty()?;
                    }
                }
            }
            StoreMode::Workspace {
                published,
                work_active,
                ..
            } => {
                for (shard_idx, store_lock) in published.stores.iter().enumerate() {
                    let mut store = lock_candidate_store_with_timeout(
                        store_lock,
                        shard_idx,
                        "flush published meta",
                    )?;
                    let _ = store.persist_meta_if_dirty()?;
                }
                if let Some(work_active) = work_active {
                    for (shard_idx, store_lock) in work_active.stores.iter().enumerate() {
                        let mut store = lock_candidate_store_with_timeout(
                            store_lock,
                            shard_idx,
                            "flush active work meta",
                        )?;
                        let _ = store.persist_meta_if_dirty()?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns the published and work roots when running in workspace mode.
    fn workspace_roots(&self) -> Result<Option<(PathBuf, PathBuf)>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { .. } => None,
            StoreMode::Forest { .. } => None,
            StoreMode::Workspace {
                root,
                published,
                work_active,
                ..
            } => Some((
                published.root()?,
                work_active
                    .as_ref()
                    .map(|work_active| work_active.root())
                    .transpose()?
                    .unwrap_or_else(|| preferred_workspace_work_root(root)),
            )),
        })
    }

    /// Returns true when a mutation changes the same stores that published
    /// queries read from immediately.
    fn mutation_affects_published_queries(&self) -> Result<bool> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(matches!(*mode, StoreMode::Direct { .. }))
    }

    /// Starts a mutating operation unless publishing currently pauses writes.
    fn begin_mutation(&self, operation: &str) -> Result<ActiveMutationGuard<'_>> {
        self.active_mutations.fetch_add(1, Ordering::AcqRel);
        if self.mutations_paused.load(Ordering::Acquire) {
            self.active_mutations.fetch_sub(1, Ordering::AcqRel);
            return Err(SspryError::from(format!(
                "server is publishing; {operation} temporarily disabled; retry later"
            )));
        }
        Ok(ActiveMutationGuard { state: self })
    }

    /// Marks the workspace work set dirty, refreshes timestamps, and wakes
    /// maintenance workers.
    fn mark_work_mutation(&self) {
        self.work_dirty.store(true, Ordering::SeqCst);
        self.last_work_mutation_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
        let _ = self.invalidate_work_stats_cache();
        self.notify_maintenance_workers();
    }

    /// Drops cached stats for the active work set if one exists.
    fn invalidate_work_stats_cache(&self) -> Result<()> {
        if let Some(work) = self.work_store_set_if_present()? {
            work.invalidate_stats_cache()?;
        }
        Ok(())
    }

    /// Drops cached stats for the published store set.
    fn invalidate_published_stats_cache(&self) -> Result<()> {
        let published = self.published_store_set()?;
        published.invalidate_stats_cache()
    }

    /// Computes the document-count threshold that triggers workspace
    /// backpressure or auto-publish pressure handling.
    fn work_buffer_document_threshold(&self) -> u64 {
        let scaled = self
            .config
            .memory_budget_bytes
            .checked_div(WORK_BUFFER_DOCUMENT_BUDGET_BYTES)
            .unwrap_or(0);
        scaled.clamp(
            WORK_BUFFER_MIN_DOCUMENT_THRESHOLD,
            WORK_BUFFER_MAX_DOCUMENT_THRESHOLD,
        )
    }

    /// Computes the estimated input-byte threshold that triggers workspace
    /// backpressure or auto-publish pressure handling.
    fn work_buffer_input_bytes_threshold(&self) -> u64 {
        self.config
            .memory_budget_bytes
            .saturating_mul(WORK_BUFFER_INPUT_BYTES_MULTIPLIER)
            .max(WORK_BUFFER_MIN_INPUT_BYTES_THRESHOLD)
    }

    /// Computes the RSS threshold used to treat the work buffer as under memory
    /// pressure.
    fn work_buffer_rss_threshold_bytes(&self) -> u64 {
        self.config
            .memory_budget_bytes
            .saturating_mul(WORK_BUFFER_RSS_TRIGGER_NUMERATOR)
            / WORK_BUFFER_RSS_TRIGGER_DENOMINATOR
    }

    /// Captures the current work-buffer pressure snapshot used by adaptive
    /// publish and indexing backpressure logic.
    fn work_buffer_pressure_snapshot(
        &self,
        current_rss_bytes: u64,
        pending_tier2_snapshot_shards: u64,
    ) -> WorkBufferPressure {
        let estimated_documents = self.work_active_estimated_documents.load(Ordering::Acquire);
        let estimated_input_bytes = self
            .work_active_estimated_input_bytes
            .load(Ordering::Acquire);
        let active_index_clients = self.active_index_clients.load(Ordering::Acquire);
        let active_index_sessions = self.active_index_sessions.load(Ordering::Acquire);
        let publish_runs_total = self.publish_runs_total.load(Ordering::Acquire);
        let mut document_threshold = self.work_buffer_document_threshold();
        let mut input_bytes_threshold = self.work_buffer_input_bytes_threshold();
        if (active_index_clients > 0 || active_index_sessions > 0) && publish_runs_total > 0 {
            document_threshold =
                document_threshold.min(WORK_BUFFER_REPUBLISH_MAX_DOCUMENT_THRESHOLD);
            input_bytes_threshold = input_bytes_threshold.min(
                (self
                    .config
                    .memory_budget_bytes
                    .checked_div(WORK_BUFFER_REPUBLISH_INPUT_BYTES_DIVISOR)
                    .unwrap_or(0))
                .max(WORK_BUFFER_REPUBLISH_MIN_INPUT_BYTES_THRESHOLD),
            );
        }
        let rss_threshold_bytes = self.work_buffer_rss_threshold_bytes();
        let index_backpressure_delay_ms = if self.active_index_sessions.load(Ordering::Acquire) == 0
        {
            0
        } else if self.publish_in_progress.load(Ordering::Acquire) {
            if estimated_documents >= document_threshold
                || estimated_input_bytes >= input_bytes_threshold
                || current_rss_bytes >= rss_threshold_bytes
            {
                INDEX_BACKPRESSURE_HEAVY_DELAY_MS
            } else {
                INDEX_BACKPRESSURE_PUBLISH_DELAY_MS
            }
        } else if self.publish_requested.load(Ordering::Acquire)
            || self.mutations_paused.load(Ordering::Acquire)
        {
            INDEX_BACKPRESSURE_PUBLISH_DELAY_MS
        } else {
            0
        };
        WorkBufferPressure {
            estimated_documents,
            estimated_input_bytes,
            current_rss_bytes,
            document_threshold,
            input_bytes_threshold,
            rss_threshold_bytes,
            pending_tier2_snapshot_shards,
            index_backpressure_delay_ms,
        }
    }

    /// Adds newly indexed work-buffer estimates for documents and input bytes.
    fn record_work_buffer_growth(&self, inserted_documents: u64, inserted_input_bytes: u64) {
        if !self.config.workspace_mode {
            return;
        }
        if inserted_documents > 0 {
            self.work_active_estimated_documents
                .fetch_add(inserted_documents, Ordering::SeqCst);
        }
        if inserted_input_bytes > 0 {
            self.work_active_estimated_input_bytes
                .fetch_add(inserted_input_bytes, Ordering::SeqCst);
        }
    }

    /// Resets work-buffer growth estimates after publish or work-root reset.
    fn reset_work_buffer_estimates(&self) {
        self.work_active_estimated_documents
            .store(0, Ordering::SeqCst);
        self.work_active_estimated_input_bytes
            .store(0, Ordering::SeqCst);
    }

    /// Applies a bounded sleep when the active workspace buffer is under enough
    /// pressure to warrant slowing ingest.
    fn maybe_apply_index_backpressure(&self, batch_documents: usize, batch_input_bytes: u64) {
        if !self.config.workspace_mode || batch_documents == 0 {
            self.last_index_backpressure_delay_ms
                .store(0, Ordering::SeqCst);
            return;
        }
        let adaptive = self.adaptive_publish_snapshot_or_default(current_unix_ms());
        let (current_rss_kb, _) = current_process_memory_kb();
        let mut pressure = self.work_buffer_pressure_snapshot(
            current_rss_kb
                .saturating_mul(1024)
                .try_into()
                .unwrap_or(u64::MAX),
            adaptive.tier2_pending_shards,
        );
        pressure.estimated_documents = pressure
            .estimated_documents
            .saturating_add(batch_documents as u64);
        pressure.estimated_input_bytes = pressure
            .estimated_input_bytes
            .saturating_add(batch_input_bytes);
        let delay_ms = if self.active_index_sessions.load(Ordering::Acquire) == 0 {
            0
        } else if self.publish_in_progress.load(Ordering::Acquire) {
            if pressure.estimated_documents >= pressure.document_threshold
                || pressure.estimated_input_bytes >= pressure.input_bytes_threshold
                || pressure.current_rss_bytes >= pressure.rss_threshold_bytes
            {
                INDEX_BACKPRESSURE_HEAVY_DELAY_MS
            } else {
                INDEX_BACKPRESSURE_PUBLISH_DELAY_MS
            }
        } else if self.publish_requested.load(Ordering::Acquire)
            || self.mutations_paused.load(Ordering::Acquire)
        {
            INDEX_BACKPRESSURE_PUBLISH_DELAY_MS
        } else {
            0
        };
        self.last_index_backpressure_delay_ms
            .store(delay_ms, Ordering::SeqCst);
        if delay_ms == 0 {
            return;
        }
        self.index_backpressure_events_total
            .fetch_add(1, Ordering::SeqCst);
        self.index_backpressure_sleep_ms_total
            .fetch_add(delay_ms, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(delay_ms));
    }

    /// Queues published shards that still need their tier-2 snapshots sealed by
    /// background maintenance.
    fn enqueue_published_tier2_snapshot_shards<I>(&self, shard_indexes: I) -> Result<()>
    where
        I: IntoIterator<Item = usize>,
    {
        let mut pending = self
            .pending_published_tier2_snapshot_shards
            .lock()
            .map_err(|_| SspryError::from("Published Tier2 snapshot queue lock poisoned."))?;
        let mut changed = false;
        for shard_idx in shard_indexes {
            changed |= pending.insert(shard_idx);
        }
        if changed {
            self.notify_maintenance_workers();
        }
        Ok(())
    }

    /// Returns how many published shards are still waiting for tier-2 snapshot
    /// sealing.
    fn pending_published_tier2_snapshot_shard_count(&self) -> Result<usize> {
        let pending = self
            .pending_published_tier2_snapshot_shards
            .lock()
            .map_err(|_| SspryError::from("Published Tier2 snapshot queue lock poisoned."))?;
        Ok(pending.len())
    }

    /// Returns the current adaptive-publish snapshot, including pending
    /// tier-2-seal backlog.
    fn adaptive_publish_snapshot(&self, now_unix_ms: u64) -> Result<AdaptivePublishSnapshot> {
        let tier2_pending_shards = self.pending_published_tier2_snapshot_shard_count()?;
        let adaptive = self
            .adaptive_publish
            .lock()
            .map_err(|_| SspryError::from("Adaptive publish state lock poisoned."))?;
        Ok(adaptive.snapshot(now_unix_ms, tier2_pending_shards))
    }

    /// Returns an adaptive-publish snapshot or a conservative default when the
    /// snapshot state is temporarily unavailable.
    fn adaptive_publish_snapshot_or_default(&self, now_unix_ms: u64) -> AdaptivePublishSnapshot {
        self.adaptive_publish_snapshot(now_unix_ms)
            .unwrap_or(AdaptivePublishSnapshot {
                storage_class: self.config.auto_publish_storage_class.clone(),
                current_idle_ms: self.config.auto_publish_initial_idle_ms,
                mode: "moderate",
                reason: "adaptive_snapshot_unavailable",
                recent_publish_p95_ms: 0,
                recent_submit_p95_ms: 0,
                recent_store_p95_ms: 0,
                recent_publishes_in_window: 0,
                tier2_pending_shards: 0,
                healthy_cycles: 0,
            })
    }

    /// Feeds completed index-session timings into the adaptive-publish state.
    fn update_adaptive_publish_from_index_session(&self) -> Result<()> {
        let submit_ms = self
            .index_session_server_insert_batch_total_us
            .load(Ordering::Acquire)
            / 1_000;
        let store_ms = self
            .index_session_server_insert_batch_store_us
            .load(Ordering::Acquire)
            / 1_000;
        let mut adaptive = self
            .adaptive_publish
            .lock()
            .map_err(|_| SspryError::from("Adaptive publish state lock poisoned."))?;
        adaptive.update_completed_index_session(submit_ms, store_ms);
        Ok(())
    }

    /// Feeds a completed publish timing sample into the adaptive-publish state.
    fn update_adaptive_publish_from_publish(&self, now_unix_ms: u64) -> Result<()> {
        let tier2_pending_shards = self.pending_published_tier2_snapshot_shard_count()?;
        let visible_publish_ms = self.last_publish_duration_ms.load(Ordering::Acquire);
        let mut adaptive = self
            .adaptive_publish
            .lock()
            .map_err(|_| SspryError::from("Adaptive publish state lock poisoned."))?;
        adaptive.update_completed_publish(now_unix_ms, visible_publish_ms, tier2_pending_shards);
        Ok(())
    }

    /// Updates adaptive-publish state from the current tier-2 snapshot backlog
    /// even when no publish completed.
    fn update_adaptive_publish_from_seal_backlog(&self, now_unix_ms: u64) -> Result<()> {
        let tier2_pending_shards = self.pending_published_tier2_snapshot_shard_count()?;
        let mut adaptive = self
            .adaptive_publish
            .lock()
            .map_err(|_| SspryError::from("Adaptive publish state lock poisoned."))?;
        adaptive.update_seal_backlog(now_unix_ms, tier2_pending_shards);
        Ok(())
    }

    /// Attempts one background seal cycle for a published tier-2 snapshot
    /// shard.
    fn run_published_tier2_snapshot_seal_cycle(&self) -> Result<bool> {
        if self.publish_in_progress.load(Ordering::Acquire) {
            return Ok(false);
        }
        let shard_idx = {
            let mut pending = self
                .pending_published_tier2_snapshot_shards
                .lock()
                .map_err(|_| SspryError::from("Published Tier2 snapshot queue lock poisoned."))?;
            let Some(shard_idx) = pending.iter().next().copied() else {
                return Ok(false);
            };
            pending.remove(&shard_idx);
            shard_idx
        };

        self.published_tier2_snapshot_seal_in_progress
            .store(true, Ordering::SeqCst);
        let started = Instant::now();
        let result = (|| -> Result<(u64, u64)> {
            let published = self.published_store_set()?;
            let Some(store_lock) = published.stores.get(shard_idx) else {
                return Ok((0, 0));
            };
            match store_lock.try_lock() {
                Ok(_store) => Ok((1, 0)),
                Err(TryLockError::WouldBlock) => {
                    self.enqueue_published_tier2_snapshot_shards([shard_idx])?;
                    Ok((0, 0))
                }
                Err(TryLockError::Poisoned(_)) => {
                    Err(SspryError::from("Candidate store lock poisoned."))
                }
            }
        })();
        self.published_tier2_snapshot_seal_in_progress
            .store(false, Ordering::SeqCst);

        let (persisted_shards, failures) = match result {
            Ok(values) => values,
            Err(_) => {
                let _ = self.enqueue_published_tier2_snapshot_shards([shard_idx]);
                (0, 1)
            }
        };
        self.last_published_tier2_snapshot_seal_duration_ms.store(
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
        self.last_published_tier2_snapshot_seal_persisted_shards
            .store(persisted_shards, Ordering::SeqCst);
        self.last_published_tier2_snapshot_seal_failures
            .store(failures, Ordering::SeqCst);
        if persisted_shards > 0 || failures > 0 {
            self.published_tier2_snapshot_seal_runs_total
                .fetch_add(1, Ordering::SeqCst);
            self.last_published_tier2_snapshot_seal_completed_unix_ms
                .store(current_unix_ms(), Ordering::SeqCst);
        }
        let _ = self.update_adaptive_publish_from_seal_backlog(current_unix_ms());
        Ok(true)
    }

    /// Starts the exclusive remote index session after rejecting requests that
    /// would overlap with publish or paused-mutation states.
    fn handle_begin_index_session(&self) -> Result<CandidateIndexSessionResponse> {
        if self.publish_requested.load(Ordering::Acquire)
            || self.publish_in_progress.load(Ordering::Acquire)
            || self.mutations_paused.load(Ordering::Acquire)
        {
            return Err(SspryError::from(
                "server is publishing; index session unavailable; retry later",
            ));
        }
        match self
            .active_index_sessions
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {
                let now = current_unix_ms();
                self.index_session_total_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_submitted_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_processed_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_started_unix_ms
                    .store(now, Ordering::SeqCst);
                self.index_session_last_update_unix_ms
                    .store(now, Ordering::SeqCst);
                self.index_session_server_insert_batch_count
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_shards_touched
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_total_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_parse_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_group_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_build_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_finalize_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_resolve_doc_state_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_sidecars_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_sidecar_payloads_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_bloom_payload_assemble_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_bloom_payload_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_metadata_payload_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_external_id_payload_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_tier2_bloom_payload_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_doc_row_build_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_bloom_payload_bytes
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_metadata_payload_bytes
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_external_id_payload_bytes
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_doc_records_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_write_existing_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_install_docs_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_tier2_update_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_persist_meta_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_rebalance_tier2_us
                    .store(0, Ordering::SeqCst);
                self.notify_maintenance_workers();
                Ok(CandidateIndexSessionResponse {
                    message: "index session started".to_owned(),
                })
            }
            Err(_) => Err(SspryError::from(
                "another index session is already active; retry later",
            )),
        }
    }

    /// Registers one index client lease and returns the heartbeat timings that
    /// the caller must use to keep that lease alive.
    fn handle_begin_index_client(
        &self,
        request: &CandidateIndexClientBeginRequest,
    ) -> Result<CandidateIndexClientBeginResponse> {
        if self.publish_requested.load(Ordering::Acquire)
            || self.publish_in_progress.load(Ordering::Acquire)
            || self.mutations_paused.load(Ordering::Acquire)
        {
            return Err(SspryError::from(
                "server is publishing; index client unavailable; retry later",
            ));
        }
        let heartbeat_interval_ms = request.heartbeat_interval_ms.max(1);
        let lease_timeout_ms = heartbeat_interval_ms.saturating_mul(INDEX_CLIENT_LEASE_MULTIPLIER);
        let now = current_unix_ms();
        self.prune_expired_index_clients(now)?;
        let client_id = self.next_index_client_id.fetch_add(1, Ordering::SeqCst);
        let mut leases = self
            .index_client_leases
            .lock()
            .map_err(|_| SspryError::from("Index client lease lock poisoned."))?;
        leases.insert(
            client_id,
            IndexClientLease {
                lease_timeout_ms,
                last_heartbeat_unix_ms: now,
            },
        );
        self.active_index_clients
            .store(leases.len(), Ordering::SeqCst);
        self.publish_after_index_clients
            .store(false, Ordering::SeqCst);
        self.notify_maintenance_workers();
        Ok(CandidateIndexClientBeginResponse {
            message: "index client started".to_owned(),
            client_id,
            heartbeat_interval_ms,
            lease_timeout_ms,
        })
    }

    /// Refreshes the lease timestamp for one active index client and rejects
    /// unknown or expired client ids.
    fn handle_heartbeat_index_client(
        &self,
        request: &CandidateIndexClientHeartbeatRequest,
    ) -> Result<CandidateIndexSessionResponse> {
        let now = current_unix_ms();
        self.prune_expired_index_clients(now)?;
        let mut leases = self
            .index_client_leases
            .lock()
            .map_err(|_| SspryError::from("Index client lease lock poisoned."))?;
        let lease = leases
            .get_mut(&request.client_id)
            .ok_or_else(|| SspryError::from("no active index client; heartbeat rejected"))?;
        lease.last_heartbeat_unix_ms = now;
        Ok(CandidateIndexSessionResponse {
            message: "index client heartbeat updated".to_owned(),
        })
    }

    /// Updates total, submitted, and processed document counters for the
    /// currently active index session.
    fn handle_update_index_session_progress(
        &self,
        request: &CandidateIndexSessionProgressRequest,
    ) -> Result<CandidateIndexSessionResponse> {
        if self.active_index_sessions.load(Ordering::Acquire) == 0 {
            return Err(SspryError::from(
                "no active index session; cannot update progress",
            ));
        }
        if let Some(total) = request.total_documents {
            self.index_session_total_documents
                .store(total, Ordering::SeqCst);
        }
        self.index_session_submitted_documents
            .store(request.submitted_documents, Ordering::SeqCst);
        self.index_session_processed_documents
            .store(request.processed_documents, Ordering::SeqCst);
        self.index_session_last_update_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
        Ok(CandidateIndexSessionResponse {
            message: "index session progress updated".to_owned(),
        })
    }

    /// Adds inserted-document progress for server-side ingest paths that run
    /// under an active index session.
    fn record_index_session_insert_progress(&self, inserted_count: usize) {
        if inserted_count == 0 || self.active_index_sessions.load(Ordering::Acquire) == 0 {
            return;
        }
        let inserted_count = inserted_count as u64;
        self.index_session_submitted_documents
            .fetch_add(inserted_count, Ordering::SeqCst);
        self.index_session_processed_documents
            .fetch_add(inserted_count, Ordering::SeqCst);
        self.index_session_last_update_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
    }

    /// Accumulates per-batch ingest timings and byte counters into the active
    /// index session telemetry snapshot.
    fn record_index_session_insert_batch_profile(
        &self,
        documents: usize,
        shards_touched: usize,
        total: Duration,
        parse: Duration,
        group: Duration,
        build: Duration,
        store: Duration,
        finalize: Duration,
        store_profile: &CandidateInsertBatchProfile,
    ) {
        if documents == 0 || self.active_index_sessions.load(Ordering::Acquire) == 0 {
            return;
        }
        self.index_session_server_insert_batch_count
            .fetch_add(1, Ordering::SeqCst);
        self.index_session_server_insert_batch_documents
            .fetch_add(documents as u64, Ordering::SeqCst);
        self.index_session_server_insert_batch_shards_touched
            .fetch_add(shards_touched as u64, Ordering::SeqCst);
        self.index_session_server_insert_batch_total_us.fetch_add(
            total.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_parse_us.fetch_add(
            parse.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_group_us.fetch_add(
            group.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_build_us.fetch_add(
            build.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_store_us.fetch_add(
            store.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_finalize_us
            .fetch_add(
                finalize.as_micros().min(u128::from(u64::MAX)) as u64,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_resolve_doc_state_us
            .fetch_add(store_profile.resolve_doc_state_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_sidecars_us
            .fetch_add(store_profile.append_sidecars_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_sidecar_payloads_us
            .fetch_add(store_profile.append_sidecar_payloads_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_bloom_payload_assemble_us
            .fetch_add(
                store_profile.append_bloom_payload_assemble_us,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_bloom_payload_us
            .fetch_add(store_profile.append_bloom_payload_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_metadata_payload_us
            .fetch_add(store_profile.append_metadata_payload_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_external_id_payload_us
            .fetch_add(
                store_profile.append_external_id_payload_us,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_tier2_bloom_payload_us
            .fetch_add(
                store_profile.append_tier2_bloom_payload_us,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_doc_row_build_us
            .fetch_add(store_profile.append_doc_row_build_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_bloom_payload_bytes
            .fetch_add(store_profile.append_bloom_payload_bytes, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_metadata_payload_bytes
            .fetch_add(
                store_profile.append_metadata_payload_bytes,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_external_id_payload_bytes
            .fetch_add(
                store_profile.append_external_id_payload_bytes,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes
            .fetch_add(
                store_profile.append_tier2_bloom_payload_bytes,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_doc_records_us
            .fetch_add(store_profile.append_doc_records_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_write_existing_us
            .fetch_add(store_profile.write_existing_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_install_docs_us
            .fetch_add(store_profile.install_docs_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_tier2_update_us
            .fetch_add(store_profile.tier2_update_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_persist_meta_us
            .fetch_add(store_profile.persist_meta_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_rebalance_tier2_us
            .fetch_add(store_profile.rebalance_tier2_us, Ordering::SeqCst);
    }

    /// Ends the active index session, refreshes adaptive publish state, and
    /// wakes maintenance workers.
    fn handle_end_index_session(&self) -> Result<CandidateIndexSessionResponse> {
        let previous = self.active_index_sessions.swap(0, Ordering::SeqCst);
        if previous == 0 {
            return Ok(CandidateIndexSessionResponse {
                message: "no active index session".to_owned(),
            });
        }
        self.index_session_last_update_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
        let _ = self.update_adaptive_publish_from_index_session();
        self.notify_maintenance_workers();
        Ok(CandidateIndexSessionResponse {
            message: "index session finished".to_owned(),
        })
    }

    /// Releases one index client lease and requests publish follow-up when the
    /// final client exits.
    fn handle_end_index_client(
        &self,
        request: &CandidateIndexClientHeartbeatRequest,
    ) -> Result<CandidateIndexSessionResponse> {
        let now = current_unix_ms();
        self.prune_expired_index_clients(now)?;
        let mut leases = self
            .index_client_leases
            .lock()
            .map_err(|_| SspryError::from("Index client lease lock poisoned."))?;
        let removed = leases.remove(&request.client_id);
        let remaining = leases.len();
        self.active_index_clients.store(remaining, Ordering::SeqCst);
        if removed.is_none() {
            return Ok(CandidateIndexSessionResponse {
                message: "no active index client".to_owned(),
            });
        }
        if remaining == 0 {
            self.publish_after_index_clients
                .store(true, Ordering::SeqCst);
        }
        drop(leases);
        self.notify_maintenance_workers();
        let _ = self.maybe_force_publish_after_index_clients();
        Ok(CandidateIndexSessionResponse {
            message: "index client finished".to_owned(),
        })
    }

    #[cfg(test)]
    /// Serializes accumulated index-session insert-batch counters into the JSON
    /// shape used by unit tests.
    fn index_server_insert_batch_profile_json(&self) -> Value {
        let mut out = Map::new();
        for (key, value) in [
            (
                "batches",
                self.index_session_server_insert_batch_count
                    .load(Ordering::Acquire),
            ),
            (
                "documents",
                self.index_session_server_insert_batch_documents
                    .load(Ordering::Acquire),
            ),
            (
                "shards_touched_total",
                self.index_session_server_insert_batch_shards_touched
                    .load(Ordering::Acquire),
            ),
            (
                "total_us",
                self.index_session_server_insert_batch_total_us
                    .load(Ordering::Acquire),
            ),
            (
                "parse_us",
                self.index_session_server_insert_batch_parse_us
                    .load(Ordering::Acquire),
            ),
            (
                "group_us",
                self.index_session_server_insert_batch_group_us
                    .load(Ordering::Acquire),
            ),
            (
                "build_us",
                self.index_session_server_insert_batch_build_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_us",
                self.index_session_server_insert_batch_store_us
                    .load(Ordering::Acquire),
            ),
            (
                "finalize_us",
                self.index_session_server_insert_batch_finalize_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_resolve_doc_state_us",
                self.index_session_server_insert_batch_store_resolve_doc_state_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_sidecars_us",
                self.index_session_server_insert_batch_store_append_sidecars_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_sidecar_payloads_us",
                self.index_session_server_insert_batch_store_append_sidecar_payloads_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_bloom_payload_assemble_us",
                self.index_session_server_insert_batch_store_append_bloom_payload_assemble_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_bloom_payload_us",
                self.index_session_server_insert_batch_store_append_bloom_payload_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_metadata_payload_us",
                self.index_session_server_insert_batch_store_append_metadata_payload_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_external_id_payload_us",
                self.index_session_server_insert_batch_store_append_external_id_payload_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_tier2_bloom_payload_us",
                self.index_session_server_insert_batch_store_append_tier2_bloom_payload_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_doc_row_build_us",
                self.index_session_server_insert_batch_store_append_doc_row_build_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_bloom_payload_bytes",
                self.index_session_server_insert_batch_store_append_bloom_payload_bytes
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_metadata_payload_bytes",
                self.index_session_server_insert_batch_store_append_metadata_payload_bytes
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_external_id_payload_bytes",
                self.index_session_server_insert_batch_store_append_external_id_payload_bytes
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_tier2_bloom_payload_bytes",
                self.index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_doc_records_us",
                self.index_session_server_insert_batch_store_append_doc_records_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_write_existing_us",
                self.index_session_server_insert_batch_store_write_existing_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_install_docs_us",
                self.index_session_server_insert_batch_store_install_docs_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_tier2_update_us",
                self.index_session_server_insert_batch_store_tier2_update_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_persist_meta_us",
                self.index_session_server_insert_batch_store_persist_meta_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_rebalance_tier2_us",
                self.index_session_server_insert_batch_store_rebalance_tier2_us
                    .load(Ordering::Acquire),
            ),
        ] {
            out.insert(key.to_owned(), json!(value));
        }
        Value::Object(out)
    }

    /// Computes whether workspace-mode publish can run now and captures the
    /// current blocking reason and pressure snapshot.
    fn publish_readiness(&self, now_unix_ms: u64) -> PublishReadiness {
        let active_index_clients = self
            .prune_expired_index_clients(now_unix_ms)
            .unwrap_or_else(|_| self.active_index_clients.load(Ordering::Acquire));
        let work_dirty = self.work_dirty.load(Ordering::Acquire);
        let publish_requested = self.publish_requested.load(Ordering::Acquire);
        let publish_in_progress = self.publish_in_progress.load(Ordering::Acquire);
        let mutations_paused = self.mutations_paused.load(Ordering::Acquire);
        let active_index_sessions = self.active_index_sessions.load(Ordering::Acquire);
        let active_mutations = self.active_mutations.load(Ordering::Acquire);
        let publish_after_index_clients = self.publish_after_index_clients.load(Ordering::Acquire);
        let last_mutation = self.last_work_mutation_unix_ms.load(Ordering::Acquire);
        let idle_elapsed_ms = if last_mutation == 0 {
            0
        } else {
            now_unix_ms.saturating_sub(last_mutation)
        };
        let adaptive = self.adaptive_publish_snapshot_or_default(now_unix_ms);
        let idle_threshold_ms = adaptive.current_idle_ms;
        let idle_remaining_ms = idle_threshold_ms.saturating_sub(idle_elapsed_ms);
        let (current_rss_kb, _) = current_process_memory_kb();
        let pressure = self.work_buffer_pressure_snapshot(
            current_rss_kb
                .saturating_mul(1024)
                .try_into()
                .unwrap_or(u64::MAX),
            adaptive.tier2_pending_shards,
        );
        let forced_eligible = self.config.workspace_mode
            && work_dirty
            && publish_after_index_clients
            && active_index_clients == 0
            && active_index_sessions == 0
            && active_mutations == 0
            && !publish_requested
            && !publish_in_progress
            && !mutations_paused;
        let idle_eligible = self.config.workspace_mode
            && work_dirty
            && active_index_clients == 0
            && active_index_sessions == 0
            && active_mutations == 0
            && !publish_requested
            && !publish_in_progress
            && !mutations_paused
            && last_mutation != 0
            && idle_elapsed_ms >= idle_threshold_ms;
        let eligible = forced_eligible || idle_eligible;
        let blocked_reason = if !self.config.workspace_mode {
            "workspace_disabled"
        } else if forced_eligible {
            "ready_after_index_clients"
        } else if idle_eligible {
            "ready"
        } else if !work_dirty {
            "work_clean"
        } else if publish_requested {
            "publish_requested"
        } else if publish_in_progress {
            "publish_in_progress"
        } else if mutations_paused {
            "mutations_paused"
        } else if active_index_clients > 0 {
            "active_index_clients"
        } else if active_index_sessions > 0 {
            "active_index_sessions"
        } else if active_mutations > 0 {
            "active_mutations"
        } else if last_mutation == 0 {
            "awaiting_work_mutation_timestamp"
        } else if idle_elapsed_ms < idle_threshold_ms {
            "waiting_for_idle_window"
        } else {
            "ready"
        };
        PublishReadiness {
            eligible,
            blocked_reason,
            trigger_mode: if forced_eligible {
                "index_clients"
            } else if idle_eligible {
                "idle"
            } else {
                "blocked"
            },
            trigger_reason: adaptive.reason,
            idle_elapsed_ms,
            idle_threshold_ms,
            idle_remaining_ms,
            work_buffer_estimated_documents: pressure.estimated_documents,
            work_buffer_estimated_input_bytes: pressure.estimated_input_bytes,
            work_buffer_document_threshold: pressure.document_threshold,
            work_buffer_input_bytes_threshold: pressure.input_bytes_threshold,
            work_buffer_rss_threshold_bytes: pressure.rss_threshold_bytes,
            current_rss_bytes: pressure.current_rss_bytes,
            pending_tier2_snapshot_shards: pressure.pending_tier2_snapshot_shards,
            index_backpressure_delay_ms: pressure.index_backpressure_delay_ms,
        }
    }

    /// Runs one automatic publish attempt when workspace-mode readiness says it
    /// is eligible.
    fn run_auto_publish_cycle(&self) -> Result<()> {
        let readiness = self.publish_readiness(current_unix_ms());
        if !readiness.eligible {
            return Ok(());
        }
        let _ = self.handle_publish()?;
        Ok(())
    }

    /// Opportunistically prunes old retired workspace roots when no mutating or
    /// publishing activity is active.
    fn run_retired_root_prune_cycle(&self) -> Result<()> {
        if self.publish_in_progress.load(Ordering::Acquire)
            || self.active_index_clients.load(Ordering::Acquire) > 0
            || self.active_index_sessions.load(Ordering::Acquire) > 0
            || self.active_mutations.load(Ordering::Acquire) > 0
        {
            return Ok(());
        }
        let retired_root = {
            let store_mode = self
                .store_mode
                .lock()
                .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
            match &*store_mode {
                StoreMode::Workspace { root, .. } => workspace_retired_root(root),
                StoreMode::Direct { .. } | StoreMode::Forest { .. } => return Ok(()),
            }
        };
        let _ =
            prune_workspace_retired_roots(&retired_root, DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP)?;
        Ok(())
    }

    #[cfg(test)]
    /// Builds stats JSON plus collection timing for one store set, reusing the
    /// cached snapshot when it is already available.
    fn candidate_stats_json_for_store_set_profiled(
        &self,
        store_set: &StoreSet,
        operation: &str,
    ) -> Result<(Map<String, Value>, u64, CandidateStatsBuildProfile)> {
        if let Some((stats, deleted_storage_bytes)) = store_set.cached_stats()? {
            return Ok((
                stats,
                deleted_storage_bytes,
                CandidateStatsBuildProfile::default(),
            ));
        }
        let started_collect = Instant::now();
        let mut stats_rows = Vec::with_capacity(store_set.stores.len());
        let mut deleted_storage_bytes = 0u64;
        for (shard_idx, store_lock) in store_set.stores.iter().enumerate() {
            let store = lock_candidate_store_with_timeout(store_lock, shard_idx, operation)?;
            stats_rows.push(store.stats());
            deleted_storage_bytes =
                deleted_storage_bytes.saturating_add(store.deleted_storage_bytes());
        }
        let collect_store_stats_ms = started_collect
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let started_disk_usage = Instant::now();
        let disk_usage_bytes = disk_usage_under(&store_set.root()?);
        let disk_usage_ms = started_disk_usage
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let started_build_json = Instant::now();
        let stats = candidate_stats_json_from_parts_with_disk_usage(&stats_rows, disk_usage_bytes);
        let build_json_ms = started_build_json
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        store_set.set_cached_stats(stats.clone(), deleted_storage_bytes)?;
        Ok((
            stats,
            deleted_storage_bytes,
            CandidateStatsBuildProfile {
                collect_store_stats_ms,
                disk_usage_ms,
                build_json_ms,
            },
        ))
    }

    #[cfg(test)]
    /// Aggregates stats JSON plus collection timing across all published query
    /// roots for test-only diagnostics.
    fn candidate_stats_json_for_query_store_sets_profiled(
        &self,
        operation: &str,
    ) -> Result<(Map<String, Value>, u64, CandidateStatsBuildProfile)> {
        let store_sets = self.published_query_store_sets()?;
        if store_sets.len() == 1 {
            return self.candidate_stats_json_for_store_set_profiled(&store_sets[0], operation);
        }
        let started_collect = Instant::now();
        let mut stats_rows = Vec::new();
        let mut deleted_storage_bytes = 0u64;
        for store_set in &store_sets {
            for (shard_idx, store_lock) in store_set.stores.iter().enumerate() {
                let store = lock_candidate_store_with_timeout(store_lock, shard_idx, operation)?;
                stats_rows.push(store.stats());
                deleted_storage_bytes =
                    deleted_storage_bytes.saturating_add(store.deleted_storage_bytes());
            }
        }
        let collect_store_stats_ms = started_collect
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let started_disk_usage = Instant::now();
        let mut disk_usage_bytes = 0u64;
        for store_set in &store_sets {
            disk_usage_bytes =
                disk_usage_bytes.saturating_add(disk_usage_under(&store_set.root()?));
        }
        let disk_usage_ms = started_disk_usage
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let started_build_json = Instant::now();
        let mut stats =
            candidate_stats_json_from_parts_with_disk_usage(&stats_rows, disk_usage_bytes);
        stats.insert(
            "candidate_shards".to_owned(),
            json!(self.candidate_shard_count()),
        );
        let build_json_ms = started_build_json
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        Ok((
            stats,
            deleted_storage_bytes,
            CandidateStatsBuildProfile {
                collect_store_stats_ms,
                disk_usage_ms,
                build_json_ms,
            },
        ))
    }

    /// Builds a gRPC store summary for one store set by aggregating per-shard
    /// candidate stats.
    fn grpc_store_summary_for_store_set(
        &self,
        store_set: &StoreSet,
        operation: &str,
        candidate_shards: usize,
    ) -> Result<StoreSummary> {
        let mut stats_rows = Vec::with_capacity(store_set.stores.len());
        let mut deleted_storage_bytes = 0u64;
        for (shard_idx, store_lock) in store_set.stores.iter().enumerate() {
            let store = lock_candidate_store_with_timeout(store_lock, shard_idx, operation)?;
            stats_rows.push(store.stats());
            deleted_storage_bytes =
                deleted_storage_bytes.saturating_add(store.deleted_storage_bytes());
        }
        let disk_usage_bytes = disk_usage_under(&store_set.root()?);
        Ok(grpc_store_summary_from_candidate_stats(
            &stats_rows,
            disk_usage_bytes,
            deleted_storage_bytes,
            candidate_shards,
        ))
    }

    /// Builds a gRPC store summary across every published query store set for
    /// the active server mode.
    fn grpc_store_summary_for_query_store_sets(&self, operation: &str) -> Result<StoreSummary> {
        let store_sets = self.published_query_store_sets()?;
        if store_sets.len() == 1 {
            let shard_count = store_sets[0].stores.len().max(1);
            return self.grpc_store_summary_for_store_set(&store_sets[0], operation, shard_count);
        }
        let mut stats_rows = Vec::new();
        let mut deleted_storage_bytes = 0u64;
        for store_set in &store_sets {
            for (shard_idx, store_lock) in store_set.stores.iter().enumerate() {
                let store = lock_candidate_store_with_timeout(store_lock, shard_idx, operation)?;
                stats_rows.push(store.stats());
                deleted_storage_bytes =
                    deleted_storage_bytes.saturating_add(store.deleted_storage_bytes());
            }
        }
        let mut disk_usage_bytes = 0u64;
        for store_set in &store_sets {
            disk_usage_bytes =
                disk_usage_bytes.saturating_add(disk_usage_under(&store_set.root()?));
        }
        Ok(grpc_store_summary_from_candidate_stats(
            &stats_rows,
            disk_usage_bytes,
            deleted_storage_bytes,
            self.candidate_shard_count(),
        ))
    }

    /// Builds the lightweight `StatsResponse` used by CLI policy discovery and
    /// diagnostics.
    fn grpc_stats_response(&self) -> Result<StatsResponse> {
        let stats = self.grpc_store_summary_for_query_store_sets("grpc stats")?;
        let (current_rss_kb, peak_rss_kb) = current_process_memory_kb();
        let forest_source_dedup = if self.forest_mode_info()?.is_some() {
            grpc_forest_source_dedup_summary_from_root(&self.config.candidate_config.root)
        } else {
            None
        };
        Ok(StatsResponse {
            stats: Some(stats),
            memory_budget_bytes: self.config.memory_budget_bytes,
            workspace_mode: self.workspace_roots()?.is_some(),
            search_workers: self.config.search_workers as u64,
            current_rss_kb: current_rss_kb as u64,
            peak_rss_kb: peak_rss_kb as u64,
            forest_source_dedup,
        })
    }

    /// Builds the full `StatusResponse` including publish, workspace, and
    /// memory state.
    fn grpc_status_response(&self) -> Result<StatusResponse> {
        let now_unix_ms = current_unix_ms();
        let adaptive = self.adaptive_publish_snapshot_or_default(now_unix_ms);
        let readiness = self.publish_readiness(now_unix_ms);
        let published =
            self.grpc_store_summary_for_query_store_sets("grpc status published stats")?;
        let forest_source_dedup = if self.forest_mode_info()?.is_some() {
            grpc_forest_source_dedup_summary_from_root(&self.config.candidate_config.root)
        } else {
            None
        };
        let workspace_roots = self.workspace_roots()?;
        let workspace_mode = workspace_roots.is_some();
        let (published_root, work_root, has_work, work) =
            if let Some((published_root, work_root)) = workspace_roots {
                let work = if let Some(store_set) = self.work_store_set_if_present()? {
                    self.grpc_store_summary_for_store_set(
                        &store_set,
                        "grpc status work stats",
                        self.candidate_shard_count(),
                    )?
                } else {
                    grpc_empty_store_summary_for_config(
                        &self.config,
                        &work_root,
                        self.candidate_shard_count(),
                    )
                };
                (
                    published_root.display().to_string(),
                    work_root.display().to_string(),
                    true,
                    Some(work),
                )
            } else {
                (String::new(), String::new(), false, None)
            };
        let (current_rss_kb, peak_rss_kb) = current_process_memory_kb();
        Ok(StatusResponse {
            draining: self.is_shutting_down(),
            active_connections: self.active_connections.load(Ordering::Acquire) as u64,
            active_mutations: self.active_mutations.load(Ordering::Acquire) as u64,
            publish_requested: self.publish_requested.load(Ordering::Acquire),
            mutations_paused: self.mutations_paused.load(Ordering::Acquire),
            publish_in_progress: self.publish_in_progress.load(Ordering::Acquire),
            active_index_clients: self.active_index_clients.load(Ordering::Acquire) as u64,
            active_index_sessions: self.active_index_sessions.load(Ordering::Acquire) as u64,
            search_workers: self.config.search_workers as u64,
            memory_budget_bytes: self.config.memory_budget_bytes,
            current_rss_kb: current_rss_kb as u64,
            peak_rss_kb: peak_rss_kb as u64,
            adaptive_publish: Some(grpc_adaptive_publish_summary_from_snapshot(&adaptive)),
            index_session: Some(grpc_index_session_summary_from_state(self)),
            startup: Some(grpc_startup_summary_from_profile(
                &self.startup_profile,
                self.startup_cleanup_removed_roots as u64,
            )),
            workspace_mode,
            published_root,
            work_root,
            has_work,
            work,
            has_published: true,
            published: Some(published),
            publish: Some(grpc_publish_summary_from_state(self, readiness)),
            published_tier2_snapshot_seal: Some(
                grpc_published_tier2_snapshot_seal_summary_from_state(self),
            ),
            forest_source_dedup,
        })
    }

    #[cfg(test)]
    /// Reports entry count and estimated heap bytes for the normalized-plan
    /// cache used in unit tests.
    fn normalized_plan_cache_stats(&self) -> (usize, u64) {
        self.normalized_plan_cache
            .lock()
            .map(|cache| {
                let bytes = cache
                    .iter()
                    .map(|(key, value)| {
                        (std::mem::size_of::<String>() as u64)
                            .saturating_add(key.capacity() as u64)
                            .saturating_add(compiled_query_plan_memory_bytes(value.as_ref()))
                    })
                    .sum();
                (cache.len(), bytes)
            })
            .unwrap_or((0, 0))
    }

    #[cfg(test)]
    /// Reports entry count and estimated heap bytes for the query-artifact
    /// cache used in unit tests.
    fn query_artifact_cache_stats(&self) -> (usize, u64) {
        self.query_artifact_cache
            .lock()
            .map(|cache| {
                let bytes = cache
                    .iter()
                    .map(|(key, value)| {
                        (std::mem::size_of::<String>() as u64)
                            .saturating_add(key.capacity() as u64)
                            .saturating_add(runtime_query_artifacts_memory_bytes(value.as_ref()))
                    })
                    .sum();
                (cache.len(), bytes)
            })
            .unwrap_or((0, 0))
    }

    #[cfg(test)]
    /// Reports entry count and estimated heap bytes for the cached-query
    /// results store used in unit tests.
    fn query_cache_stats(&self) -> (usize, u64) {
        self.query_cache
            .lock()
            .map(|cache| {
                let bytes = cache
                    .iter()
                    .map(|(key, value)| {
                        (std::mem::size_of::<String>() as u64)
                            .saturating_add(key.capacity() as u64)
                            .saturating_add(cached_candidate_query_memory_bytes(value.as_ref()))
                    })
                    .sum();
                (cache.len(), bytes)
            })
            .unwrap_or((0, 0))
    }

    #[cfg(test)]
    /// Builds the expanded test-only stats JSON including publish, cache, and
    /// workspace diagnostics.
    fn current_stats_json(&self) -> Result<Map<String, Value>> {
        let started_total = Instant::now();
        let now_unix_ms = current_unix_ms();
        let adaptive = self.adaptive_publish_snapshot_or_default(now_unix_ms);
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let (mut stats, deleted_storage_bytes, published_stats_profile) =
            self.candidate_stats_json_for_query_store_sets_profiled("stats")?;
        let mut work_stats_profile = CandidateStatsBuildProfile::default();
        let mut retired_stats_ms = 0u64;
        stats.insert("draining".to_owned(), json!(self.is_shutting_down()));
        stats.insert(
            "active_connections".to_owned(),
            json!(self.active_connections.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_mutations".to_owned(),
            json!(self.active_mutations.load(Ordering::Acquire)),
        );
        stats.insert(
            "publish_requested".to_owned(),
            json!(self.publish_requested.load(Ordering::Acquire)),
        );
        stats.insert(
            "mutations_paused".to_owned(),
            json!(self.mutations_paused.load(Ordering::Acquire)),
        );
        stats.insert(
            "publish_in_progress".to_owned(),
            json!(self.publish_in_progress.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_index_clients".to_owned(),
            json!(self.active_index_clients.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_index_sessions".to_owned(),
            json!(self.active_index_sessions.load(Ordering::Acquire)),
        );
        stats.insert(
            "work_dirty".to_owned(),
            json!(self.work_dirty.load(Ordering::Acquire)),
        );
        stats.insert(
            "last_work_mutation_unix_ms".to_owned(),
            json!(self.last_work_mutation_unix_ms.load(Ordering::Acquire)),
        );
        stats.insert(
            "adaptive_publish".to_owned(),
            json!({
                "storage_class": adaptive.storage_class,
                "current_idle_ms": adaptive.current_idle_ms,
                "mode": adaptive.mode,
                "reason": adaptive.reason,
                "recent_publish_p95_ms": adaptive.recent_publish_p95_ms,
                "recent_submit_p95_ms": adaptive.recent_submit_p95_ms,
                "recent_store_p95_ms": adaptive.recent_store_p95_ms,
                "recent_publishes_in_window": adaptive.recent_publishes_in_window,
                "tier2_pending_shards": adaptive.tier2_pending_shards,
                "healthy_cycles": adaptive.healthy_cycles,
            }),
        );
        stats.insert(
            "search_workers".to_owned(),
            json!(self.config.search_workers),
        );
        stats.insert(
            "memory_budget_bytes".to_owned(),
            json!(self.config.memory_budget_bytes),
        );
        let (current_rss_kb, peak_rss_kb) = current_process_memory_kb();
        let (normalized_plan_cache_entries, normalized_plan_cache_bytes) =
            self.normalized_plan_cache_stats();
        let (query_artifact_cache_entries, query_artifact_cache_bytes) =
            self.query_artifact_cache_stats();
        let (query_cache_entries, query_cache_bytes) = self.query_cache_stats();
        stats.insert("current_rss_kb".to_owned(), json!(current_rss_kb));
        stats.insert("peak_rss_kb".to_owned(), json!(peak_rss_kb));
        stats.insert(
            "normalized_plan_cache_entries".to_owned(),
            json!(normalized_plan_cache_entries),
        );
        stats.insert(
            "normalized_plan_cache_bytes".to_owned(),
            json!(normalized_plan_cache_bytes),
        );
        stats.insert(
            "query_artifact_cache_entries".to_owned(),
            json!(query_artifact_cache_entries),
        );
        stats.insert(
            "query_artifact_cache_bytes".to_owned(),
            json!(query_artifact_cache_bytes),
        );
        stats.insert("query_cache_entries".to_owned(), json!(query_cache_entries));
        stats.insert("query_cache_bytes".to_owned(), json!(query_cache_bytes));
        stats.insert(
            "startup_cleanup_removed_roots".to_owned(),
            json!(self.startup_cleanup_removed_roots),
        );
        let index_total_documents = self.index_session_total_documents.load(Ordering::Acquire);
        let index_processed_documents = self
            .index_session_processed_documents
            .load(Ordering::Acquire);
        let index_submitted_documents = self
            .index_session_submitted_documents
            .load(Ordering::Acquire);
        let index_remaining_documents =
            index_total_documents.saturating_sub(index_processed_documents);
        let index_progress_percent = if index_total_documents == 0 {
            0.0
        } else {
            (index_processed_documents as f64 / index_total_documents as f64) * 100.0
        };
        let index_server_insert_batch_profile = self.index_server_insert_batch_profile_json();
        let mut index_session = Map::new();
        index_session.insert(
            "client_active".to_owned(),
            json!(self.active_index_clients.load(Ordering::Acquire) > 0),
        );
        index_session.insert(
            "active".to_owned(),
            json!(self.active_index_sessions.load(Ordering::Acquire) > 0),
        );
        index_session.insert("total_documents".to_owned(), json!(index_total_documents));
        index_session.insert(
            "submitted_documents".to_owned(),
            json!(index_submitted_documents),
        );
        index_session.insert(
            "processed_documents".to_owned(),
            json!(index_processed_documents),
        );
        index_session.insert(
            "remaining_documents".to_owned(),
            json!(index_remaining_documents),
        );
        index_session.insert("progress_percent".to_owned(), json!(index_progress_percent));
        index_session.insert(
            "started_unix_ms".to_owned(),
            json!(self.index_session_started_unix_ms.load(Ordering::Acquire)),
        );
        index_session.insert(
            "last_update_unix_ms".to_owned(),
            json!(self
                .index_session_last_update_unix_ms
                .load(Ordering::Acquire)),
        );
        index_session.insert(
            "server_insert_batch_profile".to_owned(),
            index_server_insert_batch_profile,
        );
        stats.insert("index_session".to_owned(), Value::Object(index_session));
        if let Ok(runtime) = self.compaction_runtime.lock() {
            stats.insert(
                "compaction_running".to_owned(),
                json!(runtime.running_shard.is_some()),
            );
            stats.insert(
                "compaction_running_shard".to_owned(),
                runtime
                    .running_shard
                    .map(Value::from)
                    .unwrap_or(Value::Null),
            );
            stats.insert(
                "compaction_runs_total".to_owned(),
                json!(runtime.runs_total),
            );
            stats.insert(
                "compaction_mutation_retries_total".to_owned(),
                json!(runtime.mutation_retries_total),
            );
            stats.insert(
                "last_compaction_reclaimed_docs".to_owned(),
                json!(runtime.last_reclaimed_docs),
            );
            stats.insert(
                "last_compaction_reclaimed_bytes".to_owned(),
                json!(runtime.last_reclaimed_bytes),
            );
            stats.insert(
                "last_compaction_completed_unix_ms".to_owned(),
                runtime
                    .last_completed_unix_ms
                    .map(Value::from)
                    .unwrap_or(Value::Null),
            );
            stats.insert(
                "last_compaction_error".to_owned(),
                runtime
                    .last_error
                    .as_ref()
                    .map(|value| Value::from(value.clone()))
                    .unwrap_or(Value::Null),
            );
        }
        let startup_root_json = |profile: &StoreRootStartupProfile| {
            json!({
                "total_ms": profile.total_ms,
                "opened_existing_shards": profile.opened_existing_shards,
                "initialized_new_shards": profile.initialized_new_shards,
                "doc_count": profile.doc_count,
                "store_open_total_ms": profile.store_open_total_ms,
                "store_open_manifest_ms": profile.store_open_manifest_ms,
                "store_open_meta_ms": profile.store_open_meta_ms,
                "store_open_load_state_ms": profile.store_open_load_state_ms,
                "store_open_sidecars_ms": profile.store_open_sidecars_ms,
                "store_open_rebuild_indexes_ms": profile.store_open_rebuild_indexes_ms,
                "store_open_rebuild_identity_index_ms": profile.store_open_rebuild_identity_index_ms,
            })
        };
        stats.insert(
            "startup".to_owned(),
            json!({
                "total_ms": self.startup_profile.total_ms,
                "startup_cleanup_removed_roots": self.startup_cleanup_removed_roots,
                "current": startup_root_json(&self.startup_profile.current),
                "work": startup_root_json(&self.startup_profile.work),
            }),
        );
        stats.insert(
            "deleted_storage_bytes".to_owned(),
            json!(deleted_storage_bytes),
        );
        if let Some((forest_root, tree_count)) = self.forest_mode_info()? {
            stats.insert("workspace_mode".to_owned(), json!(false));
            stats.insert("forest_mode".to_owned(), json!(true));
            stats.insert(
                "forest_root".to_owned(),
                Value::String(forest_root.display().to_string()),
            );
            stats.insert("forest_tree_count".to_owned(), json!(tree_count));
        } else if let Some((published_root, work_root)) = self.workspace_roots()? {
            let (mut work_stats, work_deleted_storage_bytes) =
                if let Some(work) = self.work_store_set_if_present()? {
                    let (work_stats, work_deleted_storage_bytes, work_profile) =
                        self.candidate_stats_json_for_store_set_profiled(&work, "work stats")?;
                    work_stats_profile = work_profile;
                    (work_stats, work_deleted_storage_bytes)
                } else {
                    (
                        empty_candidate_stats_json_for_config(
                            &self.config,
                            &work_root,
                            self.candidate_shard_count(),
                        ),
                        0,
                    )
                };
            let retired_root = workspace_retired_root(&self.config.candidate_config.root);
            let started_retired = Instant::now();
            let (retired_published_root_count, retired_published_disk_usage_bytes) =
                workspace_retired_stats(&retired_root);
            retired_stats_ms = started_retired
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            stats.insert("workspace_mode".to_owned(), json!(true));
            stats.insert(
                "published_root".to_owned(),
                Value::String(published_root.display().to_string()),
            );
            stats.insert(
                "work_root".to_owned(),
                Value::String(work_root.display().to_string()),
            );
            work_stats.insert(
                "deleted_storage_bytes".to_owned(),
                json!(work_deleted_storage_bytes),
            );
            let now_unix_ms = current_unix_ms();
            let readiness = self.publish_readiness(now_unix_ms);
            let adaptive = self.adaptive_publish_snapshot_or_default(now_unix_ms);
            let published_doc_count = stats.get("doc_count").and_then(Value::as_u64).unwrap_or(0);
            let published_active_doc_count = stats
                .get("active_doc_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let published_disk_usage_bytes = stats
                .get("disk_usage_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let work_doc_count = work_stats
                .get("doc_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let work_active_doc_count = work_stats
                .get("active_doc_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let work_disk_usage_bytes = work_stats
                .get("disk_usage_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let mut publish = Map::new();
            publish.insert(
                "pending".to_owned(),
                json!(self.work_dirty.load(Ordering::Acquire)),
            );
            publish.insert("eligible".to_owned(), json!(readiness.eligible));
            publish.insert(
                "blocked_reason".to_owned(),
                Value::String(readiness.blocked_reason.to_owned()),
            );
            publish.insert(
                "idle_elapsed_ms".to_owned(),
                json!(readiness.idle_elapsed_ms),
            );
            publish.insert(
                "idle_remaining_ms".to_owned(),
                json!(readiness.idle_remaining_ms),
            );
            publish.insert(
                "adaptive_idle_ms".to_owned(),
                json!(readiness.idle_threshold_ms),
            );
            publish.insert(
                "adaptive_mode".to_owned(),
                Value::String(adaptive.mode.to_owned()),
            );
            publish.insert(
                "adaptive_reason".to_owned(),
                Value::String(adaptive.reason.to_owned()),
            );
            publish.insert(
                "adaptive_storage_class".to_owned(),
                Value::String(adaptive.storage_class),
            );
            publish.insert(
                "trigger_mode".to_owned(),
                Value::String(readiness.trigger_mode.to_owned()),
            );
            publish.insert(
                "trigger_reason".to_owned(),
                Value::String(readiness.trigger_reason.to_owned()),
            );
            publish.insert(
                "work_buffer_estimated_documents".to_owned(),
                json!(readiness.work_buffer_estimated_documents),
            );
            publish.insert(
                "work_buffer_estimated_input_bytes".to_owned(),
                json!(readiness.work_buffer_estimated_input_bytes),
            );
            publish.insert(
                "work_buffer_document_threshold".to_owned(),
                json!(readiness.work_buffer_document_threshold),
            );
            publish.insert(
                "work_buffer_input_bytes_threshold".to_owned(),
                json!(readiness.work_buffer_input_bytes_threshold),
            );
            publish.insert(
                "work_buffer_rss_threshold_bytes".to_owned(),
                json!(readiness.work_buffer_rss_threshold_bytes),
            );
            publish.insert(
                "current_rss_bytes".to_owned(),
                json!(readiness.current_rss_bytes),
            );
            publish.insert(
                "pressure_publish_blocked_by_seal_backlog".to_owned(),
                json!(readiness.pending_tier2_snapshot_shards > 0),
            );
            publish.insert(
                "pending_tier2_snapshot_shards".to_owned(),
                json!(readiness.pending_tier2_snapshot_shards),
            );
            publish.insert(
                "index_backpressure_delay_ms".to_owned(),
                json!(readiness.index_backpressure_delay_ms),
            );
            publish.insert(
                "index_backpressure_events_total".to_owned(),
                json!(self.index_backpressure_events_total.load(Ordering::Acquire)),
            );
            publish.insert(
                "index_backpressure_sleep_ms_total".to_owned(),
                json!(self
                    .index_backpressure_sleep_ms_total
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "adaptive_recent_publish_p95_ms".to_owned(),
                json!(adaptive.recent_publish_p95_ms),
            );
            publish.insert(
                "adaptive_recent_submit_p95_ms".to_owned(),
                json!(adaptive.recent_submit_p95_ms),
            );
            publish.insert(
                "adaptive_recent_store_p95_ms".to_owned(),
                json!(adaptive.recent_store_p95_ms),
            );
            publish.insert(
                "adaptive_recent_publishes_in_window".to_owned(),
                json!(adaptive.recent_publishes_in_window),
            );
            publish.insert(
                "adaptive_tier2_pending_shards".to_owned(),
                json!(adaptive.tier2_pending_shards),
            );
            publish.insert(
                "adaptive_healthy_cycles".to_owned(),
                json!(adaptive.healthy_cycles),
            );
            publish.insert("published_doc_count".to_owned(), json!(published_doc_count));
            publish.insert(
                "published_active_doc_count".to_owned(),
                json!(published_active_doc_count),
            );
            publish.insert(
                "published_disk_usage_bytes".to_owned(),
                json!(published_disk_usage_bytes),
            );
            publish.insert("work_doc_count".to_owned(), json!(work_doc_count));
            publish.insert(
                "work_active_doc_count".to_owned(),
                json!(work_active_doc_count),
            );
            publish.insert(
                "work_disk_usage_bytes".to_owned(),
                json!(work_disk_usage_bytes),
            );
            publish.insert(
                "work_doc_delta_vs_published".to_owned(),
                json!(signed_delta_i64(work_doc_count, published_doc_count)),
            );
            publish.insert(
                "work_active_doc_delta_vs_published".to_owned(),
                json!(signed_delta_i64(
                    work_active_doc_count,
                    published_active_doc_count
                )),
            );
            publish.insert(
                "work_disk_usage_delta_vs_published".to_owned(),
                json!(signed_delta_i64(
                    work_disk_usage_bytes,
                    published_disk_usage_bytes
                )),
            );
            publish.insert(
                "retired_published_root_count".to_owned(),
                json!(retired_published_root_count),
            );
            publish.insert(
                "retired_published_disk_usage_bytes".to_owned(),
                json!(retired_published_disk_usage_bytes),
            );
            publish.insert(
                "retired_published_roots_to_keep".to_owned(),
                json!(DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP as u64),
            );
            publish.insert(
                "last_publish_started_unix_ms".to_owned(),
                json!(self.last_publish_started_unix_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_completed_unix_ms".to_owned(),
                json!(self.last_publish_completed_unix_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_duration_ms".to_owned(),
                json!(self.last_publish_duration_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_lock_wait_ms".to_owned(),
                json!(self.last_publish_lock_wait_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_swap_ms".to_owned(),
                json!(self.last_publish_swap_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_ms".to_owned(),
                json!(self.last_publish_promote_work_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_export_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_export_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_resolve_doc_state_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_resolve_doc_state_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_build_payloads_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_build_payloads_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_append_sidecars_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_append_sidecars_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_install_docs_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_install_docs_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_tier2_update_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_tier2_update_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_persist_meta_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_persist_meta_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_rebalance_tier2_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_rebalance_tier2_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_remove_work_root_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_remove_work_root_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_other_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_other_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_imported_docs".to_owned(),
                json!(self
                    .last_publish_promote_work_imported_docs
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_imported_shards".to_owned(),
                json!(self
                    .last_publish_promote_work_imported_shards
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_init_work_ms".to_owned(),
                json!(self.last_publish_init_work_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_tier2_snapshot_persist_failures".to_owned(),
                json!(self
                    .last_publish_tier2_snapshot_persist_failures
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_persisted_snapshot_shards".to_owned(),
                json!(self
                    .last_publish_persisted_snapshot_shards
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_reused_work_stores".to_owned(),
                json!(self.last_publish_reused_work_stores.load(Ordering::Acquire)),
            );
            publish.insert(
                "publish_runs_total".to_owned(),
                json!(self.publish_runs_total.load(Ordering::Acquire)),
            );
            publish.insert("observed_at_unix_ms".to_owned(), json!(now_unix_ms));
            stats.insert("work".to_owned(), Value::Object(work_stats));
            stats.insert("publish".to_owned(), Value::Object(publish));
            stats.insert(
                "published_tier2_snapshot_seal".to_owned(),
                json!({
                    "pending_shards": self.pending_published_tier2_snapshot_shard_count().unwrap_or(0),
                    "in_progress": self.published_tier2_snapshot_seal_in_progress.load(Ordering::Acquire),
                    "runs_total": self.published_tier2_snapshot_seal_runs_total.load(Ordering::Acquire),
                    "last_duration_ms": self.last_published_tier2_snapshot_seal_duration_ms.load(Ordering::Acquire),
                    "last_persisted_shards": self.last_published_tier2_snapshot_seal_persisted_shards.load(Ordering::Acquire),
                    "last_failures": self.last_published_tier2_snapshot_seal_failures.load(Ordering::Acquire),
                    "last_completed_unix_ms": self.last_published_tier2_snapshot_seal_completed_unix_ms.load(Ordering::Acquire),
                }),
            );
        } else {
            stats.insert("workspace_mode".to_owned(), json!(false));
        }
        stats.insert(
            "stats_profile".to_owned(),
            json!({
                "total_ms": started_total.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                "published": {
                    "collect_store_stats_ms": published_stats_profile.collect_store_stats_ms,
                    "disk_usage_ms": published_stats_profile.disk_usage_ms,
                    "build_json_ms": published_stats_profile.build_json_ms,
                },
                "work": {
                    "collect_store_stats_ms": work_stats_profile.collect_store_stats_ms,
                    "disk_usage_ms": work_stats_profile.disk_usage_ms,
                    "build_json_ms": work_stats_profile.build_json_ms,
                },
                "retired_stats_ms": retired_stats_ms,
            }),
        );
        Ok(stats)
    }

    #[cfg(test)]
    /// Builds the lighter test-only status JSON used by unit tests that do not
    /// need the full profiled stats payload.
    fn status_json(&self) -> Result<Map<String, Value>> {
        let now_unix_ms = current_unix_ms();
        let adaptive = self.adaptive_publish_snapshot_or_default(now_unix_ms);
        let mut stats = Map::new();
        stats.insert("draining".to_owned(), json!(self.is_shutting_down()));
        stats.insert(
            "active_connections".to_owned(),
            json!(self.active_connections.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_mutations".to_owned(),
            json!(self.active_mutations.load(Ordering::Acquire)),
        );
        stats.insert(
            "publish_requested".to_owned(),
            json!(self.publish_requested.load(Ordering::Acquire)),
        );
        stats.insert(
            "mutations_paused".to_owned(),
            json!(self.mutations_paused.load(Ordering::Acquire)),
        );
        stats.insert(
            "publish_in_progress".to_owned(),
            json!(self.publish_in_progress.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_index_clients".to_owned(),
            json!(self.active_index_clients.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_index_sessions".to_owned(),
            json!(self.active_index_sessions.load(Ordering::Acquire)),
        );
        stats.insert(
            "work_dirty".to_owned(),
            json!(self.work_dirty.load(Ordering::Acquire)),
        );
        stats.insert(
            "last_work_mutation_unix_ms".to_owned(),
            json!(self.last_work_mutation_unix_ms.load(Ordering::Acquire)),
        );
        stats.insert(
            "adaptive_publish".to_owned(),
            json!({
                "storage_class": adaptive.storage_class,
                "current_idle_ms": adaptive.current_idle_ms,
                "mode": adaptive.mode,
                "reason": adaptive.reason,
                "recent_publish_p95_ms": adaptive.recent_publish_p95_ms,
                "recent_submit_p95_ms": adaptive.recent_submit_p95_ms,
                "recent_store_p95_ms": adaptive.recent_store_p95_ms,
                "recent_publishes_in_window": adaptive.recent_publishes_in_window,
                "tier2_pending_shards": adaptive.tier2_pending_shards,
                "healthy_cycles": adaptive.healthy_cycles,
            }),
        );
        stats.insert(
            "search_workers".to_owned(),
            json!(self.config.search_workers),
        );
        stats.insert(
            "memory_budget_bytes".to_owned(),
            json!(self.config.memory_budget_bytes),
        );
        let (current_rss_kb, peak_rss_kb) = current_process_memory_kb();
        let (normalized_plan_cache_entries, normalized_plan_cache_bytes) =
            self.normalized_plan_cache_stats();
        let (query_artifact_cache_entries, query_artifact_cache_bytes) =
            self.query_artifact_cache_stats();
        let (query_cache_entries, query_cache_bytes) = self.query_cache_stats();
        stats.insert("current_rss_kb".to_owned(), json!(current_rss_kb));
        stats.insert("peak_rss_kb".to_owned(), json!(peak_rss_kb));
        stats.insert(
            "normalized_plan_cache_entries".to_owned(),
            json!(normalized_plan_cache_entries),
        );
        stats.insert(
            "normalized_plan_cache_bytes".to_owned(),
            json!(normalized_plan_cache_bytes),
        );
        stats.insert(
            "query_artifact_cache_entries".to_owned(),
            json!(query_artifact_cache_entries),
        );
        stats.insert(
            "query_artifact_cache_bytes".to_owned(),
            json!(query_artifact_cache_bytes),
        );
        stats.insert("query_cache_entries".to_owned(), json!(query_cache_entries));
        stats.insert("query_cache_bytes".to_owned(), json!(query_cache_bytes));
        stats.insert(
            "startup_cleanup_removed_roots".to_owned(),
            json!(self.startup_cleanup_removed_roots),
        );

        let index_total_documents = self.index_session_total_documents.load(Ordering::Acquire);
        let index_processed_documents = self
            .index_session_processed_documents
            .load(Ordering::Acquire);
        let index_submitted_documents = self
            .index_session_submitted_documents
            .load(Ordering::Acquire);
        let index_remaining_documents =
            index_total_documents.saturating_sub(index_processed_documents);
        let index_progress_percent = if index_total_documents == 0 {
            0.0
        } else {
            (index_processed_documents as f64 / index_total_documents as f64) * 100.0
        };
        let index_server_insert_batch_profile = self.index_server_insert_batch_profile_json();
        stats.insert(
            "index_session".to_owned(),
            json!({
                "active": self.active_index_sessions.load(Ordering::Acquire) > 0,
                "client_active": self.active_index_clients.load(Ordering::Acquire) > 0,
                "total_documents": index_total_documents,
                "submitted_documents": index_submitted_documents,
                "processed_documents": index_processed_documents,
                "remaining_documents": index_remaining_documents,
                "progress_percent": index_progress_percent,
                "started_unix_ms": self.index_session_started_unix_ms.load(Ordering::Acquire),
                "last_update_unix_ms": self.index_session_last_update_unix_ms.load(Ordering::Acquire),
                "server_insert_batch_profile": index_server_insert_batch_profile,
            }),
        );

        stats.insert(
            "startup".to_owned(),
            json!({
                "total_ms": self.startup_profile.total_ms,
                "startup_cleanup_removed_roots": self.startup_cleanup_removed_roots,
                "current": {
                    "total_ms": self.startup_profile.current.total_ms,
                    "opened_existing_shards": self.startup_profile.current.opened_existing_shards,
                    "initialized_new_shards": self.startup_profile.current.initialized_new_shards,
                    "doc_count": self.startup_profile.current.doc_count,
                },
                "work": {
                    "total_ms": self.startup_profile.work.total_ms,
                    "opened_existing_shards": self.startup_profile.work.opened_existing_shards,
                    "initialized_new_shards": self.startup_profile.work.initialized_new_shards,
                    "doc_count": self.startup_profile.work.doc_count,
                }
            }),
        );

        if let Some((forest_root, tree_count)) = self.forest_mode_info()? {
            stats.insert("workspace_mode".to_owned(), json!(false));
            stats.insert("forest_mode".to_owned(), json!(true));
            stats.insert(
                "forest_root".to_owned(),
                Value::String(forest_root.display().to_string()),
            );
            stats.insert("forest_tree_count".to_owned(), json!(tree_count));
        } else if let Some((published_root, work_root)) = self.workspace_roots()? {
            let retired_root = workspace_retired_root(&self.config.candidate_config.root);
            let (retired_published_root_count, retired_published_disk_usage_bytes) =
                workspace_retired_stats(&retired_root);
            let now_unix_ms = current_unix_ms();
            let readiness = self.publish_readiness(now_unix_ms);
            stats.insert("workspace_mode".to_owned(), json!(true));
            stats.insert(
                "published_root".to_owned(),
                Value::String(published_root.display().to_string()),
            );
            stats.insert(
                "work_root".to_owned(),
                Value::String(work_root.display().to_string()),
            );
            let (mut work_stats, work_deleted_storage_bytes) =
                if let Some(work) = self.work_store_set_if_present()? {
                    if let Some((work_stats, work_deleted_storage_bytes)) = work.cached_stats()? {
                        (work_stats, work_deleted_storage_bytes)
                    } else {
                        (
                            empty_candidate_stats_json_for_config(
                                &self.config,
                                &work_root,
                                self.candidate_shard_count(),
                            ),
                            0,
                        )
                    }
                } else {
                    (
                        empty_candidate_stats_json_for_config(
                            &self.config,
                            &work_root,
                            self.candidate_shard_count(),
                        ),
                        0,
                    )
                };
            work_stats.insert(
                "deleted_storage_bytes".to_owned(),
                json!(work_deleted_storage_bytes),
            );
            stats.insert("work".to_owned(), Value::Object(work_stats));
            let mut publish = Map::new();
            publish.insert(
                "pending".to_owned(),
                json!(self.work_dirty.load(Ordering::Acquire)),
            );
            publish.insert("eligible".to_owned(), json!(readiness.eligible));
            publish.insert(
                "blocked_reason".to_owned(),
                Value::String(readiness.blocked_reason.to_owned()),
            );
            publish.insert(
                "trigger_mode".to_owned(),
                Value::String(readiness.trigger_mode.to_owned()),
            );
            publish.insert(
                "trigger_reason".to_owned(),
                Value::String(readiness.trigger_reason.to_owned()),
            );
            publish.insert(
                "idle_elapsed_ms".to_owned(),
                json!(readiness.idle_elapsed_ms),
            );
            publish.insert(
                "idle_remaining_ms".to_owned(),
                json!(readiness.idle_remaining_ms),
            );
            publish.insert(
                "work_buffer_estimated_documents".to_owned(),
                json!(readiness.work_buffer_estimated_documents),
            );
            publish.insert(
                "work_buffer_estimated_input_bytes".to_owned(),
                json!(readiness.work_buffer_estimated_input_bytes),
            );
            publish.insert(
                "work_buffer_document_threshold".to_owned(),
                json!(readiness.work_buffer_document_threshold),
            );
            publish.insert(
                "work_buffer_input_bytes_threshold".to_owned(),
                json!(readiness.work_buffer_input_bytes_threshold),
            );
            publish.insert(
                "work_buffer_rss_threshold_bytes".to_owned(),
                json!(readiness.work_buffer_rss_threshold_bytes),
            );
            publish.insert(
                "current_rss_bytes".to_owned(),
                json!(readiness.current_rss_bytes),
            );
            publish.insert(
                "pressure_publish_blocked_by_seal_backlog".to_owned(),
                json!(readiness.pending_tier2_snapshot_shards > 0),
            );
            publish.insert(
                "pending_tier2_snapshot_shards".to_owned(),
                json!(readiness.pending_tier2_snapshot_shards),
            );
            publish.insert(
                "index_backpressure_delay_ms".to_owned(),
                json!(readiness.index_backpressure_delay_ms),
            );
            publish.insert(
                "index_backpressure_events_total".to_owned(),
                json!(self.index_backpressure_events_total.load(Ordering::Acquire)),
            );
            publish.insert(
                "index_backpressure_sleep_ms_total".to_owned(),
                json!(self
                    .index_backpressure_sleep_ms_total
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "retired_published_root_count".to_owned(),
                json!(retired_published_root_count),
            );
            publish.insert(
                "retired_published_disk_usage_bytes".to_owned(),
                json!(retired_published_disk_usage_bytes),
            );
            publish.insert(
                "retired_published_roots_to_keep".to_owned(),
                json!(DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP as u64),
            );
            publish.insert(
                "last_publish_started_unix_ms".to_owned(),
                json!(self.last_publish_started_unix_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_completed_unix_ms".to_owned(),
                json!(self.last_publish_completed_unix_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_duration_ms".to_owned(),
                json!(self.last_publish_duration_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_lock_wait_ms".to_owned(),
                json!(self.last_publish_lock_wait_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_swap_ms".to_owned(),
                json!(self.last_publish_swap_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_ms".to_owned(),
                json!(self.last_publish_promote_work_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_export_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_export_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_resolve_doc_state_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_resolve_doc_state_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_build_payloads_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_build_payloads_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_append_sidecars_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_append_sidecars_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_install_docs_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_install_docs_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_tier2_update_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_tier2_update_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_persist_meta_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_persist_meta_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_import_rebalance_tier2_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_import_rebalance_tier2_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_remove_work_root_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_remove_work_root_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_other_ms".to_owned(),
                json!(self
                    .last_publish_promote_work_other_ms
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_imported_docs".to_owned(),
                json!(self
                    .last_publish_promote_work_imported_docs
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_imported_shards".to_owned(),
                json!(self
                    .last_publish_promote_work_imported_shards
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_init_work_ms".to_owned(),
                json!(self.last_publish_init_work_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_tier2_snapshot_persist_failures".to_owned(),
                json!(self
                    .last_publish_tier2_snapshot_persist_failures
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_persisted_snapshot_shards".to_owned(),
                json!(self
                    .last_publish_persisted_snapshot_shards
                    .load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_reused_work_stores".to_owned(),
                json!(self.last_publish_reused_work_stores.load(Ordering::Acquire)),
            );
            publish.insert(
                "publish_runs_total".to_owned(),
                json!(self.publish_runs_total.load(Ordering::Acquire)),
            );
            publish.insert("observed_at_unix_ms".to_owned(), json!(now_unix_ms));
            stats.insert("publish".to_owned(), Value::Object(publish));
            stats.insert(
                "published_tier2_snapshot_seal".to_owned(),
                json!({
                    "pending_shards": self.pending_published_tier2_snapshot_shard_count().unwrap_or(0),
                    "in_progress": self.published_tier2_snapshot_seal_in_progress.load(Ordering::Acquire),
                    "runs_total": self.published_tier2_snapshot_seal_runs_total.load(Ordering::Acquire),
                    "last_duration_ms": self.last_published_tier2_snapshot_seal_duration_ms.load(Ordering::Acquire),
                    "last_persisted_shards": self.last_published_tier2_snapshot_seal_persisted_shards.load(Ordering::Acquire),
                    "last_failures": self.last_published_tier2_snapshot_seal_failures.load(Ordering::Acquire),
                    "last_completed_unix_ms": self.last_published_tier2_snapshot_seal_completed_unix_ms.load(Ordering::Acquire),
                }),
            );
        } else {
            stats.insert("workspace_mode".to_owned(), json!(false));
            stats.insert("forest_mode".to_owned(), json!(false));
        }
        Ok(stats)
    }

    /// Returns the configured candidate shard count, always normalized to at
    /// least one.
    fn candidate_shard_count(&self) -> usize {
        self.config.candidate_shards.max(1)
    }

    /// Returns the raw identity width implied by the configured candidate source.
    pub(crate) fn candidate_identity_bytes_len(&self) -> usize {
        match self.config.candidate_config.id_source.as_str() {
            "md5" => 16,
            "sha1" => 20,
            "sha256" => 32,
            "sha512" => 64,
            _ => 32,
        }
    }

    /// Maps a document hash to its candidate shard index.
    fn candidate_store_index_for_identity(&self, identity: &[u8]) -> usize {
        candidate_shard_index(identity, self.candidate_shard_count())
    }

    /// Merges per-shard tier labels into one user-facing summary label.
    fn merge_candidate_tier_used(values: &[String]) -> String {
        let normalized = values
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<std::collections::HashSet<_>>();
        if normalized.is_empty() {
            "unknown".to_owned()
        } else if normalized.len() == 1 {
            normalized
                .into_iter()
                .next()
                .unwrap_or_else(|| "unknown".to_owned())
        } else {
            "tier1+tier2".to_owned()
        }
    }

    /// Clears the normalized, query-artifact, and query caches after mutations
    /// that can change search results.
    fn invalidate_search_caches(&self) {
        #[cfg(test)]
        if let Ok(mut cache) = self.normalized_plan_cache.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.query_artifact_cache.lock() {
            cache.clear();
        }
        #[cfg(test)]
        if let Ok(mut cache) = self.query_cache.lock() {
            cache.clear();
        }
    }

    /// Selects the next shard index to consider for background compaction.
    fn next_compaction_candidate_shard(&self) -> usize {
        let shard_count = self.candidate_shard_count().max(1);
        self.next_compaction_shard.fetch_add(1, Ordering::Relaxed) % shard_count
    }

    /// Prunes retired generations for one shard in a concrete store set and
    /// refreshes that store set's cached stats when anything was removed.
    fn garbage_collect_retired_generations(
        &self,
        stores: &StoreSet,
        shard_idx: usize,
    ) -> Result<usize> {
        let mut store = stores.stores[shard_idx]
            .lock()
            .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
        let removed = store.garbage_collect_retired_generations()?;
        if removed > 0 {
            let _ = stores.invalidate_stats_cache();
        }
        Ok(removed)
    }

    /// Finds the next published-query shard whose deleted-document snapshot is
    /// worth compacting. In forest mode this scans each tree's shard at the
    /// current shard index before moving to the next shard index.
    fn find_compaction_candidate(
        &self,
        store_sets: &[Arc<StoreSet>],
    ) -> Result<Option<(Arc<StoreSet>, usize, CandidateCompactionSnapshot)>> {
        let shard_count = self.candidate_shard_count().max(1);
        let start = self.next_compaction_candidate_shard();
        for offset in 0..shard_count {
            let shard_idx = (start + offset) % shard_count;
            for stores in store_sets {
                let _ = self.garbage_collect_retired_generations(stores, shard_idx);
                let store = stores.stores[shard_idx]
                    .lock()
                    .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
                if let Some(snapshot) = store.prepare_compaction_snapshot(false)? {
                    self.next_compaction_shard
                        .store((shard_idx + 1) % shard_count, Ordering::Relaxed);
                    return Ok(Some((stores.clone(), shard_idx, snapshot)));
                }
            }
        }
        Ok(None)
    }

    /// Records the latest compaction error in the shared runtime state.
    fn record_compaction_error(&self, message: String) {
        if let Ok(mut runtime) = self.compaction_runtime.lock() {
            runtime.running_shard = None;
            runtime.last_error = Some(message);
        }
    }

    /// Chooses how long the background compaction worker should sleep before
    /// re-checking published shards for newly eligible delete reclamation.
    fn next_compaction_wait_timeout(&self) -> Duration {
        const DEFAULT_WAIT: Duration = Duration::from_secs(30);
        const READY_RETRY_WAIT: Duration = Duration::from_millis(100);

        let Ok(store_sets) = self.published_query_store_sets() else {
            return DEFAULT_WAIT;
        };

        let mut min_wait = None::<Duration>;
        for stores in store_sets {
            for store in &stores.stores {
                let Ok(store) = store.lock() else {
                    return DEFAULT_WAIT;
                };
                let Some(wait) = store.pending_compaction_wait() else {
                    continue;
                };
                if wait.is_zero() {
                    return READY_RETRY_WAIT;
                }
                min_wait = Some(match min_wait {
                    Some(current) => current.min(wait),
                    None => wait,
                });
            }
        }

        min_wait
            .map(|wait| wait.min(DEFAULT_WAIT))
            .unwrap_or(DEFAULT_WAIT)
    }

    /// Runs one background compaction cycle, covering snapshot selection,
    /// snapshot writing, and install/retry bookkeeping.
    fn run_compaction_cycle_once(&self) -> Result<CompactionCycleOutcome> {
        let forest_mode = self.forest_mode_info()?.is_some();
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let store_sets = self.published_query_store_sets()?;
        let Some((stores, shard_idx, snapshot)) = self.find_compaction_candidate(&store_sets)?
        else {
            return Ok(CompactionCycleOutcome::Idle);
        };

        {
            let mut runtime = self
                .compaction_runtime
                .lock()
                .map_err(|_| SspryError::from("Compaction runtime lock poisoned."))?;
            runtime.running_shard = Some(shard_idx);
            runtime.last_error = None;
        }

        let compacted_root = compaction_work_root(
            &candidate_shard_root(&stores.root()?, self.candidate_shard_count(), shard_idx),
            "compact",
        );
        let build_result = write_compacted_snapshot(&snapshot, &compacted_root);
        let apply_result = match build_result {
            Ok(()) => {
                let mut store = stores.stores[shard_idx]
                    .lock()
                    .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
                store.apply_compaction_snapshot(&snapshot, &compacted_root)
            }
            Err(err) => Err(err),
        };

        match apply_result {
            Ok(Some(result)) => {
                let _ = stores.invalidate_stats_cache();
                let source_ref_result = if forest_mode {
                    stores
                        .root()
                        .and_then(|root| build_tree_source_ref(&root).map(|_| ()))
                } else {
                    Ok(())
                };
                let mut runtime = self
                    .compaction_runtime
                    .lock()
                    .map_err(|_| SspryError::from("Compaction runtime lock poisoned."))?;
                runtime.running_shard = None;
                runtime.runs_total = runtime.runs_total.saturating_add(1);
                runtime.last_reclaimed_docs = result.reclaimed_docs;
                runtime.last_reclaimed_bytes = result.reclaimed_bytes;
                runtime.last_completed_unix_ms = Some(current_unix_ms());
                runtime.last_error = source_ref_result
                    .as_ref()
                    .err()
                    .map(|err| err.to_string());
                drop(runtime);
                source_ref_result?;
                Ok(CompactionCycleOutcome::Progress)
            }
            Ok(None) => {
                let _ = fs::remove_dir_all(&compacted_root);
                let mut runtime = self
                    .compaction_runtime
                    .lock()
                    .map_err(|_| SspryError::from("Compaction runtime lock poisoned."))?;
                runtime.running_shard = None;
                runtime.mutation_retries_total = runtime.mutation_retries_total.saturating_add(1);
                Ok(CompactionCycleOutcome::RetryLater)
            }
            Err(err) => {
                let _ = fs::remove_dir_all(&compacted_root);
                self.record_compaction_error(err.to_string());
                Ok(CompactionCycleOutcome::RetryLater)
            }
        }
    }

    #[cfg(test)]
    /// Executes one compaction cycle synchronously so tests can assert on the
    /// immediate post-compaction state.
    fn run_compaction_cycle_for_tests(&self) -> Result<()> {
        let _ = self.run_compaction_cycle_once()?;
        Ok(())
    }

    /// Returns the currently published tree roots when the server is running in
    /// forest mode.
    fn published_forest_tree_roots(&self) -> Result<Option<Vec<PathBuf>>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        match &*mode {
            StoreMode::Forest { trees, .. } => trees
                .iter()
                .map(|stores| stores.root())
                .collect::<Result<Vec<_>>>()
                .map(Some),
            _ => Ok(None),
        }
    }

    /// Returns the currently published tree roots and store sets when the
    /// server is running in forest mode.
    fn published_forest_tree_sets(&self) -> Result<Option<Vec<(PathBuf, Arc<StoreSet>)>>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        match &*mode {
            StoreMode::Forest { trees, .. } => trees
                .iter()
                .map(|stores| Ok((stores.root()?, stores.clone())))
                .collect::<Result<Vec<_>>>()
                .map(Some),
            _ => Ok(None),
        }
    }

    /// Runs one tree-level source-id reference maintenance pass when forest
    /// mode is active and enough new inserts have accumulated since the last
    /// successful build.
    fn run_tree_source_ref_cycle_once(&self, min_new_docs: u64) -> Result<CompactionCycleOutcome> {
        let Some(tree_roots) = self.published_forest_tree_roots()? else {
            return Ok(CompactionCycleOutcome::Idle);
        };
        if self.publish_requested.load(Ordering::Acquire)
            || self.active_index_sessions.load(Ordering::Acquire) > 0
            || self.active_index_clients.load(Ordering::Acquire) > 0
        {
            return Ok(CompactionCycleOutcome::RetryLater);
        }

        let _op = match self.operation_gate.try_write() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Ok(CompactionCycleOutcome::RetryLater),
            Err(TryLockError::Poisoned(_)) => {
                return Err(SspryError::from("Server operation gate lock poisoned."));
            }
        };

        for tree_root in tree_roots {
            if !tree_source_ref_build_due(&tree_root, min_new_docs)? {
                continue;
            }
            let _ = build_tree_source_ref(&tree_root)?;
            return Ok(CompactionCycleOutcome::Progress);
        }
        Ok(CompactionCycleOutcome::Idle)
    }

    #[cfg(test)]
    /// Executes one tree-level source-id reference maintenance pass
    /// synchronously so tests can assert on the published artifact.
    fn run_tree_source_ref_cycle_for_tests(&self, min_new_docs: u64) -> Result<()> {
        let _ = self.run_tree_source_ref_cycle_once(min_new_docs)?;
        Ok(())
    }

    /// Runs one forest-wide source-id deduplication pass when forest mode is
    /// active, tree-level source refs are current, and enough new inserts have
    /// accumulated since the last successful merge checkpoint.
    fn run_forest_source_dedup_cycle_once(
        &self,
        min_new_docs: u64,
    ) -> Result<CompactionCycleOutcome> {
        let Some(tree_sets) = self.published_forest_tree_sets()? else {
            return Ok(CompactionCycleOutcome::Idle);
        };
        if tree_sets.len() < 2 {
            return Ok(CompactionCycleOutcome::Idle);
        }
        if self.publish_requested.load(Ordering::Acquire)
            || self.active_index_sessions.load(Ordering::Acquire) > 0
            || self.active_index_clients.load(Ordering::Acquire) > 0
        {
            return Ok(CompactionCycleOutcome::RetryLater);
        }

        let tree_roots = tree_sets
            .iter()
            .map(|(root, _)| root.clone())
            .collect::<Vec<_>>();
        let _op = match self.operation_gate.try_write() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Ok(CompactionCycleOutcome::RetryLater),
            Err(TryLockError::Poisoned(_)) => {
                return Err(SspryError::from("Server operation gate lock poisoned."));
            }
        };
        if !forest_source_dedup_due(
            &self.config.candidate_config.root,
            &tree_roots,
            min_new_docs,
        )? {
            return Ok(CompactionCycleOutcome::Idle);
        }

        let mut affected_tree_indexes = HashSet::<usize>::new();
        let (duplicate_groups, deleted_docs) =
            for_each_forest_source_ref_duplicate_victim(&tree_roots, |tree_idx, entry| {
                let (_, stores) = &tree_sets[tree_idx];
                let shard_idx = usize::try_from(entry.shard_idx).map_err(|_| {
                    SspryError::from(format!(
                        "forest dedup shard index overflow for tree {}",
                        tree_roots[tree_idx].display()
                    ))
                })?;
                let mut store = lock_candidate_store_with_timeout(
                    &stores.stores[shard_idx],
                    shard_idx,
                    "forest dedup delete",
                )?;
                let result = store
                    .delete_document_by_pointer(entry.doc_id, &hex::encode(&entry.identity))?;
                if result.status != "deleted" {
                    return Err(SspryError::from(format!(
                        "forest dedup stale duplicate pointer at {} shard {} doc_id {}",
                        tree_roots[tree_idx].display(),
                        shard_idx,
                        entry.doc_id
                    )));
                }
                affected_tree_indexes.insert(tree_idx);
                Ok(())
            })?;

        for tree_idx in &affected_tree_indexes {
            let tree_root = &tree_roots[*tree_idx];
            let _ = build_tree_source_ref(tree_root)?;
            let (_, stores) = &tree_sets[*tree_idx];
            stores.invalidate_stats_cache()?;
        }

        let summary: ForestSourceDedupResult = record_forest_source_dedup_pass(
            &self.config.candidate_config.root,
            &tree_roots,
            duplicate_groups,
            deleted_docs,
            affected_tree_indexes.len(),
        )?;
        if summary.deleted_docs > 0 {
            self.invalidate_search_caches();
        }
        Ok(CompactionCycleOutcome::Progress)
    }

    #[cfg(test)]
    /// Executes one forest-wide source-id deduplication pass synchronously so
    /// tests can assert on the resulting deleted documents and rebuilt refs.
    fn run_forest_source_dedup_cycle_for_tests(
        &self,
        min_new_docs: u64,
    ) -> Result<ForestSourceDedupResult> {
        let tree_roots = self
            .published_forest_tree_roots()?
            .ok_or_else(|| SspryError::from("forest mode is unavailable"))?;
        let _ = self.run_forest_source_dedup_cycle_once(min_new_docs)?;
        let manifest = read_forest_source_dedup_manifest(&self.config.candidate_config.root)?
            .ok_or_else(|| SspryError::from("forest source dedup manifest missing"))?;
        Ok(ForestSourceDedupResult {
            duplicate_groups: manifest.last_duplicate_groups,
            deleted_docs: manifest.last_deleted_docs,
            affected_trees: manifest.last_affected_trees,
            total_inserted_docs: manifest.total_inserted_docs,
            tree_count: tree_roots.len(),
            identity_bytes: manifest.identity_bytes,
            id_source: manifest.id_source,
        })
    }

    /// Serializes a compiled query plan into the cache key used by artifact and
    /// cached query results.
    fn query_cache_key(plan: &CompiledQueryPlan) -> Result<String> {
        serde_json::to_string(plan).map_err(SspryError::from)
    }

    /// Builds or reuses runtime query artifacts shared across all shards for
    /// one compiled plan.
    fn shared_runtime_query_artifacts(
        &self,
        plan: &CompiledQueryPlan,
    ) -> Result<Arc<RuntimeQueryArtifacts>> {
        let key = Self::query_cache_key(plan)?;
        if let Some(entry) = self
            .query_artifact_cache
            .lock()
            .map_err(|_| SspryError::from("Query artifact cache lock poisoned."))?
            .get(&key)
        {
            record_counter("rpc.handle_candidate_query_artifact_cache_hits_total", 1);
            return Ok(entry);
        }
        record_counter("rpc.handle_candidate_query_artifact_cache_misses_total", 1);
        let entry = build_runtime_query_artifacts(plan)?;
        let entry_bytes = runtime_query_artifacts_memory_bytes(entry.as_ref());
        if entry_bytes > QUERY_ARTIFACT_CACHE_MAX_ENTRY_BYTES {
            record_counter(
                "rpc.handle_candidate_query_artifact_cache_skipped_oversize_total",
                1,
            );
            return Ok(entry);
        }
        let mut cache = self
            .query_artifact_cache
            .lock()
            .map_err(|_| SspryError::from("Query artifact cache lock poisoned."))?;
        cache.insert(key, entry.clone());
        Ok(entry)
    }

    /// Collects candidate hashes from one store using prebuilt runtime-query artifacts
    /// and an uncapped internal max-candidates setting.
    fn collect_query_matches_single_store(
        store: &mut CandidateStore,
        plan: &CompiledQueryPlan,
        runtime: &RuntimeQueryArtifacts,
    ) -> Result<(Vec<String>, Vec<String>, CandidateQueryProfile)> {
        let mut scan_plan = plan.clone();
        scan_plan.max_candidates = 0.0;
        let (hits, tier_used, query_profile) =
            store.collect_query_hits_with_runtime_hash(&scan_plan, runtime)?;
        Ok((hits, vec![tier_used], query_profile))
    }

    /// Enumerates the concrete search work units for one request. Direct and
    /// workspace modes produce one unit per shard; forest mode produces one unit
    /// per `(tree, shard)` pair.
    fn search_work_units(store_sets: &[Arc<StoreSet>]) -> Vec<SearchWorkUnit> {
        let mut work_units = Vec::new();
        for (store_set_idx, stores) in store_sets.iter().enumerate() {
            for store_idx in 0..stores.stores.len() {
                work_units.push(SearchWorkUnit {
                    store_set_idx,
                    store_idx,
                });
            }
        }
        work_units
    }

    /// Collects one streamed query against a single shard/tree work unit while
    /// preserving the hit ordering for frame emission.
    fn collect_stream_query_matches_store(
        stores: &Arc<StoreSet>,
        work_unit: SearchWorkUnit,
        plan: &CompiledQueryPlan,
        runtime: &RuntimeQueryArtifacts,
        include_external_ids: bool,
        plan_key: Option<&str>,
    ) -> Result<StreamStoreQueryResult> {
        let store_lock = stores
            .stores
            .get(work_unit.store_idx)
            .ok_or_else(|| SspryError::from("Candidate store shard is not initialized."))?;
        let mut store = lock_candidate_store_blocking(store_lock)?;
        let store_started = Instant::now();
        let (local_hits, local_tiers, local_profile) =
            Self::collect_query_matches_single_store(&mut store, plan, runtime)?;
        if let Some(plan_key) = plan_key {
            search_trace_log(format!(
                "stream.store.done plan_key={} store_set_idx={} store_idx={} hits={} tier_used={:?} docs_scanned={} tier1_loads={} tier2_loads={} elapsed_ms={}",
                plan_key,
                work_unit.store_set_idx,
                work_unit.store_idx,
                local_hits.len(),
                local_tiers,
                local_profile.docs_scanned,
                local_profile.tier1_bloom_loads,
                local_profile.tier2_bloom_loads,
                store_started.elapsed().as_millis()
            ));
        }
        let external_ids = if include_external_ids {
            Some(store.external_ids_for_identities(&local_hits))
        } else {
            None
        };
        drop(store);
        Ok((
            work_unit,
            (local_hits, external_ids),
            local_tiers,
            local_profile,
        ))
    }

    /// Collects one bundled search pass against a single shard/tree work unit
    /// and returns one accumulator per rule.
    fn collect_stream_query_matches_store_batch(
        stores: &Arc<StoreSet>,
        work_unit: SearchWorkUnit,
        plans: &[CompiledQueryPlan],
        runtime: &[Arc<RuntimeQueryArtifacts>],
        include_external_ids: bool,
    ) -> Result<BundledStoreQueryResult> {
        let mut partials = (0..plans.len())
            .map(|_| BundledQueryPartial::default())
            .collect::<Vec<_>>();
        let store_lock = stores
            .stores
            .get(work_unit.store_idx)
            .ok_or_else(|| SspryError::from("Candidate store shard is not initialized."))?;
        let mut store = lock_candidate_store_blocking(store_lock)?;
        for (index, (hits, tier_used, query_profile, eval_nanos)) in store
            .collect_query_hits_with_runtime_hash_batch(plans, runtime)?
            .into_iter()
            .enumerate()
        {
            let Some(partial) = partials.get_mut(index) else {
                continue;
            };
            partial.external_ids =
                include_external_ids.then(|| store.external_ids_for_identities(&hits));
            partial.hashes = hits;
            partial.tier_used = tier_used;
            partial.query_profile = query_profile;
            partial.eval_nanos = eval_nanos;
        }
        drop(store);
        Ok((work_unit, partials))
    }

    #[cfg(test)]
    /// Evaluates a compiled plan across all published shards, applies
    /// truncation, and returns the cached-query shape used by tests.
    fn collect_query_matches_all_shards(
        &self,
        plan: &CompiledQueryPlan,
    ) -> Result<CachedCandidateQuery> {
        let runtime = self.shared_runtime_query_artifacts(plan)?;
        let store_sets = self.published_query_store_sets()?;
        let searchable_doc_count = store_sets
            .iter()
            .flat_map(|stores| stores.stores.iter())
            .map(|store_lock| {
                let store = lock_candidate_store_blocking(store_lock)?;
                Ok::<usize, SspryError>(store.live_doc_count())
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .sum::<usize>();
        let resolved_limit = resolve_max_candidates(searchable_doc_count, plan.max_candidates);
        if store_sets.len() == 1 && self.candidate_shard_count() == 1 {
            let mut store = lock_candidate_store_blocking(&store_sets[0].stores[0])?;
            let (hits, tier_used, query_profile) =
                Self::collect_query_matches_single_store(&mut store, plan, &runtime)?;
            let mut ordered_hashes = hits;
            let truncated = resolved_limit != usize::MAX && ordered_hashes.len() > resolved_limit;
            if truncated {
                ordered_hashes.truncate(resolved_limit);
            }
            return Ok(CachedCandidateQuery {
                ordered_hashes,
                truncated,
                truncated_limit: truncated.then_some(resolved_limit),
                tier_used: Self::merge_candidate_tier_used(&tier_used),
                query_profile,
            });
        }

        let work_units = Self::search_work_units(&store_sets);
        let worker_count = resolve_search_workers(self.config.search_workers, work_units.len());

        if worker_count <= 1 {
            let mut hits = HashSet::<String>::new();
            let mut tier_used = Vec::<String>::new();
            let mut query_profile = CandidateQueryProfile::default();
            for work_unit in &work_units {
                let (_, (local_hits, _), local_tiers, local_profile) =
                    Self::collect_stream_query_matches_store(
                        &store_sets[work_unit.store_set_idx],
                        *work_unit,
                        plan,
                        runtime.as_ref(),
                        false,
                        None,
                    )?;
                hits.extend(local_hits);
                tier_used.extend(local_tiers);
                query_profile.merge_from(&local_profile);
            }
            let mut ordered_hashes = hits.into_iter().collect::<Vec<_>>();
            let truncated = resolved_limit != usize::MAX && ordered_hashes.len() > resolved_limit;
            if truncated {
                ordered_hashes.truncate(resolved_limit);
            }
            return Ok(CachedCandidateQuery {
                ordered_hashes,
                truncated,
                truncated_limit: truncated.then_some(resolved_limit),
                tier_used: Self::merge_candidate_tier_used(&tier_used),
                query_profile,
            });
        }

        let next_unit = AtomicUsize::new(0);
        let partials = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let store_sets = &store_sets;
                let work_units = &work_units;
                let plan = plan;
                let runtime = runtime.clone();
                let next_unit = &next_unit;
                handles.push(scope.spawn(
                    move || -> Result<(HashSet<String>, Vec<String>, CandidateQueryProfile)> {
                        let mut local_hits = HashSet::<String>::new();
                        let mut local_tiers = Vec::<String>::new();
                        let mut local_profile = CandidateQueryProfile::default();
                        loop {
                            let work_idx = next_unit.fetch_add(1, Ordering::Relaxed);
                            if work_idx >= work_units.len() {
                                break;
                            }
                            let work_unit = work_units[work_idx];
                            let (_, (hits, _), tiers, profile) =
                                Self::collect_stream_query_matches_store(
                                    &store_sets[work_unit.store_set_idx],
                                    work_unit,
                                    plan,
                                    runtime.as_ref(),
                                    false,
                                    None,
                                )?;
                            local_hits.extend(hits);
                            local_tiers.extend(tiers);
                            local_profile.merge_from(&profile);
                        }
                        Ok((local_hits, local_tiers, local_profile))
                    },
                ));
            }

            let mut merged = Vec::with_capacity(handles.len());
            for handle in handles {
                let partial = handle
                    .join()
                    .map_err(|_| SspryError::from("Candidate query worker panicked."))??;
                merged.push(partial);
            }
            Ok::<Vec<(HashSet<String>, Vec<String>, CandidateQueryProfile)>, SspryError>(merged)
        })?;

        let mut hits = HashSet::<String>::new();
        let mut tier_used = Vec::<String>::new();
        let mut query_profile = CandidateQueryProfile::default();
        for (local_hits, local_tiers, local_profile) in partials {
            hits.extend(local_hits);
            tier_used.extend(local_tiers);
            query_profile.merge_from(&local_profile);
        }
        let mut ordered_hashes = hits.into_iter().collect::<Vec<_>>();
        let truncated = resolved_limit != usize::MAX && ordered_hashes.len() > resolved_limit;
        if truncated {
            ordered_hashes.truncate(resolved_limit);
        }
        Ok(CachedCandidateQuery {
            ordered_hashes,
            truncated,
            truncated_limit: truncated.then_some(resolved_limit),
            tier_used: Self::merge_candidate_tier_used(&tier_used),
            query_profile,
        })
    }

    #[cfg(test)]
    /// Decodes one wire-format insert row into validated typed payloads for the
    /// test-only direct insert helpers.
    fn parse_candidate_insert_document(
        &self,
        document: &CandidateDocumentWire,
        field_prefix: &str,
    ) -> Result<ParsedCandidateInsertDocument> {
        let identity =
            decode_identity(&document.identity, &self.config.candidate_config.id_source)?;
        let bloom_filter = base64::engine::general_purpose::STANDARD
            .decode(document.bloom_filter_b64.as_bytes())
            .map_err(|_| {
                SspryError::from(format!(
                    "{field_prefix}.bloom_filter_b64 must be valid base64."
                ))
            })?;
        let tier2_bloom_filter = if let Some(payload) = &document.tier2_bloom_filter_b64 {
            base64::engine::general_purpose::STANDARD
                .decode(payload.as_bytes())
                .map_err(|_| {
                    SspryError::from(format!(
                        "{field_prefix}.tier2_bloom_filter_b64 must be valid base64."
                    ))
                })?
        } else {
            Vec::new()
        };
        let bloom_item_estimate = document
            .bloom_item_estimate
            .map(|value| {
                if value < 0 {
                    Err(SspryError::from(format!(
                        "{field_prefix}.bloom_item_estimate must be >= 0."
                    )))
                } else {
                    Ok(value as usize)
                }
            })
            .transpose()?;
        let metadata = if let Some(payload) = &document.metadata_b64 {
            base64::engine::general_purpose::STANDARD
                .decode(payload.as_bytes())
                .map_err(|_| {
                    SspryError::from(format!("{field_prefix}.metadata_b64 must be valid base64."))
                })?
        } else {
            Vec::new()
        };
        let tier2_bloom_item_estimate = document
            .tier2_bloom_item_estimate
            .map(|value| {
                if value < 0 {
                    Err(SspryError::from(format!(
                        "{field_prefix}.tier2_bloom_item_estimate must be >= 0."
                    )))
                } else {
                    Ok(value as usize)
                }
            })
            .transpose()?;
        Ok((
            identity,
            document.file_size,
            bloom_item_estimate,
            bloom_filter,
            tier2_bloom_item_estimate,
            tier2_bloom_filter,
            document.special_population,
            metadata,
            document.external_id.clone(),
        ))
    }

    /// Converts one store-level insert result into the RPC response shape.
    fn candidate_insert_response(
        result: crate::candidate::CandidateInsertResult,
    ) -> CandidateInsertResponse {
        CandidateInsertResponse {
            status: result.status,
            doc_id: result.doc_id,
            identity: result.identity,
        }
    }

    #[cfg(test)]
    /// Inserts one already-parsed test document, updating workspace/search
    /// bookkeeping just like the public insert path.
    fn handle_candidate_insert_parsed(
        &self,
        parsed: ParsedCandidateInsertDocument,
    ) -> Result<CandidateInsertResponse> {
        self.maybe_apply_index_backpressure(1, parsed.1);
        let _mutation = self.begin_mutation("insert")?;
        let _op = if self.mutation_affects_published_queries()? {
            Some(
                self.operation_gate
                    .read()
                    .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?,
            )
        } else {
            None
        };
        let shard_idx = self.candidate_store_index_for_identity(&parsed.0);
        let work = self.work_store_set()?;
        let mut store =
            lock_candidate_store_with_timeout(&work.stores[shard_idx], shard_idx, "insert")?;
        let result = store.insert_document_with_metadata(
            parsed.0,
            parsed.1,
            parsed.2,
            None,
            parsed.4,
            None,
            parsed.3.len(),
            &parsed.3,
            parsed.5.len(),
            &parsed.5,
            parsed.7.as_slice(),
            parsed.6,
            parsed.8,
        )?;
        drop(store);
        self.mark_work_mutation();
        self.record_work_buffer_growth(1, parsed.1);
        if self.mutation_affects_published_queries()? {
            self.invalidate_search_caches();
        }
        self.record_index_session_insert_progress(1);
        Ok(Self::candidate_insert_response(result))
    }

    #[cfg(test)]
    /// Parses and inserts one candidate document through the test-only direct
    /// helper path.
    fn handle_candidate_insert(
        &self,
        document: &CandidateDocumentWire,
    ) -> Result<CandidateInsertResponse> {
        let _scope = scope("rpc.handle_candidate_insert");
        let parsed = self.parse_candidate_insert_document(document, "request.payload")?;
        self.handle_candidate_insert_parsed(parsed)
    }

    /// Executes a parsed insert batch across the appropriate shards, recording
    /// batch profiling and workspace mutation bookkeeping.
    fn handle_candidate_insert_batch_parsed(
        &self,
        parsed_documents: Vec<ParsedCandidateInsertDocument>,
        batch_input_bytes: u64,
        parse_elapsed: Duration,
    ) -> Result<CandidateInsertBatchResponse> {
        let _scope = scope("rpc.handle_candidate_insert_batch");
        let document_count = parsed_documents.len();
        self.maybe_apply_index_backpressure(document_count, batch_input_bytes);
        let _mutation = self.begin_mutation("insert batch")?;
        let _op = if self.mutation_affects_published_queries()? {
            Some(
                self.operation_gate
                    .read()
                    .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?,
            )
        } else {
            None
        };
        let started_total = Instant::now();
        let mut group_elapsed = Duration::ZERO;
        let mut build_elapsed = Duration::ZERO;
        let mut store_elapsed = Duration::ZERO;
        let mut store_profile_total = CandidateInsertBatchProfile::default();
        let shards_touched;

        let mut results = vec![None; parsed_documents.len()];
        let work = self.work_store_set()?;
        if self.candidate_shard_count() == 1 {
            shards_touched = usize::from(!parsed_documents.is_empty());
            let mut store = lock_candidate_store_with_timeout(&work.stores[0], 0, "insert batch")?;
            let started_build = Instant::now();
            let batch = parsed_documents
                .iter()
                .map(|row| {
                    (
                        row.0.clone(),
                        row.1,
                        row.2,
                        None,
                        row.4,
                        None,
                        row.3.len(),
                        row.3.clone(),
                        row.5.len(),
                        row.5.clone(),
                        row.7.clone(),
                        row.6,
                        row.8.clone(),
                    )
                })
                .collect::<Vec<_>>();
            build_elapsed += started_build.elapsed();
            let started_store = Instant::now();
            for (idx, result) in store
                .insert_documents_batch(&batch)?
                .into_iter()
                .enumerate()
            {
                results[idx] = Some(Self::candidate_insert_response(result));
            }
            let store_profile = store.last_insert_batch_profile();
            store_profile_total.resolve_doc_state_us = store_profile_total
                .resolve_doc_state_us
                .saturating_add(store_profile.resolve_doc_state_us);
            store_profile_total.append_sidecars_us = store_profile_total
                .append_sidecars_us
                .saturating_add(store_profile.append_sidecars_us);
            store_profile_total.append_sidecar_payloads_us = store_profile_total
                .append_sidecar_payloads_us
                .saturating_add(store_profile.append_sidecar_payloads_us);
            store_profile_total.append_bloom_payload_assemble_us = store_profile_total
                .append_bloom_payload_assemble_us
                .saturating_add(store_profile.append_bloom_payload_assemble_us);
            store_profile_total.append_bloom_payload_us = store_profile_total
                .append_bloom_payload_us
                .saturating_add(store_profile.append_bloom_payload_us);
            store_profile_total.append_metadata_payload_us = store_profile_total
                .append_metadata_payload_us
                .saturating_add(store_profile.append_metadata_payload_us);
            store_profile_total.append_external_id_payload_us = store_profile_total
                .append_external_id_payload_us
                .saturating_add(store_profile.append_external_id_payload_us);
            store_profile_total.append_tier2_bloom_payload_us = store_profile_total
                .append_tier2_bloom_payload_us
                .saturating_add(store_profile.append_tier2_bloom_payload_us);
            store_profile_total.append_doc_row_build_us = store_profile_total
                .append_doc_row_build_us
                .saturating_add(store_profile.append_doc_row_build_us);
            store_profile_total.append_bloom_payload_bytes = store_profile_total
                .append_bloom_payload_bytes
                .saturating_add(store_profile.append_bloom_payload_bytes);
            store_profile_total.append_metadata_payload_bytes = store_profile_total
                .append_metadata_payload_bytes
                .saturating_add(store_profile.append_metadata_payload_bytes);
            store_profile_total.append_external_id_payload_bytes = store_profile_total
                .append_external_id_payload_bytes
                .saturating_add(store_profile.append_external_id_payload_bytes);
            store_profile_total.append_tier2_bloom_payload_bytes = store_profile_total
                .append_tier2_bloom_payload_bytes
                .saturating_add(store_profile.append_tier2_bloom_payload_bytes);
            store_profile_total.append_doc_records_us = store_profile_total
                .append_doc_records_us
                .saturating_add(store_profile.append_doc_records_us);
            store_profile_total.write_existing_us = store_profile_total
                .write_existing_us
                .saturating_add(store_profile.write_existing_us);
            store_profile_total.install_docs_us = store_profile_total
                .install_docs_us
                .saturating_add(store_profile.install_docs_us);
            store_profile_total.tier2_update_us = store_profile_total
                .tier2_update_us
                .saturating_add(store_profile.tier2_update_us);
            store_profile_total.persist_meta_us = store_profile_total
                .persist_meta_us
                .saturating_add(store_profile.persist_meta_us);
            store_profile_total.rebalance_tier2_us = store_profile_total
                .rebalance_tier2_us
                .saturating_add(store_profile.rebalance_tier2_us);
            store_elapsed += started_store.elapsed();
        } else {
            let started_group = Instant::now();
            let mut grouped = HashMap::<usize, Vec<(usize, ParsedCandidateInsertDocument)>>::new();
            for (idx, row) in parsed_documents.into_iter().enumerate() {
                let shard_idx = self.candidate_store_index_for_identity(&row.0);
                grouped.entry(shard_idx).or_default().push((idx, row));
            }
            group_elapsed = started_group.elapsed();
            shards_touched = grouped.len();
            for (shard_idx, rows) in grouped {
                let mut store = lock_candidate_store_with_timeout(
                    &work.stores[shard_idx],
                    shard_idx,
                    "insert batch",
                )?;
                let started_build = Instant::now();
                let batch = rows
                    .iter()
                    .map(|(_, row)| {
                        (
                            row.0.clone(),
                            row.1,
                            row.2,
                            None,
                            row.4,
                            None,
                            row.3.len(),
                            row.3.clone(),
                            row.5.len(),
                            row.5.clone(),
                            row.7.clone(),
                            row.6,
                            row.8.clone(),
                        )
                    })
                    .collect::<Vec<_>>();
                build_elapsed += started_build.elapsed();
                let started_store = Instant::now();
                for ((original_idx, _), result) in rows
                    .into_iter()
                    .zip(store.insert_documents_batch(&batch)?.into_iter())
                {
                    results[original_idx] = Some(Self::candidate_insert_response(result));
                }
                let store_profile = store.last_insert_batch_profile();
                store_profile_total.resolve_doc_state_us = store_profile_total
                    .resolve_doc_state_us
                    .saturating_add(store_profile.resolve_doc_state_us);
                store_profile_total.append_sidecars_us = store_profile_total
                    .append_sidecars_us
                    .saturating_add(store_profile.append_sidecars_us);
                store_profile_total.append_sidecar_payloads_us = store_profile_total
                    .append_sidecar_payloads_us
                    .saturating_add(store_profile.append_sidecar_payloads_us);
                store_profile_total.append_bloom_payload_assemble_us = store_profile_total
                    .append_bloom_payload_assemble_us
                    .saturating_add(store_profile.append_bloom_payload_assemble_us);
                store_profile_total.append_bloom_payload_us = store_profile_total
                    .append_bloom_payload_us
                    .saturating_add(store_profile.append_bloom_payload_us);
                store_profile_total.append_metadata_payload_us = store_profile_total
                    .append_metadata_payload_us
                    .saturating_add(store_profile.append_metadata_payload_us);
                store_profile_total.append_external_id_payload_us = store_profile_total
                    .append_external_id_payload_us
                    .saturating_add(store_profile.append_external_id_payload_us);
                store_profile_total.append_tier2_bloom_payload_us = store_profile_total
                    .append_tier2_bloom_payload_us
                    .saturating_add(store_profile.append_tier2_bloom_payload_us);
                store_profile_total.append_doc_row_build_us = store_profile_total
                    .append_doc_row_build_us
                    .saturating_add(store_profile.append_doc_row_build_us);
                store_profile_total.append_bloom_payload_bytes = store_profile_total
                    .append_bloom_payload_bytes
                    .saturating_add(store_profile.append_bloom_payload_bytes);
                store_profile_total.append_metadata_payload_bytes = store_profile_total
                    .append_metadata_payload_bytes
                    .saturating_add(store_profile.append_metadata_payload_bytes);
                store_profile_total.append_external_id_payload_bytes = store_profile_total
                    .append_external_id_payload_bytes
                    .saturating_add(store_profile.append_external_id_payload_bytes);
                store_profile_total.append_tier2_bloom_payload_bytes = store_profile_total
                    .append_tier2_bloom_payload_bytes
                    .saturating_add(store_profile.append_tier2_bloom_payload_bytes);
                store_profile_total.append_doc_records_us = store_profile_total
                    .append_doc_records_us
                    .saturating_add(store_profile.append_doc_records_us);
                store_profile_total.write_existing_us = store_profile_total
                    .write_existing_us
                    .saturating_add(store_profile.write_existing_us);
                store_profile_total.install_docs_us = store_profile_total
                    .install_docs_us
                    .saturating_add(store_profile.install_docs_us);
                store_profile_total.tier2_update_us = store_profile_total
                    .tier2_update_us
                    .saturating_add(store_profile.tier2_update_us);
                store_profile_total.persist_meta_us = store_profile_total
                    .persist_meta_us
                    .saturating_add(store_profile.persist_meta_us);
                store_profile_total.rebalance_tier2_us = store_profile_total
                    .rebalance_tier2_us
                    .saturating_add(store_profile.rebalance_tier2_us);
                store_elapsed += started_store.elapsed();
            }
        }
        let started_finalize = Instant::now();
        let results = results.into_iter().flatten().collect::<Vec<_>>();
        if !results.is_empty() {
            self.mark_work_mutation();
            self.record_work_buffer_growth(results.len() as u64, batch_input_bytes);
        }
        if self.mutation_affects_published_queries()? {
            self.invalidate_search_caches();
        }
        self.record_index_session_insert_progress(results.len());
        let finalize_elapsed = started_finalize.elapsed();
        self.record_index_session_insert_batch_profile(
            document_count,
            shards_touched,
            started_total.elapsed(),
            parse_elapsed,
            group_elapsed,
            build_elapsed,
            store_elapsed,
            finalize_elapsed,
            &store_profile_total,
        );
        Ok(CandidateInsertBatchResponse {
            inserted_count: results.len(),
            results,
        })
    }

    #[cfg(test)]
    /// Parses and inserts a batch of test documents through the shared
    /// batch-insert implementation.
    fn handle_candidate_insert_batch(
        &self,
        documents: &[CandidateDocumentWire],
    ) -> Result<CandidateInsertBatchResponse> {
        let batch_input_bytes = documents
            .iter()
            .map(|document| document.file_size)
            .sum::<u64>();
        let started_parse = Instant::now();
        let mut parsed_documents = Vec::with_capacity(documents.len());
        for (idx, document) in documents.iter().enumerate() {
            parsed_documents.push(self.parse_candidate_insert_document(
                document,
                &format!("request.payload.documents[{idx}]"),
            )?);
        }
        self.handle_candidate_insert_batch_parsed(
            parsed_documents,
            batch_input_bytes,
            started_parse.elapsed(),
        )
    }

    /// Deletes one document from the published shard set and invalidates
    /// related search/stat caches.
    fn handle_candidate_delete(&self, identity: &str) -> Result<CandidateDeleteResponse> {
        let _scope = scope("rpc.handle_candidate_delete");
        let _mutation = self.begin_mutation("delete")?;
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let decoded = decode_identity(identity, &self.config.candidate_config.id_source)?;
        let shard_idx = self.candidate_store_index_for_identity(&decoded);
        let published = self.published_store_set()?;
        let mut published_store = lock_candidate_store_with_timeout(
            &published.stores[shard_idx],
            shard_idx,
            "delete published",
        )?;
        let published_result = published_store.delete_document(identity)?;
        drop(published_store);
        if published_result.status == "deleted" {
            let _ = self.enqueue_published_tier2_snapshot_shards([shard_idx]);
            self.notify_maintenance_workers();
        }

        if published_result.status == "deleted" {
            let _ = self.invalidate_published_stats_cache();
        }
        self.invalidate_search_caches();
        Ok(CandidateDeleteResponse {
            status: published_result.status,
            identity: published_result.identity,
            doc_id: published_result.doc_id,
        })
    }

    #[cfg(test)]
    /// Runs the test-only direct candidate query path with caching, cursoring,
    /// and chunking behavior that matches the public RPC shape.
    fn handle_candidate_query(
        &self,
        request: CandidateQueryRequest,
        plan: &CompiledQueryPlan,
    ) -> Result<CandidateQueryResponse> {
        let _scope = scope("rpc.handle_candidate_query");
        let _search = self.begin_search_request()?;
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let chunk_size = request
            .chunk_size
            .unwrap_or(DEFAULT_CANDIDATE_QUERY_CHUNK_SIZE)
            .max(1);
        let cache_key = Self::query_cache_key(plan)?;
        let cached = {
            let mut cache = self
                .query_cache
                .lock()
                .map_err(|_| SspryError::from("Query cache lock poisoned."))?;
            cache.get(&cache_key)
        };
        let cached = if let Some(entry) = cached {
            record_counter("rpc.handle_candidate_query_cache_hits_total", 1);
            entry
        } else {
            record_counter("rpc.handle_candidate_query_cache_misses_total", 1);
            let entry = Arc::new(self.collect_query_matches_all_shards(plan)?);
            let mut cache = self
                .query_cache
                .lock()
                .map_err(|_| SspryError::from("Query cache lock poisoned."))?;
            cache.insert(cache_key, entry.clone());
            entry
        };

        let total_candidates = cached.ordered_hashes.len();
        let start = request.cursor.min(total_candidates);
        let end = (start + chunk_size).min(total_candidates);
        let page = cached.ordered_hashes[start..end].to_vec();
        let next_cursor = if end < total_candidates {
            Some(end)
        } else {
            None
        };
        record_counter(
            "rpc.handle_candidate_query_total_candidates",
            total_candidates as u64,
        );
        let external_ids = if request.include_external_ids {
            let mut values = vec![None; page.len()];
            let mut by_shard = HashMap::<usize, Vec<(usize, String)>>::new();
            let query_store_sets = self.published_query_store_sets()?;
            for (idx, identity_hex) in page.iter().enumerate() {
                let decoded =
                    decode_identity(identity_hex, &self.config.candidate_config.id_source)?;
                let shard_idx = self.candidate_store_index_for_identity(&decoded);
                by_shard
                    .entry(shard_idx)
                    .or_default()
                    .push((idx, identity_hex.clone()));
            }
            for stores in query_store_sets {
                for (shard_idx, items) in &by_shard {
                    let Some(store_lock) = stores.stores.get(*shard_idx) else {
                        continue;
                    };
                    let store = lock_candidate_store_with_timeout(
                        store_lock,
                        *shard_idx,
                        "query external ids",
                    )?;
                    let hashes = items
                        .iter()
                        .map(|(_, value)| value.clone())
                        .collect::<Vec<_>>();
                    for ((idx, _), external_id) in items
                        .iter()
                        .cloned()
                        .zip(store.external_ids_for_identities(&hashes))
                    {
                        if values[idx].is_none() && external_id.is_some() {
                            values[idx] = external_id;
                        }
                    }
                }
            }
            Some(values)
        } else {
            None
        };
        let _ = self.invalidate_published_stats_cache();
        Ok(CandidateQueryResponse {
            returned_count: page.len(),
            identities: page,
            total_candidates,
            cursor: start,
            next_cursor,
            truncated: cached.truncated,
            truncated_limit: cached.truncated_limit,
            tier_used: cached.tier_used.clone(),
            query_profile: cached.query_profile.clone(),
            external_ids,
        })
    }

    /// Streams a paginated candidate query response frame-by-frame, optionally
    /// attaching external ids.
    fn stream_candidate_query_frames<F>(
        &self,
        request: CandidateQueryRequest,
        plan: &CompiledQueryPlan,
        mut on_frame: F,
    ) -> Result<()>
    where
        F: FnMut(CandidateQueryStreamFrame) -> Result<()>,
    {
        let _scope = scope("rpc.stream_candidate_query");
        let _search = self.begin_search_request()?;
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let trace_enabled = search_trace_enabled();
        let plan_key = if trace_enabled {
            Some(Self::query_cache_key(plan)?)
        } else {
            None
        };
        let stream_started = Instant::now();
        let chunk_size = request
            .chunk_size
            .unwrap_or(DEFAULT_CANDIDATE_QUERY_CHUNK_SIZE)
            .max(1);
        if let Some(plan_key) = plan_key.as_deref() {
            search_trace_log(format!(
                "stream.begin plan_key={} chunk_size={} include_external_ids={} max_candidates={} root={:?}",
                plan_key, chunk_size, request.include_external_ids, plan.max_candidates, plan.root
            ));
        }
        let artifacts_started = Instant::now();
        let runtime = self.shared_runtime_query_artifacts(plan)?;
        if let Some(plan_key) = plan_key.as_deref() {
            search_trace_log(format!(
                "stream.runtime plan_key={} elapsed_ms={} runtime_bytes={}",
                plan_key,
                artifacts_started.elapsed().as_millis(),
                runtime_query_artifacts_memory_bytes(runtime.as_ref())
            ));
        }
        let store_sets = self.published_query_store_sets()?;
        let searchable_doc_count = if plan.max_candidates.is_finite() && plan.max_candidates > 0.0 {
            Some(
                store_sets
                    .iter()
                    .flat_map(|stores| stores.stores.iter())
                    .map(|store_lock| {
                        let store = lock_candidate_store_blocking(store_lock)?;
                        Ok::<usize, SspryError>(store.live_doc_count())
                    })
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .sum::<usize>(),
            )
        } else {
            None
        };
        let candidate_limit =
            searchable_doc_count.and_then(|doc_count| {
                match resolve_max_candidates(doc_count, plan.max_candidates) {
                    usize::MAX => None,
                    value => Some(value),
                }
            });
        if let Some(plan_key) = plan_key.as_deref() {
            search_trace_log(format!(
                "stream.scope plan_key={} store_sets={} searchable_doc_count={:?} candidate_limit={:?}",
                plan_key,
                store_sets.len(),
                searchable_doc_count,
                candidate_limit
            ));
        }

        if let Some(plan_key) = plan_key.as_deref() {
            for (store_set_idx, stores) in store_sets.iter().enumerate() {
                search_trace_log(format!(
                    "stream.store_set.begin plan_key={} idx={} root={}",
                    plan_key,
                    store_set_idx,
                    stores.root()?.display()
                ));
            }
        }
        let work_units = Self::search_work_units(&store_sets);
        let worker_count = resolve_search_workers(self.config.search_workers, work_units.len());
        let mut partials = if work_units.len() <= 1 || worker_count <= 1 {
            let mut partials = Vec::with_capacity(work_units.len());
            for work_unit in &work_units {
                partials.push(Self::collect_stream_query_matches_store(
                    &store_sets[work_unit.store_set_idx],
                    *work_unit,
                    plan,
                    runtime.as_ref(),
                    request.include_external_ids,
                    plan_key.as_deref(),
                )?);
            }
            partials
        } else {
            let next_unit = AtomicUsize::new(0);
            let plan_key = plan_key.as_deref();
            let include_external_ids = request.include_external_ids;
            let partials = thread::scope(|scope| {
                let mut handles = Vec::with_capacity(worker_count);
                for _ in 0..worker_count {
                    let store_sets = &store_sets;
                    let work_units = &work_units;
                    let plan = plan;
                    let runtime = runtime.clone();
                    let next_unit = &next_unit;
                    handles.push(scope.spawn(move || -> Result<Vec<StreamStoreQueryResult>> {
                        let mut local = Vec::new();
                        loop {
                            let work_idx = next_unit.fetch_add(1, Ordering::Relaxed);
                            if work_idx >= work_units.len() {
                                break;
                            }
                            let work_unit = work_units[work_idx];
                            local.push(Self::collect_stream_query_matches_store(
                                &store_sets[work_unit.store_set_idx],
                                work_unit,
                                plan,
                                runtime.as_ref(),
                                include_external_ids,
                                plan_key,
                            )?);
                        }
                        Ok(local)
                    }));
                }

                let mut merged = Vec::new();
                for handle in handles {
                    let partial = handle
                        .join()
                        .map_err(|_| SspryError::from("Candidate query worker panicked."))??;
                    merged.extend(partial);
                }
                Ok::<Vec<StreamStoreQueryResult>, SspryError>(merged)
            })?;
            partials
        };
        partials.sort_by_key(|(work_unit, _, _, _)| *work_unit);

        let mut tier_used = Vec::<String>::new();
        let mut query_profile = CandidateQueryProfile::default();
        for (_, (hits, external_ids), local_tiers, local_profile) in partials {
            tier_used.extend(local_tiers);
            query_profile.merge_from(&local_profile);
            if hits.is_empty() {
                continue;
            }

            match external_ids {
                Some(values) => {
                    for (hash_chunk, external_id_chunk) in
                        hits.chunks(chunk_size).zip(values.chunks(chunk_size))
                    {
                        on_frame(CandidateQueryStreamFrame {
                            identities: hash_chunk.to_vec(),
                            external_ids: Some(external_id_chunk.to_vec()),
                            candidate_limit,
                            stream_complete: false,
                            rule_complete: false,
                            target_rule_name: String::new(),
                            tier_used: String::new(),
                            query_profile: CandidateQueryProfile::default(),
                            query_eval_nanos: 0,
                        })?;
                    }
                }
                None => {
                    for hash_chunk in hits.chunks(chunk_size) {
                        on_frame(CandidateQueryStreamFrame {
                            identities: hash_chunk.to_vec(),
                            external_ids: None,
                            candidate_limit,
                            stream_complete: false,
                            rule_complete: false,
                            target_rule_name: String::new(),
                            tier_used: String::new(),
                            query_profile: CandidateQueryProfile::default(),
                            query_eval_nanos: 0,
                        })?;
                    }
                }
            }
        }

        on_frame(CandidateQueryStreamFrame {
            identities: Vec::new(),
            external_ids: None,
            candidate_limit,
            stream_complete: true,
            rule_complete: false,
            target_rule_name: String::new(),
            tier_used: Self::merge_candidate_tier_used(&tier_used),
            query_profile,
            query_eval_nanos: 0,
        })?;
        if let Some(plan_key) = plan_key.as_deref() {
            search_trace_log(format!(
                "stream.end plan_key={} total_ms={}",
                plan_key,
                stream_started.elapsed().as_millis()
            ));
        }
        Ok(())
    }

    /// Emits one bundled work-unit result immediately while folding its
    /// terminal query counters into the per-rule totals used for rule-complete
    /// frames.
    fn emit_stream_candidate_query_frames_batch_partial<F>(
        partial: BundledStoreQueryResult,
        named_plans: &[(String, CompiledQueryPlan)],
        chunk_size: usize,
        candidate_limits: &[Option<usize>],
        accumulators: &mut [BundledQueryAccumulator],
        mut on_frame: F,
    ) -> Result<()>
    where
        F: FnMut(CandidateQueryStreamFrame) -> Result<()>,
    {
        let (_, local_partials) = partial;
        for (index, local) in local_partials.into_iter().enumerate() {
            let Some((rule_name, _)) = named_plans.get(index) else {
                continue;
            };
            let Some(accumulator) = accumulators.get_mut(index) else {
                continue;
            };
            accumulator.merge_from_partial(&local);

            match local.external_ids {
                Some(values) => {
                    for (hash_chunk, external_id_chunk) in local
                        .hashes
                        .chunks(chunk_size)
                        .zip(values.chunks(chunk_size))
                    {
                        on_frame(CandidateQueryStreamFrame {
                            identities: hash_chunk.to_vec(),
                            external_ids: Some(external_id_chunk.to_vec()),
                            candidate_limit: candidate_limits[index],
                            stream_complete: false,
                            rule_complete: false,
                            target_rule_name: rule_name.clone(),
                            tier_used: String::new(),
                            query_profile: CandidateQueryProfile::default(),
                            query_eval_nanos: 0,
                        })?;
                    }
                }
                None => {
                    for hash_chunk in local.hashes.chunks(chunk_size) {
                        on_frame(CandidateQueryStreamFrame {
                            identities: hash_chunk.to_vec(),
                            external_ids: None,
                            candidate_limit: candidate_limits[index],
                            stream_complete: false,
                            rule_complete: false,
                            target_rule_name: rule_name.clone(),
                            tier_used: String::new(),
                            query_profile: CandidateQueryProfile::default(),
                            query_eval_nanos: 0,
                        })?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Streams one bundled search response by evaluating every named plan in a
    /// shared pass over each shard and grouping the streamed output by rule.
    fn stream_candidate_query_frames_batch<F>(
        &self,
        request: CandidateQueryRequest,
        named_plans: &[(String, CompiledQueryPlan)],
        mut on_frame: F,
    ) -> Result<()>
    where
        F: FnMut(CandidateQueryStreamFrame) -> Result<()>,
    {
        let _scope = scope("rpc.stream_candidate_query_batch");
        let _search = self.begin_search_request()?;
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let chunk_size = request
            .chunk_size
            .unwrap_or(DEFAULT_CANDIDATE_QUERY_CHUNK_SIZE)
            .max(1);
        let plans = named_plans
            .iter()
            .map(|(_, plan)| plan.clone())
            .collect::<Vec<_>>();
        let runtime = plans
            .iter()
            .map(|plan| self.shared_runtime_query_artifacts(plan))
            .collect::<Result<Vec<_>>>()?;
        let store_sets = self.published_query_store_sets()?;
        let searchable_doc_count = if plans
            .iter()
            .any(|plan| plan.max_candidates.is_finite() && plan.max_candidates > 0.0)
        {
            Some(
                store_sets
                    .iter()
                    .flat_map(|stores| stores.stores.iter())
                    .map(|store_lock| {
                        let store = lock_candidate_store_blocking(store_lock)?;
                        Ok::<usize, SspryError>(store.live_doc_count())
                    })
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .sum::<usize>(),
            )
        } else {
            None
        };
        let candidate_limits = plans
            .iter()
            .map(|plan| {
                searchable_doc_count.and_then(|doc_count| {
                    match resolve_max_candidates(doc_count, plan.max_candidates) {
                        usize::MAX => None,
                        value => Some(value),
                    }
                })
            })
            .collect::<Vec<_>>();
        let mut accumulators = (0..named_plans.len())
            .map(|_| BundledQueryAccumulator::default())
            .collect::<Vec<_>>();
        let work_units = Self::search_work_units(&store_sets);
        let worker_count = resolve_search_workers(self.config.search_workers, work_units.len());
        if work_units.len() <= 1 || worker_count <= 1 {
            for work_unit in &work_units {
                Self::emit_stream_candidate_query_frames_batch_partial(
                    Self::collect_stream_query_matches_store_batch(
                        &store_sets[work_unit.store_set_idx],
                        *work_unit,
                        &plans,
                        &runtime,
                        request.include_external_ids,
                    )?,
                    named_plans,
                    chunk_size,
                    &candidate_limits,
                    &mut accumulators,
                    &mut on_frame,
                )?;
            }
        } else {
            let next_unit = AtomicUsize::new(0);
            let include_external_ids = request.include_external_ids;
            let aborted = AtomicBool::new(false);
            thread::scope(|scope| -> Result<()> {
                let (tx, rx) = std::sync::mpsc::channel::<Result<BundledStoreQueryResult>>();
                let mut handles = Vec::with_capacity(worker_count);
                for _ in 0..worker_count {
                    let store_sets = &store_sets;
                    let work_units = &work_units;
                    let plans = &plans;
                    let runtime = runtime.clone();
                    let next_unit = &next_unit;
                    let aborted = &aborted;
                    let tx = tx.clone();
                    handles.push(scope.spawn(move || -> Result<()> {
                        loop {
                            if aborted.load(Ordering::Relaxed) {
                                break;
                            }
                            let work_idx = next_unit.fetch_add(1, Ordering::Relaxed);
                            if work_idx >= work_units.len() {
                                break;
                            }
                            let work_unit = work_units[work_idx];
                            let partial = Self::collect_stream_query_matches_store_batch(
                                &store_sets[work_unit.store_set_idx],
                                work_unit,
                                plans,
                                &runtime,
                                include_external_ids,
                            );
                            if partial.is_err() {
                                aborted.store(true, Ordering::Relaxed);
                            }
                            if tx.send(partial).is_err() {
                                break;
                            }
                        }
                        Ok(())
                    }));
                }
                drop(tx);

                let mut first_error = None;
                for partial in rx {
                    match partial {
                        Ok(partial) => {
                            if first_error.is_some() {
                                continue;
                            }
                            Self::emit_stream_candidate_query_frames_batch_partial(
                                partial,
                                named_plans,
                                chunk_size,
                                &candidate_limits,
                                &mut accumulators,
                                &mut on_frame,
                            )?;
                        }
                        Err(err) => {
                            aborted.store(true, Ordering::Relaxed);
                            if first_error.is_none() {
                                first_error = Some(err);
                            }
                        }
                    }
                }

                for handle in handles {
                    handle.join().map_err(|_| {
                        SspryError::from("Bundled candidate query worker panicked.")
                    })??;
                }

                if let Some(err) = first_error {
                    return Err(err);
                }
                Ok(())
            })?;
        }

        for (index, (rule_name, _)) in named_plans.iter().enumerate() {
            let Some(accumulator) = accumulators.get_mut(index) else {
                continue;
            };
            on_frame(CandidateQueryStreamFrame {
                identities: Vec::new(),
                external_ids: None,
                candidate_limit: candidate_limits[index],
                stream_complete: false,
                rule_complete: true,
                target_rule_name: rule_name.clone(),
                tier_used: Self::merge_candidate_tier_used(&accumulator.tier_used),
                query_profile: accumulator.query_profile.clone(),
                query_eval_nanos: accumulator.eval_nanos,
            })?;
        }

        on_frame(CandidateQueryStreamFrame {
            identities: Vec::new(),
            external_ids: None,
            candidate_limit: None,
            stream_complete: true,
            rule_complete: false,
            target_rule_name: String::new(),
            tier_used: String::new(),
            query_profile: CandidateQueryProfile::default(),
            query_eval_nanos: 0,
        })?;
        Ok(())
    }

    /// Publishes workspace work roots into the published view while pausing
    /// mutations and recording detailed publish telemetry.
    fn handle_publish(&self) -> Result<CandidatePublishResponse> {
        if self
            .publish_requested
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SspryError::from(
                "server is already publishing; retry later",
            ));
        }
        self.mutations_paused.store(true, Ordering::SeqCst);
        self.notify_maintenance_workers();
        while self.active_mutations.load(Ordering::Acquire) > 0 {
            thread::sleep(Duration::from_millis(10));
        }
        self.publish_in_progress.store(true, Ordering::SeqCst);
        let result = (|| -> Result<CandidatePublishResponse> {
            let publish_lock_wait_started = Instant::now();
            self.last_publish_lock_wait_ms.store(0, Ordering::SeqCst);
            self.last_publish_promote_work_ms.store(0, Ordering::SeqCst);
            self.last_publish_promote_work_export_ms
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_import_ms
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_remove_work_root_ms
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_other_ms
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_imported_docs
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_imported_shards
                .store(0, Ordering::SeqCst);
            self.last_publish_tier2_snapshot_persist_failures
                .store(0, Ordering::SeqCst);
            self.last_publish_persisted_snapshot_shards
                .store(0, Ordering::SeqCst);
            let _op = self
                .operation_gate
                .write()
                .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
            self.last_publish_lock_wait_ms.store(
                publish_lock_wait_started
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
            let publish_started_unix_ms = current_unix_ms();
            self.last_publish_started_unix_ms
                .store(publish_started_unix_ms, Ordering::SeqCst);
            let (
                workspace_root,
                current_root,
                retired_parent,
                publish_work,
                publish_work_root,
                next_work_root,
                published_store_set,
                published_is_empty,
            ) = {
                let mut store_mode = self
                    .store_mode
                    .lock()
                    .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
                let workspace_root = match &*store_mode {
                    StoreMode::Direct { .. } => {
                        return Err(SspryError::from(
                            "publish is only available for workspace stores",
                        ));
                    }
                    StoreMode::Forest { .. } => {
                        return Err(SspryError::from(
                            "publish is not available for forest-root servers",
                        ));
                    }
                    StoreMode::Workspace { root, .. } => root.clone(),
                };
                let current_root = workspace_current_root(&workspace_root);
                let retired_parent = workspace_retired_root(&workspace_root);
                let published_store_set = match &*store_mode {
                    StoreMode::Workspace { published, .. } => published.clone(),
                    StoreMode::Direct { .. } | StoreMode::Forest { .. } => {
                        unreachable!("workspace already checked")
                    }
                };
                let published_is_empty = published_store_set.stores.iter().all(|store_lock| {
                    store_lock
                        .lock()
                        .map(|store| store.stats().doc_count == 0)
                        .unwrap_or(false)
                });
                let (publish_work, publish_work_root, next_work_root) = match &mut *store_mode {
                    StoreMode::Workspace {
                        root, work_active, ..
                    } => {
                        let publish_work = work_active.take();
                        let publish_work_root = publish_work
                            .as_ref()
                            .map(|stores| stores.root())
                            .transpose()?;
                        let next_work_root =
                            if self.active_index_sessions.load(Ordering::Acquire) > 0 {
                                Some(match publish_work_root.as_deref() {
                                    Some(active_root) => {
                                        alternate_workspace_work_root(root, active_root)
                                    }
                                    None => preferred_workspace_work_root(root),
                                })
                            } else {
                                None
                            };
                        (publish_work, publish_work_root, next_work_root)
                    }
                    StoreMode::Direct { .. } | StoreMode::Forest { .. } => {
                        unreachable!("workspace already checked")
                    }
                };
                (
                    workspace_root,
                    current_root,
                    retired_parent,
                    publish_work,
                    publish_work_root,
                    next_work_root,
                    published_store_set,
                    published_is_empty,
                )
            };
            self.work_dirty.store(false, Ordering::SeqCst);
            self.reset_work_buffer_estimates();
            self.last_work_mutation_unix_ms.store(0, Ordering::SeqCst);
            self.mutations_paused.store(false, Ordering::SeqCst);
            let publish_shard_count = self.candidate_shard_count();
            let removed_current = 0usize;
            let mut removed_work = 0usize;
            let mut reuse_work_stores = false;
            let mut changed_shards = vec![false; publish_shard_count];
            let published_store_set = if let Some(publish_work) = publish_work {
                let publish_work_root = publish_work_root
                    .ok_or_else(|| SspryError::from("active work root is unavailable"))?;
                if published_is_empty {
                    let swap_started = Instant::now();
                    if current_root.exists() {
                        fs::create_dir_all(&retired_parent)?;
                        let retired_root = next_workspace_retired_root_path(&retired_parent);
                        fs::rename(&current_root, &retired_root)?;
                    }
                    fs::rename(&publish_work_root, &current_root)?;
                    self.last_publish_swap_ms.store(
                        swap_started
                            .elapsed()
                            .as_millis()
                            .try_into()
                            .unwrap_or(u64::MAX),
                        Ordering::SeqCst,
                    );
                    let promote_started = Instant::now();
                    self.last_publish_promote_work_export_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_import_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_import_resolve_doc_state_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_import_build_payloads_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_import_append_sidecars_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_import_install_docs_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_import_tier2_update_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_import_persist_meta_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_import_rebalance_tier2_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_remove_work_root_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_other_ms
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_imported_docs
                        .store(0, Ordering::SeqCst);
                    self.last_publish_promote_work_imported_shards
                        .store(0, Ordering::SeqCst);
                    publish_work.retarget_root(&current_root, publish_shard_count)?;
                    reuse_work_stores = true;
                    let published_store_set = publish_work;
                    self.last_publish_promote_work_ms.store(
                        promote_started
                            .elapsed()
                            .as_millis()
                            .try_into()
                            .unwrap_or(u64::MAX),
                        Ordering::SeqCst,
                    );
                    for (shard_idx, store_lock) in published_store_set.stores.iter().enumerate() {
                        let store = store_lock
                            .lock()
                            .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
                        if store.stats().doc_count > 0 {
                            changed_shards[shard_idx] = true;
                        }
                    }
                    published_store_set
                } else {
                    self.last_publish_swap_ms.store(0, Ordering::SeqCst);
                    let promote_started = Instant::now();
                    let mut export_ms_total = 0u128;
                    let mut import_ms_total = 0u128;
                    let mut import_profile_total = CandidateImportBatchProfile::default();
                    let mut imported_docs_total = 0u64;
                    let mut imported_shards_total = 0u64;
                    for (shard_idx, store_lock) in publish_work.stores.iter().enumerate() {
                        let mut work_store = lock_candidate_store_with_timeout(
                            store_lock,
                            shard_idx,
                            "publish export work",
                        )?;
                        let export_started = Instant::now();
                        let imported = work_store.export_live_documents()?;
                        export_ms_total =
                            export_ms_total.saturating_add(export_started.elapsed().as_millis());
                        if imported.is_empty() {
                            continue;
                        }
                        changed_shards[shard_idx] = true;
                        imported_docs_total =
                            imported_docs_total.saturating_add(imported.len() as u64);
                        imported_shards_total = imported_shards_total.saturating_add(1);
                        let import_started = Instant::now();
                        let mut published_store = published_store_set.stores[shard_idx]
                            .lock()
                            .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
                        let all_known_new = imported.iter().all(|document| {
                            !published_store.contains_live_document_identity(&document.identity)
                        });
                        if all_known_new {
                            published_store.import_documents_batch_known_new_quiet(&imported)?
                        } else {
                            published_store.import_documents_batch_quiet(&imported)?
                        }
                        let import_profile = published_store.last_import_batch_profile();
                        import_profile_total.resolve_doc_state_ms = import_profile_total
                            .resolve_doc_state_ms
                            .saturating_add(import_profile.resolve_doc_state_ms);
                        import_profile_total.build_payloads_ms = import_profile_total
                            .build_payloads_ms
                            .saturating_add(import_profile.build_payloads_ms);
                        import_profile_total.append_sidecars_ms = import_profile_total
                            .append_sidecars_ms
                            .saturating_add(import_profile.append_sidecars_ms);
                        import_profile_total.install_docs_ms = import_profile_total
                            .install_docs_ms
                            .saturating_add(import_profile.install_docs_ms);
                        import_profile_total.tier2_update_ms = import_profile_total
                            .tier2_update_ms
                            .saturating_add(import_profile.tier2_update_ms);
                        import_profile_total.persist_meta_ms = import_profile_total
                            .persist_meta_ms
                            .saturating_add(import_profile.persist_meta_ms);
                        import_profile_total.rebalance_tier2_ms = import_profile_total
                            .rebalance_tier2_ms
                            .saturating_add(import_profile.rebalance_tier2_ms);
                        import_ms_total =
                            import_ms_total.saturating_add(import_started.elapsed().as_millis());
                    }
                    let remove_started = Instant::now();
                    if publish_work_root.exists() {
                        fs::remove_dir_all(&publish_work_root)?;
                    }
                    let remove_ms = remove_started.elapsed().as_millis();
                    let promote_ms = promote_started.elapsed().as_millis();
                    self.last_publish_promote_work_ms
                        .store(promote_ms.try_into().unwrap_or(u64::MAX), Ordering::SeqCst);
                    self.last_publish_promote_work_export_ms.store(
                        export_ms_total.try_into().unwrap_or(u64::MAX),
                        Ordering::SeqCst,
                    );
                    self.last_publish_promote_work_import_ms.store(
                        import_ms_total.try_into().unwrap_or(u64::MAX),
                        Ordering::SeqCst,
                    );
                    self.last_publish_promote_work_import_resolve_doc_state_ms
                        .store(import_profile_total.resolve_doc_state_ms, Ordering::SeqCst);
                    self.last_publish_promote_work_import_build_payloads_ms
                        .store(import_profile_total.build_payloads_ms, Ordering::SeqCst);
                    self.last_publish_promote_work_import_append_sidecars_ms
                        .store(import_profile_total.append_sidecars_ms, Ordering::SeqCst);
                    self.last_publish_promote_work_import_install_docs_ms
                        .store(import_profile_total.install_docs_ms, Ordering::SeqCst);
                    self.last_publish_promote_work_import_tier2_update_ms
                        .store(import_profile_total.tier2_update_ms, Ordering::SeqCst);
                    self.last_publish_promote_work_import_persist_meta_ms
                        .store(import_profile_total.persist_meta_ms, Ordering::SeqCst);
                    self.last_publish_promote_work_import_rebalance_tier2_ms
                        .store(import_profile_total.rebalance_tier2_ms, Ordering::SeqCst);
                    self.last_publish_promote_work_remove_work_root_ms
                        .store(remove_ms.try_into().unwrap_or(u64::MAX), Ordering::SeqCst);
                    self.last_publish_promote_work_other_ms.store(
                        promote_ms
                            .saturating_sub(export_ms_total)
                            .saturating_sub(import_ms_total)
                            .saturating_sub(remove_ms)
                            .try_into()
                            .unwrap_or(0),
                        Ordering::SeqCst,
                    );
                    self.last_publish_promote_work_imported_docs
                        .store(imported_docs_total, Ordering::SeqCst);
                    self.last_publish_promote_work_imported_shards
                        .store(imported_shards_total, Ordering::SeqCst);
                    published_store_set
                }
            } else {
                self.last_publish_swap_ms.store(0, Ordering::SeqCst);
                self.last_publish_promote_work_ms.store(0, Ordering::SeqCst);
                published_store_set
            };
            let persisted_snapshot_shards =
                changed_shards.iter().filter(|changed| **changed).count();
            self.last_publish_persisted_snapshot_shards.store(
                persisted_snapshot_shards.try_into().unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );

            let persist_tier2_started = Instant::now();
            self.enqueue_published_tier2_snapshot_shards(
                changed_shards
                    .iter()
                    .enumerate()
                    .filter_map(|(shard_idx, changed)| changed.then_some(shard_idx)),
            )?;
            let _persist_tier2_elapsed = persist_tier2_started.elapsed();
            self.last_publish_tier2_snapshot_persist_failures
                .store(0, Ordering::SeqCst);

            let removed_retired_roots = prune_workspace_retired_roots(
                &retired_parent,
                DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP,
            )?;
            self.last_publish_reused_work_stores
                .store(reuse_work_stores, Ordering::SeqCst);

            let next_work_active = if let Some(next_work_root) = next_work_root {
                let init_work_started = Instant::now();
                let (next_work_stores, removed, _) =
                    ensure_candidate_stores_at_root(&self.config, &next_work_root)?;
                removed_work = removed;
                self.last_publish_init_work_ms.store(
                    init_work_started
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
                    Ordering::SeqCst,
                );
                Some(Arc::new(StoreSet::new(next_work_root, next_work_stores)))
            } else {
                self.last_publish_init_work_ms.store(0, Ordering::SeqCst);
                None
            };
            {
                let mut store_mode = self
                    .store_mode
                    .lock()
                    .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
                match &mut *store_mode {
                    StoreMode::Workspace {
                        root,
                        published,
                        work_active,
                        ..
                    } => {
                        *root = workspace_root.clone();
                        *published = published_store_set;
                        *work_active = next_work_active;
                    }
                    StoreMode::Direct { .. } | StoreMode::Forest { .. } => {
                        unreachable!("workspace already checked")
                    }
                }
            }
            if self.active_index_sessions.load(Ordering::Acquire) == 0 {
                self.index_session_total_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_submitted_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_processed_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_started_unix_ms
                    .store(0, Ordering::SeqCst);
                self.index_session_last_update_unix_ms
                    .store(0, Ordering::SeqCst);
            }
            let publish_completed_unix_ms = current_unix_ms();
            self.last_publish_completed_unix_ms
                .store(publish_completed_unix_ms, Ordering::SeqCst);
            self.last_publish_duration_ms.store(
                publish_completed_unix_ms.saturating_sub(publish_started_unix_ms),
                Ordering::SeqCst,
            );
            self.publish_runs_total.fetch_add(1, Ordering::SeqCst);
            self.publish_after_index_clients
                .store(false, Ordering::SeqCst);
            let _ = self.update_adaptive_publish_from_publish(publish_completed_unix_ms);
            self.invalidate_search_caches();
            Ok(CandidatePublishResponse {
                message: format!(
                    "published work root to {} (startup cleanup removed {}, retired cleanup removed {})",
                    current_root.display(),
                    removed_current.saturating_add(removed_work),
                    removed_retired_roots,
                ),
            })
        })();
        self.publish_in_progress.store(false, Ordering::SeqCst);
        self.mutations_paused.store(false, Ordering::SeqCst);
        self.publish_requested.store(false, Ordering::SeqCst);
        self.notify_maintenance_workers();
        result
    }
}
