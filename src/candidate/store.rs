use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use memmap2::{Mmap, MmapOptions};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::candidate::bloom::{
    DEFAULT_BLOOM_POSITION_LANES, bloom_word_masks_in_lane, raw_filter_matches_word_masks,
};
use crate::candidate::cache::BoundedCache;
use crate::candidate::filter_policy::{
    choose_filter_bytes_for_file_size, derive_document_bloom_hash_count,
};
use crate::candidate::grams::{
    DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes, pack_exact_gram,
};
use crate::candidate::query_plan::{CompiledQueryPlan, PatternPlan, QueryNode};
use crate::candidate::{
    MetadataCompareOp, PE_ENTRY_POINT_PREFIX_BYTES, metadata_field_matches_compare,
    metadata_field_matches_compare_f32, metadata_fields_compare, metadata_file_prefix_8,
    metadata_pe_entry_point_prefix,
};
use crate::perf::{record_counter, record_max, scope};
use crate::{Result, SspryError};

const STORE_VERSION: u32 = 2;
const DEFAULT_FILTER_BYTES: usize = 2048;
const DEFAULT_BLOOM_HASHES: usize = 7;
const DEFAULT_FILTER_MIN_BYTES: usize = 1;
const DEFAULT_FILTER_MAX_BYTES: usize = 0;
pub const DEFAULT_TIER1_FILTER_TARGET_FP: f64 = 0.38;
pub const DEFAULT_TIER2_FILTER_TARGET_FP: f64 = 0.18;
const DEFAULT_COMPACTION_IDLE_COOLDOWN_S: f64 = 5.0;
const QUERY_ARTIFACT_CACHE_CAPACITY: usize = 32;

#[derive(Clone, Debug)]
pub struct CandidateConfig {
    pub root: PathBuf,
    pub id_source: String,
    pub store_path: bool,
    pub tier2_gram_size: usize,
    pub tier1_gram_size: usize,
    pub tier1_filter_target_fp: Option<f64>,
    pub tier2_filter_target_fp: Option<f64>,
    pub filter_target_fp: Option<f64>,
    pub compaction_idle_cooldown_s: f64,
    pub source_dedup_min_new_docs: u64,
}

impl Default for CandidateConfig {
    /// Returns the default on-disk store configuration used by CLI and server
    /// initialization.
    fn default() -> Self {
        Self {
            root: PathBuf::from("candidate_db"),
            id_source: "sha256".to_owned(),
            store_path: false,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
            tier1_filter_target_fp: Some(DEFAULT_TIER1_FILTER_TARGET_FP),
            tier2_filter_target_fp: Some(DEFAULT_TIER2_FILTER_TARGET_FP),
            filter_target_fp: None,
            compaction_idle_cooldown_s: DEFAULT_COMPACTION_IDLE_COOLDOWN_S,
            source_dedup_min_new_docs: 1_000,
        }
    }
}

impl CandidateConfig {
    /// Resolves the effective tier-1 false-positive target, falling back to the
    /// shared `filter_target_fp` when set.
    pub fn resolved_tier1_filter_target_fp(&self) -> Option<f64> {
        self.tier1_filter_target_fp.or(self.filter_target_fp)
    }

    /// Resolves the effective tier-2 false-positive target, falling back to the
    /// shared `filter_target_fp` when set.
    pub fn resolved_tier2_filter_target_fp(&self) -> Option<f64> {
        self.tier2_filter_target_fp.or(self.filter_target_fp)
    }
}

#[derive(Clone, Debug)]
pub struct CandidateInsertResult {
    pub status: String,
    pub doc_id: u64,
    pub identity: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CandidateInsertBatchProfile {
    pub resolve_doc_state_us: u64,
    pub append_sidecars_us: u64,
    pub append_sidecar_payloads_us: u64,
    pub append_bloom_payload_assemble_us: u64,
    pub append_bloom_payload_us: u64,
    pub append_metadata_payload_us: u64,
    pub append_external_id_payload_us: u64,
    pub append_tier2_bloom_payload_us: u64,
    pub append_doc_row_build_us: u64,
    pub append_bloom_payload_bytes: u64,
    pub append_metadata_payload_bytes: u64,
    pub append_external_id_payload_bytes: u64,
    pub append_tier2_bloom_payload_bytes: u64,
    pub append_doc_records_us: u64,
    pub write_existing_us: u64,
    pub install_docs_us: u64,
    pub tier2_update_us: u64,
    pub persist_meta_us: u64,
    pub rebalance_tier2_us: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CandidateImportBatchProfile {
    pub resolve_doc_state_ms: u64,
    pub build_payloads_ms: u64,
    pub append_sidecars_ms: u64,
    pub append_sidecar_payloads_ms: u64,
    pub append_doc_records_ms: u64,
    pub install_docs_ms: u64,
    pub tier2_update_ms: u64,
    pub persist_meta_ms: u64,
    pub rebalance_tier2_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CandidateDocRowPayloadProfile {
    bloom_us: u64,
    metadata_us: u64,
    external_id_us: u64,
    tier2_bloom_us: u64,
    bloom_bytes: u64,
    metadata_bytes: u64,
    external_id_bytes: u64,
    tier2_bloom_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct CandidateDeleteResult {
    pub status: String,
    pub identity: String,
    pub doc_id: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct CandidateStoreOpenProfile {
    pub doc_count: usize,
    pub manifest_ms: u64,
    pub meta_ms: u64,
    pub load_state_ms: u64,
    pub sidecars_ms: u64,
    pub rebuild_indexes_ms: u64,
    pub rebuild_identity_index_ms: u64,
    pub total_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CandidateStoreRebuildProfile {
    identity_index_ms: u64,
    total_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ImportedCandidateDocument {
    pub identity: Vec<u8>,
    pub identity_hex: String,
    pub file_size: u64,
    pub filter_bytes: usize,
    pub bloom_hashes: usize,
    pub tier2_filter_bytes: usize,
    pub tier2_bloom_hashes: usize,
    pub bloom_filter: Vec<u8>,
    pub tier2_bloom_filter: Vec<u8>,
    pub special_population: bool,
    pub metadata_bytes: Vec<u8>,
    pub external_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CandidateQueryResult {
    pub identities: Vec<String>,
    pub total_candidates: usize,
    pub returned_count: usize,
    pub cursor: usize,
    pub next_cursor: Option<usize>,
    pub truncated: bool,
    pub truncated_limit: Option<usize>,
    pub tier_used: String,
    pub query_profile: CandidateQueryProfile,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CandidateQueryProfile {
    pub docs_scanned: u64,
    pub metadata_loads: u64,
    pub metadata_bytes: u64,
    pub tier1_bloom_loads: u64,
    pub tier1_bloom_bytes: u64,
    pub tier2_bloom_loads: u64,
    pub tier2_bloom_bytes: u64,
}

impl CandidateQueryProfile {
    /// Adds another query profile into this one using saturating counters.
    pub(crate) fn merge_from(&mut self, other: &Self) {
        self.docs_scanned = self.docs_scanned.saturating_add(other.docs_scanned);
        self.metadata_loads = self.metadata_loads.saturating_add(other.metadata_loads);
        self.metadata_bytes = self.metadata_bytes.saturating_add(other.metadata_bytes);
        self.tier1_bloom_loads = self
            .tier1_bloom_loads
            .saturating_add(other.tier1_bloom_loads);
        self.tier1_bloom_bytes = self
            .tier1_bloom_bytes
            .saturating_add(other.tier1_bloom_bytes);
        self.tier2_bloom_loads = self
            .tier2_bloom_loads
            .saturating_add(other.tier2_bloom_loads);
        self.tier2_bloom_bytes = self
            .tier2_bloom_bytes
            .saturating_add(other.tier2_bloom_bytes);
    }

    /// Returns the saturating counter delta between two profile snapshots.
    pub(crate) fn delta_since(&self, earlier: &Self) -> Self {
        Self {
            docs_scanned: self.docs_scanned.saturating_sub(earlier.docs_scanned),
            metadata_loads: self.metadata_loads.saturating_sub(earlier.metadata_loads),
            metadata_bytes: self.metadata_bytes.saturating_sub(earlier.metadata_bytes),
            tier1_bloom_loads: self
                .tier1_bloom_loads
                .saturating_sub(earlier.tier1_bloom_loads),
            tier1_bloom_bytes: self
                .tier1_bloom_bytes
                .saturating_sub(earlier.tier1_bloom_bytes),
            tier2_bloom_loads: self
                .tier2_bloom_loads
                .saturating_sub(earlier.tier2_bloom_loads),
            tier2_bloom_bytes: self
                .tier2_bloom_bytes
                .saturating_sub(earlier.tier2_bloom_bytes),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CandidateStats {
    pub doc_count: usize,
    pub deleted_doc_count: usize,
    pub id_source: String,
    pub store_path: bool,
    pub tier1_filter_target_fp: Option<f64>,
    pub tier2_filter_target_fp: Option<f64>,
    pub tier2_gram_size: usize,
    pub tier1_gram_size: usize,
    pub compaction_idle_cooldown_s: f64,
    pub source_dedup_min_new_docs: u64,
    pub compaction_cooldown_remaining_s: f64,
    pub compaction_waiting_for_cooldown: bool,
    pub compaction_generation: u64,
    pub retired_generation_count: usize,
    pub query_count: u64,
    pub tier2_scanned_docs_total: u64,
    pub tier2_docs_matched_total: u64,
    pub tier2_match_ratio: f64,
    pub docs_vector_bytes: u64,
    pub doc_rows_bytes: u64,
    pub tier2_doc_rows_bytes: u64,
    pub identity_index_bytes: u64,
    pub special_doc_positions_bytes: u64,
    pub query_artifact_cache_entries: usize,
    pub query_artifact_cache_bytes: u64,
    pub mapped_bloom_bytes: u64,
    pub mapped_tier2_bloom_bytes: u64,
    pub mapped_metadata_bytes: u64,
    pub mapped_external_id_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct ForestMeta {
    version: u32,
    id_source: String,
    store_path: bool,
    tier2_gram_size: usize,
    tier1_gram_size: usize,
    tier1_filter_target_fp: Option<f64>,
    tier2_filter_target_fp: Option<f64>,
    compaction_idle_cooldown_s: f64,
    source_dedup_min_new_docs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct StoreLocalMeta {
    version: u32,
    next_doc_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct LegacyStoreMeta {
    version: u32,
    next_doc_id: u64,
    id_source: String,
    store_path: bool,
    tier2_gram_size: usize,
    tier1_gram_size: usize,
    tier1_filter_target_fp: Option<f64>,
    tier2_filter_target_fp: Option<f64>,
    filter_target_fp: Option<f64>,
    compaction_idle_cooldown_s: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct ShardCompactionManifest {
    current_generation: u64,
    retired_roots: Vec<String>,
}

impl Default for ShardCompactionManifest {
    /// Returns the initial compaction manifest with generation one and no
    /// retired roots.
    fn default() -> Self {
        Self {
            current_generation: 1,
            retired_roots: Vec::new(),
        }
    }
}

impl Default for ForestMeta {
    /// Returns the forest-wide metadata defaults for a freshly initialized
    /// store.
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            id_source: "sha256".to_owned(),
            store_path: false,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
            tier1_filter_target_fp: Some(DEFAULT_TIER1_FILTER_TARGET_FP),
            tier2_filter_target_fp: Some(DEFAULT_TIER2_FILTER_TARGET_FP),
            compaction_idle_cooldown_s: DEFAULT_COMPACTION_IDLE_COOLDOWN_S,
            source_dedup_min_new_docs: 1_000,
        }
    }
}

impl Default for StoreLocalMeta {
    /// Returns the local per-root metadata defaults for a freshly initialized
    /// store.
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            next_doc_id: 1,
        }
    }
}

impl Default for LegacyStoreMeta {
    /// Returns the legacy single-file metadata defaults used during
    /// compatibility upgrades.
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            next_doc_id: 1,
            id_source: "sha256".to_owned(),
            store_path: false,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
            tier1_filter_target_fp: Some(DEFAULT_TIER1_FILTER_TARGET_FP),
            tier2_filter_target_fp: Some(DEFAULT_TIER2_FILTER_TARGET_FP),
            filter_target_fp: None,
            compaction_idle_cooldown_s: DEFAULT_COMPACTION_IDLE_COOLDOWN_S,
        }
    }
}

impl ForestMeta {
    /// Returns the effective tier-1 false-positive target stored in forest
    /// metadata.
    fn resolved_tier1_filter_target_fp(&self) -> Option<f64> {
        self.tier1_filter_target_fp
    }

    /// Returns the effective tier-2 false-positive target stored in forest
    /// metadata.
    fn resolved_tier2_filter_target_fp(&self) -> Option<f64> {
        self.tier2_filter_target_fp
    }
}

impl From<&LegacyStoreMeta> for ForestMeta {
    /// Upgrades legacy store metadata into the split forest-wide metadata
    /// format.
    fn from(value: &LegacyStoreMeta) -> Self {
        Self {
            version: value.version,
            id_source: value.id_source.clone(),
            store_path: value.store_path,
            tier2_gram_size: value.tier2_gram_size,
            tier1_gram_size: value.tier1_gram_size,
            tier1_filter_target_fp: value.tier1_filter_target_fp.or(value.filter_target_fp),
            tier2_filter_target_fp: value.tier2_filter_target_fp.or(value.filter_target_fp),
            compaction_idle_cooldown_s: value.compaction_idle_cooldown_s,
            source_dedup_min_new_docs: 1_000,
        }
    }
}

impl From<&LegacyStoreMeta> for StoreLocalMeta {
    /// Upgrades legacy store metadata into the split local metadata format.
    fn from(value: &LegacyStoreMeta) -> Self {
        Self {
            version: value.version,
            next_doc_id: value.next_doc_id,
        }
    }
}

#[derive(Clone, Debug)]
struct CandidateDoc {
    doc_id: u64,
    identity: String,
    file_size: u64,
    filter_bytes: usize,
    bloom_hashes: usize,
    tier2_filter_bytes: usize,
    tier2_bloom_hashes: usize,
    special_population: bool,
    deleted: bool,
}

/// Validates and normalizes a candidate identity hex string using the expected
/// raw source-id width.
fn normalize_identity_hex(value: &str, identity_bytes: usize, label: &str) -> Result<String> {
    let text = value.trim().to_ascii_lowercase();
    let expected_hex_len = identity_bytes.saturating_mul(2);
    if text.len() != expected_hex_len || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(SspryError::from(format!(
            "{label} must be exactly {expected_hex_len} hexadecimal characters.",
        )));
    }
    Ok(text)
}

/// Estimates the heap retained by one in-memory candidate document record.
fn candidate_doc_memory_bytes(doc: &CandidateDoc) -> u64 {
    (std::mem::size_of::<CandidateDoc>() as u64).saturating_add(doc.identity.capacity() as u64)
}

/// Converts an `Instant` into a saturated microsecond count for profiling
/// fields stored as `u64`.
fn elapsed_us(started: Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

const DOC_META_ROW_BYTES: usize = 56;
const TIER2_DOC_META_ROW_BYTES: usize = 24;
const APPEND_PAYLOAD_SYNC_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;
const TREE_SOURCE_REF_MANIFEST_VERSION: u32 = 1;
const FOREST_SOURCE_DEDUP_MANIFEST_VERSION: u32 = 1;
const TREE_SOURCE_REF_RUN_MAX_ENTRIES: usize = 16_384;
const DOC_FLAG_DELETED: u8 = 0x02;
const DOC_FLAG_SPECIAL_POPULATION: u8 = 0x04;

/// Returns whether the tier-2-only search experiment is enabled through the
/// process environment.
fn experiment_tier2_only_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("SSPRY_EXPERIMENT_TIER2_ONLY")
            .ok()
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

/// Returns whether the tier-2-plus-metadata-only search experiment is enabled.
fn experiment_tier2_and_metadata_only_enabled() -> bool {
    #[cfg(test)]
    {
        let override_value = EXPERIMENT_TIER2_AND_METADATA_ONLY_OVERRIDE.with(|value| value.get());
        if override_value != 0 {
            return override_value == 2;
        }
    }
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("SSPRY_EXPERIMENT_TIER2_AND_METADATA_ONLY")
            .ok()
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

#[cfg(test)]
thread_local! {
    static EXPERIMENT_TIER2_AND_METADATA_ONLY_OVERRIDE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy, Debug, Default)]
struct DocMetaRow {
    file_size: u64,
    filter_bytes: u32,
    flags: u8,
    bloom_hashes: u8,
    bloom_offset: u64,
    bloom_len: u32,
    external_id_offset: u64,
    external_id_len: u32,
    metadata_offset: u64,
    metadata_len: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct Tier2DocMetaRow {
    filter_bytes: u32,
    bloom_hashes: u8,
    bloom_offset: u64,
    bloom_len: u32,
}

impl Tier2DocMetaRow {
    /// Encodes one tier-2 metadata row into the fixed-width on-disk format.
    fn encode(self) -> [u8; TIER2_DOC_META_ROW_BYTES] {
        let mut out = [0u8; TIER2_DOC_META_ROW_BYTES];
        out[0..4].copy_from_slice(&self.filter_bytes.to_le_bytes());
        out[4] = self.bloom_hashes;
        out[8..16].copy_from_slice(&self.bloom_offset.to_le_bytes());
        out[16..20].copy_from_slice(&self.bloom_len.to_le_bytes());
        out
    }

    /// Decodes one fixed-width tier-2 metadata row from disk.
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TIER2_DOC_META_ROW_BYTES {
            return Err(SspryError::from(
                "Invalid candidate tier2 doc meta row size",
            ));
        }
        Ok(Self {
            filter_bytes: u32::from_le_bytes(bytes[0..4].try_into().expect("tier2_filter_bytes")),
            bloom_hashes: bytes[4],
            bloom_offset: u64::from_le_bytes(bytes[8..16].try_into().expect("tier2_bloom_offset")),
            bloom_len: u32::from_le_bytes(bytes[16..20].try_into().expect("tier2_bloom_len")),
        })
    }
}

impl DocMetaRow {
    /// Encodes one primary document metadata row into the fixed-width on-disk
    /// format.
    fn encode(self) -> [u8; DOC_META_ROW_BYTES] {
        let mut out = [0u8; DOC_META_ROW_BYTES];
        out[0..8].copy_from_slice(&self.file_size.to_le_bytes());
        out[8..12].copy_from_slice(&self.filter_bytes.to_le_bytes());
        out[12] = self.flags;
        out[13] = self.bloom_hashes;
        out[16..24].copy_from_slice(&self.bloom_offset.to_le_bytes());
        out[24..28].copy_from_slice(&self.bloom_len.to_le_bytes());
        out[28..36].copy_from_slice(&self.external_id_offset.to_le_bytes());
        out[36..40].copy_from_slice(&self.external_id_len.to_le_bytes());
        out[40..48].copy_from_slice(&self.metadata_offset.to_le_bytes());
        out[48..52].copy_from_slice(&self.metadata_len.to_le_bytes());
        out
    }

    /// Decodes one fixed-width primary document metadata row from disk.
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DOC_META_ROW_BYTES {
            return Err(SspryError::from("Invalid candidate doc meta row size"));
        }
        Ok(Self {
            file_size: u64::from_le_bytes(bytes[0..8].try_into().expect("file_size")),
            filter_bytes: u32::from_le_bytes(bytes[8..12].try_into().expect("filter_bytes")),
            flags: bytes[12],
            bloom_hashes: bytes[13],
            bloom_offset: u64::from_le_bytes(bytes[16..24].try_into().expect("bloom_offset")),
            bloom_len: u32::from_le_bytes(bytes[24..28].try_into().expect("bloom_len")),
            external_id_offset: u64::from_le_bytes(
                bytes[28..36].try_into().expect("external_id_offset"),
            ),
            external_id_len: u32::from_le_bytes(bytes[36..40].try_into().expect("external_id_len")),
            metadata_offset: u64::from_le_bytes(bytes[40..48].try_into().expect("metadata_offset")),
            metadata_len: u32::from_le_bytes(bytes[48..52].try_into().expect("metadata_len")),
        })
    }
}

#[derive(Clone, Debug, Default)]
struct Tier2Telemetry {
    query_count: u64,
    tier2_scanned_docs_total: u64,
    tier2_docs_matched_total: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlobSidecarAccessMode {
    MmapWholeFile,
    PositionedRead,
}

#[derive(Debug)]
struct BlobSidecar {
    path: PathBuf,
    access_mode: BlobSidecarAccessMode,
    mmap: OnceLock<std::result::Result<Option<Mmap>, String>>,
    file: OnceLock<std::result::Result<fs::File, String>>,
}

impl BlobSidecar {
    /// Creates a sidecar handle that will access the file using the requested
    /// strategy.
    fn with_access_mode(path: PathBuf, access_mode: BlobSidecarAccessMode) -> Self {
        Self {
            path,
            access_mode,
            mmap: OnceLock::new(),
            file: OnceLock::new(),
        }
    }

    /// Prepares the sidecar for reading by opening or mapping it when a
    /// payload already exists.
    fn map_if_exists(&self) -> Result<()> {
        match self.access_mode {
            BlobSidecarAccessMode::MmapWholeFile => {
                let _ = self.mmap_if_exists()?;
            }
            BlobSidecarAccessMode::PositionedRead => {
                if self.path.exists()
                    && self
                        .path
                        .metadata()
                        .map_err(|err| {
                            SspryError::from(format!(
                                "Failed to stat {}: {err}",
                                self.path.display()
                            ))
                        })?
                        .len()
                        > 0
                {
                    let _ = self.file_handle()?;
                }
            }
        }
        Ok(())
    }

    /// Returns the lazily created mmap for this sidecar when mmap access is
    /// enabled and the file exists.
    fn mmap_if_exists(&self) -> Result<Option<&Mmap>> {
        if self.access_mode != BlobSidecarAccessMode::MmapWholeFile {
            return Ok(None);
        }
        self.mmap
            .get_or_init(|| {
                if !self.path.exists() {
                    return Ok(None);
                }
                let file = fs::File::open(&self.path)
                    .map_err(|err| format!("Failed to open {}: {err}", self.path.display()))?;
                if file
                    .metadata()
                    .map_err(|err| format!("Failed to stat {}: {err}", self.path.display()))?
                    .len()
                    == 0
                {
                    return Ok(None);
                }
                let mmap = unsafe { MmapOptions::new().map(&file) }
                    .map_err(|err| format!("Failed to mmap {}: {err}", self.path.display()))?;
                Ok(Some(mmap))
            })
            .as_ref()
            .map_err(|err: &String| SspryError::from(err.clone()))
            .map(|mmap: &Option<Mmap>| mmap.as_ref())
    }

    /// Returns the lazily opened file handle used for positioned reads.
    fn file_handle(&self) -> Result<&fs::File> {
        self.file
            .get_or_init(|| {
                fs::File::open(&self.path)
                    .map_err(|err| format!("Failed to open {}: {err}", self.path.display()))
            })
            .as_ref()
            .map_err(|err: &String| SspryError::from(err.clone()))
    }

    /// Drops any cached mmap or file handle so subsequent reads reopen the
    /// sidecar.
    fn invalidate(&mut self) {
        self.mmap = OnceLock::new();
        self.file = OnceLock::new();
    }

    /// Repoints the sidecar at a different path and clears any cached handles.
    fn retarget(&mut self, path: PathBuf) {
        self.path = path;
        self.mmap = OnceLock::new();
        self.file = OnceLock::new();
    }

    /// Reads one sidecar payload range, borrowing from an mmap when possible
    /// and falling back to positioned I/O otherwise.
    fn read_bytes<'a>(
        &'a self,
        offset: u64,
        len: usize,
        label: &str,
        doc_id: u64,
    ) -> Result<Cow<'a, [u8]>> {
        if len == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        if let Some(mmap) = self.mmap_if_exists()? {
            let start = offset as usize;
            let end = start.saturating_add(len);
            if end > mmap.len() {
                return Err(SspryError::from(format!(
                    "Invalid {label} payload stored for doc_id {doc_id}"
                )));
            }
            return Ok(Cow::Borrowed(&mmap[start..end]));
        }

        let mut bytes = vec![0u8; len];
        read_exact_at(self.file_handle()?, offset, &mut bytes).map_err(|err| {
            SspryError::from(format!(
                "Invalid {label} payload stored for doc_id {doc_id}: {err}"
            ))
        })?;
        Ok(Cow::Owned(bytes))
    }

    #[cfg(test)]
    /// Returns an in-place view into the mmap-backed blob sidecar when the
    /// caller is running in whole-file mmap mode.
    fn mmap_slice<'a>(&'a self, offset: u64, len: usize, label: &str) -> Result<Option<&'a [u8]>> {
        if len == 0 {
            return Ok(Some(&[]));
        }
        if self.access_mode != BlobSidecarAccessMode::MmapWholeFile {
            return Ok(None);
        }
        let Some(mmap) = self.mmap_if_exists()? else {
            return Ok(None);
        };
        let start = offset as usize;
        let end = start.saturating_add(len);
        if end > mmap.len() {
            return Err(SspryError::from(format!(
                "Invalid {label} payload range at {}",
                self.path.display()
            )));
        }
        Ok(Some(&mmap[start..end]))
    }

    /// Returns the number of bytes currently held in the sidecar's mmap cache.
    fn mapped_bytes(&self) -> u64 {
        self.mmap
            .get()
            .and_then(|result: &std::result::Result<Option<Mmap>, String>| result.as_ref().ok())
            .and_then(|mmap: &Option<Mmap>| mmap.as_ref())
            .map(|mmap: &Mmap| mmap.len() as u64)
            .unwrap_or(0)
    }
}

#[derive(Debug)]
struct StoreSidecars {
    blooms: BlobSidecar,
    tier2_blooms: BlobSidecar,
    metadata: BlobSidecar,
    external_ids: BlobSidecar,
}

impl StoreSidecars {
    /// Creates the set of sidecar readers rooted at the current store path.
    fn new(root: &Path) -> Self {
        Self {
            blooms: BlobSidecar::with_access_mode(
                blooms_path(root),
                BlobSidecarAccessMode::MmapWholeFile,
            ),
            tier2_blooms: BlobSidecar::with_access_mode(
                tier2_blooms_path(root),
                BlobSidecarAccessMode::PositionedRead,
            ),
            metadata: BlobSidecar::with_access_mode(
                doc_metadata_path(root),
                BlobSidecarAccessMode::PositionedRead,
            ),
            external_ids: BlobSidecar::with_access_mode(
                external_ids_path(root),
                BlobSidecarAccessMode::PositionedRead,
            ),
        }
    }

    /// Builds a sidecar set and prepares it for existing on-disk payloads.
    fn map_existing(root: &Path) -> Result<Self> {
        Ok(Self::new(root))
    }

    /// Refreshes every sidecar mapping or file handle after on-disk mutations.
    fn refresh_maps(&mut self) -> Result<()> {
        self.blooms.map_if_exists()?;
        self.tier2_blooms.map_if_exists()?;
        self.metadata.map_if_exists()?;
        self.external_ids.map_if_exists()?;
        Ok(())
    }

    /// Invalidates every cached sidecar handle.
    fn invalidate_all(&mut self) {
        self.blooms.invalidate();
        self.tier2_blooms.invalidate();
        self.metadata.invalidate();
        self.external_ids.invalidate();
    }

    /// Repoints every sidecar at a different store root.
    fn retarget_root(&mut self, root: &Path) {
        self.blooms.retarget(blooms_path(root));
        self.tier2_blooms.retarget(tier2_blooms_path(root));
        self.metadata.retarget(doc_metadata_path(root));
        self.external_ids.retarget(external_ids_path(root));
    }

    /// Returns the mapped-byte totals for each sidecar payload.
    fn mapped_bytes(&self) -> (u64, u64, u64, u64) {
        (
            self.blooms.mapped_bytes(),
            self.tier2_blooms.mapped_bytes(),
            self.metadata.mapped_bytes(),
            self.external_ids.mapped_bytes(),
        )
    }
}

/// Performs a positioned read that fills the entire destination buffer or
/// returns `UnexpectedEof`.
fn read_exact_at(file: &fs::File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    let mut read_total = 0usize;
    while read_total < buf.len() {
        let read_now = file.read_at(
            &mut buf[read_total..],
            offset.saturating_add(read_total as u64),
        )?;
        if read_now == 0 {
            return Err(std::io::Error::from(ErrorKind::UnexpectedEof));
        }
        read_total += read_now;
    }
    Ok(())
}

#[derive(Debug)]
struct AppendFile {
    path: PathBuf,
    handle: Option<fs::File>,
    offset: u64,
    sync_threshold_bytes: u64,
    bytes_since_sync: u64,
}

impl AppendFile {
    /// Opens an append-only file wrapper with no forced sync threshold.
    fn new(path: PathBuf) -> Result<Self> {
        Self::new_with_sync_threshold(path, 0)
    }

    /// Opens an append-only file wrapper and records the current end-of-file
    /// offset.
    fn new_with_sync_threshold(path: PathBuf, sync_threshold_bytes: u64) -> Result<Self> {
        let offset = fs::metadata(&path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Ok(Self {
            path,
            handle: None,
            offset,
            sync_threshold_bytes,
            bytes_since_sync: 0,
        })
    }

    /// Appends bytes to the file, returning the starting offset of the newly
    /// written payload.
    fn append(&mut self, bytes: &[u8]) -> Result<u64> {
        let offset = self.offset;
        if bytes.is_empty() {
            return Ok(offset);
        }
        if self.handle.is_none() {
            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)?;
            }
            self.handle = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)?,
            );
        }
        let handle = self
            .handle
            .as_mut()
            .ok_or_else(|| SspryError::from("append handle unexpectedly unavailable"))?;
        handle.write_all(bytes)?;
        self.offset = self.offset.saturating_add(bytes.len() as u64);
        self.bytes_since_sync = self.bytes_since_sync.saturating_add(bytes.len() as u64);
        if self.sync_threshold_bytes > 0 && self.bytes_since_sync >= self.sync_threshold_bytes {
            handle.sync_data()?;
            self.bytes_since_sync = 0;
        }
        Ok(offset)
    }

    /// Repoints the append file at a different path and resets its cached
    /// handle and offsets.
    fn retarget(&mut self, path: PathBuf) {
        self.path = path;
        self.handle = None;
        self.offset = fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        self.bytes_since_sync = 0;
    }
}

#[derive(Debug)]
struct StoreAppendWriters {
    blooms: AppendFile,
    tier2_blooms: AppendFile,
    metadata: AppendFile,
    external_ids: AppendFile,
    sha_by_docid: AppendFile,
    doc_meta: AppendFile,
    tier2_doc_meta: AppendFile,
}

impl StoreAppendWriters {
    /// Creates the append-only writers used for all mutable store sidecars.
    fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            blooms: AppendFile::new_with_sync_threshold(
                blooms_path(root),
                APPEND_PAYLOAD_SYNC_THRESHOLD_BYTES,
            )?,
            tier2_blooms: AppendFile::new_with_sync_threshold(
                tier2_blooms_path(root),
                APPEND_PAYLOAD_SYNC_THRESHOLD_BYTES,
            )?,
            metadata: AppendFile::new(doc_metadata_path(root))?,
            external_ids: AppendFile::new(external_ids_path(root))?,
            sha_by_docid: AppendFile::new(sha_by_docid_path(root))?,
            doc_meta: AppendFile::new(doc_meta_path(root))?,
            tier2_doc_meta: AppendFile::new(tier2_doc_meta_path(root))?,
        })
    }

    /// Repoints every append writer at a different store root.
    fn retarget_root(&mut self, root: &Path) {
        self.blooms.retarget(blooms_path(root));
        self.tier2_blooms.retarget(tier2_blooms_path(root));
        self.metadata.retarget(doc_metadata_path(root));
        self.external_ids.retarget(external_ids_path(root));
        self.sha_by_docid.retarget(sha_by_docid_path(root));
        self.doc_meta.retarget(doc_meta_path(root));
        self.tier2_doc_meta.retarget(tier2_doc_meta_path(root));
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CandidateCompactionSnapshot {
    root: PathBuf,
    meta: ForestMeta,
    mutation_counter: u64,
    current_generation: u64,
    live_docs: Vec<CompactionDocRef>,
    reclaimed_docs: usize,
    reclaimed_bytes: u64,
}

#[derive(Clone, Debug)]
struct CompactionDocRef {
    identity: Vec<u8>,
    file_size: u64,
    filter_bytes: usize,
    bloom_hashes: usize,
    tier2_filter_bytes: usize,
    tier2_bloom_hashes: usize,
    row: DocMetaRow,
    tier2_row: Tier2DocMetaRow,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CandidateCompactionResult {
    pub reclaimed_docs: usize,
    pub reclaimed_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct TreeSourceRefManifest {
    version: u32,
    id_source: String,
    identity_bytes: usize,
    candidate_shards: usize,
    entry_count: u64,
    total_inserted_docs: u64,
    last_built_unix_ms: Option<u64>,
}

impl Default for TreeSourceRefManifest {
    /// Returns the empty manifest state before the first successful tree-level
    /// source-id reference build.
    fn default() -> Self {
        Self {
            version: TREE_SOURCE_REF_MANIFEST_VERSION,
            id_source: String::new(),
            identity_bytes: 0,
            candidate_shards: 0,
            entry_count: 0,
            total_inserted_docs: 0,
            last_built_unix_ms: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ForestSourceDedupManifest {
    pub(crate) version: u32,
    pub(crate) id_source: String,
    pub(crate) identity_bytes: usize,
    pub(crate) tree_count: usize,
    pub(crate) total_inserted_docs: u64,
    pub(crate) last_built_unix_ms: Option<u64>,
    pub(crate) last_duplicate_groups: u64,
    pub(crate) last_deleted_docs: u64,
    pub(crate) last_affected_trees: usize,
}

impl Default for ForestSourceDedupManifest {
    /// Returns the empty manifest state before the first successful
    /// forest-wide source-id deduplication pass.
    fn default() -> Self {
        Self {
            version: FOREST_SOURCE_DEDUP_MANIFEST_VERSION,
            id_source: String::new(),
            identity_bytes: 0,
            tree_count: 0,
            total_inserted_docs: 0,
            last_built_unix_ms: None,
            last_duplicate_groups: 0,
            last_deleted_docs: 0,
            last_affected_trees: 0,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TreeSourceRefBuildResult {
    pub entry_count: u64,
    pub total_inserted_docs: u64,
    pub candidate_shards: usize,
    pub identity_bytes: usize,
    pub id_source: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TreeSourceRefEntry {
    pub identity: Vec<u8>,
    pub shard_idx: u32,
    pub doc_id: u64,
}

impl Ord for TreeSourceRefEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.identity
            .cmp(&other.identity)
            .then_with(|| self.shard_idx.cmp(&other.shard_idx))
            .then_with(|| self.doc_id.cmp(&other.doc_id))
    }
}

impl PartialOrd for TreeSourceRefEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ForestSourceDedupResult {
    pub duplicate_groups: u64,
    pub deleted_docs: u64,
    pub affected_trees: usize,
    pub total_inserted_docs: u64,
    pub tree_count: usize,
    pub identity_bytes: usize,
    pub id_source: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ForestSourceDedupSummaryState {
    pub min_new_docs: u64,
    pub last_completed_unix_ms: Option<u64>,
    pub last_duplicate_groups: u64,
    pub last_deleted_docs: u64,
    pub last_affected_trees: usize,
    pub last_total_inserted_docs: u64,
}

#[derive(Debug)]
pub(crate) struct RuntimeQueryArtifacts {
    patterns: HashMap<String, PatternPlan>,
    runtime_patterns: HashMap<String, RuntimePatternArtifacts>,
    impossible_query: bool,
}

#[derive(Clone, Debug, Default)]
struct RuntimeAlternativeArtifacts {
    use_any_lane: bool,
    lane_variants: Vec<Vec<usize>>,
}

#[derive(Clone, Debug)]
struct RuntimePatternArtifacts {
    tier1: Vec<RuntimeAlternativeArtifacts>,
    tier2: Vec<RuntimeAlternativeArtifacts>,
}

#[derive(Debug)]
pub struct CandidateStore {
    root: PathBuf,
    meta: ForestMeta,
    local_meta: StoreLocalMeta,
    docs: Vec<CandidateDoc>,
    doc_rows: Vec<DocMetaRow>,
    tier2_doc_rows: Vec<Tier2DocMetaRow>,
    sidecars: StoreSidecars,
    append_writers: StoreAppendWriters,
    identity_to_pos: HashMap<String, usize>,
    special_doc_positions: Vec<usize>,
    mutation_counter: u64,
    compaction_generation: u64,
    retired_generation_roots: Vec<String>,
    last_write_activity_monotonic: Option<Instant>,
    tier2_telemetry: Tier2Telemetry,
    query_artifact_cache: BoundedCache<String, Arc<RuntimeQueryArtifacts>>,
    memory_budget_bytes: u64,
    total_shards: usize,
    meta_persist_dirty: bool,
    last_insert_batch_profile: CandidateInsertBatchProfile,
    last_import_batch_profile: CandidateImportBatchProfile,
}

#[derive(Clone, Copy, Debug, Default)]
struct TierFlags {
    used_tier1: bool,
    used_tier2: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct MatchOutcome {
    matched: bool,
    tiers: TierFlags,
}

#[derive(Default)]
struct QueryEvalCache {
    pattern_outcomes: HashMap<String, MatchOutcome>,
}

#[derive(Default)]
struct BatchedQueryResult {
    hits: Vec<String>,
    tiers: TierFlags,
    profile: CandidateQueryProfile,
    eval_nanos: u128,
}

struct LazyDocQueryInputs<'a> {
    doc: &'a CandidateDoc,
    metadata_bytes: Option<Cow<'a, [u8]>>,
    tier1_bloom_bytes: Option<Cow<'a, [u8]>>,
    tier2_bloom_bytes: Option<Cow<'a, [u8]>>,
    profile: CandidateQueryProfile,
}

impl<'a> LazyDocQueryInputs<'a> {
    /// Creates a lazy view over one document that only loads sidecar payloads
    /// on demand during query evaluation.
    fn new(doc: &'a CandidateDoc) -> Self {
        Self {
            doc,
            metadata_bytes: None,
            tier1_bloom_bytes: None,
            tier2_bloom_bytes: None,
            profile: CandidateQueryProfile::default(),
        }
    }

    #[cfg(test)]
    /// Creates a lazy query input wrapper with pre-fetched payloads for tests.
    fn from_prefetched(
        doc: &'a CandidateDoc,
        metadata_bytes: &'a [u8],
        tier1_bloom_bytes: &'a [u8],
        tier2_bloom_bytes: &'a [u8],
    ) -> Self {
        Self {
            doc,
            metadata_bytes: Some(Cow::Borrowed(metadata_bytes)),
            tier1_bloom_bytes: Some(Cow::Borrowed(tier1_bloom_bytes)),
            tier2_bloom_bytes: Some(Cow::Borrowed(tier2_bloom_bytes)),
            profile: CandidateQueryProfile::default(),
        }
    }

    /// Consumes the lazy wrapper and returns the accumulated query profile.
    fn into_profile(self) -> CandidateQueryProfile {
        self.profile
    }

    /// Loads and caches compact metadata bytes for the current document.
    fn metadata_bytes<F>(&mut self, load: &mut F) -> Result<&[u8]>
    where
        F: FnMut() -> Result<Cow<'a, [u8]>>,
    {
        if self.metadata_bytes.is_none() {
            let bytes = load()?;
            self.profile.metadata_loads = self.profile.metadata_loads.saturating_add(1);
            self.profile.metadata_bytes = self
                .profile
                .metadata_bytes
                .saturating_add(bytes.len() as u64);
            self.metadata_bytes = Some(bytes);
        }
        Ok(self.metadata_bytes.as_deref().unwrap_or(&[]))
    }

    /// Loads and caches the tier-1 bloom payload for the current document.
    fn tier1_bloom_bytes<F>(&mut self, load: &mut F) -> Result<&[u8]>
    where
        F: FnMut() -> Result<Cow<'a, [u8]>>,
    {
        if self.tier1_bloom_bytes.is_none() {
            let bytes = load()?;
            self.profile.tier1_bloom_loads = self.profile.tier1_bloom_loads.saturating_add(1);
            self.profile.tier1_bloom_bytes = self
                .profile
                .tier1_bloom_bytes
                .saturating_add(bytes.len() as u64);
            self.tier1_bloom_bytes = Some(bytes);
        }
        Ok(self.tier1_bloom_bytes.as_deref().unwrap_or(&[]))
    }

    /// Loads and caches the tier-2 bloom payload for the current document.
    fn tier2_bloom_bytes<F>(&mut self, load: &mut F) -> Result<&[u8]>
    where
        F: FnMut() -> Result<Cow<'a, [u8]>>,
    {
        if self.tier2_bloom_bytes.is_none() {
            let bytes = load()?;
            self.profile.tier2_bloom_loads = self.profile.tier2_bloom_loads.saturating_add(1);
            self.profile.tier2_bloom_bytes = self
                .profile
                .tier2_bloom_bytes
                .saturating_add(bytes.len() as u64);
            self.tier2_bloom_bytes = Some(bytes);
        }
        Ok(self.tier2_bloom_bytes.as_deref().unwrap_or(&[]))
    }
}

impl TierFlags {
    /// Merges another tier-usage flag set into this one.
    fn merge(&mut self, other: TierFlags) {
        self.used_tier1 |= other.used_tier1;
        self.used_tier2 |= other.used_tier2;
    }

    /// Returns a user-facing label for the tiers touched during evaluation.
    fn as_label(self) -> String {
        match (self.used_tier1, self.used_tier2) {
            (true, true) => "tier1+tier2".to_owned(),
            (true, false) => "tier1".to_owned(),
            (false, true) => "tier2".to_owned(),
            (false, false) => "none".to_owned(),
        }
    }
}

/// Extracts one page of query hits together with pagination metadata.
fn paginate_query_hits(
    matched_hits: &[String],
    cursor: usize,
    chunk_size: usize,
) -> (Vec<String>, usize, usize, usize, Option<usize>) {
    let total = matched_hits.len();
    let start = cursor.min(total);
    let size = chunk_size.max(1);
    let end = (start + size).min(total);
    let page = matched_hits[start..end].to_vec();
    let next_cursor = if end < total { Some(end) } else { None };

    (page, total, start, end, next_cursor)
}

/// Loads the forest-wide metadata file, upgrading from legacy metadata when
/// needed.
fn load_forest_meta(root: &Path) -> Result<ForestMeta> {
    let policy_root = forest_policy_root(root);
    let policy_path = forest_meta_path(&policy_root);
    if policy_path.exists() {
        let meta: ForestMeta = serde_json::from_slice(&fs::read(&policy_path)?).map_err(|_| {
            SspryError::from(format!(
                "Invalid candidate metadata at {}",
                policy_path.display()
            ))
        })?;
        if meta.version != STORE_VERSION {
            return Err(SspryError::from(format!(
                "Unsupported candidate store version: {}",
                meta.version
            )));
        }
        return Ok(meta);
    }

    let legacy_path = forest_meta_path(root);
    let legacy: LegacyStoreMeta =
        serde_json::from_slice(&fs::read(&legacy_path)?).map_err(|_| {
            SspryError::from(format!(
                "Invalid candidate metadata at {}",
                legacy_path.display()
            ))
        })?;
    if legacy.version != STORE_VERSION {
        return Err(SspryError::from(format!(
            "Unsupported candidate store version: {}",
            legacy.version
        )));
    }
    Ok(ForestMeta::from(&legacy))
}

/// Loads the per-root local metadata file, upgrading from legacy metadata when
/// needed.
fn load_store_local_meta(root: &Path) -> Result<StoreLocalMeta> {
    let local_path = store_local_meta_path(root);
    if local_path.exists() {
        let meta: StoreLocalMeta =
            serde_json::from_slice(&fs::read(&local_path)?).map_err(|_| {
                SspryError::from(format!(
                    "Invalid candidate local metadata at {}",
                    local_path.display()
                ))
            })?;
        if meta.version != STORE_VERSION {
            return Err(SspryError::from(format!(
                "Unsupported candidate store version: {}",
                meta.version
            )));
        }
        return Ok(meta);
    }

    let legacy_path = forest_meta_path(root);
    let legacy: LegacyStoreMeta =
        serde_json::from_slice(&fs::read(&legacy_path)?).map_err(|_| {
            SspryError::from(format!(
                "Invalid candidate metadata at {}",
                legacy_path.display()
            ))
        })?;
    if legacy.version != STORE_VERSION {
        return Err(SspryError::from(format!(
            "Unsupported candidate store version: {}",
            legacy.version
        )));
    }
    Ok(StoreLocalMeta::from(&legacy))
}

/// Returns the current insert watermark for one tree by summing the next-doc-id
/// counters across all of its shards.
fn tree_total_inserted_docs(root: &Path, shard_count: usize) -> Result<u64> {
    let mut total = 0u64;
    for shard_idx in 0..shard_count.max(1) {
        let shard_root = candidate_shard_root(root, shard_count, shard_idx);
        let local_meta = load_store_local_meta(&shard_root)?;
        total = total.saturating_add(local_meta.next_doc_id.saturating_sub(1));
    }
    Ok(total)
}

/// Returns the current wall-clock timestamp as a saturated Unix-millisecond
/// counter for manifest bookkeeping.
fn current_unix_ms_saturated() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
struct TreeSourceRefPlan {
    manifest: Option<TreeSourceRefManifest>,
    id_source: String,
    identity_bytes: usize,
    candidate_shards: usize,
    total_inserted_docs: u64,
}

#[derive(Clone, Debug)]
struct ForestSourceDedupPlan {
    manifest: Option<ForestSourceDedupManifest>,
    id_source: String,
    identity_bytes: usize,
    tree_count: usize,
    total_inserted_docs: u64,
}

/// Loads the current tree-level source-id reference inputs and any previously
/// persisted manifest so maintenance can decide whether a rebuild is due.
fn tree_source_ref_plan(root: &Path) -> Result<TreeSourceRefPlan> {
    let meta = load_forest_meta(root)?;
    let candidate_shards = read_candidate_shard_count(root)?.unwrap_or(1).max(1);
    let identity_bytes = identity_bytes_for_source(&meta.id_source)?;
    Ok(TreeSourceRefPlan {
        manifest: read_tree_source_ref_manifest(root)?,
        id_source: meta.id_source,
        identity_bytes,
        candidate_shards,
        total_inserted_docs: tree_total_inserted_docs(root, candidate_shards)?,
    })
}

/// Reports whether a tree-level source-id reference file is present and in sync
/// with the current published tree contents.
pub(crate) fn tree_source_ref_is_current(root: &Path) -> Result<bool> {
    let plan = tree_source_ref_plan(root)?;
    if plan.total_inserted_docs == 0 {
        return Ok(true);
    }

    let Some(manifest) = plan.manifest.as_ref() else {
        return Ok(false);
    };
    Ok(tree_source_ref_path(root).is_file()
        && manifest.version == TREE_SOURCE_REF_MANIFEST_VERSION
        && manifest.id_source == plan.id_source
        && manifest.identity_bytes == plan.identity_bytes
        && manifest.candidate_shards == plan.candidate_shards
        && manifest.total_inserted_docs == plan.total_inserted_docs)
}

/// Loads the current forest-wide source-id dedup inputs and any previously
/// persisted manifest so maintenance can decide whether another pass is due.
fn forest_source_dedup_plan(root: &Path, tree_roots: &[PathBuf]) -> Result<ForestSourceDedupPlan> {
    let meta = load_forest_meta(root)?;
    let identity_bytes = identity_bytes_for_source(&meta.id_source)?;
    let mut total_inserted_docs = 0u64;
    for tree_root in tree_roots {
        let candidate_shards = read_candidate_shard_count(tree_root)?.unwrap_or(1).max(1);
        total_inserted_docs = total_inserted_docs
            .saturating_add(tree_total_inserted_docs(tree_root, candidate_shards)?);
    }
    Ok(ForestSourceDedupPlan {
        manifest: read_forest_source_dedup_manifest(root)?,
        id_source: meta.id_source,
        identity_bytes,
        tree_count: tree_roots.len(),
        total_inserted_docs,
    })
}

/// Loads the persisted forest-wide source-id deduplication policy and most
/// recent maintenance checkpoint for diagnostics.
pub(crate) fn forest_source_dedup_summary_state(
    root: &Path,
) -> Result<ForestSourceDedupSummaryState> {
    let meta = load_forest_meta(root)?;
    let manifest = read_forest_source_dedup_manifest(root)?;
    Ok(ForestSourceDedupSummaryState {
        min_new_docs: meta.source_dedup_min_new_docs.max(1),
        last_completed_unix_ms: manifest.as_ref().and_then(|value| value.last_built_unix_ms),
        last_duplicate_groups: manifest
            .as_ref()
            .map(|value| value.last_duplicate_groups)
            .unwrap_or(0),
        last_deleted_docs: manifest
            .as_ref()
            .map(|value| value.last_deleted_docs)
            .unwrap_or(0),
        last_affected_trees: manifest
            .as_ref()
            .map(|value| value.last_affected_trees)
            .unwrap_or(0),
        last_total_inserted_docs: manifest
            .as_ref()
            .map(|value| value.total_inserted_docs)
            .unwrap_or(0),
    })
}

/// Returns whether the forest-wide source-id deduplication pass should run for
/// the current published forest. All non-empty trees must already have current
/// tree-level reference files before the merge can start.
pub(crate) fn forest_source_dedup_due(
    root: &Path,
    tree_roots: &[PathBuf],
    min_new_docs: u64,
) -> Result<bool> {
    if tree_roots.len() < 2 {
        return Ok(false);
    }

    for tree_root in tree_roots {
        if !tree_source_ref_is_current(tree_root)? {
            return Ok(false);
        }
    }

    let plan = forest_source_dedup_plan(root, tree_roots)?;
    if plan.total_inserted_docs == 0 {
        return Ok(false);
    }

    let manifest_matches = plan.manifest.as_ref().is_some_and(|manifest| {
        manifest.version == FOREST_SOURCE_DEDUP_MANIFEST_VERSION
            && manifest.id_source == plan.id_source
            && manifest.identity_bytes == plan.identity_bytes
            && manifest.tree_count == plan.tree_count
    });
    if !manifest_matches {
        return Ok(plan.total_inserted_docs >= min_new_docs);
    }

    let manifest = plan.manifest.as_ref().expect("checked manifest above");
    let new_docs = plan
        .total_inserted_docs
        .saturating_sub(manifest.total_inserted_docs);
    Ok(new_docs > 0 && new_docs >= min_new_docs)
}

/// Returns whether a tree-level source-id reference rebuild should run for the
/// current published tree root.
pub(crate) fn tree_source_ref_build_due(root: &Path, min_new_docs: u64) -> Result<bool> {
    let plan = tree_source_ref_plan(root)?;
    if plan.total_inserted_docs == 0 {
        return Ok(false);
    }

    let file_exists = tree_source_ref_path(root).is_file();
    let manifest_matches = plan.manifest.as_ref().is_some_and(|manifest| {
        manifest.version == TREE_SOURCE_REF_MANIFEST_VERSION
            && manifest.id_source == plan.id_source
            && manifest.identity_bytes == plan.identity_bytes
            && manifest.candidate_shards == plan.candidate_shards
    });
    if !file_exists || !manifest_matches {
        return Ok(plan.total_inserted_docs >= min_new_docs);
    }

    let built_total = plan
        .manifest
        .as_ref()
        .map(|manifest| manifest.total_inserted_docs)
        .unwrap_or(0);
    let new_docs = plan.total_inserted_docs.saturating_sub(built_total);
    Ok(new_docs > 0 && new_docs >= min_new_docs)
}

/// Reads the next tree-level source-id reference entry from one sorted run.
pub(crate) fn read_next_tree_source_ref_entry(
    reader: &mut BufReader<fs::File>,
    identity_bytes: usize,
) -> Result<Option<TreeSourceRefEntry>> {
    let mut first = [0u8; 1];
    match reader.read(&mut first) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("single-byte read returned more than one byte"),
        Err(err) => return Err(err.into()),
    }

    let mut identity = vec![0u8; identity_bytes];
    identity[0] = first[0];
    if identity_bytes > 1 {
        reader.read_exact(&mut identity[1..])?;
    }

    let mut shard_idx = [0u8; 4];
    reader.read_exact(&mut shard_idx)?;
    let mut doc_id = [0u8; 8];
    reader.read_exact(&mut doc_id)?;
    Ok(Some(TreeSourceRefEntry {
        identity,
        shard_idx: u32::from_le_bytes(shard_idx),
        doc_id: u64::from_le_bytes(doc_id),
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ForestSourceRefHeapEntry {
    tree_idx: usize,
    entry: TreeSourceRefEntry,
}

impl Ord for ForestSourceRefHeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.entry
            .identity
            .cmp(&other.entry.identity)
            .then_with(|| self.tree_idx.cmp(&other.tree_idx))
            .then_with(|| self.entry.shard_idx.cmp(&other.entry.shard_idx))
            .then_with(|| self.entry.doc_id.cmp(&other.entry.doc_id))
    }
}

impl PartialOrd for ForestSourceRefHeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn flush_forest_source_ref_duplicate_group<F>(
    group: &mut Vec<(usize, TreeSourceRefEntry)>,
    duplicate_groups: &mut u64,
    deleted_docs: &mut u64,
    on_victim: &mut F,
) -> Result<()>
where
    F: FnMut(usize, &TreeSourceRefEntry) -> Result<()>,
{
    if group.len() <= 1 {
        group.clear();
        return Ok(());
    }

    group.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.shard_idx.cmp(&right.1.shard_idx))
            .then_with(|| left.1.doc_id.cmp(&right.1.doc_id))
    });

    *duplicate_groups = duplicate_groups.saturating_add(1);
    for (tree_idx, entry) in group.iter().skip(1).rev() {
        on_victim(*tree_idx, entry)?;
        *deleted_docs = deleted_docs.saturating_add(1);
    }
    group.clear();
    Ok(())
}

/// Streams duplicate victims from the current forest-wide tree source-ref files
/// in source-id order without materializing the full forest in memory. The
/// oldest tree, identified by the lowest sorted tree index, is kept.
pub(crate) fn for_each_forest_source_ref_duplicate_victim<F>(
    tree_roots: &[PathBuf],
    mut on_victim: F,
) -> Result<(u64, u64)>
where
    F: FnMut(usize, &TreeSourceRefEntry) -> Result<()>,
{
    if tree_roots.len() < 2 {
        return Ok((0, 0));
    }

    let mut readers = Vec::<Option<BufReader<fs::File>>>::with_capacity(tree_roots.len());
    let mut identity_bytes = None::<usize>;
    let mut heap = BinaryHeap::<Reverse<ForestSourceRefHeapEntry>>::new();
    for (tree_idx, tree_root) in tree_roots.iter().enumerate() {
        let manifest = read_tree_source_ref_manifest(tree_root)?.ok_or_else(|| {
            SspryError::from(format!(
                "tree source ref manifest missing at {}",
                tree_root.display()
            ))
        })?;
        let current_identity_bytes = manifest.identity_bytes;
        match identity_bytes {
            Some(expected) if expected != current_identity_bytes => {
                return Err(SspryError::from(format!(
                    "forest source ref identity width mismatch at {}",
                    tree_root.display()
                )));
            }
            None => identity_bytes = Some(current_identity_bytes),
            _ => {}
        }
        let path = tree_source_ref_path(tree_root);
        let mut reader = BufReader::new(fs::File::open(&path)?);
        if let Some(entry) = read_next_tree_source_ref_entry(&mut reader, current_identity_bytes)? {
            heap.push(Reverse(ForestSourceRefHeapEntry { tree_idx, entry }));
        }
        readers.push(Some(reader));
    }

    let Some(identity_bytes) = identity_bytes else {
        return Ok((0, 0));
    };

    let mut duplicate_groups = 0u64;
    let mut deleted_docs = 0u64;
    let mut current_group = Vec::<(usize, TreeSourceRefEntry)>::new();
    let mut current_identity = None::<Vec<u8>>;
    while let Some(Reverse(item)) = heap.pop() {
        if current_identity
            .as_ref()
            .is_some_and(|identity| identity != &item.entry.identity)
        {
            flush_forest_source_ref_duplicate_group(
                &mut current_group,
                &mut duplicate_groups,
                &mut deleted_docs,
                &mut on_victim,
            )?;
            current_identity = None;
        }
        if current_identity.is_none() {
            current_identity = Some(item.entry.identity.clone());
        }
        current_group.push((item.tree_idx, item.entry));

        if let Some(reader) = readers[item.tree_idx].as_mut() {
            if let Some(next_entry) = read_next_tree_source_ref_entry(reader, identity_bytes)? {
                heap.push(Reverse(ForestSourceRefHeapEntry {
                    tree_idx: item.tree_idx,
                    entry: next_entry,
                }));
            }
        }
    }
    flush_forest_source_ref_duplicate_group(
        &mut current_group,
        &mut duplicate_groups,
        &mut deleted_docs,
        &mut on_victim,
    )?;
    Ok((duplicate_groups, deleted_docs))
}

/// Writes one sorted run of tree-level source-id reference entries.
fn write_tree_source_ref_run(
    entries: &mut Vec<TreeSourceRefEntry>,
    run_path: &Path,
    identity_bytes: usize,
) -> Result<()> {
    entries.sort_unstable();
    let mut writer = BufWriter::new(fs::File::create(run_path)?);
    for entry in entries.iter() {
        if entry.identity.len() != identity_bytes {
            return Err(SspryError::from(format!(
                "tree source ref entry identity width mismatch at {}",
                run_path.display()
            )));
        }
        writer.write_all(&entry.identity)?;
        writer.write_all(&entry.shard_idx.to_le_bytes())?;
        writer.write_all(&entry.doc_id.to_le_bytes())?;
    }
    writer.flush()?;
    entries.clear();
    Ok(())
}

/// Flushes the current in-memory source-id reference chunk into one sorted run
/// on disk.
fn flush_tree_source_ref_run(
    entries: &mut Vec<TreeSourceRefEntry>,
    run_dir: &Path,
    run_paths: &mut Vec<PathBuf>,
    next_run_idx: &mut usize,
    identity_bytes: usize,
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let run_path = run_dir.join(format!("run_{:06}.bin", *next_run_idx));
    *next_run_idx = next_run_idx.saturating_add(1);
    write_tree_source_ref_run(entries, &run_path, identity_bytes)?;
    run_paths.push(run_path);
    Ok(())
}

/// Streams one shard's live documents into the current sorted-run builder while
/// validating the on-disk sidecar layout.
fn append_tree_source_ref_entries_from_shard(
    shard_root: &Path,
    shard_idx: u32,
    identity_bytes: usize,
    chunk_entries: &mut Vec<TreeSourceRefEntry>,
    run_dir: &Path,
    run_paths: &mut Vec<PathBuf>,
    next_run_idx: &mut usize,
    entry_count: &mut u64,
) -> Result<()> {
    if !sha_by_docid_path(shard_root).exists() || !doc_meta_path(shard_root).exists() {
        return Ok(());
    }

    let mut identity_file = fs::File::open(sha_by_docid_path(shard_root))?;
    let mut row_file = fs::File::open(doc_meta_path(shard_root))?;
    let identity_len = identity_file.metadata()?.len() as usize;
    let row_len = row_file.metadata()?.len() as usize;
    if identity_len % identity_bytes != 0 || row_len % DOC_META_ROW_BYTES != 0 {
        return Err(SspryError::from(format!(
            "Invalid candidate binary document state at {}",
            shard_root.display()
        )));
    }
    let doc_count = identity_len / identity_bytes;
    if doc_count != row_len / DOC_META_ROW_BYTES {
        return Err(SspryError::from(format!(
            "Mismatched candidate binary document state at {}",
            shard_root.display()
        )));
    }

    let mut row_bytes = [0u8; DOC_META_ROW_BYTES];
    for index in 0..doc_count {
        let mut identity = vec![0u8; identity_bytes];
        identity_file.read_exact(&mut identity)?;
        row_file.read_exact(&mut row_bytes)?;
        let row = DocMetaRow::decode(&row_bytes)?;
        if (row.flags & DOC_FLAG_DELETED) != 0 {
            continue;
        }
        chunk_entries.push(TreeSourceRefEntry {
            identity,
            shard_idx,
            doc_id: (index + 1) as u64,
        });
        *entry_count = entry_count.saturating_add(1);
        if chunk_entries.len() >= TREE_SOURCE_REF_RUN_MAX_ENTRIES {
            flush_tree_source_ref_run(
                chunk_entries,
                run_dir,
                run_paths,
                next_run_idx,
                identity_bytes,
            )?;
        }
    }
    Ok(())
}

/// Merges all sorted source-id reference runs into the final tree-level
/// reference file.
fn merge_tree_source_ref_runs(
    run_paths: &[PathBuf],
    identity_bytes: usize,
    output_path: &Path,
) -> Result<()> {
    let mut writer = BufWriter::new(fs::File::create(output_path)?);
    if run_paths.is_empty() {
        writer.flush()?;
        return Ok(());
    }

    let mut readers = Vec::with_capacity(run_paths.len());
    let mut heap = BinaryHeap::<Reverse<(TreeSourceRefEntry, usize)>>::new();
    for (run_idx, path) in run_paths.iter().enumerate() {
        let mut reader = BufReader::new(fs::File::open(path)?);
        if let Some(entry) = read_next_tree_source_ref_entry(&mut reader, identity_bytes)? {
            heap.push(Reverse((entry, run_idx)));
        }
        readers.push(reader);
    }

    while let Some(Reverse((entry, run_idx))) = heap.pop() {
        writer.write_all(&entry.identity)?;
        writer.write_all(&entry.shard_idx.to_le_bytes())?;
        writer.write_all(&entry.doc_id.to_le_bytes())?;
        if let Some(next_entry) =
            read_next_tree_source_ref_entry(&mut readers[run_idx], identity_bytes)?
        {
            heap.push(Reverse((next_entry, run_idx)));
        }
    }
    writer.flush()?;
    Ok(())
}

/// Builds the sorted tree-level source-id reference file used by future
/// forest-wide deduplication passes.
pub(crate) fn build_tree_source_ref(root: &Path) -> Result<TreeSourceRefBuildResult> {
    let plan = tree_source_ref_plan(root)?;
    let temp_root = root.join(".source_id_refs.tmp");
    let result = (|| {
        if temp_root.exists() {
            fs::remove_dir_all(&temp_root)?;
        }
        let run_dir = temp_root.join("runs");
        fs::create_dir_all(&run_dir)?;

        let mut chunk_entries = Vec::<TreeSourceRefEntry>::with_capacity(TREE_SOURCE_REF_RUN_MAX_ENTRIES);
        let mut run_paths = Vec::<PathBuf>::new();
        let mut next_run_idx = 0usize;
        let mut entry_count = 0u64;
        for shard_idx in 0..plan.candidate_shards {
            append_tree_source_ref_entries_from_shard(
                &candidate_shard_root(root, plan.candidate_shards, shard_idx),
                shard_idx as u32,
                plan.identity_bytes,
                &mut chunk_entries,
                &run_dir,
                &mut run_paths,
                &mut next_run_idx,
                &mut entry_count,
            )?;
        }
        flush_tree_source_ref_run(
            &mut chunk_entries,
            &run_dir,
            &mut run_paths,
            &mut next_run_idx,
            plan.identity_bytes,
        )?;

        let temp_output_path = temp_root.join("source_id_refs.sorted.bin");
        merge_tree_source_ref_runs(&run_paths, plan.identity_bytes, &temp_output_path)?;
        fs::rename(&temp_output_path, tree_source_ref_path(root))?;

        let manifest = TreeSourceRefManifest {
            version: TREE_SOURCE_REF_MANIFEST_VERSION,
            id_source: plan.id_source.clone(),
            identity_bytes: plan.identity_bytes,
            candidate_shards: plan.candidate_shards,
            entry_count,
            total_inserted_docs: plan.total_inserted_docs,
            last_built_unix_ms: Some(current_unix_ms_saturated()),
        };
        write_tree_source_ref_manifest(root, &manifest)?;

        Ok(TreeSourceRefBuildResult {
            entry_count,
            total_inserted_docs: plan.total_inserted_docs,
            candidate_shards: plan.candidate_shards,
            identity_bytes: plan.identity_bytes,
            id_source: plan.id_source,
        })
    })();
    let _ = fs::remove_dir_all(&temp_root);
    result
}

/// Persists the completion checkpoint for one forest-wide source-id
/// deduplication pass and returns the summarized result.
pub(crate) fn record_forest_source_dedup_pass(
    root: &Path,
    tree_roots: &[PathBuf],
    duplicate_groups: u64,
    deleted_docs: u64,
    affected_trees: usize,
) -> Result<ForestSourceDedupResult> {
    let plan = forest_source_dedup_plan(root, tree_roots)?;
    let manifest = ForestSourceDedupManifest {
        version: FOREST_SOURCE_DEDUP_MANIFEST_VERSION,
        id_source: plan.id_source.clone(),
        identity_bytes: plan.identity_bytes,
        tree_count: plan.tree_count,
        total_inserted_docs: plan.total_inserted_docs,
        last_built_unix_ms: Some(current_unix_ms_saturated()),
        last_duplicate_groups: duplicate_groups,
        last_deleted_docs: deleted_docs,
        last_affected_trees: affected_trees,
    };
    write_forest_source_dedup_manifest(root, &manifest)?;
    Ok(ForestSourceDedupResult {
        duplicate_groups,
        deleted_docs,
        affected_trees,
        total_inserted_docs: plan.total_inserted_docs,
        tree_count: plan.tree_count,
        identity_bytes: plan.identity_bytes,
        id_source: plan.id_source,
    })
}

#[cfg(test)]
/// Reads the tree-level source-id reference file back into decoded entries for
/// integration tests.
pub(crate) fn read_tree_source_ref_entries(root: &Path) -> Result<Vec<TreeSourceRefEntry>> {
    let manifest = read_tree_source_ref_manifest(root)?
        .ok_or_else(|| SspryError::from("tree source ref manifest missing"))?;
    let mut reader = BufReader::new(fs::File::open(tree_source_ref_path(root))?);
    let mut entries = Vec::with_capacity(manifest.entry_count as usize);
    while let Some(entry) = read_next_tree_source_ref_entry(&mut reader, manifest.identity_bytes)? {
        entries.push(entry);
    }
    Ok(entries)
}

impl CandidateStore {
    /// Creates an empty candidate store on disk and writes the initial metadata
    /// and append-only sidecar files.
    pub fn init(config: CandidateConfig, force: bool) -> Result<Self> {
        validate_config(&config)?;
        fs::create_dir_all(&config.root)?;
        let compaction_manifest_path = shard_compaction_manifest_path(&config.root);
        let policy_root = forest_policy_root(&config.root);
        fs::create_dir_all(&policy_root)?;
        let meta_path = forest_meta_path(&policy_root);
        let local_meta_path = store_local_meta_path(&config.root);
        let legacy_meta_path = forest_meta_path(&config.root);
        let sha_path = sha_by_docid_path(&config.root);
        let doc_meta_path = doc_meta_path(&config.root);
        let tier2_doc_meta_path = tier2_doc_meta_path(&config.root);
        let doc_metadata_path = doc_metadata_path(&config.root);
        let blooms_path = blooms_path(&config.root);
        let tier2_blooms_path = tier2_blooms_path(&config.root);
        let external_ids_path = external_ids_path(&config.root);
        if !force
            && (local_meta_path.exists()
                || legacy_meta_path.exists()
                || sha_path.exists()
                || doc_meta_path.exists()
                || tier2_doc_meta_path.exists()
                || doc_metadata_path.exists()
                || blooms_path.exists()
                || tier2_blooms_path.exists()
                || external_ids_path.exists())
        {
            return Err(SspryError::from(format!(
                "Candidate store already exists at {}. Use --force to overwrite.",
                config.root.display()
            )));
        }
        if force {
            if let Ok(manifest) = read_shard_compaction_manifest(&config.root) {
                for retired in manifest.retired_roots {
                    let retired_path = config
                        .root
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(retired);
                    let _ = fs::remove_dir_all(retired_path);
                }
            }
            let _ = fs::remove_file(&compaction_manifest_path);
            let _ = fs::remove_file(&meta_path);
            let _ = fs::remove_file(&local_meta_path);
            if legacy_meta_path != meta_path {
                let _ = fs::remove_file(&legacy_meta_path);
            }
            let _ = fs::remove_file(&sha_path);
            let _ = fs::remove_file(&doc_meta_path);
            let _ = fs::remove_file(&tier2_doc_meta_path);
            let _ = fs::remove_file(&doc_metadata_path);
            let _ = fs::remove_file(&blooms_path);
            let _ = fs::remove_file(&tier2_blooms_path);
            let _ = fs::remove_file(&external_ids_path);
        }

        let mut store = Self {
            root: config.root.clone(),
            meta: ForestMeta {
                version: STORE_VERSION,
                id_source: config.id_source.clone(),
                store_path: config.store_path,
                tier2_gram_size: config.tier2_gram_size,
                tier1_gram_size: config.tier1_gram_size,
                tier1_filter_target_fp: config.resolved_tier1_filter_target_fp(),
                tier2_filter_target_fp: config.resolved_tier2_filter_target_fp(),
                compaction_idle_cooldown_s: config.compaction_idle_cooldown_s.max(0.0),
                source_dedup_min_new_docs: config.source_dedup_min_new_docs.max(1),
            },
            local_meta: StoreLocalMeta::default(),
            docs: Vec::new(),
            doc_rows: Vec::new(),
            tier2_doc_rows: Vec::new(),
            sidecars: StoreSidecars::new(&config.root),
            append_writers: StoreAppendWriters::new(&config.root)?,
            identity_to_pos: HashMap::new(),
            special_doc_positions: Vec::new(),
            mutation_counter: 0,
            compaction_generation: 1,
            retired_generation_roots: Vec::new(),
            last_write_activity_monotonic: None,
            tier2_telemetry: Tier2Telemetry::default(),
            query_artifact_cache: BoundedCache::new(QUERY_ARTIFACT_CACHE_CAPACITY),
            memory_budget_bytes: 0,
            total_shards: 1,
            meta_persist_dirty: false,
            last_insert_batch_profile: CandidateInsertBatchProfile::default(),
            last_import_batch_profile: CandidateImportBatchProfile::default(),
        };
        store.persist_meta()?;
        write_shard_compaction_manifest(&config.root, &ShardCompactionManifest::default())?;
        Ok(store)
    }

    /// Opens an existing candidate store without returning the detailed open
    /// timing profile.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_profiled(root).map(|(store, _)| store)
    }

    /// Opens an existing candidate store, reloads persisted state, rebuilds
    /// in-memory indexes, and returns per-phase timing details.
    pub fn open_profiled(root: impl AsRef<Path>) -> Result<(Self, CandidateStoreOpenProfile)> {
        let root = root.as_ref().to_path_buf();
        let started_total = Instant::now();
        let manifest_started = Instant::now();
        let compaction_manifest = ensure_shard_compaction_manifest(&root)?;
        let manifest_ms = manifest_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let meta_started = Instant::now();
        let meta = load_forest_meta(&root)?;
        let local_meta = load_store_local_meta(&root)?;
        let meta_ms = meta_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let load_state_started = Instant::now();
        let (docs, doc_rows, tier2_doc_rows) = load_candidate_store_state(&root, &meta.id_source)?;
        let load_state_ms = load_state_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let sidecars_started = Instant::now();
        let mut store = Self {
            root: root.clone(),
            meta,
            local_meta,
            docs,
            doc_rows,
            tier2_doc_rows,
            sidecars: StoreSidecars::map_existing(root.as_path())?,
            append_writers: StoreAppendWriters::new(root.as_path())?,
            identity_to_pos: HashMap::new(),
            special_doc_positions: Vec::new(),
            mutation_counter: 0,
            compaction_generation: compaction_manifest.current_generation,
            retired_generation_roots: compaction_manifest.retired_roots,
            last_write_activity_monotonic: None,
            tier2_telemetry: Tier2Telemetry::default(),
            query_artifact_cache: BoundedCache::new(QUERY_ARTIFACT_CACHE_CAPACITY),
            memory_budget_bytes: 0,
            total_shards: 1,
            meta_persist_dirty: false,
            last_insert_batch_profile: CandidateInsertBatchProfile::default(),
            last_import_batch_profile: CandidateImportBatchProfile::default(),
        };
        let sidecars_ms = sidecars_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let normalized_next_doc_id = store.docs.len() as u64 + 1;
        if store.local_meta.next_doc_id != normalized_next_doc_id {
            store.local_meta.next_doc_id = normalized_next_doc_id;
            store.meta_persist_dirty = true;
        }
        let rebuild_profile = store.rebuild_indexes_profiled()?;
        let profile = CandidateStoreOpenProfile {
            doc_count: store.docs.len(),
            manifest_ms,
            meta_ms,
            load_state_ms,
            sidecars_ms,
            rebuild_indexes_ms: rebuild_profile.total_ms,
            rebuild_identity_index_ms: rebuild_profile.identity_index_ms,
            total_ms: started_total
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        };
        Ok((store, profile))
    }

    /// Applies process-local runtime limits that influence cache sizes and
    /// sharded execution without mutating on-disk store metadata.
    pub fn apply_runtime_limits(
        &mut self,
        memory_budget_bytes: u64,
        total_shards: usize,
    ) -> Result<()> {
        self.memory_budget_bytes = memory_budget_bytes;
        self.total_shards = total_shards.max(1);
        Ok(())
    }

    /// Reconstructs the user-facing configuration view from the current store
    /// metadata.
    pub fn config(&self) -> CandidateConfig {
        let tier1_filter_target_fp = self.meta.resolved_tier1_filter_target_fp();
        let tier2_filter_target_fp = self.meta.resolved_tier2_filter_target_fp();
        CandidateConfig {
            root: self.root.clone(),
            id_source: self.meta.id_source.clone(),
            store_path: self.meta.store_path,
            tier2_gram_size: self.meta.tier2_gram_size,
            tier1_gram_size: self.meta.tier1_gram_size,
            tier1_filter_target_fp,
            tier2_filter_target_fp,
            filter_target_fp: None,
            compaction_idle_cooldown_s: self.meta.compaction_idle_cooldown_s,
            source_dedup_min_new_docs: self.meta.source_dedup_min_new_docs,
        }
    }

    /// Retargets this instance to a different root after an on-disk move or
    /// compaction swap, updating sidecar and append writer paths as well.
    pub fn retarget_root(&mut self, root: impl AsRef<Path>) {
        let root = root.as_ref();
        self.root = root.to_path_buf();
        self.sidecars.retarget_root(root);
        self.append_writers.retarget_root(root);
    }

    /// Drops cached query-artifact state so later searches rebuild it from the
    /// current store contents.
    pub fn clear_search_caches(&mut self) {
        self.query_artifact_cache.clear();
    }

    /// Records a mutating operation, refreshes cooldown bookkeeping, and
    /// invalidates cached query artifacts.
    fn mark_write_activity(&mut self) {
        self.mutation_counter = self.mutation_counter.saturating_add(1);
        self.last_write_activity_monotonic = Some(Instant::now());
        self.query_artifact_cache.clear();
    }

    /// Tracks documents that belong to the special-population lane so they can
    /// be scanned separately from regular documents.
    fn remember_special_doc_position(&mut self, pos: usize) {
        if !self.special_doc_positions.contains(&pos) {
            self.special_doc_positions.push(pos);
        }
    }

    /// Returns true when at least one non-deleted document belongs to the
    /// special-population lane.
    fn has_live_special_docs(&self) -> bool {
        self.special_doc_positions.iter().any(|pos| {
            self.docs
                .get(*pos)
                .map(|doc| doc.special_population && !doc.deleted)
                .unwrap_or(false)
        })
    }

    /// Returns true when at least one non-deleted regular document is present.
    fn has_live_regular_docs(&self) -> bool {
        self.docs
            .iter()
            .any(|doc| !doc.deleted && !doc.special_population)
    }

    /// Estimates how many bytes are currently occupied by logically deleted
    /// documents across the persisted sidecar files.
    pub fn deleted_storage_bytes(&self) -> u64 {
        let mut total = 0u64;
        for ((row, tier2_row), doc) in self
            .doc_rows
            .iter()
            .zip(&self.tier2_doc_rows)
            .zip(&self.docs)
        {
            if !doc.deleted {
                continue;
            }
            total = total
                .saturating_add(32)
                .saturating_add(DOC_META_ROW_BYTES as u64)
                .saturating_add(TIER2_DOC_META_ROW_BYTES as u64)
                .saturating_add(row.bloom_len as u64)
                .saturating_add(tier2_row.bloom_len as u64)
                .saturating_add(row.metadata_len as u64)
                .saturating_add(row.external_id_len as u64);
        }
        total
    }

    /// Builds an immutable snapshot describing the live documents that should
    /// be copied into a compacted generation.
    pub(crate) fn prepare_compaction_snapshot(
        &self,
        force: bool,
    ) -> Result<Option<CandidateCompactionSnapshot>> {
        let reclaimed_docs = self.docs.iter().filter(|doc| doc.deleted).count();
        if reclaimed_docs == 0 {
            return Ok(None);
        }
        if !force && self.compaction_cooldown_remaining_s() > 0.0 {
            return Ok(None);
        }

        let mut live_docs = Vec::with_capacity(self.docs.len().saturating_sub(reclaimed_docs));
        for ((doc, row), tier2_row) in self
            .docs
            .iter()
            .zip(&self.doc_rows)
            .zip(&self.tier2_doc_rows)
        {
            if doc.deleted {
                continue;
            }
            live_docs.push(CompactionDocRef {
                identity: hex::decode(&doc.identity)?,
                file_size: doc.file_size,
                filter_bytes: doc.filter_bytes,
                bloom_hashes: doc.bloom_hashes,
                tier2_filter_bytes: doc.tier2_filter_bytes,
                tier2_bloom_hashes: doc.tier2_bloom_hashes,
                row: *row,
                tier2_row: *tier2_row,
            });
        }

        Ok(Some(CandidateCompactionSnapshot {
            root: self.root.clone(),
            meta: self.meta.clone(),
            mutation_counter: self.mutation_counter,
            current_generation: self.compaction_generation,
            live_docs,
            reclaimed_docs,
            reclaimed_bytes: self.deleted_storage_bytes(),
        }))
    }

    /// Installs a completed compacted generation if no intervening writes have
    /// occurred since the snapshot was prepared.
    pub(crate) fn apply_compaction_snapshot(
        &mut self,
        snapshot: &CandidateCompactionSnapshot,
        compacted_root: &Path,
    ) -> Result<Option<CandidateCompactionResult>> {
        if self.mutation_counter != snapshot.mutation_counter
            || self.compaction_generation != snapshot.current_generation
        {
            return Ok(None);
        }

        let root = self.root.clone();
        let retired_root = retired_generation_root(&root, snapshot.current_generation);
        if retired_root.exists() {
            let _ = fs::remove_dir_all(&retired_root);
        }

        let mut manifest = ShardCompactionManifest {
            current_generation: snapshot.current_generation.saturating_add(1),
            retired_roots: self.retired_generation_roots.clone(),
        };
        manifest.retired_roots.push(
            retired_root
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| retired_root.display().to_string()),
        );

        self.sidecars.invalidate_all();
        fs::rename(&root, &retired_root)?;
        if let Err(err) = fs::rename(compacted_root, &root) {
            let _ = fs::rename(&retired_root, &root);
            return Err(err.into());
        }
        if let Err(err) = write_shard_compaction_manifest(&root, &manifest) {
            let _ = fs::remove_dir_all(&root);
            let _ = fs::rename(&retired_root, &root);
            return Err(err);
        }

        let mut reopened = match CandidateStore::open(&root) {
            Ok(store) => store,
            Err(err) => {
                let _ = fs::remove_dir_all(&root);
                let _ = fs::rename(&retired_root, &root);
                return Err(err);
            }
        };
        if let Err(err) = reopened.apply_runtime_limits(self.memory_budget_bytes, self.total_shards)
        {
            let _ = fs::remove_dir_all(&root);
            let _ = fs::rename(&retired_root, &root);
            return Err(err);
        }
        *self = reopened;

        Ok(Some(CandidateCompactionResult {
            reclaimed_docs: snapshot.reclaimed_docs,
            reclaimed_bytes: snapshot.reclaimed_bytes,
        }))
    }

    /// Removes retired generation directories that are no longer needed after a
    /// successful compaction swap.
    pub(crate) fn garbage_collect_retired_generations(&mut self) -> Result<usize> {
        if self.retired_generation_roots.is_empty() {
            return Ok(0);
        }
        let parent = self.root.parent().unwrap_or_else(|| Path::new("."));
        let mut kept = Vec::with_capacity(self.retired_generation_roots.len());
        let mut removed = 0usize;
        for retired in &self.retired_generation_roots {
            let path = parent.join(retired);
            match fs::remove_dir_all(&path) {
                Ok(()) => removed = removed.saturating_add(1),
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    removed = removed.saturating_add(1);
                }
                Err(_) => kept.push(retired.clone()),
            }
        }
        if removed > 0 {
            self.retired_generation_roots = kept.clone();
            write_shard_compaction_manifest(
                &self.root,
                &ShardCompactionManifest {
                    current_generation: self.compaction_generation,
                    retired_roots: kept,
                },
            )?;
        }
        Ok(removed)
    }

    /// Reports whether background compaction has pending work for this store
    /// and, if so, how long the worker should wait before trying again.
    pub(crate) fn pending_compaction_wait(&self) -> Option<Duration> {
        if !self.docs.iter().any(|doc| doc.deleted) {
            return None;
        }
        let remaining_s = self.compaction_cooldown_remaining_s();
        if remaining_s <= 0.0 {
            return Some(Duration::ZERO);
        }
        Some(Duration::from_secs_f64(remaining_s))
    }

    /// Reports how much longer automatic compaction should wait for the store
    /// to remain idle.
    fn compaction_cooldown_remaining_s(&self) -> f64 {
        let cooldown_s = self.meta.compaction_idle_cooldown_s.max(0.0);
        if cooldown_s <= 0.0 {
            return 0.0;
        }
        let Some(last_write) = self.last_write_activity_monotonic else {
            return 0.0;
        };
        (cooldown_s - last_write.elapsed().as_secs_f64()).max(0.0)
    }

    /// Chooses the tier-1 bloom size for a document using the configured false
    /// positive target and optional item-count estimate.
    fn resolve_tier1_filter_bytes_for_file_size(
        &self,
        file_size: u64,
        bloom_item_estimate: Option<usize>,
    ) -> Result<usize> {
        choose_filter_bytes_for_file_size(
            file_size,
            DEFAULT_FILTER_BYTES,
            Some(DEFAULT_FILTER_MIN_BYTES),
            Some(DEFAULT_FILTER_MAX_BYTES),
            self.meta.resolved_tier1_filter_target_fp(),
            bloom_item_estimate,
        )
    }

    /// Chooses the tier-2 bloom size for a document using the configured false
    /// positive target and optional item-count estimate.
    fn resolve_tier2_filter_bytes_for_file_size(
        &self,
        file_size: u64,
        bloom_item_estimate: Option<usize>,
    ) -> Result<usize> {
        choose_filter_bytes_for_file_size(
            file_size,
            DEFAULT_FILTER_BYTES,
            Some(DEFAULT_FILTER_MIN_BYTES),
            Some(DEFAULT_FILTER_MAX_BYTES),
            self.meta.resolved_tier2_filter_target_fp(),
            bloom_item_estimate,
        )
    }

    #[cfg(test)]
    /// Test-only wrapper that exposes the tier-1 sizing policy directly.
    pub(crate) fn resolve_filter_bytes_for_file_size(
        &self,
        file_size: u64,
        bloom_item_estimate: Option<usize>,
    ) -> Result<usize> {
        self.resolve_tier1_filter_bytes_for_file_size(file_size, bloom_item_estimate)
    }

    /// Derives the bloom hash count for a document from the effective filter
    /// size and optional item-count estimate.
    fn resolve_bloom_hashes_for_document(
        &self,
        filter_bytes: usize,
        bloom_item_estimate: Option<usize>,
        bloom_hashes: Option<usize>,
    ) -> usize {
        derive_document_bloom_hash_count(
            filter_bytes,
            bloom_item_estimate,
            bloom_hashes.unwrap_or(DEFAULT_BLOOM_HASHES),
        )
    }

    /// Inserts or restores one document when the caller already prepared the
    /// tier-1 and tier-2 bloom payloads.
    pub fn insert_document<I>(
        &mut self,
        identity: I,
        file_size: u64,
        bloom_item_estimate: Option<usize>,
        bloom_hashes: Option<usize>,
        tier2_bloom_item_estimate: Option<usize>,
        tier2_bloom_hashes: Option<usize>,
        filter_bytes: usize,
        bloom_filter: &[u8],
        tier2_filter_bytes: usize,
        tier2_bloom_filter: &[u8],
        external_id: Option<String>,
    ) -> Result<CandidateInsertResult>
    where
        I: Into<Vec<u8>>,
    {
        self.insert_document_with_metadata(
            identity,
            file_size,
            bloom_item_estimate,
            bloom_hashes,
            tier2_bloom_item_estimate,
            tier2_bloom_hashes,
            filter_bytes,
            bloom_filter,
            tier2_filter_bytes,
            tier2_bloom_filter,
            &[],
            false,
            external_id,
        )
    }

    /// Inserts or restores one document, validating bloom sizing rules and
    /// persisting optional metadata and external identifiers alongside it.
    pub fn insert_document_with_metadata<I>(
        &mut self,
        identity: I,
        file_size: u64,
        bloom_item_estimate: Option<usize>,
        bloom_hashes: Option<usize>,
        tier2_bloom_item_estimate: Option<usize>,
        tier2_bloom_hashes: Option<usize>,
        filter_bytes: usize,
        bloom_filter: &[u8],
        tier2_filter_bytes: usize,
        tier2_bloom_filter: &[u8],
        metadata: &[u8],
        special_population: bool,
        external_id: Option<String>,
    ) -> Result<CandidateInsertResult>
    where
        I: Into<Vec<u8>>,
    {
        let mut total_scope = scope("candidate.insert_document");
        total_scope.add_bytes(file_size);
        let identity = identity.into();
        if filter_bytes == 0 {
            return Err(SspryError::from("filter_bytes must be > 0"));
        }
        let expected_filter_bytes =
            self.resolve_tier1_filter_bytes_for_file_size(file_size, bloom_item_estimate)?;
        let expected_bloom_hashes = self.resolve_bloom_hashes_for_document(
            expected_filter_bytes,
            bloom_item_estimate,
            bloom_hashes,
        );
        if filter_bytes != expected_filter_bytes {
            return Err(SspryError::from(format!(
                "filter_bytes must equal expected filter size ({expected_filter_bytes})"
            )));
        }
        if bloom_filter.len() != expected_filter_bytes {
            return Err(SspryError::from(format!(
                "bloom_filter length must equal filter_bytes ({expected_filter_bytes})"
            )));
        }
        let expected_tier2_filter_bytes =
            self.resolve_tier2_filter_bytes_for_file_size(file_size, tier2_bloom_item_estimate)?;
        let expected_tier2_bloom_hashes = self.resolve_bloom_hashes_for_document(
            expected_tier2_filter_bytes,
            tier2_bloom_item_estimate,
            tier2_bloom_hashes,
        );
        if !tier2_bloom_filter.is_empty() {
            if tier2_filter_bytes != expected_tier2_filter_bytes {
                return Err(SspryError::from(format!(
                    "tier2_filter_bytes must equal expected filter size ({expected_tier2_filter_bytes})"
                )));
            }
            if tier2_bloom_filter.len() != expected_tier2_filter_bytes {
                return Err(SspryError::from(format!(
                    "tier2_bloom_filter length must equal tier2_filter_bytes ({expected_tier2_filter_bytes})"
                )));
            }
        }
        let identity_hex = hex::encode(&identity);

        // Bloom-only ingest only needs the per-document bloom payloads here.
        let status;
        let doc_id;
        if let Some(existing_pos) = self.identity_to_pos.get(&identity_hex).copied() {
            if !self.docs[existing_pos].deleted {
                let existing = &self.docs[existing_pos];
                return Ok(CandidateInsertResult {
                    status: "already_exists".to_owned(),
                    doc_id: existing.doc_id,
                    identity: existing.identity.clone(),
                });
            }
            let snapshot = {
                let existing = &mut self.docs[existing_pos];
                existing.file_size = file_size;
                existing.filter_bytes = filter_bytes;
                existing.bloom_hashes = expected_bloom_hashes;
                existing.tier2_filter_bytes = tier2_filter_bytes;
                existing.tier2_bloom_hashes = if tier2_bloom_filter.is_empty() {
                    0
                } else {
                    expected_tier2_bloom_hashes
                };
                existing.special_population = special_population;
                existing.deleted = false;
                existing.clone()
            };
            let row = self.build_doc_row(
                snapshot.file_size,
                snapshot.filter_bytes,
                snapshot.bloom_hashes,
                snapshot.deleted,
                snapshot.special_population,
                metadata,
                external_id.as_deref(),
                bloom_filter,
            )?;
            let tier2_row = self.build_tier2_doc_row(
                snapshot.tier2_filter_bytes,
                snapshot.tier2_bloom_hashes,
                tier2_bloom_filter,
            )?;
            status = "restored".to_owned();
            doc_id = snapshot.doc_id;
            {
                let _scope = scope("candidate.insert_document.persist");
                self.doc_rows[existing_pos] = row;
                self.tier2_doc_rows[existing_pos] = tier2_row;
                self.write_doc_row(snapshot.doc_id, row)?;
                self.write_tier2_doc_row(snapshot.doc_id, tier2_row)?;
            }
            if snapshot.special_population {
                self.remember_special_doc_position(existing_pos);
            }
        } else {
            doc_id = self.local_meta.next_doc_id;
            self.local_meta.next_doc_id += 1;
            let doc = CandidateDoc {
                doc_id,
                identity: identity_hex.clone(),
                file_size,
                filter_bytes,
                bloom_hashes: expected_bloom_hashes,
                tier2_filter_bytes,
                tier2_bloom_hashes: if tier2_bloom_filter.is_empty() {
                    0
                } else {
                    expected_tier2_bloom_hashes
                },
                special_population,
                deleted: false,
            };
            {
                let _scope = scope("candidate.insert_document.persist");
                let row = self.build_doc_row(
                    doc.file_size,
                    doc.filter_bytes,
                    doc.bloom_hashes,
                    doc.deleted,
                    doc.special_population,
                    metadata,
                    external_id.as_deref(),
                    bloom_filter,
                )?;
                let tier2_row = self.build_tier2_doc_row(
                    doc.tier2_filter_bytes,
                    doc.tier2_bloom_hashes,
                    tier2_bloom_filter,
                )?;
                self.mark_meta_dirty();
                self.append_new_doc(&identity, row, tier2_row)?;
                self.doc_rows.push(row);
                self.tier2_doc_rows.push(tier2_row);
            }
            self.docs.push(doc.clone());
            let new_pos = self.docs.len() - 1;
            self.identity_to_pos.insert(identity_hex.clone(), new_pos);
            if doc.special_population {
                self.remember_special_doc_position(new_pos);
            }
            status = "inserted".to_owned();
        }

        self.sidecars.invalidate_all();

        self.mark_write_activity();
        Ok(CandidateInsertResult {
            status,
            doc_id,
            identity: identity_hex,
        })
    }

    /// Inserts or restores a batch of documents while amortizing append-only
    /// sidecar writes and collecting batch profiling metrics.
    pub fn insert_documents_batch(
        &mut self,
        documents: &[(
            Vec<u8>,
            u64,
            Option<usize>,
            Option<usize>,
            Option<usize>,
            Option<usize>,
            usize,
            Vec<u8>,
            usize,
            Vec<u8>,
            Vec<u8>,
            bool,
            Option<String>,
        )],
    ) -> Result<Vec<CandidateInsertResult>> {
        struct PendingNewInsert<'a> {
            identity: &'a [u8],
            identity_hex: String,
            doc: CandidateDoc,
            metadata: &'a [u8],
            external_id: Option<&'a str>,
            bloom_filter: &'a [u8],
            tier2_bloom_filter: &'a [u8],
        }

        let mut total_scope = scope("candidate.insert_documents_batch");
        let mut results = Vec::with_capacity(documents.len());
        let mut modified = false;
        let mut meta_dirty = false;
        let mut insert_profile = CandidateInsertBatchProfile::default();
        let mut tier2_updates = Vec::<(usize, usize, usize, &[u8])>::with_capacity(documents.len());
        let mut tier2_pattern_updates =
            Vec::<(usize, usize, usize, &[u8])>::with_capacity(documents.len());
        let mut pending_new_inserts = Vec::<PendingNewInsert<'_>>::new();

        for document in documents {
            let (
                identity,
                file_size,
                bloom_item_estimate,
                bloom_hashes,
                tier2_bloom_item_estimate,
                tier2_bloom_hashes,
                filter_bytes,
                bloom_filter,
                tier2_filter_bytes,
                tier2_bloom_filter,
                metadata,
                special_population,
                external_id,
            ) = document;
            total_scope.add_bytes(*file_size);
            if *filter_bytes == 0 {
                return Err(SspryError::from("filter_bytes must be > 0"));
            }
            let expected_filter_bytes =
                self.resolve_tier1_filter_bytes_for_file_size(*file_size, *bloom_item_estimate)?;
            let expected_bloom_hashes = self.resolve_bloom_hashes_for_document(
                expected_filter_bytes,
                *bloom_item_estimate,
                *bloom_hashes,
            );
            if *filter_bytes != expected_filter_bytes {
                self.last_insert_batch_profile = insert_profile;
                return Err(SspryError::from(format!(
                    "filter_bytes must equal expected filter size ({expected_filter_bytes})"
                )));
            }
            if bloom_filter.len() != expected_filter_bytes {
                self.last_insert_batch_profile = insert_profile;
                return Err(SspryError::from(format!(
                    "bloom_filter length must equal filter_bytes ({expected_filter_bytes})"
                )));
            }
            let expected_tier2_filter_bytes = self
                .resolve_tier2_filter_bytes_for_file_size(*file_size, *tier2_bloom_item_estimate)?;
            let expected_tier2_bloom_hashes = self.resolve_bloom_hashes_for_document(
                expected_tier2_filter_bytes,
                *tier2_bloom_item_estimate,
                *tier2_bloom_hashes,
            );
            if !tier2_bloom_filter.is_empty() {
                if *tier2_filter_bytes != expected_tier2_filter_bytes {
                    self.last_insert_batch_profile = insert_profile;
                    return Err(SspryError::from(format!(
                        "tier2_filter_bytes must equal expected filter size ({expected_tier2_filter_bytes})"
                    )));
                }
                if tier2_bloom_filter.len() != expected_tier2_filter_bytes {
                    self.last_insert_batch_profile = insert_profile;
                    return Err(SspryError::from(format!(
                        "tier2_bloom_filter length must equal tier2_filter_bytes ({expected_tier2_filter_bytes})"
                    )));
                }
            }

            let resolve_doc_state_started = Instant::now();
            let identity_hex = hex::encode(identity);
            let _ = bloom_item_estimate;

            if let Some(existing_pos) = self.identity_to_pos.get(&identity_hex).copied() {
                if !self.docs[existing_pos].deleted {
                    let existing = &self.docs[existing_pos];
                    results.push(CandidateInsertResult {
                        status: "already_exists".to_owned(),
                        doc_id: existing.doc_id,
                        identity: existing.identity.clone(),
                    });
                    insert_profile.resolve_doc_state_us = insert_profile
                        .resolve_doc_state_us
                        .saturating_add(elapsed_us(resolve_doc_state_started));
                    continue;
                }

                insert_profile.resolve_doc_state_us = insert_profile
                    .resolve_doc_state_us
                    .saturating_add(elapsed_us(resolve_doc_state_started));
                let write_existing_started = Instant::now();
                let snapshot = {
                    let existing = &mut self.docs[existing_pos];
                    existing.file_size = *file_size;
                    existing.filter_bytes = *filter_bytes;
                    existing.bloom_hashes = expected_bloom_hashes;
                    existing.tier2_filter_bytes = *tier2_filter_bytes;
                    existing.tier2_bloom_hashes = if tier2_bloom_filter.is_empty() {
                        0
                    } else {
                        expected_tier2_bloom_hashes
                    };
                    existing.special_population = *special_population;
                    existing.deleted = false;
                    existing.clone()
                };
                let row = self.build_doc_row(
                    snapshot.file_size,
                    snapshot.filter_bytes,
                    snapshot.bloom_hashes,
                    snapshot.deleted,
                    snapshot.special_population,
                    metadata,
                    external_id.as_deref(),
                    bloom_filter,
                )?;
                let tier2_row = self.build_tier2_doc_row(
                    snapshot.tier2_filter_bytes,
                    snapshot.tier2_bloom_hashes,
                    tier2_bloom_filter,
                )?;
                self.doc_rows[existing_pos] = row;
                self.tier2_doc_rows[existing_pos] = tier2_row;
                self.write_doc_row(snapshot.doc_id, row)?;
                self.write_tier2_doc_row(snapshot.doc_id, tier2_row)?;
                insert_profile.write_existing_us = insert_profile
                    .write_existing_us
                    .saturating_add(elapsed_us(write_existing_started));
                if !snapshot.special_population {
                    tier2_updates.push((
                        existing_pos,
                        *filter_bytes,
                        expected_bloom_hashes,
                        bloom_filter,
                    ));
                }
                if !snapshot.special_population && !tier2_bloom_filter.is_empty() {
                    tier2_pattern_updates.push((
                        existing_pos,
                        *tier2_filter_bytes,
                        expected_tier2_bloom_hashes,
                        tier2_bloom_filter,
                    ));
                }
                modified = true;
                results.push(CandidateInsertResult {
                    status: "restored".to_owned(),
                    doc_id: snapshot.doc_id,
                    identity: identity_hex,
                });
                continue;
            }

            insert_profile.resolve_doc_state_us = insert_profile
                .resolve_doc_state_us
                .saturating_add(elapsed_us(resolve_doc_state_started));
            let doc_id = self.local_meta.next_doc_id;
            self.local_meta.next_doc_id += 1;
            let doc = CandidateDoc {
                doc_id,
                identity: identity_hex.clone(),
                file_size: *file_size,
                filter_bytes: *filter_bytes,
                bloom_hashes: expected_bloom_hashes,
                tier2_filter_bytes: *tier2_filter_bytes,
                tier2_bloom_hashes: if tier2_bloom_filter.is_empty() {
                    0
                } else {
                    expected_tier2_bloom_hashes
                },
                special_population: *special_population,
                deleted: false,
            };
            modified = true;
            meta_dirty = true;
            results.push(CandidateInsertResult {
                status: "inserted".to_owned(),
                doc_id,
                identity: identity_hex,
            });
            pending_new_inserts.push(PendingNewInsert {
                identity: identity.as_slice(),
                identity_hex: doc.identity.clone(),
                doc,
                metadata,
                external_id: external_id.as_deref(),
                bloom_filter,
                tier2_bloom_filter,
            });
        }

        if !pending_new_inserts.is_empty() {
            let append_sidecars_started = Instant::now();
            let bloom_base = self.append_writers.blooms.offset;
            let tier2_bloom_base = self.append_writers.tier2_blooms.offset;
            let bloom_total_bytes = pending_new_inserts
                .iter()
                .map(|pending| pending.bloom_filter.len())
                .sum::<usize>();
            let tier2_bloom_total_bytes = pending_new_inserts
                .iter()
                .map(|pending| pending.tier2_bloom_filter.len())
                .sum::<usize>();
            let mut blooms_payload = Vec::<u8>::with_capacity(bloom_total_bytes);
            let mut tier2_blooms_payload = Vec::<u8>::with_capacity(tier2_bloom_total_bytes);
            let mut sha_by_docid_payload =
                Vec::<u8>::with_capacity(pending_new_inserts.len() * self.identity_bytes_len());
            let mut doc_meta_payload =
                Vec::<u8>::with_capacity(pending_new_inserts.len() * DOC_META_ROW_BYTES);
            let mut tier2_doc_meta_payload =
                Vec::<u8>::with_capacity(pending_new_inserts.len() * TIER2_DOC_META_ROW_BYTES);
            let mut bloom_offsets = Vec::<u64>::with_capacity(pending_new_inserts.len());
            let mut tier2_bloom_offsets = Vec::<u64>::with_capacity(pending_new_inserts.len());
            let assemble_bloom_payloads_started = Instant::now();
            for pending in &pending_new_inserts {
                bloom_offsets.push(bloom_base + blooms_payload.len() as u64);
                blooms_payload.extend_from_slice(pending.bloom_filter);
                if pending.tier2_bloom_filter.is_empty() {
                    tier2_bloom_offsets.push(0);
                } else {
                    tier2_bloom_offsets.push(tier2_bloom_base + tier2_blooms_payload.len() as u64);
                    tier2_blooms_payload.extend_from_slice(pending.tier2_bloom_filter);
                }
            }
            insert_profile.append_bloom_payload_assemble_us = insert_profile
                .append_bloom_payload_assemble_us
                .saturating_add(elapsed_us(assemble_bloom_payloads_started));
            let append_bloom_started = Instant::now();
            self.append_writers.blooms.append(&blooms_payload)?;
            insert_profile.append_bloom_payload_us = insert_profile
                .append_bloom_payload_us
                .saturating_add(elapsed_us(append_bloom_started));
            insert_profile.append_bloom_payload_bytes = insert_profile
                .append_bloom_payload_bytes
                .saturating_add(bloom_total_bytes as u64);
            let append_tier2_bloom_started = Instant::now();
            self.append_writers
                .tier2_blooms
                .append(&tier2_blooms_payload)?;
            insert_profile.append_tier2_bloom_payload_us = insert_profile
                .append_tier2_bloom_payload_us
                .saturating_add(elapsed_us(append_tier2_bloom_started));
            insert_profile.append_tier2_bloom_payload_bytes = insert_profile
                .append_tier2_bloom_payload_bytes
                .saturating_add(tier2_bloom_total_bytes as u64);

            let mut prepared_rows =
                Vec::<(PendingNewInsert<'_>, DocMetaRow, Tier2DocMetaRow)>::with_capacity(
                    bloom_offsets.len(),
                );
            for ((pending, bloom_offset), tier2_bloom_offset) in pending_new_inserts
                .into_iter()
                .zip(bloom_offsets.into_iter())
                .zip(tier2_bloom_offsets.into_iter())
            {
                let build_doc_row_started = Instant::now();
                let (row, row_profile) = self.build_doc_row_with_bloom_offset_profile(
                    pending.doc.file_size,
                    pending.doc.filter_bytes,
                    pending.doc.bloom_hashes,
                    pending.doc.deleted,
                    pending.doc.special_population,
                    pending.metadata,
                    pending.external_id,
                    bloom_offset,
                    pending.bloom_filter.len(),
                )?;
                insert_profile.append_doc_row_build_us = insert_profile
                    .append_doc_row_build_us
                    .saturating_add(elapsed_us(build_doc_row_started));
                let tier2_row = if pending.tier2_bloom_filter.is_empty() {
                    Tier2DocMetaRow::default()
                } else {
                    Tier2DocMetaRow {
                        filter_bytes: pending.doc.tier2_filter_bytes as u32,
                        bloom_hashes: pending.doc.tier2_bloom_hashes.min(u8::MAX as usize) as u8,
                        bloom_offset: tier2_bloom_offset,
                        bloom_len: pending.tier2_bloom_filter.len() as u32,
                    }
                };
                insert_profile.append_metadata_payload_us = insert_profile
                    .append_metadata_payload_us
                    .saturating_add(row_profile.metadata_us);
                insert_profile.append_metadata_payload_bytes = insert_profile
                    .append_metadata_payload_bytes
                    .saturating_add(row_profile.metadata_bytes);
                insert_profile.append_external_id_payload_us = insert_profile
                    .append_external_id_payload_us
                    .saturating_add(row_profile.external_id_us);
                insert_profile.append_external_id_payload_bytes = insert_profile
                    .append_external_id_payload_bytes
                    .saturating_add(row_profile.external_id_bytes);
                sha_by_docid_payload.extend_from_slice(pending.identity);
                doc_meta_payload.extend_from_slice(&row.encode());
                tier2_doc_meta_payload.extend_from_slice(&tier2_row.encode());
                prepared_rows.push((pending, row, tier2_row));
            }

            let append_doc_records_started = Instant::now();
            self.append_writers
                .sha_by_docid
                .append(&sha_by_docid_payload)?;
            self.append_writers.doc_meta.append(&doc_meta_payload)?;
            self.append_writers
                .tier2_doc_meta
                .append(&tier2_doc_meta_payload)?;
            insert_profile.append_doc_records_us = insert_profile
                .append_doc_records_us
                .saturating_add(elapsed_us(append_doc_records_started));

            for (pending, row, tier2_row) in prepared_rows {
                let install_docs_started = Instant::now();
                let pos = self.docs.len();
                self.doc_rows.push(row);
                self.tier2_doc_rows.push(tier2_row);
                self.docs.push(pending.doc.clone());
                self.identity_to_pos.insert(pending.identity_hex, pos);
                if pending.doc.special_population {
                    self.remember_special_doc_position(pos);
                }
                insert_profile.install_docs_us = insert_profile
                    .install_docs_us
                    .saturating_add(elapsed_us(install_docs_started));
                if !pending.doc.special_population {
                    tier2_updates.push((
                        pos,
                        pending.doc.filter_bytes,
                        pending.doc.bloom_hashes,
                        pending.bloom_filter,
                    ));
                }
                if !pending.doc.special_population && !pending.tier2_bloom_filter.is_empty() {
                    tier2_pattern_updates.push((
                        pos,
                        pending.doc.tier2_filter_bytes,
                        pending.doc.tier2_bloom_hashes,
                        pending.tier2_bloom_filter,
                    ));
                }
            }
            insert_profile.append_sidecar_payloads_us =
                insert_profile.append_sidecar_payloads_us.saturating_add(
                    insert_profile
                        .append_bloom_payload_us
                        .saturating_add(insert_profile.append_external_id_payload_us)
                        .saturating_add(insert_profile.append_tier2_bloom_payload_us),
                );
            insert_profile.append_sidecars_us = insert_profile
                .append_sidecars_us
                .saturating_add(elapsed_us(append_sidecars_started));
        }

        if modified {
            let tier2_update_started = Instant::now();
            insert_profile.tier2_update_us = insert_profile
                .tier2_update_us
                .saturating_add(elapsed_us(tier2_update_started));
            if meta_dirty {
                self.mark_meta_dirty();
            }
            self.sidecars.invalidate_all();
            self.mark_write_activity();
        }
        self.last_insert_batch_profile = insert_profile;
        Ok(results)
    }

    /// Marks one document as deleted and persists the deleted flag in the
    /// fixed-width metadata row.
    pub fn delete_document(&mut self, identity_hex: &str) -> Result<CandidateDeleteResult> {
        let _scope = scope("candidate.delete_document");
        let normalized =
            normalize_identity_hex(identity_hex, self.identity_bytes_len(), &self.meta.id_source)?;
        if let Some(pos) = self.identity_to_pos.get(&normalized).copied() {
            return self.delete_document_at_position(pos, normalized);
        }
        Ok(CandidateDeleteResult {
            status: "missing".to_owned(),
            identity: normalized,
            doc_id: None,
        })
    }

    /// Marks one specific document pointer as deleted, validating that the
    /// pointed row still matches the expected identity before mutating it.
    pub(crate) fn delete_document_by_pointer(
        &mut self,
        doc_id: u64,
        expected_identity_hex: &str,
    ) -> Result<CandidateDeleteResult> {
        let _scope = scope("candidate.delete_document_by_pointer");
        let normalized = normalize_identity_hex(
            expected_identity_hex,
            self.identity_bytes_len(),
            &self.meta.id_source,
        )?;
        let Some(pos) = self.document_position_for_doc_id(doc_id) else {
            return Ok(CandidateDeleteResult {
                status: "missing".to_owned(),
                identity: normalized,
                doc_id: None,
            });
        };
        if self.docs[pos].identity != normalized {
            return Ok(CandidateDeleteResult {
                status: "missing".to_owned(),
                identity: normalized,
                doc_id: None,
            });
        }
        self.delete_document_at_position(pos, normalized)
    }

    /// Resolves one document id back to its in-memory slot. The fast path uses
    /// the append-order invariant, with a linear fallback for any future layout
    /// that breaks that assumption.
    fn document_position_for_doc_id(&self, doc_id: u64) -> Option<usize> {
        let fast_pos = doc_id
            .checked_sub(1)
            .and_then(|value| usize::try_from(value).ok());
        if let Some(pos) = fast_pos {
            if self.docs.get(pos).is_some_and(|doc| doc.doc_id == doc_id) {
                return Some(pos);
            }
        }
        self.docs.iter().position(|doc| doc.doc_id == doc_id)
    }

    /// Applies the persistent deleted flag to one already-resolved document
    /// slot.
    fn delete_document_at_position(
        &mut self,
        pos: usize,
        normalized_identity: String,
    ) -> Result<CandidateDeleteResult> {
        if self.docs[pos].deleted {
            return Ok(CandidateDeleteResult {
                status: "missing".to_owned(),
                identity: normalized_identity,
                doc_id: None,
            });
        }
        let snapshot = {
            let doc = &mut self.docs[pos];
            doc.deleted = true;
            doc.clone()
        };
        let result = CandidateDeleteResult {
            status: "deleted".to_owned(),
            identity: snapshot.identity.clone(),
            doc_id: Some(snapshot.doc_id),
        };
        let mut row = self.doc_rows[pos];
        row.flags |= DOC_FLAG_DELETED;
        self.doc_rows[pos] = row;
        self.write_doc_row(snapshot.doc_id, row)?;
        self.mark_write_activity();
        record_counter("candidate.delete_document_deleted_total", 1);
        Ok(result)
    }

    /// Materializes every live document into an importable batch representation
    /// including bloom payloads, metadata, and external ids.
    pub fn export_live_documents(&mut self) -> Result<Vec<ImportedCandidateDocument>> {
        self.sidecars.refresh_maps()?;
        let mut out = Vec::with_capacity(self.docs.len());
        for pos in 0..self.docs.len() {
            let doc = &self.docs[pos];
            if doc.deleted {
                continue;
            }
            out.push(ImportedCandidateDocument {
                identity: hex::decode(&doc.identity)?,
                identity_hex: doc.identity.clone(),
                file_size: doc.file_size,
                filter_bytes: doc.filter_bytes,
                bloom_hashes: doc.bloom_hashes,
                tier2_filter_bytes: doc.tier2_filter_bytes,
                tier2_bloom_hashes: doc.tier2_bloom_hashes,
                bloom_filter: self.doc_bloom_bytes(pos)?.into_owned(),
                tier2_bloom_filter: self.doc_tier2_bloom_bytes(pos)?.into_owned(),
                special_population: doc.special_population,
                metadata_bytes: self.doc_metadata_bytes(pos)?.into_owned(),
                external_id: self.doc_external_id(pos)?,
            });
        }
        Ok(out)
    }

    /// Imports a batch of exported documents, deduplicating against existing
    /// live entries and returning per-document results.
    pub fn import_documents_batch(
        &mut self,
        documents: &[ImportedCandidateDocument],
    ) -> Result<Vec<CandidateInsertResult>> {
        self.import_documents_batch_impl(documents, false, true)
    }

    /// Imports a batch of exported documents while assuming they are all new,
    /// avoiding duplicate checks where the caller can guarantee uniqueness.
    pub fn import_documents_batch_known_new(
        &mut self,
        documents: &[ImportedCandidateDocument],
    ) -> Result<Vec<CandidateInsertResult>> {
        self.import_documents_batch_impl(documents, true, true)
    }

    /// Imports a batch of exported documents while suppressing per-document
    /// results.
    pub fn import_documents_batch_quiet(
        &mut self,
        documents: &[ImportedCandidateDocument],
    ) -> Result<()> {
        let _ = self.import_documents_batch_impl(documents, false, false)?;
        Ok(())
    }

    /// Quiet variant of `import_documents_batch_known_new`.
    pub fn import_documents_batch_known_new_quiet(
        &mut self,
        documents: &[ImportedCandidateDocument],
    ) -> Result<()> {
        let _ = self.import_documents_batch_impl(documents, true, false)?;
        Ok(())
    }

    /// Shared implementation for import-style batch ingestion from exported
    /// document payloads.
    fn import_documents_batch_impl(
        &mut self,
        documents: &[ImportedCandidateDocument],
        assume_new: bool,
        collect_results: bool,
    ) -> Result<Vec<CandidateInsertResult>> {
        struct PendingImportedInsert<'a> {
            doc_id: u64,
            identity_hex: String,
            document: &'a ImportedCandidateDocument,
        }

        let mut total_scope = scope("candidate.import_documents_batch");
        let mut results = if collect_results {
            Vec::with_capacity(documents.len())
        } else {
            Vec::new()
        };
        let mut pending_inserts = Vec::<PendingImportedInsert<'_>>::new();
        let mut modified = false;
        let mut meta_dirty = false;
        let mut import_profile = CandidateImportBatchProfile::default();

        let resolve_doc_state_started = Instant::now();
        for document in documents {
            total_scope.add_bytes(document.file_size);
            let identity_hex = document.identity_hex.clone();

            if !assume_new {
                if let Some(existing_pos) = self.identity_to_pos.get(&identity_hex).copied() {
                    if !self.docs[existing_pos].deleted {
                        let existing = &self.docs[existing_pos];
                        if collect_results {
                            results.push(CandidateInsertResult {
                                status: "already_exists".to_owned(),
                                doc_id: existing.doc_id,
                                identity: existing.identity.clone(),
                            });
                        }
                        continue;
                    }

                    let snapshot = {
                        let existing = &mut self.docs[existing_pos];
                        existing.file_size = document.file_size;
                        existing.filter_bytes = document.filter_bytes;
                        existing.bloom_hashes = document.bloom_hashes;
                        existing.tier2_filter_bytes = document.tier2_filter_bytes;
                        existing.tier2_bloom_hashes = document.tier2_bloom_hashes;
                        existing.special_population = document.special_population;
                        existing.deleted = false;
                        existing.clone()
                    };
                    let row = self.build_doc_row(
                        snapshot.file_size,
                        snapshot.filter_bytes,
                        snapshot.bloom_hashes,
                        snapshot.deleted,
                        snapshot.special_population,
                        &document.metadata_bytes,
                        document.external_id.as_deref(),
                        &document.bloom_filter,
                    )?;
                    let tier2_row = self.build_tier2_doc_row(
                        snapshot.tier2_filter_bytes,
                        snapshot.tier2_bloom_hashes,
                        &document.tier2_bloom_filter,
                    )?;
                    self.doc_rows[existing_pos] = row;
                    self.tier2_doc_rows[existing_pos] = tier2_row;
                    self.write_doc_row(snapshot.doc_id, row)?;
                    self.write_tier2_doc_row(snapshot.doc_id, tier2_row)?;
                    if snapshot.special_population {
                        self.remember_special_doc_position(existing_pos);
                    }
                    modified = true;
                    if collect_results {
                        results.push(CandidateInsertResult {
                            status: "restored".to_owned(),
                            doc_id: snapshot.doc_id,
                            identity: identity_hex,
                        });
                    }
                    continue;
                }
            }

            let doc_id = self.local_meta.next_doc_id;
            self.local_meta.next_doc_id += 1;
            pending_inserts.push(PendingImportedInsert {
                doc_id,
                identity_hex,
                document,
            });
            modified = true;
            meta_dirty = true;
        }
        import_profile.resolve_doc_state_ms = resolve_doc_state_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);

        if !pending_inserts.is_empty() {
            let bloom_base = self.append_writers.blooms.offset;
            let external_ids_base = self.append_writers.external_ids.offset;
            let metadata_base = self.append_writers.metadata.offset;
            let tier2_blooms_base = self.append_writers.tier2_blooms.offset;
            let bloom_total_bytes = pending_inserts
                .iter()
                .map(|pending| pending.document.bloom_filter.len())
                .sum::<usize>();
            let tier2_bloom_total_bytes = pending_inserts
                .iter()
                .map(|pending| pending.document.tier2_bloom_filter.len())
                .sum::<usize>();
            let external_ids_total_bytes = pending_inserts
                .iter()
                .map(|pending| {
                    pending
                        .document
                        .external_id
                        .as_deref()
                        .map(str::len)
                        .unwrap_or(0)
                })
                .sum::<usize>();
            let metadata_total_bytes = pending_inserts
                .iter()
                .map(|pending| pending.document.metadata_bytes.len())
                .sum::<usize>();
            let mut blooms_payload = Vec::<u8>::with_capacity(bloom_total_bytes);
            let mut external_ids_payload = Vec::<u8>::with_capacity(external_ids_total_bytes);
            let mut metadata_payload = Vec::<u8>::with_capacity(metadata_total_bytes);
            let mut tier2_blooms_payload = Vec::<u8>::with_capacity(tier2_bloom_total_bytes);
            let mut sha_by_docid_payload =
                Vec::<u8>::with_capacity(pending_inserts.len() * self.identity_bytes_len());
            let mut doc_meta_payload =
                Vec::<u8>::with_capacity(pending_inserts.len() * DOC_META_ROW_BYTES);
            let mut tier2_doc_meta_payload =
                Vec::<u8>::with_capacity(pending_inserts.len() * TIER2_DOC_META_ROW_BYTES);
            let mut prepared = Vec::<(
                CandidateDoc,
                DocMetaRow,
                Tier2DocMetaRow,
                String,
                usize,
                usize,
                &'_ [u8],
                usize,
                usize,
                &'_ [u8],
            )>::with_capacity(pending_inserts.len());

            let build_payloads_started = Instant::now();
            for pending in pending_inserts {
                let document = pending.document;
                let bloom_offset = bloom_base + blooms_payload.len() as u64;
                blooms_payload.extend_from_slice(&document.bloom_filter);

                let (external_id_offset, external_id_len) =
                    if let Some(external_id) = document.external_id.as_deref() {
                        let bytes = external_id.as_bytes();
                        let offset = external_ids_base + external_ids_payload.len() as u64;
                        external_ids_payload.extend_from_slice(bytes);
                        (offset, bytes.len() as u32)
                    } else {
                        (0, 0)
                    };
                let (metadata_offset, metadata_len) = if document.metadata_bytes.is_empty() {
                    (0, 0)
                } else {
                    let offset = metadata_base + metadata_payload.len() as u64;
                    metadata_payload.extend_from_slice(&document.metadata_bytes);
                    (offset, document.metadata_bytes.len() as u32)
                };

                let tier2_row = if document.tier2_bloom_filter.is_empty() {
                    Tier2DocMetaRow::default()
                } else {
                    let bloom_offset = tier2_blooms_base + tier2_blooms_payload.len() as u64;
                    tier2_blooms_payload.extend_from_slice(&document.tier2_bloom_filter);
                    Tier2DocMetaRow {
                        filter_bytes: document.tier2_filter_bytes as u32,
                        bloom_hashes: document.tier2_bloom_hashes.min(u8::MAX as usize) as u8,
                        bloom_offset,
                        bloom_len: document.tier2_bloom_filter.len() as u32,
                    }
                };

                let row = DocMetaRow {
                    file_size: document.file_size,
                    filter_bytes: document.filter_bytes as u32,
                    flags: u8::from(document.special_population) * DOC_FLAG_SPECIAL_POPULATION,
                    bloom_hashes: document.bloom_hashes.min(u8::MAX as usize) as u8,
                    bloom_offset,
                    bloom_len: document.bloom_filter.len() as u32,
                    external_id_offset,
                    external_id_len,
                    metadata_offset,
                    metadata_len,
                };

                let doc = CandidateDoc {
                    doc_id: pending.doc_id,
                    identity: pending.identity_hex.clone(),
                    file_size: document.file_size,
                    filter_bytes: document.filter_bytes,
                    bloom_hashes: document.bloom_hashes,
                    tier2_filter_bytes: document.tier2_filter_bytes,
                    tier2_bloom_hashes: document.tier2_bloom_hashes,
                    special_population: document.special_population,
                    deleted: false,
                };

                sha_by_docid_payload.extend_from_slice(&document.identity);
                doc_meta_payload.extend_from_slice(&row.encode());
                tier2_doc_meta_payload.extend_from_slice(&tier2_row.encode());
                prepared.push((
                    doc,
                    row,
                    tier2_row,
                    pending.identity_hex,
                    document.filter_bytes,
                    document.bloom_hashes,
                    document.bloom_filter.as_slice(),
                    document.tier2_filter_bytes,
                    document.tier2_bloom_hashes,
                    document.tier2_bloom_filter.as_slice(),
                ));
            }
            import_profile.build_payloads_ms = build_payloads_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);

            let append_sidecars_started = Instant::now();
            self.append_writers.blooms.append(&blooms_payload)?;
            self.append_writers
                .external_ids
                .append(&external_ids_payload)?;
            self.append_writers.metadata.append(&metadata_payload)?;
            self.append_writers
                .tier2_blooms
                .append(&tier2_blooms_payload)?;
            self.append_writers
                .sha_by_docid
                .append(&sha_by_docid_payload)?;
            self.append_writers.doc_meta.append(&doc_meta_payload)?;
            self.append_writers
                .tier2_doc_meta
                .append(&tier2_doc_meta_payload)?;
            import_profile.append_sidecars_ms = append_sidecars_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);

            let mut tier2_updates =
                Vec::<(usize, usize, usize, &'_ [u8])>::with_capacity(prepared.len());
            let mut tier2_pattern_updates =
                Vec::<(usize, usize, usize, &'_ [u8])>::with_capacity(prepared.len());
            let install_docs_started = Instant::now();
            for (
                doc,
                row,
                tier2_row,
                identity_hex,
                filter_bytes,
                bloom_hashes,
                bloom_filter,
                tier2_filter_bytes,
                tier2_bloom_hashes,
                tier2_bloom_filter,
            ) in prepared
            {
                self.doc_rows.push(row);
                self.tier2_doc_rows.push(tier2_row);
                let pos = self.docs.len();
                self.docs.push(doc.clone());
                self.identity_to_pos.insert(identity_hex.clone(), pos);
                if doc.special_population {
                    self.remember_special_doc_position(pos);
                }
                if !doc.special_population {
                    tier2_updates.push((pos, filter_bytes, bloom_hashes, bloom_filter));
                }
                if !doc.special_population && !tier2_bloom_filter.is_empty() {
                    tier2_pattern_updates.push((
                        pos,
                        tier2_filter_bytes,
                        tier2_bloom_hashes,
                        tier2_bloom_filter,
                    ));
                }
                if collect_results {
                    results.push(CandidateInsertResult {
                        status: "inserted".to_owned(),
                        doc_id: doc.doc_id,
                        identity: identity_hex,
                    });
                }
            }
            import_profile.install_docs_ms = install_docs_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            let tier2_update_started = Instant::now();
            import_profile.tier2_update_ms = tier2_update_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
        }

        if modified {
            if meta_dirty {
                self.mark_meta_dirty();
            }
            self.sidecars.invalidate_all();
            self.mark_write_activity();
        }

        self.last_import_batch_profile = import_profile;

        Ok(results)
    }

    /// Returns the raw identity width for documents stored in this forest.
    fn identity_bytes_len(&self) -> usize {
        match self.meta.id_source.as_str() {
            "md5" => 16,
            "sha1" => 20,
            "sha256" => 32,
            "sha512" => 64,
            _ => 32,
        }
    }

    /// Returns profiling data captured during the most recent batch insert
    /// operation.
    pub fn last_insert_batch_profile(&self) -> CandidateInsertBatchProfile {
        self.last_insert_batch_profile
    }

    /// Returns profiling data captured during the most recent import-style
    /// batch insert operation.
    pub fn last_import_batch_profile(&self) -> CandidateImportBatchProfile {
        self.last_import_batch_profile
    }

    /// Reports whether the given canonical identity is present as a non-deleted document
    /// in the store.
    pub fn contains_live_document_identity(&self, identity: &[u8]) -> bool {
        let identity_hex = hex::encode(identity);
        self.identity_to_pos
            .get(&identity_hex)
            .copied()
            .map(|pos| !self.docs[pos].deleted)
            .unwrap_or(false)
    }

    /// Extracts identity hash constraints that can seed an exact lookup before
    /// the general scan path runs.
    fn identity_seed_hashes(node: &QueryNode) -> Option<HashSet<String>> {
        match node.kind.as_str() {
            "identity_eq" => node
                .pattern_id
                .as_ref()
                .map(|pattern_id| HashSet::from([pattern_id.clone()])),
            "and" => {
                let mut seed_sets = node.children.iter().filter_map(Self::identity_seed_hashes);
                let mut seeds = seed_sets.next()?;
                for child_seeds in seed_sets {
                    seeds.retain(|hash| child_seeds.contains(hash));
                    if seeds.is_empty() {
                        break;
                    }
                }
                Some(seeds)
            }
            "or" => {
                let mut seeds = HashSet::new();
                for child in &node.children {
                    let child_seeds = Self::identity_seed_hashes(child)?;
                    seeds.extend(child_seeds);
                }
                Some(seeds)
            }
            _ => None,
        }
    }

    /// Attempts to answer a runtime-hash query from exact identity seeds so
    /// only the matching documents need full evaluation.
    fn query_identity_seed_hits_runtime(
        &self,
        plan: &CompiledQueryPlan,
        runtime: &RuntimeQueryArtifacts,
        gram_cache: &mut RuntimeGramMaskCache,
    ) -> Result<Option<(Vec<String>, TierFlags, CandidateQueryProfile)>> {
        let Some(seed_hashes) = Self::identity_seed_hashes(&plan.root) else {
            return Ok(None);
        };
        let query_now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut matched_hits = Vec::<String>::new();
        let mut used_tiers = TierFlags::default();
        let mut query_profile = CandidateQueryProfile::default();
        for sha256 in seed_hashes {
            let Some(pos) = self.identity_to_pos.get(&sha256).copied() else {
                continue;
            };
            let doc = &self.docs[pos];
            if doc.deleted {
                continue;
            }
            query_profile.docs_scanned = query_profile.docs_scanned.saturating_add(1);
            let mut doc_inputs = LazyDocQueryInputs::new(doc);
            let mut load_metadata = || self.doc_metadata_bytes(pos);
            let mut load_tier1 = || self.doc_bloom_bytes(pos);
            let mut load_tier2 = || self.doc_tier2_bloom_bytes(pos);
            let mut eval_cache = QueryEvalCache::default();
            let outcome = evaluate_node_runtime(
                &plan.root,
                &mut doc_inputs,
                &mut load_metadata,
                &mut load_tier1,
                &mut load_tier2,
                runtime,
                plan,
                query_now_unix,
                &mut eval_cache,
                gram_cache,
            )?;
            if outcome.matched {
                matched_hits.push(doc.identity.clone());
                used_tiers.merge(outcome.tiers);
            }
            query_profile.merge_from(&doc_inputs.into_profile());
        }
        Ok(Some((matched_hits, used_tiers, query_profile)))
    }

    /// Executes a query plan against the store and returns one paginated page
    /// of candidate identities.
    pub fn query_candidates(
        &mut self,
        plan: &CompiledQueryPlan,
        cursor: usize,
        chunk_size: usize,
    ) -> Result<CandidateQueryResult> {
        let mut total_scope = scope("candidate.query_candidates");
        let runtime = self.runtime_query_artifacts(plan)?;
        self.query_candidates_with_runtime_hash_and_scope(
            plan,
            runtime.as_ref(),
            cursor,
            chunk_size,
            &mut total_scope,
        )
    }

    /// Collects the full hit list for a runtime-hash query without paginating
    /// it.
    pub(crate) fn collect_query_hits_with_runtime_hash(
        &mut self,
        plan: &CompiledQueryPlan,
        runtime: &RuntimeQueryArtifacts,
    ) -> Result<(Vec<String>, String, CandidateQueryProfile)> {
        if runtime.impossible_query {
            return Ok((
                Vec::new(),
                "none".to_owned(),
                CandidateQueryProfile::default(),
            ));
        }
        let mut gram_cache = RuntimeGramMaskCache::default();
        let (matched_hits, used_tiers, query_profile) = if let Some(identity_hits) =
            self.query_identity_seed_hits_runtime(plan, runtime, &mut gram_cache)?
        {
            identity_hits
        } else {
            self.scan_query_hits_runtime(plan, runtime, &mut gram_cache)?
        };
        self.record_query_execution_profile(&query_profile, matched_hits.len());
        Ok((matched_hits, used_tiers.as_label(), query_profile))
    }

    /// Collects hit lists for multiple runtime-hash queries while scanning
    /// each document at most once per lane.
    pub(crate) fn collect_query_hits_with_runtime_hash_batch(
        &mut self,
        plans: &[CompiledQueryPlan],
        runtime: &[Arc<RuntimeQueryArtifacts>],
    ) -> Result<Vec<(Vec<String>, String, CandidateQueryProfile, u128)>> {
        if plans.len() != runtime.len() {
            return Err(SspryError::from(
                "Bundled runtime-hash queries require the same number of plans and artifacts.",
            ));
        }

        let mut results = (0..plans.len())
            .map(|_| BatchedQueryResult::default())
            .collect::<Vec<_>>();
        let mut should_record_metrics = vec![false; plans.len()];
        let mut scan_rule_indices = Vec::new();
        let mut gram_cache = RuntimeGramMaskCache::default();

        for (index, (plan, runtime)) in plans.iter().zip(runtime.iter()).enumerate() {
            if runtime.impossible_query {
                continue;
            }
            should_record_metrics[index] = true;
            let started = Instant::now();
            if let Some((hits, tiers, profile)) =
                self.query_identity_seed_hits_runtime(plan, runtime.as_ref(), &mut gram_cache)?
            {
                let result = &mut results[index];
                result.hits = hits;
                result.tiers = tiers;
                result.profile = profile;
                result.eval_nanos = started.elapsed().as_nanos();
            } else {
                scan_rule_indices.push(index);
            }
        }

        if !scan_rule_indices.is_empty() {
            let query_now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if self.has_live_regular_docs() {
                self.scan_query_hits_all_docs_batch_runtime(
                    plans,
                    runtime,
                    &scan_rule_indices,
                    query_now_unix,
                    &mut gram_cache,
                    &mut results,
                )?;
            }
            if self.has_live_special_docs() {
                self.scan_query_hits_special_lane_batch_runtime(
                    plans,
                    runtime,
                    &scan_rule_indices,
                    query_now_unix,
                    &mut gram_cache,
                    &mut results,
                )?;
            }
        }

        let mut output = Vec::with_capacity(results.len());
        for (index, result) in results.into_iter().enumerate() {
            if should_record_metrics[index] {
                self.record_query_execution_profile(&result.profile, result.hits.len());
            }
            output.push((
                result.hits,
                result.tiers.as_label(),
                result.profile,
                result.eval_nanos,
            ));
        }
        Ok(output)
    }

    /// Records the standard query counters and telemetry for one completed
    /// query profile.
    fn record_query_execution_profile(
        &mut self,
        query_profile: &CandidateQueryProfile,
        matched_hit_count: usize,
    ) {
        record_counter(
            "candidate.query_candidates_docs_scanned_total",
            query_profile.docs_scanned,
        );
        record_counter(
            "candidate.query_candidates_matches_total",
            matched_hit_count as u64,
        );
        record_counter(
            "candidate.query_candidates_metadata_loads_total",
            query_profile.metadata_loads,
        );
        record_counter(
            "candidate.query_candidates_metadata_bytes_total",
            query_profile.metadata_bytes,
        );
        record_counter(
            "candidate.query_candidates_tier1_bloom_loads_total",
            query_profile.tier1_bloom_loads,
        );
        record_counter(
            "candidate.query_candidates_tier1_bloom_bytes_total",
            query_profile.tier1_bloom_bytes,
        );
        record_counter(
            "candidate.query_candidates_tier2_bloom_loads_total",
            query_profile.tier2_bloom_loads,
        );
        record_counter(
            "candidate.query_candidates_tier2_bloom_bytes_total",
            query_profile.tier2_bloom_bytes,
        );
        record_max(
            "candidate.query_candidates_max_matches",
            matched_hit_count as u64,
        );
        self.record_query_metrics(query_profile.docs_scanned, matched_hit_count as u64);
    }

    /// Runs the core query execution path using runtime query artifacts and
    /// updates aggregate query metrics.
    fn collect_query_hits_with_runtime_hash_and_scope(
        &mut self,
        plan: &CompiledQueryPlan,
        runtime: &RuntimeQueryArtifacts,
        mut total_scope: Option<&mut crate::perf::Scope>,
    ) -> Result<(Vec<String>, String, CandidateQueryProfile)> {
        let mut gram_cache = RuntimeGramMaskCache::default();
        let (matched_hits, used_tiers, query_profile) = if let Some(identity_hits) =
            self.query_identity_seed_hits_runtime(plan, runtime, &mut gram_cache)?
        {
            identity_hits
        } else {
            self.scan_query_hits_runtime(plan, runtime, &mut gram_cache)?
        };
        if let Some(scope) = total_scope.as_mut() {
            scope.add_items(query_profile.docs_scanned);
        }
        self.record_query_execution_profile(&query_profile, matched_hits.len());
        Ok((matched_hits, used_tiers.as_label(), query_profile))
    }

    /// Applies max-candidate truncation and cursor pagination to a runtime
    /// query result set.
    fn query_candidates_with_runtime_hash_and_scope(
        &mut self,
        plan: &CompiledQueryPlan,
        runtime: &RuntimeQueryArtifacts,
        cursor: usize,
        chunk_size: usize,
        total_scope: &mut crate::perf::Scope,
    ) -> Result<CandidateQueryResult> {
        let (mut matched_hits, tier_used, query_profile) =
            self.collect_query_hits_with_runtime_hash_and_scope(plan, runtime, Some(total_scope))?;
        let max_candidates = if plan.max_candidates <= 0.0 {
            usize::MAX
        } else {
            plan.max_candidates.ceil().min(usize::MAX as f64) as usize
        };
        let truncated = max_candidates != usize::MAX && matched_hits.len() > max_candidates;
        if truncated {
            matched_hits.truncate(max_candidates);
        }
        let (page, total, start, end, next_cursor) =
            paginate_query_hits(&matched_hits, cursor, chunk_size);

        Ok(CandidateQueryResult {
            identities: page,
            total_candidates: total,
            returned_count: end.saturating_sub(start),
            cursor: start,
            next_cursor,
            truncated,
            truncated_limit: truncated.then_some(max_candidates),
            tier_used,
            query_profile,
        })
    }

    /// Dispatches runtime-hash query evaluation across the regular and
    /// special-population lanes and merges their results.
    fn scan_query_hits_runtime(
        &self,
        plan: &CompiledQueryPlan,
        runtime: &RuntimeQueryArtifacts,
        gram_cache: &mut RuntimeGramMaskCache,
    ) -> Result<(Vec<String>, TierFlags, CandidateQueryProfile)> {
        let has_regular_docs = self.has_live_regular_docs();
        let has_special_docs = self.has_live_special_docs();
        let mut query_profile = CandidateQueryProfile::default();
        if !has_regular_docs && !has_special_docs {
            return Ok((Vec::new(), TierFlags::default(), query_profile));
        }
        let query_now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut matched_hits = Vec::<String>::new();
        let mut used_tiers = TierFlags::default();

        if has_regular_docs {
            let (hits, tiers, profile) =
                self.scan_query_hits_all_docs_runtime(plan, runtime, query_now_unix, gram_cache)?;
            matched_hits.extend(hits);
            used_tiers.merge(tiers);
            query_profile.merge_from(&profile);
        }

        if has_special_docs {
            let (hits, tiers, profile) = self.scan_query_hits_special_lane_runtime(
                plan,
                runtime,
                query_now_unix,
                gram_cache,
            )?;
            matched_hits.extend(hits);
            used_tiers.merge(tiers);
            query_profile.merge_from(&profile);
        }

        Ok((matched_hits, used_tiers, query_profile))
    }

    /// Evaluates one document against every runtime-hash bundled rule while
    /// sharing doc-side payload loads and query gram masks across rules.
    fn evaluate_query_batch_doc_runtime(
        &self,
        pos: usize,
        doc: &CandidateDoc,
        plans: &[CompiledQueryPlan],
        runtime: &[Arc<RuntimeQueryArtifacts>],
        scan_rule_indices: &[usize],
        query_now_unix: u64,
        gram_cache: &mut RuntimeGramMaskCache,
        results: &mut [BatchedQueryResult],
    ) -> Result<()> {
        let mut doc_inputs = LazyDocQueryInputs::new(doc);
        let mut load_metadata = || self.doc_metadata_bytes(pos);
        let mut load_tier1 = || self.doc_bloom_bytes(pos);
        let mut load_tier2 = || self.doc_tier2_bloom_bytes(pos);
        let mut eval_caches = (0..scan_rule_indices.len())
            .map(|_| QueryEvalCache::default())
            .collect::<Vec<_>>();

        for (cache_idx, result_idx) in scan_rule_indices.iter().copied().enumerate() {
            let Some(result) = results.get_mut(result_idx) else {
                continue;
            };
            result.profile.docs_scanned = result.profile.docs_scanned.saturating_add(1);
            let profile_before = doc_inputs.profile.clone();
            let started = Instant::now();
            let outcome = evaluate_node_runtime(
                &plans[result_idx].root,
                &mut doc_inputs,
                &mut load_metadata,
                &mut load_tier1,
                &mut load_tier2,
                runtime[result_idx].as_ref(),
                &plans[result_idx],
                query_now_unix,
                &mut eval_caches[cache_idx],
                gram_cache,
            )?;
            result.eval_nanos = result
                .eval_nanos
                .saturating_add(started.elapsed().as_nanos());
            let profile_delta = doc_inputs.profile.delta_since(&profile_before);
            result.profile.merge_from(&profile_delta);
            if outcome.matched {
                result.hits.push(doc.identity.clone());
                result.tiers.merge(outcome.tiers);
            }
        }
        Ok(())
    }

    /// Evaluates bundled runtime-hash queries against every live regular doc
    /// in one pass.
    fn scan_query_hits_all_docs_batch_runtime(
        &self,
        plans: &[CompiledQueryPlan],
        runtime: &[Arc<RuntimeQueryArtifacts>],
        scan_rule_indices: &[usize],
        query_now_unix: u64,
        gram_cache: &mut RuntimeGramMaskCache,
        results: &mut [BatchedQueryResult],
    ) -> Result<()> {
        for (pos, doc) in self.docs.iter().enumerate() {
            if doc.deleted || doc.special_population {
                continue;
            }
            self.evaluate_query_batch_doc_runtime(
                pos,
                doc,
                plans,
                runtime,
                scan_rule_indices,
                query_now_unix,
                gram_cache,
                results,
            )?;
        }
        Ok(())
    }

    /// Evaluates bundled runtime-hash queries against every live
    /// special-population doc in one pass.
    fn scan_query_hits_special_lane_batch_runtime(
        &self,
        plans: &[CompiledQueryPlan],
        runtime: &[Arc<RuntimeQueryArtifacts>],
        scan_rule_indices: &[usize],
        query_now_unix: u64,
        gram_cache: &mut RuntimeGramMaskCache,
        results: &mut [BatchedQueryResult],
    ) -> Result<()> {
        for pos in &self.special_doc_positions {
            let Some(doc) = self.docs.get(*pos) else {
                continue;
            };
            if doc.deleted || !doc.special_population {
                continue;
            }
            self.evaluate_query_batch_doc_runtime(
                *pos,
                doc,
                plans,
                runtime,
                scan_rule_indices,
                query_now_unix,
                gram_cache,
                results,
            )?;
        }
        Ok(())
    }

    /// Evaluates a runtime-hash query only against the special-population
    /// lane, which is stored separately from ordinary documents.
    fn scan_query_hits_special_lane_runtime(
        &self,
        plan: &CompiledQueryPlan,
        runtime: &RuntimeQueryArtifacts,
        query_now_unix: u64,
        gram_cache: &mut RuntimeGramMaskCache,
    ) -> Result<(Vec<String>, TierFlags, CandidateQueryProfile)> {
        let mut matched_hits = Vec::<String>::new();
        let mut used_tiers = TierFlags::default();
        let mut query_profile = CandidateQueryProfile::default();
        for pos in &self.special_doc_positions {
            let Some(doc) = self.docs.get(*pos) else {
                continue;
            };
            if doc.deleted || !doc.special_population {
                continue;
            }
            query_profile.docs_scanned = query_profile.docs_scanned.saturating_add(1);
            let mut doc_inputs = LazyDocQueryInputs::new(doc);
            let mut load_metadata = || self.doc_metadata_bytes(*pos);
            let mut load_tier1 = || self.doc_bloom_bytes(*pos);
            let mut load_tier2 = || self.doc_tier2_bloom_bytes(*pos);
            let mut eval_cache = QueryEvalCache::default();
            let outcome = evaluate_node_runtime(
                &plan.root,
                &mut doc_inputs,
                &mut load_metadata,
                &mut load_tier1,
                &mut load_tier2,
                runtime,
                plan,
                query_now_unix,
                &mut eval_cache,
                gram_cache,
            )?;
            if outcome.matched {
                matched_hits.push(doc.identity.clone());
                used_tiers.merge(outcome.tiers);
            }
            query_profile.merge_from(&doc_inputs.into_profile());
        }
        Ok((matched_hits, used_tiers, query_profile))
    }

    /// Evaluates a runtime-hash query across every live regular document in
    /// the store.
    fn scan_query_hits_all_docs_runtime(
        &self,
        plan: &CompiledQueryPlan,
        runtime: &RuntimeQueryArtifacts,
        query_now_unix: u64,
        gram_cache: &mut RuntimeGramMaskCache,
    ) -> Result<(Vec<String>, TierFlags, CandidateQueryProfile)> {
        let mut matched_hits = Vec::<String>::new();
        let mut used_tiers = TierFlags::default();
        let mut query_profile = CandidateQueryProfile::default();
        for (pos, doc) in self.docs.iter().enumerate() {
            if doc.deleted || doc.special_population {
                continue;
            }
            query_profile.docs_scanned = query_profile.docs_scanned.saturating_add(1);
            let mut doc_inputs = LazyDocQueryInputs::new(doc);
            let mut load_metadata = || self.doc_metadata_bytes(pos);
            let mut load_tier1 = || self.doc_bloom_bytes(pos);
            let mut load_tier2 = || self.doc_tier2_bloom_bytes(pos);
            let mut eval_cache = QueryEvalCache::default();
            let outcome = evaluate_node_runtime(
                &plan.root,
                &mut doc_inputs,
                &mut load_metadata,
                &mut load_tier1,
                &mut load_tier2,
                runtime,
                plan,
                query_now_unix,
                &mut eval_cache,
                gram_cache,
            )?;
            if outcome.matched {
                matched_hits.push(doc.identity.clone());
                used_tiers.merge(outcome.tiers);
            }
            query_profile.merge_from(&doc_inputs.into_profile());
        }
        Ok((matched_hits, used_tiers, query_profile))
    }

    /// Estimates memory owned by the document vector, including heap
    /// allocations inside stored document records.
    fn docs_vector_memory_bytes(&self) -> u64 {
        (self.docs.capacity() as u64)
            .saturating_mul(std::mem::size_of::<CandidateDoc>() as u64)
            .saturating_add(
                self.docs
                    .iter()
                    .map(candidate_doc_memory_bytes)
                    .sum::<u64>()
                    .saturating_sub(
                        (self.docs.len() as u64)
                            .saturating_mul(std::mem::size_of::<CandidateDoc>() as u64),
                    ),
            )
    }

    /// Estimates memory used by the identity-to-document-position hash index.
    fn identity_index_memory_bytes(&self) -> u64 {
        let bucket_bytes = (self.identity_to_pos.capacity() as u64).saturating_mul(
            (std::mem::size_of::<(String, usize)>() + std::mem::size_of::<u64>()) as u64,
        );
        let key_bytes = self
            .identity_to_pos
            .keys()
            .map(|sha| sha.capacity() as u64)
            .sum::<u64>();
        bucket_bytes.saturating_add(key_bytes)
    }

    /// Estimates memory retained by the query-artifact cache, including cached
    /// key strings and runtime artifact payloads.
    fn query_artifact_cache_memory_bytes(&self) -> u64 {
        self.query_artifact_cache
            .iter()
            .map(|(key, value)| {
                (std::mem::size_of::<String>() as u64)
                    .saturating_add(key.capacity() as u64)
                    .saturating_add(runtime_query_artifacts_memory_bytes(value.as_ref()))
            })
            .sum()
    }

    /// Returns the number of non-deleted documents currently visible in the
    /// store.
    pub fn live_doc_count(&self) -> usize {
        self.docs.iter().filter(|doc| !doc.deleted).count()
    }

    /// Summarizes document counts, tier telemetry, compaction state, and
    /// in-memory footprint for diagnostics.
    pub fn stats(&self) -> CandidateStats {
        let doc_count = self.live_doc_count();
        let deleted_doc_count = self.docs.iter().filter(|doc| doc.deleted).count();
        let cooldown_remaining = self.compaction_cooldown_remaining_s();
        let tier2_match_ratio = if self.tier2_telemetry.tier2_scanned_docs_total > 0 {
            self.tier2_telemetry.tier2_docs_matched_total as f64
                / self.tier2_telemetry.tier2_scanned_docs_total as f64
        } else {
            0.0
        };
        let (
            mapped_bloom_bytes,
            mapped_tier2_bloom_bytes,
            mapped_metadata_bytes,
            mapped_external_id_bytes,
        ) = self.sidecars.mapped_bytes();
        CandidateStats {
            doc_count,
            deleted_doc_count,
            id_source: self.meta.id_source.clone(),
            store_path: self.meta.store_path,
            tier1_filter_target_fp: self.meta.resolved_tier1_filter_target_fp(),
            tier2_filter_target_fp: self.meta.resolved_tier2_filter_target_fp(),
            tier2_gram_size: self.meta.tier2_gram_size,
            tier1_gram_size: self.meta.tier1_gram_size,
            compaction_idle_cooldown_s: self.meta.compaction_idle_cooldown_s,
            source_dedup_min_new_docs: self.meta.source_dedup_min_new_docs,
            compaction_cooldown_remaining_s: cooldown_remaining,
            compaction_waiting_for_cooldown: cooldown_remaining > 0.0,
            compaction_generation: self.compaction_generation,
            retired_generation_count: self.retired_generation_roots.len(),
            query_count: self.tier2_telemetry.query_count,
            tier2_scanned_docs_total: self.tier2_telemetry.tier2_scanned_docs_total,
            tier2_docs_matched_total: self.tier2_telemetry.tier2_docs_matched_total,
            tier2_match_ratio,
            docs_vector_bytes: self.docs_vector_memory_bytes(),
            doc_rows_bytes: (self.doc_rows.capacity() as u64)
                .saturating_mul(std::mem::size_of::<DocMetaRow>() as u64),
            tier2_doc_rows_bytes: (self.tier2_doc_rows.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Tier2DocMetaRow>() as u64),
            identity_index_bytes: self.identity_index_memory_bytes(),
            special_doc_positions_bytes: (self.special_doc_positions.capacity() as u64)
                .saturating_mul(std::mem::size_of::<usize>() as u64),
            query_artifact_cache_entries: self.query_artifact_cache.len(),
            query_artifact_cache_bytes: self.query_artifact_cache_memory_bytes(),
            mapped_bloom_bytes,
            mapped_tier2_bloom_bytes,
            mapped_metadata_bytes,
            mapped_external_id_bytes,
        }
    }

    /// Returns external identifiers for the provided identity list, preserving
    /// input order and using `None` for missing/deleted documents.
    pub fn external_ids_for_identities(&self, hashes: &[String]) -> Vec<Option<String>> {
        hashes
            .iter()
            .map(|sha256| match self.identity_to_pos.get(sha256).copied() {
                Some(pos) if !self.docs[pos].deleted => self.doc_external_id(pos).ok().flatten(),
                _ => None,
            })
            .collect()
    }

    /// Returns document ids for the provided identity list, preserving input
    /// order and using `None` for missing/deleted documents.
    pub fn doc_ids_for_identities(&self, hashes: &[String]) -> Vec<Option<u64>> {
        hashes
            .iter()
            .map(|sha256| match self.identity_to_pos.get(sha256).copied() {
                Some(pos) if !self.docs[pos].deleted => Some(self.docs[pos].doc_id),
                _ => None,
            })
            .collect()
    }

    /// Loads the persisted tier-1 bloom payload for one document, using the
    /// mapped sidecar when available.
    fn doc_bloom_bytes<'a>(&'a self, pos: usize) -> Result<Cow<'a, [u8]>> {
        let doc = &self.docs[pos];
        let row = self.doc_rows[pos];
        self.sidecars.blooms.read_bytes(
            row.bloom_offset,
            row.bloom_len as usize,
            "bloom",
            doc.doc_id,
        )
    }

    /// Loads the persisted tier-2 bloom payload for one document, using the
    /// mapped sidecar when available.
    fn doc_tier2_bloom_bytes<'a>(&'a self, pos: usize) -> Result<Cow<'a, [u8]>> {
        let doc = &self.docs[pos];
        let row = self.tier2_doc_rows[pos];
        self.sidecars.tier2_blooms.read_bytes(
            row.bloom_offset,
            row.bloom_len as usize,
            "tier2_bloom",
            doc.doc_id,
        )
    }

    /// Loads and decodes the optional external id for one document.
    fn doc_external_id(&self, pos: usize) -> Result<Option<String>> {
        let doc = &self.docs[pos];
        let row = self.doc_rows[pos];
        if row.external_id_len == 0 {
            return Ok(None);
        }
        let bytes = self.sidecars.external_ids.read_bytes(
            row.external_id_offset,
            row.external_id_len as usize,
            "external_id",
            doc.doc_id,
        )?;
        Ok(Some(String::from_utf8(bytes.into_owned()).map_err(
            |_| {
                SspryError::from(format!(
                    "Invalid external_id payload stored for doc_id {}",
                    doc.doc_id
                ))
            },
        )?))
    }

    /// Loads the persisted compact metadata blob for one document.
    fn doc_metadata_bytes<'a>(&'a self, pos: usize) -> Result<Cow<'a, [u8]>> {
        let doc = &self.docs[pos];
        let row = self.doc_rows[pos];
        self.sidecars.metadata.read_bytes(
            row.metadata_offset,
            row.metadata_len as usize,
            "metadata",
            doc.doc_id,
        )
    }

    /// Persists forest and local metadata files and clears the dirty flag.
    fn persist_meta(&mut self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        let policy_root = forest_policy_root(&self.root);
        fs::create_dir_all(&policy_root)?;
        write_json(forest_meta_path(&policy_root), &self.meta)?;
        write_json(store_local_meta_path(&self.root), &self.local_meta)?;
        self.meta_persist_dirty = false;
        Ok(())
    }

    /// Marks store metadata dirty so a later flush rewrites the metadata files.
    fn mark_meta_dirty(&mut self) {
        self.meta_persist_dirty = true;
    }

    pub(crate) fn persist_meta_if_dirty(&mut self) -> Result<bool> {
        if !self.meta_persist_dirty {
            return Ok(false);
        }
        self.persist_meta()?;
        Ok(true)
    }

    /// Appends a tier-1 row payload and returns the row metadata.
    fn build_doc_row(
        &mut self,
        file_size: u64,
        filter_bytes: usize,
        bloom_hashes: usize,
        deleted: bool,
        special_population: bool,
        metadata: &[u8],
        external_id: Option<&str>,
        bloom_filter: &[u8],
    ) -> Result<DocMetaRow> {
        Ok(self
            .build_doc_row_profile(
                file_size,
                filter_bytes,
                bloom_hashes,
                deleted,
                special_population,
                metadata,
                external_id,
                bloom_filter,
            )?
            .0)
    }

    /// Builds a tier-1 row when the bloom payload was already appended, while
    /// still profiling metadata and external-id writes.
    fn build_doc_row_with_bloom_offset_profile(
        &mut self,
        file_size: u64,
        filter_bytes: usize,
        bloom_hashes: usize,
        deleted: bool,
        special_population: bool,
        metadata: &[u8],
        external_id: Option<&str>,
        bloom_offset: u64,
        bloom_len: usize,
    ) -> Result<(DocMetaRow, CandidateDocRowPayloadProfile)> {
        let mut profile = CandidateDocRowPayloadProfile::default();
        let (metadata_offset, metadata_len) = if metadata.is_empty() {
            (0, 0)
        } else {
            let metadata_started = Instant::now();
            let offset = self.append_writers.metadata.append(metadata)?;
            profile.metadata_us = elapsed_us(metadata_started);
            profile.metadata_bytes = metadata.len() as u64;
            (offset, metadata.len() as u32)
        };
        let (external_id_offset, external_id_len) = if let Some(external_id) = external_id {
            let bytes = external_id.as_bytes();
            let external_id_started = Instant::now();
            let result = (
                self.append_writers.external_ids.append(bytes)?,
                bytes.len() as u32,
            );
            profile.external_id_us = elapsed_us(external_id_started);
            profile.external_id_bytes = bytes.len() as u64;
            result
        } else {
            (0, 0)
        };
        Ok((
            DocMetaRow {
                file_size,
                filter_bytes: filter_bytes as u32,
                flags: (u8::from(deleted) * DOC_FLAG_DELETED)
                    | (u8::from(special_population) * DOC_FLAG_SPECIAL_POPULATION),
                bloom_hashes: bloom_hashes.min(u8::MAX as usize) as u8,
                bloom_offset,
                bloom_len: bloom_len as u32,
                external_id_offset,
                external_id_len,
                metadata_offset,
                metadata_len,
            },
            profile,
        ))
    }

    /// Appends a full tier-1 row payload, including bloom, metadata, and
    /// external id sidecars, and reports write-cost profiling.
    fn build_doc_row_profile(
        &mut self,
        file_size: u64,
        filter_bytes: usize,
        bloom_hashes: usize,
        deleted: bool,
        special_population: bool,
        metadata: &[u8],
        external_id: Option<&str>,
        bloom_filter: &[u8],
    ) -> Result<(DocMetaRow, CandidateDocRowPayloadProfile)> {
        let mut profile = CandidateDocRowPayloadProfile::default();
        let bloom_started = Instant::now();
        let bloom_offset = self.append_writers.blooms.append(bloom_filter)?;
        profile.bloom_us = elapsed_us(bloom_started);
        profile.bloom_bytes = bloom_filter.len() as u64;
        let (metadata_offset, metadata_len) = if metadata.is_empty() {
            (0, 0)
        } else {
            let metadata_started = Instant::now();
            let offset = self.append_writers.metadata.append(metadata)?;
            profile.metadata_us = elapsed_us(metadata_started);
            profile.metadata_bytes = metadata.len() as u64;
            (offset, metadata.len() as u32)
        };
        let (external_id_offset, external_id_len) = if let Some(external_id) = external_id {
            let bytes = external_id.as_bytes();
            let external_id_started = Instant::now();
            let result = (
                self.append_writers.external_ids.append(bytes)?,
                bytes.len() as u32,
            );
            profile.external_id_us = elapsed_us(external_id_started);
            profile.external_id_bytes = bytes.len() as u64;
            result
        } else {
            (0, 0)
        };
        let row = DocMetaRow {
            file_size,
            filter_bytes: filter_bytes as u32,
            flags: (u8::from(deleted) * DOC_FLAG_DELETED)
                | (u8::from(special_population) * DOC_FLAG_SPECIAL_POPULATION),
            bloom_hashes: bloom_hashes.min(u8::MAX as usize) as u8,
            bloom_offset,
            bloom_len: bloom_filter.len() as u32,
            external_id_offset,
            external_id_len,
            metadata_offset,
            metadata_len,
        };
        Ok((row, profile))
    }

    /// Appends a tier-2 row payload and returns only the row metadata.
    fn build_tier2_doc_row(
        &mut self,
        tier2_filter_bytes: usize,
        tier2_bloom_hashes: usize,
        tier2_bloom_filter: &[u8],
    ) -> Result<Tier2DocMetaRow> {
        Ok(self
            .build_tier2_doc_row_profile(
                tier2_filter_bytes,
                tier2_bloom_hashes,
                tier2_bloom_filter,
            )?
            .0)
    }

    /// Appends a tier-2 bloom payload and returns the row metadata plus a
    /// profile describing the write cost.
    fn build_tier2_doc_row_profile(
        &mut self,
        tier2_filter_bytes: usize,
        tier2_bloom_hashes: usize,
        tier2_bloom_filter: &[u8],
    ) -> Result<(Tier2DocMetaRow, CandidateDocRowPayloadProfile)> {
        if tier2_bloom_filter.is_empty() {
            return Ok((
                Tier2DocMetaRow::default(),
                CandidateDocRowPayloadProfile::default(),
            ));
        }
        let mut profile = CandidateDocRowPayloadProfile::default();
        let bloom_started = Instant::now();
        let bloom_offset = self
            .append_writers
            .tier2_blooms
            .append(tier2_bloom_filter)?;
        profile.tier2_bloom_us = elapsed_us(bloom_started);
        profile.tier2_bloom_bytes = tier2_bloom_filter.len() as u64;
        Ok((
            Tier2DocMetaRow {
                filter_bytes: tier2_filter_bytes as u32,
                bloom_hashes: tier2_bloom_hashes.min(u8::MAX as usize) as u8,
                bloom_offset,
                bloom_len: tier2_bloom_filter.len() as u32,
            },
            profile,
        ))
    }

    /// Appends the fixed-width per-document sidecar rows for a newly assigned
    /// document id.
    fn append_new_doc(
        &mut self,
        identity: &[u8],
        row: DocMetaRow,
        tier2_row: Tier2DocMetaRow,
    ) -> Result<()> {
        self.append_writers.sha_by_docid.append(identity)?;
        self.append_writers.doc_meta.append(&row.encode())?;
        self.append_writers
            .tier2_doc_meta
            .append(&tier2_row.encode())?;
        Ok(())
    }

    /// Overwrites an existing tier-1 row at the position associated with the
    /// given document id.
    fn write_doc_row(&self, doc_id: u64, row: DocMetaRow) -> Result<()> {
        if doc_id == 0 {
            return Err(SspryError::from("doc_id must be positive"));
        }
        write_at(
            doc_meta_path(&self.root),
            (doc_id - 1) * DOC_META_ROW_BYTES as u64,
            &row.encode(),
        )
    }

    /// Overwrites an existing tier-2 row at the position associated with the
    /// given document id.
    fn write_tier2_doc_row(&self, doc_id: u64, row: Tier2DocMetaRow) -> Result<()> {
        if doc_id == 0 {
            return Err(SspryError::from("doc_id must be positive"));
        }
        write_at(
            tier2_doc_meta_path(&self.root),
            (doc_id - 1) * TIER2_DOC_META_ROW_BYTES as u64,
            &row.encode(),
        )
    }

    /// Updates cumulative query telemetry counters used by diagnostics and
    /// status reporting.
    fn record_query_metrics(&mut self, tier2_scanned_docs: u64, tier2_docs_matched: u64) {
        self.tier2_telemetry.query_count = self.tier2_telemetry.query_count.saturating_add(1);
        self.tier2_telemetry.tier2_scanned_docs_total = self
            .tier2_telemetry
            .tier2_scanned_docs_total
            .saturating_add(tier2_scanned_docs);
        self.tier2_telemetry.tier2_docs_matched_total = self
            .tier2_telemetry
            .tier2_docs_matched_total
            .saturating_add(tier2_docs_matched);
    }

    /// Rebuilds transient in-memory indexes from the loaded document list and
    /// normalizes legacy row defaults encountered on disk.
    fn rebuild_indexes_profiled(&mut self) -> Result<CandidateStoreRebuildProfile> {
        let started_total = Instant::now();
        self.identity_to_pos.clear();
        self.special_doc_positions.clear();
        let sha_started = Instant::now();
        for (index, doc) in self.docs.iter_mut().enumerate() {
            if doc.bloom_hashes == 0 {
                doc.bloom_hashes = DEFAULT_BLOOM_HASHES;
                if let Some(row) = self.doc_rows.get_mut(index) {
                    row.bloom_hashes = DEFAULT_BLOOM_HASHES.min(u8::MAX as usize) as u8;
                }
            }
            self.identity_to_pos.insert(doc.identity.clone(), index);
            if doc.special_population {
                self.special_doc_positions.push(index);
            }
        }
        let identity_index_ms = sha_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        Ok(CandidateStoreRebuildProfile {
            identity_index_ms,
            total_ms: started_total
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        })
    }

    /// Serializes a compiled query plan into the query-artifact cache key.
    fn query_artifact_cache_key(plan: &CompiledQueryPlan) -> Result<String> {
        serde_json::to_string(plan).map_err(SspryError::from)
    }

    /// Builds or reuses the runtime artifacts needed to evaluate one query
    /// plan against this store.
    fn runtime_query_artifacts(
        &mut self,
        plan: &CompiledQueryPlan,
    ) -> Result<Arc<RuntimeQueryArtifacts>> {
        let key = Self::query_artifact_cache_key(plan)?;
        if let Some(entry) = self.query_artifact_cache.get(&key) {
            record_counter("candidate.query_artifact_cache_hits_total", 1);
            return Ok(entry);
        }
        record_counter("candidate.query_artifact_cache_misses_total", 1);
        let entry = build_runtime_query_artifacts(plan)?;
        self.query_artifact_cache.insert(key, entry.clone());
        Ok(entry)
    }
}

pub(crate) fn write_compacted_snapshot(
    snapshot: &CandidateCompactionSnapshot,
    compacted_root: &Path,
) -> Result<()> {
    if compacted_root.exists() {
        fs::remove_dir_all(compacted_root)?;
    }
    fs::create_dir_all(compacted_root)?;

    let paths = [
        sha_by_docid_path(compacted_root),
        doc_meta_path(compacted_root),
        tier2_doc_meta_path(compacted_root),
        doc_metadata_path(compacted_root),
        blooms_path(compacted_root),
        tier2_blooms_path(compacted_root),
        external_ids_path(compacted_root),
    ];
    for path in &paths {
        let _ = fs::remove_file(path);
    }

    for doc in &snapshot.live_docs {
        let bloom_bytes = read_blob_from_path(
            &blooms_path(&snapshot.root),
            doc.row.bloom_offset,
            doc.row.bloom_len as usize,
            "bloom",
            0,
        )?;
        let tier2_bloom_bytes = if doc.tier2_row.bloom_len == 0 {
            Vec::new()
        } else {
            read_blob_from_path(
                &tier2_blooms_path(&snapshot.root),
                doc.tier2_row.bloom_offset,
                doc.tier2_row.bloom_len as usize,
                "tier2_bloom",
                0,
            )?
        };
        let external_id = if doc.row.external_id_len == 0 {
            None
        } else {
            let bytes = read_blob_from_path(
                &external_ids_path(&snapshot.root),
                doc.row.external_id_offset,
                doc.row.external_id_len as usize,
                "external_id",
                0,
            )?;
            Some(String::from_utf8(bytes).map_err(|_| {
                SspryError::from("Invalid UTF-8 external_id payload during compaction.")
            })?)
        };
        let metadata = if doc.row.metadata_len == 0 {
            Vec::new()
        } else {
            read_blob_from_path(
                &doc_metadata_path(&snapshot.root),
                doc.row.metadata_offset,
                doc.row.metadata_len as usize,
                "metadata",
                0,
            )?
        };

        let row = DocMetaRow {
            file_size: doc.file_size,
            filter_bytes: doc.filter_bytes as u32,
            flags: 0,
            bloom_hashes: doc.bloom_hashes.min(u8::MAX as usize) as u8,
            bloom_offset: append_blob(blooms_path(compacted_root), &bloom_bytes)?,
            bloom_len: bloom_bytes.len() as u32,
            external_id_offset: if let Some(external_id) = &external_id {
                append_blob(external_ids_path(compacted_root), external_id.as_bytes())?
            } else {
                0
            },
            external_id_len: external_id
                .as_ref()
                .map(|value| value.len() as u32)
                .unwrap_or(0),
            metadata_offset: if metadata.is_empty() {
                0
            } else {
                append_blob(doc_metadata_path(compacted_root), &metadata)?
            },
            metadata_len: metadata.len() as u32,
        };
        let tier2_row = if tier2_bloom_bytes.is_empty() {
            Tier2DocMetaRow::default()
        } else {
            Tier2DocMetaRow {
                filter_bytes: doc.tier2_filter_bytes as u32,
                bloom_hashes: doc.tier2_bloom_hashes.min(u8::MAX as usize) as u8,
                bloom_offset: append_blob(tier2_blooms_path(compacted_root), &tier2_bloom_bytes)?,
                bloom_len: tier2_bloom_bytes.len() as u32,
            }
        };
        append_blob(sha_by_docid_path(compacted_root), &doc.identity)?;
        append_blob(doc_meta_path(compacted_root), &row.encode())?;
        append_blob(tier2_doc_meta_path(compacted_root), &tier2_row.encode())?;
    }

    write_json(
        forest_meta_path(&forest_policy_root(compacted_root)),
        &snapshot.meta,
    )?;
    write_json(
        store_local_meta_path(compacted_root),
        &StoreLocalMeta {
            version: STORE_VERSION,
            next_doc_id: snapshot.live_docs.len() as u64 + 1,
        },
    )?;
    Ok(())
}

// Storage layout, path, and compaction helper functions live in a sibling file so
// the main store type stays focused on lifecycle and mutations.
include!("store/storage.rs");

// Prepared-query construction and AST evaluation live in a sibling file to keep
// the store implementation navigable.
include!("store/query_eval.rs");

#[cfg(test)]
mod tests;
