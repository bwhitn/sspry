use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use memmap2::{Mmap, MmapOptions};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::candidate::bloom::{
    DEFAULT_BLOOM_POSITION_LANES, bloom_word_masks_in_lane, raw_filter_matches_word_masks,
};
use crate::candidate::cache::BoundedCache;
use crate::candidate::filter_policy::{
    align_filter_bytes, choose_filter_bytes_for_file_size, derive_document_bloom_hash_count,
};
use crate::candidate::grams::{
    DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes, pack_exact_gram,
};
use crate::candidate::query_plan::{CompiledQueryPlan, PatternPlan, QueryNode};
use crate::candidate::{
    MetadataCompareOp, metadata_field_matches_compare, metadata_field_matches_compare_f32,
    metadata_fields_compare, metadata_file_prefix_8,
};
use crate::perf::{record_counter, record_max, scope};
use crate::{Result, SspryError};

const STORE_VERSION: u32 = 2;
const DEFAULT_FILTER_BYTES: usize = 2048;
const DEFAULT_BLOOM_HASHES: usize = 7;
const DEFAULT_FILTER_MIN_BYTES: usize = 1;
const DEFAULT_FILTER_MAX_BYTES: usize = 0;
pub const DEFAULT_TIER1_FILTER_TARGET_FP: f64 = 0.40;
pub const DEFAULT_TIER2_FILTER_TARGET_FP: f64 = 0.23;
const DEFAULT_COMPACTION_IDLE_COOLDOWN_S: f64 = 5.0;
const PREPARED_QUERY_CACHE_CAPACITY: usize = 32;

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
}

impl Default for CandidateConfig {
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
        }
    }
}

impl CandidateConfig {
    pub fn resolved_tier1_filter_target_fp(&self) -> Option<f64> {
        self.tier1_filter_target_fp.or(self.filter_target_fp)
    }

    pub fn resolved_tier2_filter_target_fp(&self) -> Option<f64> {
        self.tier2_filter_target_fp.or(self.filter_target_fp)
    }
}

#[derive(Clone, Debug)]
pub struct CandidateInsertResult {
    pub status: String,
    pub doc_id: u64,
    pub sha256: String,
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
    pub sha256: String,
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
    pub rebuild_sha_index_ms: u64,
    pub total_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CandidateStoreRebuildProfile {
    sha_index_ms: u64,
    total_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ImportedCandidateDocument {
    pub sha256: [u8; 32],
    pub sha256_hex: String,
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
    pub sha256: Vec<String>,
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
pub struct CandidatePreparedQueryProfile {
    pub impossible_query: bool,
    pub prepared_query_bytes: u64,
    pub prepared_pattern_plan_bytes: u64,
    pub prepared_mask_cache_bytes: u64,
    pub pattern_count: u64,
    pub mask_cache_entries: u64,
    pub fixed_literal_count: u64,
    pub tier1_alternatives: u64,
    pub tier2_alternatives: u64,
    pub tier1_shift_variants: u64,
    pub tier2_shift_variants: u64,
    pub tier1_any_lane_alternatives: u64,
    pub tier2_any_lane_alternatives: u64,
    pub tier1_compacted_any_lane_alternatives: u64,
    pub tier2_compacted_any_lane_alternatives: u64,
    pub any_lane_variant_sets: u64,
    pub compacted_any_lane_grams: u64,
    pub max_pattern_bytes: u64,
    pub max_pattern_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CandidateQueryProfile {
    pub tree_gate_trees_considered: u64,
    pub tree_gate_passed: u64,
    pub tree_gate_tier1_pruned: u64,
    pub tree_gate_tier2_pruned: u64,
    pub tree_gate_special_docs_bypass: u64,
    pub docs_scanned: u64,
    pub metadata_loads: u64,
    pub metadata_bytes: u64,
    pub tier1_bloom_loads: u64,
    pub tier1_bloom_bytes: u64,
    pub tier2_bloom_loads: u64,
    pub tier2_bloom_bytes: u64,
}

impl CandidateQueryProfile {
    pub(crate) fn merge_from(&mut self, other: &Self) {
        self.tree_gate_trees_considered = self
            .tree_gate_trees_considered
            .saturating_add(other.tree_gate_trees_considered);
        self.tree_gate_passed = self.tree_gate_passed.saturating_add(other.tree_gate_passed);
        self.tree_gate_tier1_pruned = self
            .tree_gate_tier1_pruned
            .saturating_add(other.tree_gate_tier1_pruned);
        self.tree_gate_tier2_pruned = self
            .tree_gate_tier2_pruned
            .saturating_add(other.tree_gate_tier2_pruned);
        self.tree_gate_special_docs_bypass = self
            .tree_gate_special_docs_bypass
            .saturating_add(other.tree_gate_special_docs_bypass);
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
}

impl CandidatePreparedQueryProfile {
    fn accumulate_shifted(&mut self, shifted: &ShiftedRequiredMasks, tier2: bool) {
        let shift_count = shifted.shifts.len() as u64;
        if tier2 {
            self.tier2_shift_variants = self.tier2_shift_variants.saturating_add(shift_count);
        } else {
            self.tier1_shift_variants = self.tier1_shift_variants.saturating_add(shift_count);
        }
        if !shifted.any_lane_values.is_empty() {
            if tier2 {
                self.tier2_any_lane_alternatives =
                    self.tier2_any_lane_alternatives.saturating_add(1);
            } else {
                self.tier1_any_lane_alternatives =
                    self.tier1_any_lane_alternatives.saturating_add(1);
            }
            self.any_lane_variant_sets = self
                .any_lane_variant_sets
                .saturating_add(shifted.any_lane_values.len() as u64);
        }
        if !shifted.any_lane_grams.is_empty() {
            if tier2 {
                self.tier2_compacted_any_lane_alternatives =
                    self.tier2_compacted_any_lane_alternatives.saturating_add(1);
            } else {
                self.tier1_compacted_any_lane_alternatives =
                    self.tier1_compacted_any_lane_alternatives.saturating_add(1);
            }
            self.compacted_any_lane_grams = self
                .compacted_any_lane_grams
                .saturating_add(shifted.any_lane_grams.len() as u64);
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
    pub compaction_cooldown_remaining_s: f64,
    pub compaction_waiting_for_cooldown: bool,
    pub compaction_generation: u64,
    pub retired_generation_count: usize,
    pub query_count: u64,
    pub tier2_scanned_docs_total: u64,
    pub tier2_docs_matched_total: u64,
    pub tier2_match_ratio: f64,
    pub tree_tier1_gate_bytes: u64,
    pub tree_tier2_gate_bytes: u64,
    pub docs_vector_bytes: u64,
    pub doc_rows_bytes: u64,
    pub tier2_doc_rows_bytes: u64,
    pub sha_index_bytes: u64,
    pub special_doc_positions_bytes: u64,
    pub prepared_query_cache_entries: usize,
    pub prepared_query_cache_bytes: u64,
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
    fn default() -> Self {
        Self {
            current_generation: 1,
            retired_roots: Vec::new(),
        }
    }
}

impl Default for ForestMeta {
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
        }
    }
}

impl Default for StoreLocalMeta {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            next_doc_id: 1,
        }
    }
}

impl Default for LegacyStoreMeta {
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
    fn resolved_tier1_filter_target_fp(&self) -> Option<f64> {
        self.tier1_filter_target_fp
    }

    fn resolved_tier2_filter_target_fp(&self) -> Option<f64> {
        self.tier2_filter_target_fp
    }
}

impl From<&LegacyStoreMeta> for ForestMeta {
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
        }
    }
}

impl From<&LegacyStoreMeta> for StoreLocalMeta {
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
    sha256: String,
    file_size: u64,
    filter_bytes: usize,
    bloom_hashes: usize,
    tier2_filter_bytes: usize,
    tier2_bloom_hashes: usize,
    special_population: bool,
    deleted: bool,
}

fn candidate_doc_memory_bytes(doc: &CandidateDoc) -> u64 {
    (std::mem::size_of::<CandidateDoc>() as u64).saturating_add(doc.sha256.capacity() as u64)
}

const DOC_META_ROW_BYTES: usize = 56;
const TIER2_DOC_META_ROW_BYTES: usize = 24;
const APPEND_PAYLOAD_SYNC_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;
const DOC_FLAG_DELETED: u8 = 0x02;
const DOC_FLAG_SPECIAL_POPULATION: u8 = 0x04;

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

fn experiment_disable_tree_gates_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("SSPRY_EXPERIMENT_DISABLE_TREE_GATES")
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
    fn encode(self) -> [u8; TIER2_DOC_META_ROW_BYTES] {
        let mut out = [0u8; TIER2_DOC_META_ROW_BYTES];
        out[0..4].copy_from_slice(&self.filter_bytes.to_le_bytes());
        out[4] = self.bloom_hashes;
        out[8..16].copy_from_slice(&self.bloom_offset.to_le_bytes());
        out[16..20].copy_from_slice(&self.bloom_len.to_le_bytes());
        out
    }

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
    fn with_access_mode(path: PathBuf, access_mode: BlobSidecarAccessMode) -> Self {
        Self {
            path,
            access_mode,
            mmap: OnceLock::new(),
            file: OnceLock::new(),
        }
    }

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

    fn file_handle(&self) -> Result<&fs::File> {
        self.file
            .get_or_init(|| {
                fs::File::open(&self.path)
                    .map_err(|err| format!("Failed to open {}: {err}", self.path.display()))
            })
            .as_ref()
            .map_err(|err: &String| SspryError::from(err.clone()))
    }

    fn invalidate(&mut self) {
        self.mmap = OnceLock::new();
        self.file = OnceLock::new();
    }

    fn retarget(&mut self, path: PathBuf) {
        self.path = path;
        self.mmap = OnceLock::new();
        self.file = OnceLock::new();
    }

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

    fn map_existing(root: &Path) -> Result<Self> {
        Ok(Self::new(root))
    }

    fn refresh_maps(&mut self) -> Result<()> {
        self.blooms.map_if_exists()?;
        self.tier2_blooms.map_if_exists()?;
        self.metadata.map_if_exists()?;
        self.external_ids.map_if_exists()?;
        Ok(())
    }

    fn invalidate_all(&mut self) {
        self.blooms.invalidate();
        self.tier2_blooms.invalidate();
        self.metadata.invalidate();
        self.external_ids.invalidate();
    }

    fn retarget_root(&mut self, root: &Path) {
        self.blooms.retarget(blooms_path(root));
        self.tier2_blooms.retarget(tier2_blooms_path(root));
        self.metadata.retarget(doc_metadata_path(root));
        self.external_ids.retarget(external_ids_path(root));
    }

    fn mapped_bytes(&self) -> (u64, u64, u64, u64) {
        (
            self.blooms.mapped_bytes(),
            self.tier2_blooms.mapped_bytes(),
            self.metadata.mapped_bytes(),
            self.external_ids.mapped_bytes(),
        )
    }
}

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
    fn new(path: PathBuf) -> Result<Self> {
        Self::new_with_sync_threshold(path, 0)
    }

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

#[derive(Clone, Debug, Default)]
struct TreeBloomGateIndex {
    bucket_for_key: FxHashMap<(usize, usize), (usize, usize)>,
    summary_bytes_by_bucket: FxHashMap<(usize, usize), usize>,
    masks_by_bucket: FxHashMap<(usize, usize), Vec<u8>>,
    summary_memory_bytes: u64,
}

impl TreeBloomGateIndex {
    fn memory_bytes(&self) -> u64 {
        self.masks_by_bucket
            .values()
            .map(|mask| mask.len() as u64)
            .sum()
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
    sha256: [u8; 32],
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

#[derive(Debug)]
pub(crate) struct PreparedQueryArtifacts {
    patterns: HashMap<String, PatternPlan>,
    mask_cache: PatternMaskCache,
    impossible_query: bool,
}

fn bloom_bucket_key(filter_bytes: usize, bloom_hashes: usize) -> (usize, usize) {
    (align_filter_bytes(filter_bytes.max(1)), bloom_hashes)
}

fn merge_bloom_bytes_into_tree_gate(gate: &mut [u8], bloom_bytes: &[u8]) {
    let shared_len = gate.len().min(bloom_bytes.len());
    let word_len = shared_len / 8;
    for word_idx in 0..word_len {
        let start = word_idx * 8;
        let end = start + 8;
        let merged = u64::from_le_bytes(
            gate[start..end]
                .try_into()
                .expect("word-sized tree gate chunk"),
        ) | u64::from_le_bytes(
            bloom_bytes[start..end]
                .try_into()
                .expect("word-sized bloom chunk"),
        );
        gate[start..end].copy_from_slice(&merged.to_le_bytes());
    }
    for idx in (word_len * 8)..shared_len {
        gate[idx] |= bloom_bytes[idx];
    }
}

fn ensure_tree_gate_capacity_for(
    index: &mut TreeBloomGateIndex,
    filter_bytes: usize,
    bloom_hashes: usize,
) {
    let filter_key = (filter_bytes, bloom_hashes);
    let bucket_key = bloom_bucket_key(filter_bytes, bloom_hashes);
    let summary_bytes = align_filter_bytes(bucket_key.0.max(1));
    index.bucket_for_key.insert(filter_key, bucket_key);
    if index
        .summary_bytes_by_bucket
        .insert(bucket_key, summary_bytes)
        .is_none()
    {
        index.summary_memory_bytes = index
            .summary_memory_bytes
            .saturating_add(summary_bytes as u64);
    }
    index
        .masks_by_bucket
        .entry(bucket_key)
        .or_insert_with(|| vec![0u8; summary_bytes]);
}

fn update_tree_gate_for_doc_bytes_inner(
    index: &mut TreeBloomGateIndex,
    filter_bytes: usize,
    bloom_hashes: usize,
    bloom_bytes: &[u8],
) {
    ensure_tree_gate_capacity_for(index, filter_bytes, bloom_hashes);
    let bucket_key = bloom_bucket_key(filter_bytes, bloom_hashes);
    if let Some(mask) = index.masks_by_bucket.get_mut(&bucket_key) {
        merge_bloom_bytes_into_tree_gate(mask, bloom_bytes);
    }
}

fn update_tree_gate_for_doc_bytes_batch<'a>(
    index: &mut TreeBloomGateIndex,
    updates: &[(usize, usize, usize, &'a [u8])],
) {
    for (_, filter_bytes, bloom_hashes, bloom_bytes) in updates {
        update_tree_gate_for_doc_bytes_inner(index, *filter_bytes, *bloom_hashes, bloom_bytes);
    }
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
    sha_to_pos: HashMap<String, usize>,
    special_doc_positions: Vec<usize>,
    mutation_counter: u64,
    compaction_generation: u64,
    retired_generation_roots: Vec<String>,
    last_write_activity_monotonic: Option<Instant>,
    tree_tier1_gates: TreeBloomGateIndex,
    tree_tier2_gates: TreeBloomGateIndex,
    tier2_telemetry: Tier2Telemetry,
    prepared_query_cache: BoundedCache<String, Arc<PreparedQueryArtifacts>>,
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

struct LazyDocQueryInputs<'a> {
    doc: &'a CandidateDoc,
    metadata_bytes: Option<Cow<'a, [u8]>>,
    tier1_bloom_bytes: Option<Cow<'a, [u8]>>,
    tier2_bloom_bytes: Option<Cow<'a, [u8]>>,
    profile: CandidateQueryProfile,
}

impl<'a> LazyDocQueryInputs<'a> {
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

    fn into_profile(self) -> CandidateQueryProfile {
        self.profile
    }

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
    fn merge(&mut self, other: TierFlags) {
        self.used_tier1 |= other.used_tier1;
        self.used_tier2 |= other.used_tier2;
    }

    fn as_label(self) -> String {
        match (self.used_tier1, self.used_tier2) {
            (true, true) => "tier1+tier2".to_owned(),
            (true, false) => "tier1".to_owned(),
            (false, true) => "tier2".to_owned(),
            (false, false) => "none".to_owned(),
        }
    }
}

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

impl CandidateStore {
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
            let _ = fs::remove_file(&tree_tier1_gates_path(&config.root));
            let _ = fs::remove_file(&tree_tier2_gates_path(&config.root));
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
            },
            local_meta: StoreLocalMeta::default(),
            docs: Vec::new(),
            doc_rows: Vec::new(),
            tier2_doc_rows: Vec::new(),
            sidecars: StoreSidecars::new(&config.root),
            append_writers: StoreAppendWriters::new(&config.root)?,
            sha_to_pos: HashMap::new(),
            special_doc_positions: Vec::new(),
            mutation_counter: 0,
            compaction_generation: 1,
            retired_generation_roots: Vec::new(),
            last_write_activity_monotonic: None,
            tree_tier1_gates: TreeBloomGateIndex::default(),
            tree_tier2_gates: TreeBloomGateIndex::default(),
            tier2_telemetry: Tier2Telemetry::default(),
            prepared_query_cache: BoundedCache::new(PREPARED_QUERY_CACHE_CAPACITY),
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

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_profiled(root).map(|(store, _)| store)
    }

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
        let (docs, doc_rows, tier2_doc_rows) = load_candidate_store_state(&root)?;
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
            sha_to_pos: HashMap::new(),
            special_doc_positions: Vec::new(),
            mutation_counter: 0,
            compaction_generation: compaction_manifest.current_generation,
            retired_generation_roots: compaction_manifest.retired_roots,
            last_write_activity_monotonic: None,
            tree_tier1_gates: TreeBloomGateIndex::default(),
            tree_tier2_gates: TreeBloomGateIndex::default(),
            tier2_telemetry: Tier2Telemetry::default(),
            prepared_query_cache: BoundedCache::new(PREPARED_QUERY_CACHE_CAPACITY),
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
            rebuild_sha_index_ms: rebuild_profile.sha_index_ms,
            total_ms: started_total
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        };
        Ok((store, profile))
    }

    pub fn apply_runtime_limits(
        &mut self,
        memory_budget_bytes: u64,
        total_shards: usize,
    ) -> Result<()> {
        self.memory_budget_bytes = memory_budget_bytes;
        self.total_shards = total_shards.max(1);
        Ok(())
    }

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
        }
    }

    pub fn retarget_root(&mut self, root: impl AsRef<Path>) {
        let root = root.as_ref();
        self.root = root.to_path_buf();
        self.sidecars.retarget_root(root);
        self.append_writers.retarget_root(root);
    }

    pub fn clear_search_caches(&mut self) {
        self.prepared_query_cache.clear();
    }

    fn mark_write_activity(&mut self) {
        self.mutation_counter = self.mutation_counter.saturating_add(1);
        self.last_write_activity_monotonic = Some(Instant::now());
        self.prepared_query_cache.clear();
    }

    fn remember_special_doc_position(&mut self, pos: usize) {
        if !self.special_doc_positions.contains(&pos) {
            self.special_doc_positions.push(pos);
        }
    }

    fn has_live_special_docs(&self) -> bool {
        self.special_doc_positions.iter().any(|pos| {
            self.docs
                .get(*pos)
                .map(|doc| doc.special_population && !doc.deleted)
                .unwrap_or(false)
        })
    }

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
            let mut sha256 = [0u8; 32];
            hex::decode_to_slice(&doc.sha256, &mut sha256)?;
            live_docs.push(CompactionDocRef {
                sha256,
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
    pub(crate) fn resolve_filter_bytes_for_file_size(
        &self,
        file_size: u64,
        bloom_item_estimate: Option<usize>,
    ) -> Result<usize> {
        self.resolve_tier1_filter_bytes_for_file_size(file_size, bloom_item_estimate)
    }

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

    pub fn insert_document(
        &mut self,
        sha256: [u8; 32],
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
    ) -> Result<CandidateInsertResult> {
        self.insert_document_with_metadata(
            sha256,
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

    pub fn insert_document_with_metadata(
        &mut self,
        sha256: [u8; 32],
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
    ) -> Result<CandidateInsertResult> {
        let mut total_scope = scope("candidate.insert_document");
        total_scope.add_bytes(file_size);
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
        let sha256_hex = hex::encode(sha256);

        // Bloom-only ingest only needs the per-document bloom payloads here.
        let status;
        let doc_id;
        if let Some(existing_pos) = self.sha_to_pos.get(&sha256_hex).copied() {
            if !self.docs[existing_pos].deleted {
                let existing = &self.docs[existing_pos];
                return Ok(CandidateInsertResult {
                    status: "already_exists".to_owned(),
                    doc_id: existing.doc_id,
                    sha256: existing.sha256.clone(),
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
            self.update_tree_tier1_gates_for_doc_bytes_inner(existing_pos, bloom_filter)?;
            self.update_tree_tier2_gates_for_doc_bytes_inner(existing_pos, tier2_bloom_filter)?;
        } else {
            doc_id = self.local_meta.next_doc_id;
            self.local_meta.next_doc_id += 1;
            let doc = CandidateDoc {
                doc_id,
                sha256: sha256_hex.clone(),
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
                self.append_new_doc(&sha256, row, tier2_row)?;
                self.doc_rows.push(row);
                self.tier2_doc_rows.push(tier2_row);
            }
            self.docs.push(doc.clone());
            let new_pos = self.docs.len() - 1;
            self.sha_to_pos.insert(sha256_hex.clone(), new_pos);
            if doc.special_population {
                self.remember_special_doc_position(new_pos);
            }
            self.update_tree_tier1_gates_for_doc_bytes_inner(new_pos, bloom_filter)?;
            self.update_tree_tier2_gates_for_doc_bytes_inner(new_pos, tier2_bloom_filter)?;
            status = "inserted".to_owned();
        }

        self.sidecars.invalidate_all();

        self.mark_write_activity();
        Ok(CandidateInsertResult {
            status,
            doc_id,
            sha256: sha256_hex,
        })
    }

    pub fn insert_documents_batch(
        &mut self,
        documents: &[(
            [u8; 32],
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
        fn elapsed_us(started: Instant) -> u64 {
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
        }

        struct PendingNewInsert<'a> {
            sha256: [u8; 32],
            sha256_hex: String,
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
                sha256,
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
            let sha256_hex = hex::encode(sha256);
            let _ = bloom_item_estimate;

            if let Some(existing_pos) = self.sha_to_pos.get(&sha256_hex).copied() {
                if !self.docs[existing_pos].deleted {
                    let existing = &self.docs[existing_pos];
                    results.push(CandidateInsertResult {
                        status: "already_exists".to_owned(),
                        doc_id: existing.doc_id,
                        sha256: existing.sha256.clone(),
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
                    sha256: sha256_hex,
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
                sha256: sha256_hex.clone(),
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
                sha256: sha256_hex,
            });
            pending_new_inserts.push(PendingNewInsert {
                sha256: *sha256,
                sha256_hex: doc.sha256.clone(),
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
            let mut sha_by_docid_payload = Vec::<u8>::with_capacity(pending_new_inserts.len() * 32);
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
                sha_by_docid_payload.extend_from_slice(&pending.sha256);
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
                self.sha_to_pos.insert(pending.sha256_hex, pos);
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
            self.update_tree_tier1_gates_for_doc_bytes_batch(&tier2_updates)?;
            self.update_tree_tier2_gates_for_doc_bytes_batch(&tier2_pattern_updates)?;
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

    pub fn delete_document(&mut self, sha256_hex: &str) -> Result<CandidateDeleteResult> {
        let _scope = scope("candidate.delete_document");
        let normalized = normalize_sha256_hex(sha256_hex)?;
        if let Some(pos) = self.sha_to_pos.get(&normalized).copied() {
            if self.docs[pos].deleted {
                return Ok(CandidateDeleteResult {
                    status: "missing".to_owned(),
                    sha256: normalized,
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
                sha256: snapshot.sha256.clone(),
                doc_id: Some(snapshot.doc_id),
            };
            let mut row = self.doc_rows[pos];
            row.flags |= DOC_FLAG_DELETED;
            self.doc_rows[pos] = row;
            self.write_doc_row(snapshot.doc_id, row)?;
            self.rebuild_tree_gates()?;
            self.mark_write_activity();
            record_counter("candidate.delete_document_deleted_total", 1);
            return Ok(result);
        }
        Ok(CandidateDeleteResult {
            status: "missing".to_owned(),
            sha256: normalized,
            doc_id: None,
        })
    }

    pub fn export_live_documents(&mut self) -> Result<Vec<ImportedCandidateDocument>> {
        self.sidecars.refresh_maps()?;
        let mut out = Vec::with_capacity(self.docs.len());
        for pos in 0..self.docs.len() {
            let doc = &self.docs[pos];
            if doc.deleted {
                continue;
            }
            let mut sha256 = [0u8; 32];
            hex::decode_to_slice(&doc.sha256, &mut sha256)?;
            out.push(ImportedCandidateDocument {
                sha256,
                sha256_hex: doc.sha256.clone(),
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

    pub fn import_documents_batch(
        &mut self,
        documents: &[ImportedCandidateDocument],
    ) -> Result<Vec<CandidateInsertResult>> {
        self.import_documents_batch_impl(documents, false, true)
    }

    pub fn import_documents_batch_known_new(
        &mut self,
        documents: &[ImportedCandidateDocument],
    ) -> Result<Vec<CandidateInsertResult>> {
        self.import_documents_batch_impl(documents, true, true)
    }

    pub fn import_documents_batch_quiet(
        &mut self,
        documents: &[ImportedCandidateDocument],
    ) -> Result<()> {
        let _ = self.import_documents_batch_impl(documents, false, false)?;
        Ok(())
    }

    pub fn import_documents_batch_known_new_quiet(
        &mut self,
        documents: &[ImportedCandidateDocument],
    ) -> Result<()> {
        let _ = self.import_documents_batch_impl(documents, true, false)?;
        Ok(())
    }

    fn import_documents_batch_impl(
        &mut self,
        documents: &[ImportedCandidateDocument],
        assume_new: bool,
        collect_results: bool,
    ) -> Result<Vec<CandidateInsertResult>> {
        struct PendingImportedInsert<'a> {
            doc_id: u64,
            sha256_hex: String,
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
            let sha256_hex = document.sha256_hex.clone();

            if !assume_new {
                if let Some(existing_pos) = self.sha_to_pos.get(&sha256_hex).copied() {
                    if !self.docs[existing_pos].deleted {
                        let existing = &self.docs[existing_pos];
                        if collect_results {
                            results.push(CandidateInsertResult {
                                status: "already_exists".to_owned(),
                                doc_id: existing.doc_id,
                                sha256: existing.sha256.clone(),
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
                            sha256: sha256_hex,
                        });
                    }
                    continue;
                }
            }

            let doc_id = self.local_meta.next_doc_id;
            self.local_meta.next_doc_id += 1;
            pending_inserts.push(PendingImportedInsert {
                doc_id,
                sha256_hex,
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
            let mut sha_by_docid_payload = Vec::<u8>::with_capacity(pending_inserts.len() * 32);
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
                    sha256: pending.sha256_hex.clone(),
                    file_size: document.file_size,
                    filter_bytes: document.filter_bytes,
                    bloom_hashes: document.bloom_hashes,
                    tier2_filter_bytes: document.tier2_filter_bytes,
                    tier2_bloom_hashes: document.tier2_bloom_hashes,
                    special_population: document.special_population,
                    deleted: false,
                };

                sha_by_docid_payload.extend_from_slice(&document.sha256);
                doc_meta_payload.extend_from_slice(&row.encode());
                tier2_doc_meta_payload.extend_from_slice(&tier2_row.encode());
                prepared.push((
                    doc,
                    row,
                    tier2_row,
                    pending.sha256_hex,
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
                sha256_hex,
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
                self.sha_to_pos.insert(sha256_hex.clone(), pos);
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
                        sha256: sha256_hex,
                    });
                }
            }
            import_profile.install_docs_ms = install_docs_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            let tier2_update_started = Instant::now();
            self.update_tree_tier1_gates_for_doc_bytes_batch(&tier2_updates)?;
            self.update_tree_tier2_gates_for_doc_bytes_batch(&tier2_pattern_updates)?;
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

    pub fn last_insert_batch_profile(&self) -> CandidateInsertBatchProfile {
        self.last_insert_batch_profile
    }

    pub fn last_import_batch_profile(&self) -> CandidateImportBatchProfile {
        self.last_import_batch_profile
    }

    pub fn contains_live_document_sha256(&self, sha256: &[u8; 32]) -> bool {
        let sha256_hex = hex::encode(sha256);
        self.sha_to_pos
            .get(&sha256_hex)
            .copied()
            .map(|pos| !self.docs[pos].deleted)
            .unwrap_or(false)
    }

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

    fn query_identity_seed_hits(
        &self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
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
            let Some(pos) = self.sha_to_pos.get(&sha256).copied() else {
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
            let outcome = evaluate_node(
                &plan.root,
                &mut doc_inputs,
                &mut load_metadata,
                &mut load_tier1,
                &mut load_tier2,
                &prepared.patterns,
                &prepared.mask_cache,
                plan,
                query_now_unix,
                &mut eval_cache,
            )?;
            if outcome.matched {
                matched_hits.push(doc.sha256.clone());
                used_tiers.merge(outcome.tiers);
            }
            query_profile.merge_from(&doc_inputs.into_profile());
        }
        Ok(Some((matched_hits, used_tiers, query_profile)))
    }

    pub fn query_candidates(
        &mut self,
        plan: &CompiledQueryPlan,
        cursor: usize,
        chunk_size: usize,
    ) -> Result<CandidateQueryResult> {
        let mut total_scope = scope("candidate.query_candidates");
        let prepared = self.prepare_query_artifacts(plan)?;
        self.query_candidates_with_prepared_and_scope(
            plan,
            &prepared,
            cursor,
            chunk_size,
            &mut total_scope,
        )
    }

    pub fn query_tree_gate_profile(
        &mut self,
        plan: &CompiledQueryPlan,
    ) -> Result<CandidateQueryProfile> {
        let prepared = self.prepare_query_artifacts(plan)?;
        let (_, _, query_profile) = self.tree_gate_profile(plan, &prepared)?;
        Ok(query_profile)
    }

    pub(crate) fn query_candidates_with_prepared(
        &mut self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
        cursor: usize,
        chunk_size: usize,
    ) -> Result<CandidateQueryResult> {
        let mut total_scope = scope("candidate.query_candidates");
        self.query_candidates_with_prepared_and_scope(
            plan,
            prepared,
            cursor,
            chunk_size,
            &mut total_scope,
        )
    }

    fn query_candidates_with_prepared_and_scope(
        &mut self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
        cursor: usize,
        chunk_size: usize,
        total_scope: &mut crate::perf::Scope,
    ) -> Result<CandidateQueryResult> {
        if prepared.impossible_query {
            return Ok(CandidateQueryResult {
                sha256: Vec::new(),
                total_candidates: 0,
                returned_count: 0,
                cursor: 0,
                next_cursor: None,
                truncated: false,
                truncated_limit: None,
                tier_used: "none".to_owned(),
                query_profile: CandidateQueryProfile::default(),
            });
        }
        let (mut matched_hits, used_tiers, query_profile) =
            if let Some(identity_hits) = self.query_identity_seed_hits(plan, prepared)? {
                identity_hits
            } else {
                self.scan_query_hits(plan, prepared)?
            };
        total_scope.add_items(query_profile.docs_scanned);
        record_counter(
            "candidate.query_candidates_docs_scanned_total",
            query_profile.docs_scanned,
        );
        record_counter(
            "candidate.query_candidates_matches_total",
            matched_hits.len() as u64,
        );
        record_counter(
            "candidate.query_candidates_tree_gate_trees_considered_total",
            query_profile.tree_gate_trees_considered,
        );
        record_counter(
            "candidate.query_candidates_tree_gate_passed_total",
            query_profile.tree_gate_passed,
        );
        record_counter(
            "candidate.query_candidates_tree_gate_tier1_pruned_total",
            query_profile.tree_gate_tier1_pruned,
        );
        record_counter(
            "candidate.query_candidates_tree_gate_tier2_pruned_total",
            query_profile.tree_gate_tier2_pruned,
        );
        record_counter(
            "candidate.query_candidates_tree_gate_special_docs_bypass_total",
            query_profile.tree_gate_special_docs_bypass,
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
            matched_hits.len() as u64,
        );
        self.record_query_metrics(query_profile.docs_scanned, matched_hits.len() as u64);
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
            sha256: page,
            total_candidates: total,
            returned_count: end.saturating_sub(start),
            cursor: start,
            next_cursor,
            truncated,
            truncated_limit: truncated.then_some(max_candidates),
            tier_used: used_tiers.as_label(),
            query_profile,
        })
    }

    fn tree_gate_profile(
        &self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
    ) -> Result<(bool, bool, CandidateQueryProfile)> {
        if experiment_tier2_and_metadata_only_enabled() {
            let mut query_profile = CandidateQueryProfile::default();
            query_profile.tree_gate_trees_considered = 1;
            query_profile.tree_gate_passed = 1;
            return Ok((true, self.has_live_special_docs(), query_profile));
        }
        let tier2_only = experiment_tier2_only_enabled();
        let mut query_profile = CandidateQueryProfile::default();
        query_profile.tree_gate_trees_considered = 1;
        if tier2_only {
            let normal_tree_match = tree_maybe_matches_node(
                &plan.root,
                &prepared.mask_cache,
                &self.tree_tier1_gates,
                &self.tree_tier2_gates,
                true,
            )?;
            let has_special_docs = self.has_live_special_docs();
            if normal_tree_match {
                query_profile.tree_gate_passed = 1;
            } else if has_special_docs {
                query_profile.tree_gate_special_docs_bypass = 1;
            } else {
                query_profile.tree_gate_tier2_pruned = 1;
            }
            return Ok((normal_tree_match, has_special_docs, query_profile));
        }
        let tier1_tree_match = tree_maybe_matches_node(
            &plan.root,
            &prepared.mask_cache,
            &self.tree_tier1_gates,
            &self.tree_tier2_gates,
            false,
        )?;
        let normal_tree_match =
            if !plan.force_tier1_only && plan.allow_tier2_fallback && tier1_tree_match {
                tree_maybe_matches_node(
                    &plan.root,
                    &prepared.mask_cache,
                    &self.tree_tier1_gates,
                    &self.tree_tier2_gates,
                    true,
                )?
            } else {
                tier1_tree_match
            };
        let has_special_docs = self.has_live_special_docs();
        if normal_tree_match {
            query_profile.tree_gate_passed = 1;
        } else if has_special_docs {
            query_profile.tree_gate_special_docs_bypass = 1;
        } else if !tier1_tree_match {
            query_profile.tree_gate_tier1_pruned = 1;
        } else {
            query_profile.tree_gate_tier2_pruned = 1;
        }
        Ok((normal_tree_match, has_special_docs, query_profile))
    }

    fn scan_query_hits(
        &self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
    ) -> Result<(Vec<String>, TierFlags, CandidateQueryProfile)> {
        let (normal_tree_match, has_special_docs, mut query_profile) =
            self.tree_gate_profile(plan, prepared)?;
        if !normal_tree_match && !has_special_docs {
            return Ok((Vec::new(), TierFlags::default(), query_profile));
        }
        let query_now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut matched_hits = Vec::<String>::new();
        let mut used_tiers = TierFlags::default();

        if normal_tree_match {
            let (hits, tiers, profile) =
                self.scan_query_hits_all_docs(plan, prepared, query_now_unix)?;
            matched_hits.extend(hits);
            used_tiers.merge(tiers);
            query_profile.merge_from(&profile);
        }

        if has_special_docs {
            let (hits, tiers, profile) =
                self.scan_query_hits_special_lane(plan, prepared, query_now_unix)?;
            matched_hits.extend(hits);
            used_tiers.merge(tiers);
            query_profile.merge_from(&profile);
        }

        Ok((matched_hits, used_tiers, query_profile))
    }

    fn scan_query_hits_special_lane(
        &self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
        query_now_unix: u64,
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
            let outcome = evaluate_node(
                &plan.root,
                &mut doc_inputs,
                &mut load_metadata,
                &mut load_tier1,
                &mut load_tier2,
                &prepared.patterns,
                &prepared.mask_cache,
                plan,
                query_now_unix,
                &mut eval_cache,
            )?;
            if outcome.matched {
                matched_hits.push(doc.sha256.clone());
                used_tiers.merge(outcome.tiers);
            }
            query_profile.merge_from(&doc_inputs.into_profile());
        }
        Ok((matched_hits, used_tiers, query_profile))
    }

    fn scan_query_hits_all_docs(
        &self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
        query_now_unix: u64,
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
            let outcome = evaluate_node(
                &plan.root,
                &mut doc_inputs,
                &mut load_metadata,
                &mut load_tier1,
                &mut load_tier2,
                &prepared.patterns,
                &prepared.mask_cache,
                plan,
                query_now_unix,
                &mut eval_cache,
            )?;
            if outcome.matched {
                matched_hits.push(doc.sha256.clone());
                used_tiers.merge(outcome.tiers);
            }
            query_profile.merge_from(&doc_inputs.into_profile());
        }
        Ok((matched_hits, used_tiers, query_profile))
    }

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

    fn sha_index_memory_bytes(&self) -> u64 {
        let bucket_bytes = (self.sha_to_pos.capacity() as u64).saturating_mul(
            (std::mem::size_of::<(String, usize)>() + std::mem::size_of::<u64>()) as u64,
        );
        let key_bytes = self
            .sha_to_pos
            .keys()
            .map(|sha| sha.capacity() as u64)
            .sum::<u64>();
        bucket_bytes.saturating_add(key_bytes)
    }

    fn prepared_query_cache_memory_bytes(&self) -> u64 {
        self.prepared_query_cache
            .iter()
            .map(|(key, value)| {
                (std::mem::size_of::<String>() as u64)
                    .saturating_add(key.capacity() as u64)
                    .saturating_add(prepared_query_artifacts_memory_bytes(value.as_ref()))
            })
            .sum()
    }

    pub fn live_doc_count(&self) -> usize {
        self.docs.iter().filter(|doc| !doc.deleted).count()
    }

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
            compaction_cooldown_remaining_s: cooldown_remaining,
            compaction_waiting_for_cooldown: cooldown_remaining > 0.0,
            compaction_generation: self.compaction_generation,
            retired_generation_count: self.retired_generation_roots.len(),
            query_count: self.tier2_telemetry.query_count,
            tier2_scanned_docs_total: self.tier2_telemetry.tier2_scanned_docs_total,
            tier2_docs_matched_total: self.tier2_telemetry.tier2_docs_matched_total,
            tier2_match_ratio,
            tree_tier1_gate_bytes: self.tree_tier1_gates.memory_bytes(),
            tree_tier2_gate_bytes: self.tree_tier2_gates.memory_bytes(),
            docs_vector_bytes: self.docs_vector_memory_bytes(),
            doc_rows_bytes: (self.doc_rows.capacity() as u64)
                .saturating_mul(std::mem::size_of::<DocMetaRow>() as u64),
            tier2_doc_rows_bytes: (self.tier2_doc_rows.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Tier2DocMetaRow>() as u64),
            sha_index_bytes: self.sha_index_memory_bytes(),
            special_doc_positions_bytes: (self.special_doc_positions.capacity() as u64)
                .saturating_mul(std::mem::size_of::<usize>() as u64),
            prepared_query_cache_entries: self.prepared_query_cache.len(),
            prepared_query_cache_bytes: self.prepared_query_cache_memory_bytes(),
            mapped_bloom_bytes,
            mapped_tier2_bloom_bytes,
            mapped_metadata_bytes,
            mapped_external_id_bytes,
        }
    }

    pub fn external_ids_for_sha256(&self, hashes: &[String]) -> Vec<Option<String>> {
        hashes
            .iter()
            .map(|sha256| match self.sha_to_pos.get(sha256).copied() {
                Some(pos) if !self.docs[pos].deleted => self.doc_external_id(pos).ok().flatten(),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn tier1_doc_filter_keys(&self) -> Vec<(usize, usize)> {
        let mut keys = self
            .docs
            .iter()
            .filter(|doc| !doc.deleted)
            .map(|doc| (doc.filter_bytes, doc.bloom_hashes))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }

    pub(crate) fn tier2_doc_filter_keys(&self) -> Vec<(usize, usize)> {
        let mut keys = self
            .docs
            .iter()
            .filter(|doc| !doc.deleted && doc.tier2_filter_bytes > 0 && doc.tier2_bloom_hashes > 0)
            .map(|doc| (doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }

    pub fn doc_ids_for_sha256(&self, hashes: &[String]) -> Vec<Option<u64>> {
        hashes
            .iter()
            .map(|sha256| match self.sha_to_pos.get(sha256).copied() {
                Some(pos) if !self.docs[pos].deleted => Some(self.docs[pos].doc_id),
                _ => None,
            })
            .collect()
    }

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

    fn persist_meta(&mut self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        let policy_root = forest_policy_root(&self.root);
        fs::create_dir_all(&policy_root)?;
        write_json(forest_meta_path(&policy_root), &self.meta)?;
        write_json(store_local_meta_path(&self.root), &self.local_meta)?;
        self.meta_persist_dirty = false;
        Ok(())
    }

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
        fn elapsed_us(started: Instant) -> u64 {
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
        }

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
        fn elapsed_us(started: Instant) -> u64 {
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
        }

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

    fn build_tier2_doc_row_profile(
        &mut self,
        tier2_filter_bytes: usize,
        tier2_bloom_hashes: usize,
        tier2_bloom_filter: &[u8],
    ) -> Result<(Tier2DocMetaRow, CandidateDocRowPayloadProfile)> {
        fn elapsed_us(started: Instant) -> u64 {
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
        }

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

    fn append_new_doc(
        &mut self,
        sha256: &[u8; 32],
        row: DocMetaRow,
        tier2_row: Tier2DocMetaRow,
    ) -> Result<()> {
        self.append_writers.sha_by_docid.append(sha256)?;
        self.append_writers.doc_meta.append(&row.encode())?;
        self.append_writers
            .tier2_doc_meta
            .append(&tier2_row.encode())?;
        Ok(())
    }

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

    fn update_tree_tier1_gates_for_doc_bytes_inner(
        &mut self,
        pos: usize,
        bloom_bytes: &[u8],
    ) -> Result<()> {
        if experiment_disable_tree_gates_enabled() {
            return Ok(());
        }
        if pos >= self.docs.len() || self.docs[pos].deleted || self.docs[pos].special_population {
            return Ok(());
        }
        let filter_bytes = self.docs[pos].filter_bytes;
        let bloom_hashes = self.docs[pos].bloom_hashes;
        update_tree_gate_for_doc_bytes_inner(
            &mut self.tree_tier1_gates,
            filter_bytes,
            bloom_hashes,
            bloom_bytes,
        );
        Ok(())
    }

    fn update_tree_tier1_gates_for_doc_bytes_batch(
        &mut self,
        updates: &[(usize, usize, usize, &[u8])],
    ) -> Result<()> {
        if experiment_disable_tree_gates_enabled() {
            return Ok(());
        }
        update_tree_gate_for_doc_bytes_batch(&mut self.tree_tier1_gates, updates);
        Ok(())
    }

    fn update_tree_tier2_gates_for_doc_bytes_inner(
        &mut self,
        pos: usize,
        bloom_bytes: &[u8],
    ) -> Result<()> {
        if experiment_disable_tree_gates_enabled() {
            return Ok(());
        }
        if pos >= self.docs.len() || self.docs[pos].deleted || self.docs[pos].special_population {
            return Ok(());
        }
        let filter_bytes = self.docs[pos].tier2_filter_bytes;
        let bloom_hashes = self.docs[pos].tier2_bloom_hashes;
        if filter_bytes == 0 || bloom_hashes == 0 || bloom_bytes.is_empty() {
            return Ok(());
        }
        update_tree_gate_for_doc_bytes_inner(
            &mut self.tree_tier2_gates,
            filter_bytes,
            bloom_hashes,
            bloom_bytes,
        );
        Ok(())
    }

    fn update_tree_tier2_gates_for_doc_bytes_batch(
        &mut self,
        updates: &[(usize, usize, usize, &[u8])],
    ) -> Result<()> {
        if experiment_disable_tree_gates_enabled() {
            return Ok(());
        }
        update_tree_gate_for_doc_bytes_batch(&mut self.tree_tier2_gates, updates);
        Ok(())
    }

    fn update_tree_tier1_gates_for_doc_inner(&mut self, pos: usize) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted || self.docs[pos].special_population {
            return Ok(());
        }
        let doc_id = self.docs[pos].doc_id;
        let row = self.doc_rows[pos];
        let bloom_bytes = self.sidecars.blooms.read_bytes(
            row.bloom_offset,
            row.bloom_len as usize,
            "bloom",
            doc_id,
        )?;
        let owned_bloom_bytes = bloom_bytes.into_owned();
        self.update_tree_tier1_gates_for_doc_bytes_inner(pos, &owned_bloom_bytes)
    }

    fn update_tree_tier2_gates_for_doc_inner(&mut self, pos: usize) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted || self.docs[pos].special_population {
            return Ok(());
        }
        let doc_id = self.docs[pos].doc_id;
        let row = self.tier2_doc_rows[pos];
        if row.bloom_len == 0 {
            return Ok(());
        }
        let bloom_bytes = self.sidecars.tier2_blooms.read_bytes(
            row.bloom_offset,
            row.bloom_len as usize,
            "tier2_bloom",
            doc_id,
        )?;
        let owned_bloom_bytes = bloom_bytes.into_owned();
        self.update_tree_tier2_gates_for_doc_bytes_inner(pos, &owned_bloom_bytes)
    }

    fn rebuild_tree_gates(&mut self) -> Result<()> {
        self.tree_tier1_gates = TreeBloomGateIndex::default();
        self.tree_tier2_gates = TreeBloomGateIndex::default();
        if experiment_disable_tree_gates_enabled() {
            return Ok(());
        }
        for pos in 0..self.docs.len() {
            self.update_tree_tier1_gates_for_doc_inner(pos)?;
            self.update_tree_tier2_gates_for_doc_inner(pos)?;
        }
        Ok(())
    }

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

    fn rebuild_indexes_profiled(&mut self) -> Result<CandidateStoreRebuildProfile> {
        let started_total = Instant::now();
        self.sha_to_pos.clear();
        self.special_doc_positions.clear();
        let sha_started = Instant::now();
        for (index, doc) in self.docs.iter_mut().enumerate() {
            if doc.bloom_hashes == 0 {
                doc.bloom_hashes = DEFAULT_BLOOM_HASHES;
                if let Some(row) = self.doc_rows.get_mut(index) {
                    row.bloom_hashes = DEFAULT_BLOOM_HASHES.min(u8::MAX as usize) as u8;
                }
            }
            self.sha_to_pos.insert(doc.sha256.clone(), index);
            if doc.special_population {
                self.special_doc_positions.push(index);
            }
        }
        let sha_index_ms = sha_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        self.tree_tier1_gates = TreeBloomGateIndex::default();
        self.tree_tier2_gates = TreeBloomGateIndex::default();
        self.rebuild_tree_gates()?;
        Ok(CandidateStoreRebuildProfile {
            sha_index_ms,
            total_ms: started_total
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        })
    }

    pub(crate) fn remove_tree_gate_snapshots(&self) -> Result<()> {
        for path in [
            tree_tier1_gates_path(&self.root),
            tree_tier2_gates_path(&self.root),
        ] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    fn prepared_query_cache_key(plan: &CompiledQueryPlan) -> Result<String> {
        serde_json::to_string(plan).map_err(SspryError::from)
    }

    fn prepare_query_artifacts(
        &mut self,
        plan: &CompiledQueryPlan,
    ) -> Result<Arc<PreparedQueryArtifacts>> {
        let key = Self::prepared_query_cache_key(plan)?;
        if let Some(entry) = self.prepared_query_cache.get(&key) {
            record_counter("candidate.query_prepared_cache_hits_total", 1);
            return Ok(entry);
        }
        record_counter("candidate.query_prepared_cache_misses_total", 1);
        let entry = build_prepared_query_artifacts(
            plan,
            &self.tier1_doc_filter_keys(),
            &self.tier2_doc_filter_keys(),
        )?;
        self.prepared_query_cache.insert(key, entry.clone());
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
        append_blob(sha_by_docid_path(compacted_root), &doc.sha256)?;
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

fn forest_policy_root(root: &Path) -> PathBuf {
    let leaf = root.file_name().and_then(|value| value.to_str());
    if leaf.is_some_and(|name| matches!(name, "current" | "work_a" | "work_b")) {
        let parent = root.parent().unwrap_or(root);
        if parent
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with("tree_"))
        {
            return parent.parent().unwrap_or(parent).to_path_buf();
        }
        return parent.to_path_buf();
    }
    if leaf.is_some_and(|name| name.starts_with("shard_")) {
        let parent = root.parent().unwrap_or(root);
        if parent
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| matches!(name, "current" | "work_a" | "work_b"))
        {
            let workspace_root = parent.parent().unwrap_or(parent);
            if workspace_root
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with("tree_"))
            {
                return workspace_root
                    .parent()
                    .unwrap_or(workspace_root)
                    .to_path_buf();
            }
            return workspace_root.to_path_buf();
        }
        return parent.to_path_buf();
    }
    root.to_path_buf()
}

fn forest_meta_path(root: &Path) -> PathBuf {
    root.join("meta.json")
}

#[cfg(test)]
fn meta_path(root: &Path) -> PathBuf {
    forest_meta_path(root)
}

fn store_local_meta_path(root: &Path) -> PathBuf {
    root.join("store_meta.json")
}

fn sha_by_docid_path(root: &Path) -> PathBuf {
    root.join("sha256_by_docid.dat")
}

fn doc_meta_path(root: &Path) -> PathBuf {
    root.join("doc_meta.bin")
}

fn tier2_doc_meta_path(root: &Path) -> PathBuf {
    root.join("tier2_doc_meta.bin")
}

fn doc_metadata_path(root: &Path) -> PathBuf {
    root.join("doc_metadata.bin")
}

fn blooms_path(root: &Path) -> PathBuf {
    root.join("blooms.bin")
}

fn tier2_blooms_path(root: &Path) -> PathBuf {
    root.join("tier2_blooms.bin")
}

fn external_ids_path(root: &Path) -> PathBuf {
    root.join("external_ids.dat")
}

fn tree_tier1_gates_path(root: &Path) -> PathBuf {
    root.join("tree_tier1_gates.bin")
}

fn tree_tier2_gates_path(root: &Path) -> PathBuf {
    root.join("tree_tier2_gates.bin")
}

pub fn candidate_shard_manifest_path(root: &Path) -> PathBuf {
    root.join("shards.json")
}

fn shard_compaction_manifest_path(root: &Path) -> PathBuf {
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    let stem = root
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "candidate_db".to_owned());
    parent.join(format!(".{stem}.compaction.json"))
}

fn read_shard_compaction_manifest(root: &Path) -> Result<ShardCompactionManifest> {
    let path = shard_compaction_manifest_path(root);
    if !path.exists() {
        return Ok(ShardCompactionManifest::default());
    }
    serde_json::from_slice(&fs::read(&path)?).map_err(|_| {
        SspryError::from(format!(
            "Invalid candidate compaction manifest at {}",
            path.display()
        ))
    })
}

fn write_shard_compaction_manifest(root: &Path, manifest: &ShardCompactionManifest) -> Result<()> {
    write_json(shard_compaction_manifest_path(root), manifest)
}

fn ensure_shard_compaction_manifest(root: &Path) -> Result<ShardCompactionManifest> {
    let manifest = read_shard_compaction_manifest(root)?;
    write_shard_compaction_manifest(root, &manifest)?;
    Ok(manifest)
}

fn retired_generation_root(root: &Path, generation: u64) -> PathBuf {
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    let stem = root
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "candidate_db".to_owned());
    parent.join(format!(".{stem}.retired.gen{generation:06}"))
}

pub fn candidate_shard_root(root: &Path, shard_count: usize, shard_idx: usize) -> PathBuf {
    if shard_count <= 1 {
        return root.to_path_buf();
    }
    root.join(format!("shard_{shard_idx:03}"))
}

pub fn candidate_shard_index(sha256: &[u8; 32], shard_count: usize) -> usize {
    if shard_count <= 1 {
        return 0;
    }
    let head = u32::from_le_bytes([sha256[0], sha256[1], sha256[2], sha256[3]]) as usize;
    head % shard_count
}

pub fn read_candidate_shard_count(root: &Path) -> Result<Option<usize>> {
    let path = candidate_shard_manifest_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path)?).map_err(|_| {
        SspryError::from(format!(
            "Invalid candidate shard manifest at {}",
            path.display()
        ))
    })?;
    let count = raw
        .get("candidate_shards")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| {
            SspryError::from(format!(
                "Invalid candidate shard manifest at {}",
                path.display()
            ))
        })?;
    Ok(Some(count.max(1) as usize))
}

pub fn write_candidate_shard_count(root: &Path, shard_count: usize) -> Result<()> {
    fs::create_dir_all(root)?;
    write_json(
        candidate_shard_manifest_path(root),
        &serde_json::json!({ "candidate_shards": shard_count.max(1) }),
    )
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> Result<()> {
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn append_blob(path: PathBuf, bytes: &[u8]) -> Result<u64> {
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    let offset = handle.metadata()?.len();
    handle.write_all(bytes)?;
    Ok(offset)
}

fn read_blob_from_path(
    path: &Path,
    offset: u64,
    len: usize,
    label: &str,
    doc_id: u64,
) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes).map_err(|err| {
        SspryError::from(format!(
            "Failed to read {label} payload for doc_id {doc_id} from {}: {err}",
            path.display()
        ))
    })?;
    Ok(bytes)
}

fn write_at(path: PathBuf, offset: u64, bytes: &[u8]) -> Result<()> {
    let mut handle = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)?;
    handle.seek(SeekFrom::Start(offset))?;
    handle.write_all(bytes)?;
    Ok(())
}

pub(crate) fn compaction_work_root(root: &Path, suffix: &str) -> PathBuf {
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    let stem = root
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "candidate_db".to_owned());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0);
    parent.join(format!(".{stem}.{suffix}.{nonce}"))
}

pub(crate) fn cleanup_abandoned_compaction_roots(root: &Path) -> Result<usize> {
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        return Ok(0);
    }
    let stem = root
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "candidate_db".to_owned());
    let prefix = format!(".{stem}.compact-");
    let mut removed = 0usize;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(&prefix) {
            continue;
        }
        fs::remove_dir_all(entry.path())?;
        removed += 1;
    }
    Ok(removed)
}

#[cfg(test)]
fn append_u32_slice(path: PathBuf, values: &[u32]) -> Result<u64> {
    if values.is_empty() {
        return Ok(0);
    }
    let mut payload = Vec::with_capacity(values.len() * 4);
    for value in values {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    append_blob(path, &payload)
}

#[cfg(test)]
fn dir_size(path: &Path) -> u64 {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(metadata) if metadata.is_dir() => fs::read_dir(path)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.flatten())
            .map(|entry| dir_size(&entry.path()))
            .sum(),
        _ => 0,
    }
}

fn load_candidate_store_state(
    root: &Path,
) -> Result<(Vec<CandidateDoc>, Vec<DocMetaRow>, Vec<Tier2DocMetaRow>)> {
    if binary_store_exists(root) {
        return load_candidate_binary_store(root);
    }
    Ok((Vec::new(), Vec::new(), Vec::new()))
}

fn binary_store_exists(root: &Path) -> bool {
    sha_by_docid_path(root).exists()
        || doc_meta_path(root).exists()
        || tier2_doc_meta_path(root).exists()
        || doc_metadata_path(root).exists()
}

fn load_candidate_binary_store(
    root: &Path,
) -> Result<(Vec<CandidateDoc>, Vec<DocMetaRow>, Vec<Tier2DocMetaRow>)> {
    let sha_bytes = fs::read(sha_by_docid_path(root))?;
    let row_bytes = fs::read(doc_meta_path(root))?;
    let tier2_row_bytes = fs::read(tier2_doc_meta_path(root)).unwrap_or_default();
    if sha_bytes.len() % 32 != 0 || row_bytes.len() % DOC_META_ROW_BYTES != 0 {
        return Err(SspryError::from(format!(
            "Invalid candidate binary document state at {}",
            root.display()
        )));
    }
    let doc_count = sha_bytes.len() / 32;
    if doc_count != row_bytes.len() / DOC_META_ROW_BYTES {
        return Err(SspryError::from(format!(
            "Mismatched candidate binary document state at {}",
            root.display()
        )));
    }
    let mut docs = Vec::with_capacity(doc_count);
    let mut rows = Vec::with_capacity(doc_count);
    let mut tier2_rows = Vec::with_capacity(doc_count);
    for index in 0..doc_count {
        let doc_id = (index + 1) as u64;
        let sha256 = hex::encode(&sha_bytes[index * 32..(index + 1) * 32]);
        let row = DocMetaRow::decode(
            &row_bytes[index * DOC_META_ROW_BYTES..(index + 1) * DOC_META_ROW_BYTES],
        )?;
        let tier2_row = if tier2_row_bytes.len() >= (index + 1) * TIER2_DOC_META_ROW_BYTES {
            Tier2DocMetaRow::decode(
                &tier2_row_bytes
                    [index * TIER2_DOC_META_ROW_BYTES..(index + 1) * TIER2_DOC_META_ROW_BYTES],
            )?
        } else {
            Tier2DocMetaRow::default()
        };
        docs.push(CandidateDoc {
            doc_id,
            sha256,
            file_size: row.file_size,
            filter_bytes: row.filter_bytes as usize,
            bloom_hashes: usize::from(row.bloom_hashes.max(1)),
            tier2_filter_bytes: tier2_row.filter_bytes as usize,
            tier2_bloom_hashes: usize::from(tier2_row.bloom_hashes),
            special_population: (row.flags & DOC_FLAG_SPECIAL_POPULATION) != 0,
            deleted: (row.flags & DOC_FLAG_DELETED) != 0,
        });
        rows.push(row);
        tier2_rows.push(tier2_row);
    }
    Ok((docs, rows, tier2_rows))
}

#[cfg(test)]
fn read_blob<'a>(
    bytes: &'a [u8],
    offset: u64,
    len: usize,
    label: &str,
    doc_id: u64,
) -> Result<&'a [u8]> {
    let offset = offset as usize;
    let end = offset.saturating_add(len);
    if end > bytes.len() {
        return Err(SspryError::from(format!(
            "Invalid {label} payload stored for doc_id {doc_id}"
        )));
    }
    Ok(&bytes[offset..end])
}

#[cfg(test)]
fn read_u32_vec(
    bytes: &[u8],
    offset: u64,
    count: u32,
    label: &str,
    doc_id: u64,
) -> Result<Vec<u32>> {
    let slice = read_blob(bytes, offset, count as usize * 4, label, doc_id)?;
    let mut out = Vec::with_capacity(count as usize);
    for chunk in slice.chunks_exact(4) {
        out.push(u32::from_le_bytes(chunk.try_into().expect("u32 chunk")));
    }
    Ok(out)
}

fn validate_config(config: &CandidateConfig) -> Result<()> {
    if !matches!(
        config.id_source.as_str(),
        "sha256" | "md5" | "sha1" | "sha512"
    ) {
        return Err(SspryError::from(
            "id_source must be one of sha256, md5, sha1, sha512",
        ));
    }
    GramSizes::new(config.tier1_gram_size, config.tier2_gram_size)
        .map_err(|err| SspryError::from(format!("invalid gram size pair: {err}")))?;
    if !config.compaction_idle_cooldown_s.is_finite() || config.compaction_idle_cooldown_s < 0.0 {
        return Err(SspryError::from(
            "compaction_idle_cooldown_s must be finite and >= 0",
        ));
    }
    for (field, value) in [
        ("filter_target_fp", config.filter_target_fp),
        ("tier1_filter_target_fp", config.tier1_filter_target_fp),
        ("tier2_filter_target_fp", config.tier2_filter_target_fp),
    ] {
        if let Some(value) = value {
            if !(0.0 < value && value < 1.0) {
                return Err(SspryError::from(format!("{field} must be in range (0, 1)")));
            }
        }
    }
    Ok(())
}

fn normalize_sha256_hex(value: &str) -> Result<String> {
    let text = value.trim().to_ascii_lowercase();
    if text.len() != 64 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(SspryError::from(
            "sha256 must be exactly 64 hexadecimal characters.",
        ));
    }
    Ok(text)
}

type RequiredMasksByKey = FxHashMap<(usize, usize), Vec<(usize, u64)>>;

#[derive(Clone, Debug, Default)]
struct ShiftedRequiredMasks {
    shifts: Vec<RequiredMasksByKey>,
    any_lane_values: Vec<Vec<RequiredMasksByKey>>,
    any_lane_grams: Vec<u64>,
}

impl ShiftedRequiredMasks {
    fn is_empty(&self) -> bool {
        self.shifts.iter().all(RequiredMasksByKey::is_empty)
            && self
                .any_lane_values
                .iter()
                .all(|lanes| lanes.iter().all(RequiredMasksByKey::is_empty))
            && self.any_lane_grams.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
struct PreparedPatternMasks {
    tier1: Vec<ShiftedRequiredMasks>,
    tier2: Vec<ShiftedRequiredMasks>,
}

type PatternMaskCache = HashMap<String, PreparedPatternMasks>;

const MAX_LANE_POSITION_VARIANTS: usize = 64;
const PREPARED_QUERY_MASK_CACHE_BUDGET_BYTES: u64 = 128 * 1024 * 1024;

fn required_masks_by_key_memory_bytes(masks: &RequiredMasksByKey) -> u64 {
    (masks.len() as u64)
        .saturating_mul(std::mem::size_of::<((usize, usize), Vec<(usize, u64)>)>() as u64)
        .saturating_add(
            masks
                .values()
                .map(|values| {
                    (std::mem::size_of::<Vec<(usize, u64)>>() as u64).saturating_add(
                        (values.capacity() as u64)
                            .saturating_mul(std::mem::size_of::<(usize, u64)>() as u64),
                    )
                })
                .sum::<u64>(),
        )
}

fn shifted_required_masks_memory_bytes(masks: &ShiftedRequiredMasks) -> u64 {
    (std::mem::size_of::<ShiftedRequiredMasks>() as u64)
        .saturating_add(
            (masks.shifts.capacity() as u64)
                .saturating_mul(std::mem::size_of::<RequiredMasksByKey>() as u64),
        )
        .saturating_add(
            masks
                .shifts
                .iter()
                .map(required_masks_by_key_memory_bytes)
                .sum::<u64>(),
        )
        .saturating_add(
            (masks.any_lane_values.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<RequiredMasksByKey>>() as u64),
        )
        .saturating_add(
            masks
                .any_lane_values
                .iter()
                .map(|lane_maps| {
                    (std::mem::size_of::<Vec<RequiredMasksByKey>>() as u64)
                        .saturating_add(
                            (lane_maps.capacity() as u64).saturating_mul(std::mem::size_of::<
                                RequiredMasksByKey,
                            >(
                            )
                                as u64),
                        )
                        .saturating_add(
                            lane_maps
                                .iter()
                                .map(required_masks_by_key_memory_bytes)
                                .sum::<u64>(),
                        )
                })
                .sum::<u64>(),
        )
        .saturating_add(
            (masks.any_lane_grams.capacity() as u64)
                .saturating_mul(std::mem::size_of::<u64>() as u64),
        )
}

fn prepared_pattern_masks_memory_bytes(masks: &PreparedPatternMasks) -> u64 {
    (std::mem::size_of::<PreparedPatternMasks>() as u64)
        .saturating_add(
            (masks.tier1.capacity() as u64)
                .saturating_mul(std::mem::size_of::<ShiftedRequiredMasks>() as u64),
        )
        .saturating_add(
            masks
                .tier1
                .iter()
                .map(shifted_required_masks_memory_bytes)
                .sum::<u64>(),
        )
        .saturating_add(
            (masks.tier2.capacity() as u64)
                .saturating_mul(std::mem::size_of::<ShiftedRequiredMasks>() as u64),
        )
        .saturating_add(
            masks
                .tier2
                .iter()
                .map(shifted_required_masks_memory_bytes)
                .sum::<u64>(),
        )
}

fn prepared_pattern_plan_memory_bytes(pattern: &PatternPlan) -> u64 {
    let alternatives_bytes = pattern
        .alternatives
        .iter()
        .map(|alts| {
            (std::mem::size_of::<Vec<u64>>() as u64).saturating_add(
                (alts.capacity() as u64).saturating_mul(std::mem::size_of::<u64>() as u64),
            )
        })
        .sum::<u64>();
    let tier2_alternatives_bytes = pattern
        .tier2_alternatives
        .iter()
        .map(|alts| {
            (std::mem::size_of::<Vec<u64>>() as u64).saturating_add(
                (alts.capacity() as u64).saturating_mul(std::mem::size_of::<u64>() as u64),
            )
        })
        .sum::<u64>();
    let anchor_literals_bytes = pattern
        .anchor_literals
        .iter()
        .map(|literal| {
            (std::mem::size_of::<Vec<u8>>() as u64).saturating_add(literal.capacity() as u64)
        })
        .sum::<u64>();
    let fixed_literals_bytes = pattern
        .fixed_literals
        .iter()
        .map(|literal| {
            (std::mem::size_of::<Vec<u8>>() as u64).saturating_add(literal.capacity() as u64)
        })
        .sum::<u64>();
    (std::mem::size_of::<PatternPlan>() as u64)
        .saturating_add(pattern.pattern_id.capacity() as u64)
        .saturating_add(
            (pattern.alternatives.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<u64>>() as u64),
        )
        .saturating_add(alternatives_bytes)
        .saturating_add(
            (pattern.tier2_alternatives.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<u64>>() as u64),
        )
        .saturating_add(tier2_alternatives_bytes)
        .saturating_add(
            (pattern.anchor_literals.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<u8>>() as u64),
        )
        .saturating_add(anchor_literals_bytes)
        .saturating_add(
            (pattern.fixed_literals.capacity() as u64)
                .saturating_mul(std::mem::size_of::<Vec<u8>>() as u64),
        )
        .saturating_add(fixed_literals_bytes)
        .saturating_add(
            (pattern.fixed_literal_wide.capacity() as u64)
                .saturating_mul(std::mem::size_of::<bool>() as u64),
        )
        .saturating_add(
            (pattern.fixed_literal_fullword.capacity() as u64)
                .saturating_mul(std::mem::size_of::<bool>() as u64),
        )
}

pub(crate) fn prepared_query_artifacts_memory_bytes(artifacts: &PreparedQueryArtifacts) -> u64 {
    let patterns_bytes = artifacts
        .patterns
        .iter()
        .map(|(key, pattern)| {
            (std::mem::size_of::<String>() as u64)
                .saturating_add(key.capacity() as u64)
                .saturating_add(prepared_pattern_plan_memory_bytes(pattern))
        })
        .sum::<u64>();
    let mask_cache_bytes = artifacts
        .mask_cache
        .iter()
        .map(|(key, masks)| {
            (std::mem::size_of::<String>() as u64)
                .saturating_add(key.capacity() as u64)
                .saturating_add(prepared_pattern_masks_memory_bytes(masks))
        })
        .sum::<u64>();
    (std::mem::size_of::<PreparedQueryArtifacts>() as u64)
        .saturating_add(patterns_bytes)
        .saturating_add(mask_cache_bytes)
}

pub(crate) fn prepared_query_artifacts_profile(
    artifacts: &PreparedQueryArtifacts,
) -> CandidatePreparedQueryProfile {
    let mut profile = CandidatePreparedQueryProfile {
        impossible_query: artifacts.impossible_query,
        prepared_query_bytes: prepared_query_artifacts_memory_bytes(artifacts),
        ..CandidatePreparedQueryProfile::default()
    };
    for (pattern_id, pattern) in &artifacts.patterns {
        profile.pattern_count = profile.pattern_count.saturating_add(1);
        profile.fixed_literal_count = profile
            .fixed_literal_count
            .saturating_add(pattern.fixed_literals.len() as u64);
        profile.tier1_alternatives = profile
            .tier1_alternatives
            .saturating_add(pattern.alternatives.len() as u64);
        profile.tier2_alternatives = profile
            .tier2_alternatives
            .saturating_add(pattern.tier2_alternatives.len() as u64);

        let pattern_bytes = prepared_pattern_plan_memory_bytes(pattern);
        profile.prepared_pattern_plan_bytes = profile
            .prepared_pattern_plan_bytes
            .saturating_add(pattern_bytes);
        if pattern_bytes > profile.max_pattern_bytes {
            profile.max_pattern_bytes = pattern_bytes;
            profile.max_pattern_id = Some(pattern_id.clone());
        }
    }
    for masks in artifacts.mask_cache.values() {
        profile.mask_cache_entries = profile.mask_cache_entries.saturating_add(1);
        profile.prepared_mask_cache_bytes = profile
            .prepared_mask_cache_bytes
            .saturating_add(prepared_pattern_masks_memory_bytes(masks));
        for shifted in &masks.tier1 {
            profile.accumulate_shifted(shifted, false);
        }
        for shifted in &masks.tier2 {
            profile.accumulate_shifted(shifted, true);
        }
    }
    profile
}

fn lane_position_variants_for_pattern(
    values: &[u64],
    fixed_literal: &[u8],
    gram_size: usize,
    lane_count: usize,
) -> Vec<Vec<usize>> {
    if fixed_literal.is_empty() || fixed_literal.len() < gram_size {
        return vec![Vec::new()];
    }
    let mut positions_per_gram = Vec::<Vec<usize>>::with_capacity(values.len());
    let mut positions_by_gram = HashMap::<u64, Vec<usize>>::new();
    for idx in 0..=(fixed_literal.len() - gram_size) {
        let gram = pack_exact_gram(&fixed_literal[idx..idx + gram_size]);
        positions_by_gram.entry(gram).or_default().push(idx);
    }
    for (gram_idx, value) in values.iter().enumerate() {
        positions_per_gram.push(
            positions_by_gram
                .get(value)
                .cloned()
                .filter(|positions| !positions.is_empty())
                .unwrap_or_else(|| vec![gram_idx]),
        );
    }

    let mut combos = vec![Vec::<usize>::new()];
    for positions in positions_per_gram {
        let mut next = Vec::<Vec<usize>>::new();
        for combo in &combos {
            for position in &positions {
                if next.len() >= MAX_LANE_POSITION_VARIANTS {
                    break;
                }
                let mut variant = combo.clone();
                variant.push(*position);
                next.push(variant);
            }
            if next.len() >= MAX_LANE_POSITION_VARIANTS {
                break;
            }
        }
        combos = next;
        if combos.is_empty() {
            combos.push(Vec::new());
        }
    }

    let mut variants = Vec::<Vec<usize>>::new();
    for shift in 0..lane_count.max(1) {
        for combo in &combos {
            if variants.len() >= MAX_LANE_POSITION_VARIANTS {
                return variants;
            }
            variants.push(
                combo
                    .iter()
                    .map(|position| (shift + position) % lane_count.max(1))
                    .collect(),
            );
        }
    }
    if variants.is_empty() {
        variants.push(Vec::new());
    }
    variants
}

fn exact_pattern_has_ambiguous_positions(
    values: &[u64],
    fixed_literal: &[u8],
    gram_size: usize,
) -> bool {
    if fixed_literal.is_empty() || fixed_literal.len() < gram_size {
        return false;
    }
    let mut positions_by_gram = HashMap::<u64, Vec<usize>>::new();
    for idx in 0..=(fixed_literal.len() - gram_size) {
        let gram = pack_exact_gram(&fixed_literal[idx..idx + gram_size]);
        positions_by_gram.entry(gram).or_default().push(idx);
    }
    values.iter().any(|value| {
        positions_by_gram
            .get(value)
            .map(|positions| positions.len() > 1)
            .unwrap_or(false)
    })
}

fn merge_cached_lane_bloom_word_masks(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
    lanes: &[usize],
    lane_count: usize,
    cache: &mut HashMap<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>,
) -> Result<Vec<(usize, u64)>> {
    let mut merged = FxHashMap::<usize, u64>::default();
    for (gram_idx, value) in values.iter().enumerate() {
        let cached_masks = if let Some(lane) = lanes.get(gram_idx).copied() {
            let key = (*value, size_bytes, hash_count, lane, lane_count);
            if let Some(entry) = cache.get(&key) {
                entry.clone()
            } else {
                let entry =
                    bloom_word_masks_in_lane(&[*value], size_bytes, hash_count, lane, lane_count)?;
                cache.insert(key, entry.clone());
                entry
            }
        } else {
            let mut any_lane = FxHashMap::<usize, u64>::default();
            for lane in 0..lane_count.max(1) {
                let key = (*value, size_bytes, hash_count, lane, lane_count);
                let cached = if let Some(entry) = cache.get(&key) {
                    entry.clone()
                } else {
                    let entry = bloom_word_masks_in_lane(
                        &[*value],
                        size_bytes,
                        hash_count,
                        lane,
                        lane_count,
                    )?;
                    cache.insert(key, entry.clone());
                    entry
                };
                for (word_idx, mask) in cached {
                    *any_lane.entry(word_idx).or_insert(0) |= mask;
                }
            }
            any_lane.into_iter().collect()
        };
        for (word_idx, mask) in cached_masks {
            *merged.entry(word_idx).or_insert(0) |= mask;
        }
    }
    Ok(merged.into_iter().collect())
}

fn build_any_lane_required_masks(
    values: &[u64],
    filter_keys: &[(usize, usize)],
    lane_count: usize,
    cache: &mut HashMap<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>,
) -> Result<Vec<Vec<RequiredMasksByKey>>> {
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let mut per_lane = Vec::with_capacity(lane_count.max(1));
        for lane in 0..lane_count.max(1) {
            let mut by_key = RequiredMasksByKey::default();
            for (filter_bytes, bloom_hashes) in filter_keys {
                let key = (*value, *filter_bytes, *bloom_hashes, lane, lane_count);
                let cached = if let Some(entry) = cache.get(&key) {
                    entry.clone()
                } else {
                    let entry = bloom_word_masks_in_lane(
                        &[*value],
                        *filter_bytes,
                        *bloom_hashes,
                        lane,
                        lane_count,
                    )?;
                    cache.insert(key, entry.clone());
                    entry
                };
                by_key.insert((*filter_bytes, *bloom_hashes), cached);
            }
            per_lane.push(by_key);
        }
        out.push(per_lane);
    }
    Ok(out)
}

fn maybe_compact_any_lane_masks(
    shifted: &mut ShiftedRequiredMasks,
    values: &[u64],
    current_budget_bytes: &mut u64,
) {
    let current_bytes = shifted_required_masks_memory_bytes(shifted);
    if shifted.any_lane_values.is_empty()
        || current_budget_bytes.saturating_add(current_bytes)
            <= PREPARED_QUERY_MASK_CACHE_BUDGET_BYTES
    {
        *current_budget_bytes = current_budget_bytes.saturating_add(current_bytes);
        return;
    }
    shifted.any_lane_values.clear();
    shifted.any_lane_grams = values.to_vec();
    *current_budget_bytes =
        current_budget_bytes.saturating_add(shifted_required_masks_memory_bytes(shifted));
}

fn node_structurally_impossible(node: &QueryNode) -> bool {
    match node.kind.as_str() {
        "pattern" => false,
        "identity_eq" => false,
        "not" => false,
        "verifier_only_eq" => false,
        "verifier_only_at" => false,
        "verifier_only_count" => false,
        "verifier_only_in_range" => false,
        "verifier_only_loop" => false,
        "filesize_eq" => false,
        "filesize_ne" => false,
        "filesize_lt" => false,
        "filesize_le" => false,
        "filesize_gt" => false,
        "filesize_ge" => false,
        "metadata_eq" => false,
        "metadata_ne" => false,
        "metadata_lt" => false,
        "metadata_le" => false,
        "metadata_gt" => false,
        "metadata_ge" => false,
        "metadata_float_eq" => false,
        "metadata_float_ne" => false,
        "metadata_float_lt" => false,
        "metadata_float_le" => false,
        "metadata_float_gt" => false,
        "metadata_float_ge" => false,
        "metadata_time_eq" => false,
        "metadata_time_ne" => false,
        "metadata_time_lt" => false,
        "metadata_time_le" => false,
        "metadata_time_gt" => false,
        "metadata_time_ge" => false,
        "metadata_field_eq" => false,
        "metadata_field_ne" => false,
        "metadata_field_lt" => false,
        "metadata_field_le" => false,
        "metadata_field_gt" => false,
        "metadata_field_ge" => false,
        "time_now_eq" => false,
        "time_now_ne" => false,
        "time_now_lt" => false,
        "time_now_le" => false,
        "time_now_gt" => false,
        "time_now_ge" => false,
        "and" => node.children.iter().any(node_structurally_impossible),
        "or" => !node.children.is_empty() && node.children.iter().all(node_structurally_impossible),
        "n_of" => {
            let threshold = node.threshold.unwrap_or(usize::MAX);
            if threshold > node.children.len() {
                return true;
            }
            let possible_children = node
                .children
                .iter()
                .filter(|child| !node_structurally_impossible(child))
                .count();
            possible_children < threshold
        }
        _ => false,
    }
}

fn query_node_uses_pattern_blooms(node: &QueryNode) -> bool {
    match node.kind.as_str() {
        "pattern" => true,
        "and" | "or" | "n_of" | "not" => node.children.iter().any(query_node_uses_pattern_blooms),
        _ => false,
    }
}

fn query_node_contains_verifier_only(node: &QueryNode) -> bool {
    matches!(
        node.kind.as_str(),
        "verifier_only_eq"
            | "verifier_only_at"
            | "verifier_only_count"
            | "verifier_only_in_range"
            | "verifier_only_loop"
    ) || node.children.iter().any(query_node_contains_verifier_only)
}

fn build_pattern_mask_cache(
    patterns: &[PatternPlan],
    tier1_filter_keys: &[(usize, usize)],
    tier2_filter_keys: &[(usize, usize)],
    tier1_gram_size: usize,
    tier2_gram_size: usize,
) -> Result<PatternMaskCache> {
    let mut out = HashMap::with_capacity(patterns.len());
    let mut tier1_gram_cache =
        HashMap::<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>::new();
    let mut tier2_gram_cache =
        HashMap::<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>::new();
    let mut current_budget_bytes = 0u64;
    for pattern in patterns {
        let mut tier1_masks = Vec::with_capacity(pattern.alternatives.len());
        for (alt_index, alternative) in pattern.alternatives.iter().enumerate() {
            let anchor_literal = pattern
                .anchor_literals
                .get(alt_index)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut shifted_tier1 = ShiftedRequiredMasks::default();
            if anchor_literal.is_empty()
                || anchor_literal.len() < tier1_gram_size
                || exact_pattern_has_ambiguous_positions(
                    alternative,
                    anchor_literal,
                    tier1_gram_size,
                )
            {
                shifted_tier1.any_lane_values = build_any_lane_required_masks(
                    alternative,
                    tier1_filter_keys,
                    DEFAULT_BLOOM_POSITION_LANES,
                    &mut tier1_gram_cache,
                )?;
            } else {
                let lane_variants = lane_position_variants_for_pattern(
                    alternative,
                    anchor_literal,
                    tier1_gram_size,
                    DEFAULT_BLOOM_POSITION_LANES,
                );
                shifted_tier1.shifts = Vec::with_capacity(lane_variants.len());
                for lanes in &lane_variants {
                    let mut by_key = RequiredMasksByKey::default();
                    for (filter_bytes, bloom_hashes) in tier1_filter_keys {
                        let required = merge_cached_lane_bloom_word_masks(
                            alternative,
                            *filter_bytes,
                            *bloom_hashes,
                            lanes,
                            DEFAULT_BLOOM_POSITION_LANES,
                            &mut tier1_gram_cache,
                        )?;
                        by_key.insert((*filter_bytes, *bloom_hashes), required);
                    }
                    shifted_tier1.shifts.push(by_key);
                }
            }
            maybe_compact_any_lane_masks(
                &mut shifted_tier1,
                alternative,
                &mut current_budget_bytes,
            );
            tier1_masks.push(shifted_tier1);
        }

        let mut tier2_masks = Vec::with_capacity(pattern.tier2_alternatives.len());
        for (alt_index, alternative) in pattern.tier2_alternatives.iter().enumerate() {
            let anchor_literal = pattern
                .anchor_literals
                .get(alt_index)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut shifted_tier2 = ShiftedRequiredMasks::default();
            if anchor_literal.is_empty()
                || anchor_literal.len() < tier2_gram_size
                || exact_pattern_has_ambiguous_positions(
                    alternative,
                    anchor_literal,
                    tier2_gram_size,
                )
            {
                shifted_tier2.any_lane_values = build_any_lane_required_masks(
                    alternative,
                    tier2_filter_keys,
                    DEFAULT_BLOOM_POSITION_LANES,
                    &mut tier2_gram_cache,
                )?;
            } else {
                let lane_variants = lane_position_variants_for_pattern(
                    alternative,
                    anchor_literal,
                    tier2_gram_size,
                    DEFAULT_BLOOM_POSITION_LANES,
                );
                shifted_tier2.shifts = Vec::with_capacity(lane_variants.len());
                for lanes in &lane_variants {
                    let mut by_key = RequiredMasksByKey::default();
                    for (filter_bytes, bloom_hashes) in tier2_filter_keys {
                        let required = merge_cached_lane_bloom_word_masks(
                            alternative,
                            *filter_bytes,
                            *bloom_hashes,
                            lanes,
                            DEFAULT_BLOOM_POSITION_LANES,
                            &mut tier2_gram_cache,
                        )?;
                        by_key.insert((*filter_bytes, *bloom_hashes), required);
                    }
                    shifted_tier2.shifts.push(by_key);
                }
            }
            maybe_compact_any_lane_masks(
                &mut shifted_tier2,
                alternative,
                &mut current_budget_bytes,
            );
            tier2_masks.push(shifted_tier2);
        }

        out.insert(
            pattern.pattern_id.clone(),
            PreparedPatternMasks {
                tier1: tier1_masks,
                tier2: tier2_masks,
            },
        );
    }
    Ok(out)
}

pub(crate) fn build_prepared_query_artifacts(
    plan: &CompiledQueryPlan,
    tier1_filter_keys: &[(usize, usize)],
    tier2_filter_keys: &[(usize, usize)],
) -> Result<Arc<PreparedQueryArtifacts>> {
    let patterns = plan
        .patterns
        .iter()
        .cloned()
        .map(|pattern| (pattern.pattern_id.clone(), pattern))
        .collect::<HashMap<_, _>>();
    let mask_cache = build_pattern_mask_cache(
        &plan.patterns,
        tier1_filter_keys,
        tier2_filter_keys,
        plan.tier1_gram_size,
        plan.tier2_gram_size,
    )?;
    Ok(Arc::new(PreparedQueryArtifacts {
        patterns,
        mask_cache,
        impossible_query: node_structurally_impossible(&plan.root),
    }))
}

fn tree_gate_matches_required_masks(
    by_key: &RequiredMasksByKey,
    gates: &TreeBloomGateIndex,
) -> bool {
    if by_key.is_empty() {
        return true;
    }
    if gates.masks_by_bucket.is_empty() {
        return true;
    }
    by_key.iter().any(|(filter_key, required)| {
        let Some(bucket_key) = gates.bucket_for_key.get(filter_key) else {
            return false;
        };
        let Some(mask) = gates.masks_by_bucket.get(bucket_key) else {
            return false;
        };
        raw_filter_matches_word_masks(mask, required)
    })
}

fn tree_gate_matches_shifted_required_masks(
    shifted: &ShiftedRequiredMasks,
    gates: &TreeBloomGateIndex,
) -> bool {
    if shifted.is_empty() {
        return true;
    }
    if !shifted.any_lane_grams.is_empty() {
        if gates.masks_by_bucket.is_empty() {
            return true;
        }
        return shifted.any_lane_grams.iter().all(|value| {
            gates
                .bucket_for_key
                .iter()
                .any(|((filter_bytes, bloom_hashes), bucket_key)| {
                    let Some(mask) = gates.masks_by_bucket.get(bucket_key) else {
                        return false;
                    };
                    (0..DEFAULT_BLOOM_POSITION_LANES).any(|lane| {
                        bloom_word_masks_in_lane(
                            &[*value],
                            *filter_bytes,
                            *bloom_hashes,
                            lane,
                            DEFAULT_BLOOM_POSITION_LANES,
                        )
                        .ok()
                        .is_some_and(|required| raw_filter_matches_word_masks(mask, &required))
                    })
                })
        });
    }
    if !shifted.any_lane_values.is_empty() {
        return shifted.any_lane_values.iter().all(|lanes| {
            lanes
                .iter()
                .any(|by_key| tree_gate_matches_required_masks(by_key, gates))
        });
    }
    shifted
        .shifts
        .iter()
        .any(|by_key| tree_gate_matches_required_masks(by_key, gates))
}

fn tree_gate_matches_pattern(
    pattern_id: &str,
    mask_cache: &PatternMaskCache,
    tier1_gates: &TreeBloomGateIndex,
    tier2_gates: &TreeBloomGateIndex,
    allow_tier2: bool,
) -> bool {
    let Some(pattern_masks) = mask_cache.get(pattern_id) else {
        return false;
    };
    let tier2_only = experiment_tier2_only_enabled();
    pattern_masks
        .tier1
        .iter()
        .enumerate()
        .any(|(alt_index, tier1_by_key)| {
            if tier2_only {
                let Some(tier2_by_key) = pattern_masks.tier2.get(alt_index) else {
                    return true;
                };
                if tier2_by_key.is_empty() {
                    return true;
                }
                return tree_gate_matches_shifted_required_masks(tier2_by_key, tier2_gates);
            }
            if !tree_gate_matches_shifted_required_masks(tier1_by_key, tier1_gates) {
                return false;
            }
            let Some(tier2_by_key) = pattern_masks.tier2.get(alt_index) else {
                return true;
            };
            if !allow_tier2 || tier2_by_key.is_empty() {
                return true;
            }
            tree_gate_matches_shifted_required_masks(tier2_by_key, tier2_gates)
        })
}

fn tree_maybe_matches_node(
    node: &QueryNode,
    mask_cache: &PatternMaskCache,
    tier1_gates: &TreeBloomGateIndex,
    tier2_gates: &TreeBloomGateIndex,
    allow_tier2: bool,
) -> Result<bool> {
    match node.kind.as_str() {
        "pattern" => {
            let pattern_id = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| SspryError::from("pattern node requires pattern_id"))?;
            Ok(tree_gate_matches_pattern(
                pattern_id,
                mask_cache,
                tier1_gates,
                tier2_gates,
                allow_tier2,
            ))
        }
        "not" => Ok(true),
        "identity_eq" => Ok(true),
        "verifier_only_eq"
        | "verifier_only_at"
        | "verifier_only_count"
        | "verifier_only_in_range"
        | "verifier_only_loop"
        | "filesize_eq"
        | "filesize_ne"
        | "filesize_lt"
        | "filesize_le"
        | "filesize_gt"
        | "filesize_ge"
        | "metadata_eq"
        | "metadata_ne"
        | "metadata_lt"
        | "metadata_le"
        | "metadata_gt"
        | "metadata_ge"
        | "metadata_float_eq"
        | "metadata_float_ne"
        | "metadata_float_lt"
        | "metadata_float_le"
        | "metadata_float_gt"
        | "metadata_float_ge"
        | "metadata_time_eq"
        | "metadata_time_ne"
        | "metadata_time_lt"
        | "metadata_time_le"
        | "metadata_time_gt"
        | "metadata_time_ge"
        | "metadata_field_eq"
        | "metadata_field_ne"
        | "metadata_field_lt"
        | "metadata_field_le"
        | "metadata_field_gt"
        | "metadata_field_ge"
        | "time_now_eq" => Ok(true),
        "time_now_ne" | "time_now_lt" | "time_now_le" | "time_now_gt" | "time_now_ge" => Ok(true),
        "and" => {
            for child in &node.children {
                if !tree_maybe_matches_node(
                    child,
                    mask_cache,
                    tier1_gates,
                    tier2_gates,
                    allow_tier2,
                )? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        "or" => {
            for child in &node.children {
                if tree_maybe_matches_node(
                    child,
                    mask_cache,
                    tier1_gates,
                    tier2_gates,
                    allow_tier2,
                )? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        "n_of" => {
            let threshold = node
                .threshold
                .ok_or_else(|| SspryError::from("n_of node requires threshold"))?;
            let mut matched = 0usize;
            for child in &node.children {
                if tree_maybe_matches_node(
                    child,
                    mask_cache,
                    tier1_gates,
                    tier2_gates,
                    allow_tier2,
                )? {
                    matched += 1;
                    if matched >= threshold {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        other => Err(SspryError::from(format!(
            "Unsupported ast node kind: {other}"
        ))),
    }
}

fn numeric_read_literal_bytes(name: &str, literal_text: &str) -> Result<Vec<u8>> {
    match name {
        "int16" => Ok(literal_text
            .parse::<i16>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "uint16" => Ok(literal_text
            .parse::<u16>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "int16be" => Ok(literal_text
            .parse::<i16>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "uint16be" => Ok(literal_text
            .parse::<u16>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "int32" => Ok(literal_text
            .parse::<i32>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "uint32" => Ok(literal_text
            .parse::<u32>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "int32be" => Ok(literal_text
            .parse::<i32>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "uint32be" => Ok(literal_text
            .parse::<u32>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "int64" => Ok(literal_text
            .parse::<i64>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "uint64" => Ok(literal_text
            .parse::<u64>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_le_bytes()
            .to_vec()),
        "int64be" => Ok(literal_text
            .parse::<i64>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "uint64be" => Ok(literal_text
            .parse::<u64>()
            .map_err(|_| {
                SspryError::from(format!(
                    "Numeric read literal is out of range for {name}: {literal_text}"
                ))
            })?
            .to_be_bytes()
            .to_vec()),
        "float32" => Ok(literal_text
            .parse::<f32>()
            .map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?
            .to_bits()
            .to_le_bytes()
            .to_vec()),
        "float32be" => Ok(literal_text
            .parse::<f32>()
            .map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?
            .to_bits()
            .to_be_bytes()
            .to_vec()),
        "float64" => Ok(literal_text
            .parse::<f64>()
            .map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?
            .to_bits()
            .to_le_bytes()
            .to_vec()),
        "float64be" => Ok(literal_text
            .parse::<f64>()
            .map_err(|_| {
                SspryError::from(format!("Invalid float literal for {name}: {literal_text}"))
            })?
            .to_bits()
            .to_be_bytes()
            .to_vec()),
        _ => Err(SspryError::from(format!(
            "Unsupported numeric read anchor function: {name}"
        ))),
    }
}

fn verifier_only_eq_matches_file_prefix(
    expr: &str,
    file_prefix: &[u8],
    file_size: u64,
) -> Result<Option<bool>> {
    let Some((name, rest)) = expr.split_once('(') else {
        return Ok(None);
    };
    let Some((offset_text, literal_text)) = rest.split_once(")==") else {
        return Ok(None);
    };
    let Ok(offset) = offset_text.parse::<usize>() else {
        return Ok(None);
    };
    if offset != 0 {
        return Ok(None);
    }
    let expected = match numeric_read_literal_bytes(name, literal_text) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    if expected.len() > 8 {
        return Ok(None);
    }
    if file_size < expected.len() as u64 || file_prefix.len() < expected.len() {
        return Ok(Some(false));
    }
    Ok(Some(file_prefix[..expected.len()] == expected))
}

fn pattern_matches_file_prefix_at_zero(
    pattern: &PatternPlan,
    file_prefix: &[u8],
    file_size: u64,
) -> Option<bool> {
    let mut saw_supported = false;
    let mut all_supported = true;
    for idx in 0..pattern.alternatives.len() {
        let literal = pattern.fixed_literals.get(idx)?;
        let wide = pattern
            .fixed_literal_wide
            .get(idx)
            .copied()
            .unwrap_or(false);
        let fullword = pattern
            .fixed_literal_fullword
            .get(idx)
            .copied()
            .unwrap_or(false);
        if literal.is_empty() || wide || fullword || literal.len() > 8 {
            all_supported = false;
            continue;
        }
        saw_supported = true;
        if file_size < literal.len() as u64 || file_prefix.len() < literal.len() {
            continue;
        }
        if file_prefix[..literal.len()] == *literal {
            return Some(true);
        }
    }
    if saw_supported && all_supported {
        Some(false)
    } else {
        None
    }
}

fn compare_u64(lhs: u64, rhs: u64, op: MetadataCompareOp) -> bool {
    match op {
        MetadataCompareOp::Eq => lhs == rhs,
        MetadataCompareOp::Ne => lhs != rhs,
        MetadataCompareOp::Lt => lhs < rhs,
        MetadataCompareOp::Le => lhs <= rhs,
        MetadataCompareOp::Gt => lhs > rhs,
        MetadataCompareOp::Ge => lhs >= rhs,
    }
}

fn compare_op_for_node_kind(kind: &str) -> Option<MetadataCompareOp> {
    if kind.ends_with("_eq") {
        Some(MetadataCompareOp::Eq)
    } else if kind.ends_with("_ne") {
        Some(MetadataCompareOp::Ne)
    } else if kind.ends_with("_lt") {
        Some(MetadataCompareOp::Lt)
    } else if kind.ends_with("_le") {
        Some(MetadataCompareOp::Le)
    } else if kind.ends_with("_gt") {
        Some(MetadataCompareOp::Gt)
    } else if kind.ends_with("_ge") {
        Some(MetadataCompareOp::Ge)
    } else {
        None
    }
}

fn metadata_field_pair(node: &QueryNode, kind_name: &str) -> Result<(String, String)> {
    let pair = node
        .pattern_id
        .as_deref()
        .ok_or_else(|| SspryError::from(format!("{kind_name} node requires pattern_id")))?;
    let Some((lhs, rhs)) = pair.split_once('|') else {
        return Err(SspryError::from(format!(
            "{kind_name} node requires lhs|rhs pattern_id"
        )));
    };
    Ok((lhs.to_owned(), rhs.to_owned()))
}

fn evaluate_pattern<'a, FT1, FT2>(
    pattern: &PatternPlan,
    pattern_masks: &PreparedPatternMasks,
    doc_inputs: &mut LazyDocQueryInputs<'a>,
    load_tier1: &mut FT1,
    load_tier2: &mut FT2,
    plan: &CompiledQueryPlan,
) -> Result<MatchOutcome>
where
    FT1: FnMut() -> Result<Cow<'a, [u8]>>,
    FT2: FnMut() -> Result<Cow<'a, [u8]>>,
{
    let allow_tier2 = !plan.force_tier1_only && plan.allow_tier2_fallback;
    let tier2_only =
        experiment_tier2_only_enabled() || experiment_tier2_and_metadata_only_enabled();
    for (alt_index, alternative) in pattern.alternatives.iter().enumerate() {
        let tier2_alternative = pattern
            .tier2_alternatives
            .get(alt_index)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if alternative.is_empty() && tier2_alternative.is_empty() {
            return Ok(MatchOutcome {
                matched: true,
                tiers: TierFlags {
                    used_tier1: !tier2_only,
                    used_tier2: false,
                },
            });
        }
        let doc = doc_inputs.doc;
        let mut used_tier1 = false;
        if !tier2_only && !alternative.is_empty() {
            let bloom_bytes = doc_inputs.tier1_bloom_bytes(load_tier1)?;
            let primary_match = pattern_masks.tier1.get(alt_index).is_some_and(|shifted| {
                if !shifted.any_lane_grams.is_empty() {
                    shifted.any_lane_grams.iter().all(|value| {
                        (0..DEFAULT_BLOOM_POSITION_LANES).any(|lane| {
                            bloom_word_masks_in_lane(
                                &[*value],
                                doc.filter_bytes,
                                doc.bloom_hashes,
                                lane,
                                DEFAULT_BLOOM_POSITION_LANES,
                            )
                            .ok()
                            .is_some_and(|required| {
                                raw_filter_matches_word_masks(bloom_bytes, &required)
                            })
                        })
                    })
                } else if !shifted.any_lane_values.is_empty() {
                    shifted.any_lane_values.iter().all(|lanes| {
                        lanes.iter().any(|by_key| {
                            by_key
                                .get(&(doc.filter_bytes, doc.bloom_hashes))
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(bloom_bytes, required)
                                })
                        })
                    })
                } else {
                    shifted.shifts.iter().any(|by_key| {
                        by_key
                            .get(&(doc.filter_bytes, doc.bloom_hashes))
                            .is_some_and(|required| {
                                raw_filter_matches_word_masks(bloom_bytes, required)
                            })
                    })
                }
            });
            if !primary_match {
                continue;
            }
            used_tier1 = true;
        }
        let mut used_tier2 = false;
        if !tier2_alternative.is_empty() {
            if tier2_only {
                if doc.tier2_filter_bytes == 0 || doc.tier2_bloom_hashes == 0 {
                    continue;
                }
                let tier2_bloom_bytes = doc_inputs.tier2_bloom_bytes(load_tier2)?;
                if tier2_bloom_bytes.is_empty() {
                    continue;
                }
                let tier2_match = pattern_masks.tier2.get(alt_index).is_some_and(|shifted| {
                    if !shifted.any_lane_grams.is_empty() {
                        shifted.any_lane_grams.iter().all(|value| {
                            (0..DEFAULT_BLOOM_POSITION_LANES).any(|lane| {
                                bloom_word_masks_in_lane(
                                    &[*value],
                                    doc.tier2_filter_bytes,
                                    doc.tier2_bloom_hashes,
                                    lane,
                                    DEFAULT_BLOOM_POSITION_LANES,
                                )
                                .ok()
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(tier2_bloom_bytes, &required)
                                })
                            })
                        })
                    } else if !shifted.any_lane_values.is_empty() {
                        shifted.any_lane_values.iter().all(|lanes| {
                            lanes.iter().any(|by_key| {
                                by_key
                                    .get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                                    .is_some_and(|required| {
                                        raw_filter_matches_word_masks(tier2_bloom_bytes, required)
                                    })
                            })
                        })
                    } else {
                        shifted.shifts.iter().any(|by_key| {
                            by_key
                                .get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(tier2_bloom_bytes, required)
                                })
                        })
                    }
                });
                if !tier2_match {
                    continue;
                }
                used_tier2 = true;
            } else if allow_tier2 && doc.tier2_filter_bytes > 0 && doc.tier2_bloom_hashes > 0 {
                let tier2_bloom_bytes = doc_inputs.tier2_bloom_bytes(load_tier2)?;
                if tier2_bloom_bytes.is_empty() {
                    continue;
                }
                let tier2_match = pattern_masks.tier2.get(alt_index).is_some_and(|shifted| {
                    if !shifted.any_lane_grams.is_empty() {
                        shifted.any_lane_grams.iter().all(|value| {
                            (0..DEFAULT_BLOOM_POSITION_LANES).any(|lane| {
                                bloom_word_masks_in_lane(
                                    &[*value],
                                    doc.tier2_filter_bytes,
                                    doc.tier2_bloom_hashes,
                                    lane,
                                    DEFAULT_BLOOM_POSITION_LANES,
                                )
                                .ok()
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(tier2_bloom_bytes, &required)
                                })
                            })
                        })
                    } else if !shifted.any_lane_values.is_empty() {
                        shifted.any_lane_values.iter().all(|lanes| {
                            lanes.iter().any(|by_key| {
                                by_key
                                    .get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                                    .is_some_and(|required| {
                                        raw_filter_matches_word_masks(tier2_bloom_bytes, required)
                                    })
                            })
                        })
                    } else {
                        shifted.shifts.iter().any(|by_key| {
                            by_key
                                .get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                                .is_some_and(|required| {
                                    raw_filter_matches_word_masks(tier2_bloom_bytes, required)
                                })
                        })
                    }
                });
                if !tier2_match {
                    continue;
                }
                used_tier2 = true;
            }
        }
        return Ok(MatchOutcome {
            matched: true,
            tiers: TierFlags {
                used_tier1,
                used_tier2,
            },
        });
    }
    Ok(MatchOutcome::default())
}

fn evaluate_node<'a, FM, FT1, FT2>(
    node: &QueryNode,
    doc_inputs: &mut LazyDocQueryInputs<'a>,
    load_metadata: &mut FM,
    load_tier1: &mut FT1,
    load_tier2: &mut FT2,
    patterns: &HashMap<String, PatternPlan>,
    mask_cache: &PatternMaskCache,
    plan: &CompiledQueryPlan,
    query_now_unix: u64,
    eval_cache: &mut QueryEvalCache,
) -> Result<MatchOutcome>
where
    FM: FnMut() -> Result<Cow<'a, [u8]>>,
    FT1: FnMut() -> Result<Cow<'a, [u8]>>,
    FT2: FnMut() -> Result<Cow<'a, [u8]>>,
{
    match node.kind.as_str() {
        "pattern" => {
            let pattern_id = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| SspryError::from("pattern node requires pattern_id"))?;
            if let Some(outcome) = eval_cache.pattern_outcomes.get(pattern_id).copied() {
                return Ok(outcome);
            }
            let pattern = patterns
                .get(pattern_id)
                .ok_or_else(|| SspryError::from(format!("Unknown pattern id: {pattern_id}")))?;
            let pattern_masks = mask_cache
                .get(pattern_id)
                .ok_or_else(|| SspryError::from(format!("Unknown pattern id: {pattern_id}")))?;
            let outcome = evaluate_pattern(
                pattern,
                pattern_masks,
                doc_inputs,
                load_tier1,
                load_tier2,
                plan,
            )?;
            eval_cache
                .pattern_outcomes
                .insert(pattern_id.clone(), outcome);
            Ok(outcome)
        }
        "identity_eq" => {
            let expected = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| SspryError::from("identity_eq node requires pattern_id"))?;
            Ok(MatchOutcome {
                matched: doc_inputs.doc.sha256 == *expected,
                tiers: TierFlags::default(),
            })
        }
        "not" => {
            let child = node
                .children
                .first()
                .ok_or_else(|| SspryError::from("not node requires one child"))?;
            if query_node_uses_pattern_blooms(child) || query_node_contains_verifier_only(child) {
                return Ok(MatchOutcome {
                    matched: true,
                    tiers: TierFlags::default(),
                });
            }
            let outcome = evaluate_node(
                child,
                doc_inputs,
                load_metadata,
                load_tier1,
                load_tier2,
                patterns,
                mask_cache,
                plan,
                query_now_unix,
                eval_cache,
            )?;
            Ok(MatchOutcome {
                matched: !outcome.matched,
                tiers: TierFlags::default(),
            })
        }
        "verifier_only_eq" => {
            let matched = if let Some(expr) = node.pattern_id.as_deref() {
                let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
                if let Some(file_prefix) = metadata_file_prefix_8(metadata_bytes)? {
                    verifier_only_eq_matches_file_prefix(
                        expr,
                        &file_prefix,
                        doc_inputs.doc.file_size,
                    )?
                    .unwrap_or(true)
                } else {
                    true
                }
            } else {
                true
            };
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "verifier_only_at" => {
            let matched = if let Some(expr) = node.pattern_id.as_deref() {
                if let Some((pattern_id, offset_text)) = expr.split_once('@') {
                    if offset_text == "0" {
                        let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
                        if let Some(file_prefix) = metadata_file_prefix_8(metadata_bytes)? {
                            if let Some(pattern) = patterns.get(pattern_id) {
                                pattern_matches_file_prefix_at_zero(
                                    pattern,
                                    &file_prefix,
                                    doc_inputs.doc.file_size,
                                )
                                .unwrap_or(true)
                            } else {
                                true
                            }
                        } else {
                            true
                        }
                    } else {
                        true
                    }
                } else {
                    true
                }
            } else {
                true
            };
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "verifier_only_count" | "verifier_only_in_range" | "verifier_only_loop" => {
            Ok(MatchOutcome {
                matched: true,
                tiers: TierFlags::default(),
            })
        }
        "filesize_eq" | "filesize_ne" | "filesize_lt" | "filesize_le" | "filesize_gt"
        | "filesize_ge" => {
            let expected_size = node
                .threshold
                .ok_or_else(|| SspryError::from(format!("{} node requires threshold", node.kind)))?
                as u64;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported filesize node: {}", node.kind))
            })?;
            Ok(MatchOutcome {
                matched: compare_u64(doc_inputs.doc.file_size, expected_size, op),
                tiers: TierFlags::default(),
            })
        }
        "metadata_eq" | "metadata_ne" | "metadata_lt" | "metadata_le" | "metadata_gt"
        | "metadata_ge" => {
            let field = node.pattern_id.as_deref().ok_or_else(|| {
                SspryError::from(format!("{} node requires pattern_id", node.kind))
            })?;
            let expected = node
                .threshold
                .ok_or_else(|| SspryError::from(format!("{} node requires threshold", node.kind)))?
                as u64;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported metadata node: {}", node.kind))
            })?;
            let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
            let matched = metadata_field_matches_compare(metadata_bytes, field, op, expected)?
                .unwrap_or(true);
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "metadata_float_eq" | "metadata_float_ne" | "metadata_float_lt" | "metadata_float_le"
        | "metadata_float_gt" | "metadata_float_ge" => {
            let field = node.pattern_id.as_deref().ok_or_else(|| {
                SspryError::from(format!("{} node requires pattern_id", node.kind))
            })?;
            let expected = node
                .threshold
                .ok_or_else(|| SspryError::from(format!("{} node requires threshold", node.kind)))?
                as u32;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported metadata-float node: {}", node.kind))
            })?;
            let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
            let matched = metadata_field_matches_compare_f32(
                metadata_bytes,
                field,
                op,
                f32::from_bits(expected),
            )?
            .unwrap_or(true);
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "metadata_time_eq" | "metadata_time_ne" | "metadata_time_lt" | "metadata_time_le"
        | "metadata_time_gt" | "metadata_time_ge" => {
            let field = node.pattern_id.as_deref().ok_or_else(|| {
                SspryError::from(format!("{} node requires pattern_id", node.kind))
            })?;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported metadata-time node: {}", node.kind))
            })?;
            let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
            let matched =
                metadata_field_matches_compare(metadata_bytes, field, op, query_now_unix)?
                    .unwrap_or(true);
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "metadata_field_eq" | "metadata_field_ne" | "metadata_field_lt" | "metadata_field_le"
        | "metadata_field_gt" | "metadata_field_ge" => {
            let (lhs_field, rhs_field) = metadata_field_pair(node, &node.kind)?;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported metadata-field node: {}", node.kind))
            })?;
            let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
            let matched = metadata_fields_compare(metadata_bytes, &lhs_field, op, &rhs_field)?
                .unwrap_or(true);
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
            })
        }
        "time_now_eq" | "time_now_ne" | "time_now_lt" | "time_now_le" | "time_now_gt"
        | "time_now_ge" => {
            let expected = node
                .threshold
                .ok_or_else(|| SspryError::from(format!("{} node requires threshold", node.kind)))?
                as u64;
            let op = compare_op_for_node_kind(&node.kind).ok_or_else(|| {
                SspryError::from(format!("Unsupported time.now node: {}", node.kind))
            })?;
            Ok(MatchOutcome {
                matched: compare_u64(query_now_unix, expected, op),
                tiers: TierFlags::default(),
            })
        }
        "and" => {
            let mut merged = TierFlags::default();
            for child in &node.children {
                let outcome = evaluate_node(
                    child,
                    doc_inputs,
                    load_metadata,
                    load_tier1,
                    load_tier2,
                    patterns,
                    mask_cache,
                    plan,
                    query_now_unix,
                    eval_cache,
                )?;
                if !outcome.matched {
                    return Ok(MatchOutcome::default());
                }
                merged.merge(outcome.tiers);
            }
            Ok(MatchOutcome {
                matched: true,
                tiers: merged,
            })
        }
        "or" => {
            for child in &node.children {
                let outcome = evaluate_node(
                    child,
                    doc_inputs,
                    load_metadata,
                    load_tier1,
                    load_tier2,
                    patterns,
                    mask_cache,
                    plan,
                    query_now_unix,
                    eval_cache,
                )?;
                if outcome.matched {
                    return Ok(outcome);
                }
            }
            Ok(MatchOutcome::default())
        }
        "n_of" => {
            let threshold = node
                .threshold
                .ok_or_else(|| SspryError::from("n_of node requires threshold"))?;
            let mut matched_count = 0usize;
            let mut merged = TierFlags::default();
            for child in &node.children {
                let outcome = evaluate_node(
                    child,
                    doc_inputs,
                    load_metadata,
                    load_tier1,
                    load_tier2,
                    patterns,
                    mask_cache,
                    plan,
                    query_now_unix,
                    eval_cache,
                )?;
                if outcome.matched {
                    matched_count += 1;
                    merged.merge(outcome.tiers);
                    if matched_count >= threshold {
                        return Ok(MatchOutcome {
                            matched: true,
                            tiers: merged,
                        });
                    }
                }
            }
            Ok(MatchOutcome {
                matched: matched_count >= threshold,
                tiers: if matched_count >= threshold {
                    merged
                } else {
                    TierFlags::default()
                },
            })
        }
        other => Err(SspryError::from(format!(
            "Unsupported ast node kind: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use yara_x::{Compiler as YaraCompiler, Scanner as YaraScanner};

    use crate::candidate::BloomFilter;
    use crate::candidate::bloom::DEFAULT_BLOOM_POSITION_LANES;
    use crate::candidate::{
        DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes,
        extract_compact_document_metadata,
        features::scan_file_features_bloom_only_with_gram_sizes,
        pack_exact_gram,
        query_plan::{
            compile_query_plan_with_gram_sizes,
            compile_query_plan_with_gram_sizes_and_identity_source,
        },
    };

    use super::*;

    fn borrowed_bytes<'a>(bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        Ok(Cow::Borrowed(bytes))
    }

    fn yara_rule_matches_bytes(source: &str, bytes: &[u8]) -> bool {
        let mut compiler = YaraCompiler::new();
        compiler.add_source(source).expect("compile yara-x probe");
        let rules = compiler.build();
        let mut scanner = YaraScanner::new(&rules);
        scanner
            .scan(bytes)
            .expect("scan yara-x probe")
            .matching_rules()
            .next()
            .is_some()
    }

    struct Tier2AndMetadataOnlyOverrideGuard {
        previous: u8,
    }

    impl Drop for Tier2AndMetadataOnlyOverrideGuard {
        fn drop(&mut self) {
            EXPERIMENT_TIER2_AND_METADATA_ONLY_OVERRIDE.with(|value| value.set(self.previous));
        }
    }

    fn tier2_and_metadata_only_override(enabled: bool) -> Tier2AndMetadataOnlyOverrideGuard {
        let previous = EXPERIMENT_TIER2_AND_METADATA_ONLY_OVERRIDE.with(|value| {
            let previous = value.get();
            value.set(if enabled { 2 } else { 1 });
            previous
        });
        Tier2AndMetadataOnlyOverrideGuard { previous }
    }

    fn lane_bloom_bytes(filter_bytes: usize, bloom_hashes: usize, grams: &[u64]) -> Vec<u8> {
        let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
        for (idx, gram) in grams.iter().enumerate() {
            bloom
                .add_in_lane(
                    *gram,
                    idx % DEFAULT_BLOOM_POSITION_LANES,
                    DEFAULT_BLOOM_POSITION_LANES,
                )
                .expect("add gram");
        }
        bloom.into_bytes()
    }

    #[test]
    fn non_exact_patterns_use_any_lane_masks() {
        let grams = vec![
            pack_exact_gram(&[0x03, 0xf8, 0x0f, 0xb6]),
            pack_exact_gram(&[0x4f, 0x81, 0xcf, 0x00]),
        ];
        let filter_bytes = 64;
        let bloom_hashes = 3;
        let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
        bloom
            .add_in_lane(grams[0], 2, DEFAULT_BLOOM_POSITION_LANES)
            .expect("lane add first");
        bloom
            .add_in_lane(grams[1], 0, DEFAULT_BLOOM_POSITION_LANES)
            .expect("lane add second");
        let bytes = bloom.into_bytes();

        let pattern = PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![grams.clone()],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        };
        let plan = CompiledQueryPlan {
            patterns: vec![pattern.clone()],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 10.0,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };
        let cache = build_pattern_mask_cache(
            &[pattern],
            &[(filter_bytes, bloom_hashes)],
            &[],
            DEFAULT_TIER1_GRAM_SIZE,
            DEFAULT_TIER2_GRAM_SIZE,
        )
        .expect("mask cache");
        let pattern_masks = cache.get("$a").expect("pattern masks");
        assert!(pattern_masks.tier1[0].shifts.is_empty());
        assert_eq!(pattern_masks.tier1[0].any_lane_values.len(), grams.len());

        let doc = CandidateDoc {
            doc_id: 0,
            sha256: String::new(),
            file_size: 0,
            filter_bytes,
            bloom_hashes,
            tier2_filter_bytes: 0,
            tier2_bloom_hashes: 0,
            special_population: false,
            deleted: false,
        };
        let (mut inputs, load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &[], &bytes, &[]);
        let outcome = evaluate_pattern(
            &plan.patterns[0],
            pattern_masks,
            &mut inputs,
            &mut load_tier1,
            &mut load_tier2,
            &plan,
        )
        .expect("evaluate pattern");
        drop(load_metadata);
        assert!(outcome.matched);
    }

    #[test]
    fn ambiguous_exact_patterns_fall_back_to_any_lane_masks() {
        let gram = pack_exact_gram(b"abcd");
        let pattern = PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![b"abcdzzzzabcd".to_vec()],
            fixed_literals: vec![b"abcdzzzzabcd".to_vec()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        };
        let cache = build_pattern_mask_cache(
            &[pattern],
            &[(64, 3)],
            &[],
            DEFAULT_TIER1_GRAM_SIZE,
            DEFAULT_TIER2_GRAM_SIZE,
        )
        .expect("mask cache");
        let pattern_masks = cache.get("$a").expect("pattern masks");
        assert!(!pattern_masks.tier1[0].shifts.is_empty());
        assert!(pattern_masks.tier1[0].any_lane_values.is_empty());
    }

    #[test]
    fn tier2_only_patterns_do_not_match_without_tier2_bloom_hit() {
        let pattern = PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![Vec::new()],
            tier2_alternatives: vec![vec![pack_exact_gram(b"To:!")]],
            anchor_literals: vec![b"To:!".to_vec()],
            fixed_literals: vec![b"To:!".to_vec()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        };
        let plan = CompiledQueryPlan {
            patterns: vec![pattern.clone()],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 10.0,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };
        let cache = build_pattern_mask_cache(
            &[pattern],
            &[(64, 3)],
            &[(64, 3)],
            DEFAULT_TIER1_GRAM_SIZE,
            DEFAULT_TIER2_GRAM_SIZE,
        )
        .expect("mask cache");
        let pattern_masks = cache.get("$a").expect("pattern masks");
        let doc = CandidateDoc {
            doc_id: 0,
            sha256: String::new(),
            file_size: 0,
            filter_bytes: 64,
            bloom_hashes: 3,
            tier2_filter_bytes: 64,
            tier2_bloom_hashes: 3,
            special_population: false,
            deleted: false,
        };

        let (mut miss_inputs, _load_metadata, mut miss_tier1, mut miss_tier2) =
            prefetched_query_inputs(&doc, &[], &[], &[]);
        let miss = evaluate_pattern(
            &plan.patterns[0],
            pattern_masks,
            &mut miss_inputs,
            &mut miss_tier1,
            &mut miss_tier2,
            &plan,
        )
        .expect("evaluate miss");
        assert!(!miss.matched);

        let tier2_bloom = lane_bloom_bytes(64, 3, &[pack_exact_gram(b"To:!")]);
        let (mut hit_inputs, _load_metadata, mut hit_tier1, mut hit_tier2) =
            prefetched_query_inputs(&doc, &[], &[], &tier2_bloom);
        let hit = evaluate_pattern(
            &plan.patterns[0],
            pattern_masks,
            &mut hit_inputs,
            &mut hit_tier1,
            &mut hit_tier2,
            &plan,
        )
        .expect("evaluate hit");
        assert!(hit.matched);
        assert_eq!(hit.tiers.as_label(), "tier2");
    }

    #[test]
    fn tier2_only_patterns_match_from_tier2_tree_gates() {
        let pattern = PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![Vec::new()],
            tier2_alternatives: vec![vec![pack_exact_gram(b"To:!")]],
            anchor_literals: vec![b"To:!".to_vec()],
            fixed_literals: vec![b"To:!".to_vec()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        };
        let cache = build_pattern_mask_cache(
            &[pattern.clone()],
            &[(64, 3)],
            &[(64, 3)],
            DEFAULT_TIER1_GRAM_SIZE,
            DEFAULT_TIER2_GRAM_SIZE,
        )
        .expect("mask cache");
        let pattern_masks = cache.get("$a").expect("pattern masks");
        assert!(!pattern_masks.tier1[0].is_empty());
        assert!(!pattern_masks.tier2[0].is_empty());

        let mut tier2_gates = TreeBloomGateIndex::default();
        let tier2_bloom = lane_bloom_bytes(64, 3, &[pack_exact_gram(b"To:!")]);
        update_tree_gate_for_doc_bytes_inner(&mut tier2_gates, 64, 3, &tier2_bloom);

        assert!(tree_gate_matches_pattern(
            "$a",
            &cache,
            &TreeBloomGateIndex::default(),
            &tier2_gates,
            true,
        ));
    }

    fn prefetched_query_inputs<'a>(
        doc: &'a CandidateDoc,
        metadata_bytes: &'a [u8],
        tier1_bloom_bytes: &'a [u8],
        tier2_bloom_bytes: &'a [u8],
    ) -> (
        LazyDocQueryInputs<'a>,
        impl FnMut() -> Result<Cow<'a, [u8]>>,
        impl FnMut() -> Result<Cow<'a, [u8]>>,
        impl FnMut() -> Result<Cow<'a, [u8]>>,
    ) {
        (
            LazyDocQueryInputs::from_prefetched(
                doc,
                metadata_bytes,
                tier1_bloom_bytes,
                tier2_bloom_bytes,
            ),
            move || borrowed_bytes(metadata_bytes),
            move || borrowed_bytes(tier1_bloom_bytes),
            move || borrowed_bytes(tier2_bloom_bytes),
        )
    }

    #[cfg(test)]
    fn evaluate_rule_against_file_blooms(
        rule_text: &str,
        file_path: &str,
        filter_bytes: usize,
        bloom_hashes: usize,
        tier2_filter_bytes: usize,
        tier2_bloom_hashes: usize,
        allow_tier2_fallback: bool,
    ) -> Result<MatchOutcome> {
        let plan = compile_query_plan_with_gram_sizes_and_identity_source(
            rule_text,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)?,
            Some("sha256"),
            16,
            false,
            allow_tier2_fallback,
            10_000,
        )?;
        let features = scan_file_features_bloom_only_with_gram_sizes(
            file_path,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)?,
            filter_bytes,
            bloom_hashes,
            tier2_filter_bytes,
            tier2_bloom_hashes,
            64 * 1024,
        )?;
        let patterns = plan
            .patterns
            .iter()
            .map(|pattern| (pattern.pattern_id.clone(), pattern.clone()))
            .collect::<HashMap<_, _>>();
        let mask_cache = build_pattern_mask_cache(
            &plan.patterns,
            &[(filter_bytes, bloom_hashes)],
            &[(tier2_filter_bytes, tier2_bloom_hashes)],
            plan.tier1_gram_size,
            plan.tier2_gram_size,
        )?;
        let doc = CandidateDoc {
            doc_id: 0,
            sha256: hex::encode(features.sha256),
            file_size: features.file_size,
            filter_bytes,
            bloom_hashes,
            tier2_filter_bytes,
            tier2_bloom_hashes,
            special_population: features.special_population,
            deleted: false,
        };
        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(
                &doc,
                &[],
                &features.bloom_filter,
                &features.tier2_bloom_filter,
            );
        evaluate_node(
            &plan.root,
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &plan,
            0,
            &mut QueryEvalCache::default(),
        )
    }

    fn insert_primary(
        store: &mut CandidateStore,
        sha256: [u8; 32],
        file_size: u64,
        bloom_item_estimate: Option<usize>,
        bloom_hashes: Option<usize>,
        filter_bytes: usize,
        bloom_filter: &[u8],
        external_id: Option<String>,
    ) -> Result<CandidateInsertResult> {
        store.insert_document(
            sha256,
            file_size,
            bloom_item_estimate,
            bloom_hashes,
            None,
            None,
            filter_bytes,
            bloom_filter,
            0,
            &[],
            external_id,
        )
    }

    #[test]
    fn legacy_store_meta_conversion_preserves_filter_targets() {
        let legacy = LegacyStoreMeta {
            version: 7,
            next_doc_id: 11,
            id_source: "md5".to_owned(),
            store_path: true,
            tier2_gram_size: 5,
            tier1_gram_size: 4,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: Some(0.18),
            filter_target_fp: Some(0.39),
            compaction_idle_cooldown_s: 12.5,
        };

        let forest = ForestMeta::from(&legacy);
        assert_eq!(forest.version, 7);
        assert_eq!(forest.id_source, "md5");
        assert!(forest.store_path);
        assert_eq!(forest.tier1_gram_size, 4);
        assert_eq!(forest.tier2_gram_size, 5);
        assert_eq!(forest.tier1_filter_target_fp, Some(0.39));
        assert_eq!(forest.tier2_filter_target_fp, Some(0.18));

        let local = StoreLocalMeta::from(&legacy);
        assert_eq!(local.version, 7);
        assert_eq!(local.next_doc_id, 11);
    }

    #[test]
    #[ignore = "diagnostic on local corpus only"]
    fn diagnostic_scanstrings_string_matches_bloom_path() {
        let rule = r#"
rule r {
  strings:
    $a = "$*@@@*$@@@$ *@@* $@@($*)@-$*@@$-*@@$*-@@(*$)@-*$@@*-$@@*$-@@-* $@-$ *@* $-@$ *-@$ -*@*- $@($ *)(* $)U"
  condition:
    $a
}
"#;
        let outcome = evaluate_rule_against_file_blooms(
            rule,
            "/root/pertest/data/extracted/2026-03-06/2c2caad15e5af13e6290b84f03b10f43b21ffc3dfdda0581fa24caa3450484f3.exe",
            4096,
            3,
            2048,
            3,
            true,
        )
        .expect("evaluate");
        assert!(outcome.matched);
    }

    #[test]
    fn borrowed_bytes_returns_borrowed_slice() {
        let bytes = b"borrowed";
        let borrowed = borrowed_bytes(bytes).expect("borrowed bytes");
        assert!(matches!(borrowed, Cow::Borrowed(_)));
        assert_eq!(borrowed.as_ref(), bytes);
    }

    #[test]
    fn evaluate_rule_against_file_blooms_matches_simple_literal_rule() {
        let tmp = tempdir().expect("tmp");
        let sample = tmp.path().join("sample.bin");
        fs::write(&sample, b"xxABCDyy").expect("sample");
        let outcome = evaluate_rule_against_file_blooms(
            r#"
rule r {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
            sample.to_str().expect("sample path"),
            1024,
            7,
            1024,
            7,
            true,
        )
        .expect("evaluate");
        assert!(outcome.matched);
    }

    #[test]
    #[ignore = "diagnostic on local corpus only"]
    fn diagnostic_asyncrat_msg_pack_matches_bloom_path() {
        let rule = r#"
rule r {
  strings:
    $a = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
  condition:
    $a
}
"#;
        let tier1_only = evaluate_rule_against_file_blooms(
            rule,
            "/root/pertest/data/extracted/2026-02-28/5d3d41bb883bc29040f1ac52731dcdd287ca069caa720493a956d7ed635b2383.exe",
            4096,
            3,
            2048,
            3,
            false,
        )
        .expect("evaluate");
        let tier1_and_tier2 = evaluate_rule_against_file_blooms(
            rule,
            "/root/pertest/data/extracted/2026-02-28/5d3d41bb883bc29040f1ac52731dcdd287ca069caa720493a956d7ed635b2383.exe",
            4096,
            3,
            2048,
            3,
            true,
        )
        .expect("evaluate");
        assert!(
            tier1_only.matched,
            "tier1-only path should match: {:?}",
            tier1_only
        );
        assert!(
            tier1_and_tier2.matched,
            "tier1+tier2 path should now match: {:?}",
            tier1_and_tier2
        );
    }

    #[test]
    fn insert_query_delete_roundtrip() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let filter_bytes = 8;
        let bloom_hashes = DEFAULT_BLOOM_HASHES;
        let result = insert_primary(
            &mut store,
            [0x11; 32],
            8,
            None,
            None,
            filter_bytes,
            &lane_bloom_bytes(
                filter_bytes,
                bloom_hashes,
                &[pack_exact_gram(b"ABC"), pack_exact_gram(b"BCD")],
            ),
            Some("doc-1".to_owned()),
        )
        .expect("insert");
        assert_eq!(result.status, "inserted");

        let plan = compile_query_plan_with_gram_sizes(
            r#"
rule q {
  strings:
    $a = "ABC"
  condition:
    $a
}
"#,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
                .expect("default gram sizes"),
            8,
            true,
            true,
            100_000,
        )
        .expect("plan");
        let query = store.query_candidates(&plan, 0, 128).expect("query");
        assert_eq!(query.sha256, vec![hex::encode([0x11; 32])]);

        let deleted = store
            .delete_document(&hex::encode([0x11; 32]))
            .expect("delete");
        assert_eq!(deleted.status, "deleted");

        let query_after = store.query_candidates(&plan, 0, 128).expect("query");
        assert!(query_after.sha256.is_empty());

        let reopened = CandidateStore::open(root).expect("open");
        assert_eq!(reopened.stats().deleted_doc_count, 1);
    }

    #[test]
    fn whole_file_identity_queries_use_direct_lookup() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let filter_bytes = 8;
        let bloom_hashes = DEFAULT_BLOOM_HASHES;
        insert_primary(
            &mut store,
            [0x11; 32],
            8,
            None,
            None,
            filter_bytes,
            &lane_bloom_bytes(filter_bytes, bloom_hashes, &[0x4443_4241]),
            Some("doc-1".to_owned()),
        )
        .expect("insert first");
        insert_primary(
            &mut store,
            [0x22; 32],
            8,
            None,
            None,
            filter_bytes,
            &lane_bloom_bytes(filter_bytes, bloom_hashes, &[0x4443_4241]),
            Some("doc-2".to_owned()),
        )
        .expect("insert second");

        let plan = compile_query_plan_with_gram_sizes_and_identity_source(
            r#"
rule q {
  condition:
    hash.sha256(0, filesize) == "1111111111111111111111111111111111111111111111111111111111111111"
}
"#,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
                .expect("default gram sizes"),
            Some("sha256"),
            8,
            false,
            true,
            100_000,
        )
        .expect("plan");
        let query = store.query_candidates(&plan, 0, 128).expect("query");
        assert_eq!(query.sha256, vec![hex::encode([0x11; 32])]);
        assert_eq!(query.query_profile.docs_scanned, 1);
        assert_eq!(query.query_profile.tier1_bloom_loads, 0);
        assert_eq!(query.query_profile.tier2_bloom_loads, 0);
    }

    #[test]
    fn compaction_reclaims_deleted_docs_and_storage() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                compaction_idle_cooldown_s: 0.0,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let filter_bytes = 8;
        let mut bloom = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom");
        bloom.add(0x4443_4241).expect("add gram");
        let bloom_bytes = bloom.into_bytes();

        insert_primary(
            &mut store,
            [0x11; 32],
            8,
            None,
            None,
            filter_bytes,
            &bloom_bytes,
            Some("live".to_owned()),
        )
        .expect("insert live");
        insert_primary(
            &mut store,
            [0x22; 32],
            8,
            None,
            None,
            filter_bytes,
            &bloom_bytes,
            Some("deleted".to_owned()),
        )
        .expect("insert deleted");
        store
            .delete_document(&hex::encode([0x22; 32]))
            .expect("delete");

        let size_before = dir_size(&root);
        let deleted_bytes_before = store.deleted_storage_bytes();
        assert!(deleted_bytes_before > 0);

        let snapshot = store
            .prepare_compaction_snapshot(true)
            .expect("snapshot")
            .expect("snapshot available");
        let compacted_root = compaction_work_root(&root, "test-compact");
        write_compacted_snapshot(&snapshot, &compacted_root).expect("write compacted");
        let result = store
            .apply_compaction_snapshot(&snapshot, &compacted_root)
            .expect("apply compaction")
            .expect("compaction applied");

        assert_eq!(result.reclaimed_docs, 1);
        assert_eq!(store.stats().compaction_generation, 2);
        assert_eq!(store.stats().retired_generation_count, 1);
        assert_eq!(store.stats().doc_count, 1);
        assert_eq!(store.stats().deleted_doc_count, 0);
        assert_eq!(store.deleted_storage_bytes(), 0);
        assert!(dir_size(&root) < size_before);
        let retired_root = retired_generation_root(&root, 1);
        assert!(retired_root.exists());

        let reopened = CandidateStore::open(&root).expect("reopen");
        assert_eq!(reopened.stats().compaction_generation, 2);
        assert_eq!(reopened.stats().retired_generation_count, 1);
        assert_eq!(reopened.stats().doc_count, 1);
        assert_eq!(reopened.stats().deleted_doc_count, 0);
    }

    #[test]
    fn reopen_normalizes_next_doc_id_after_deferred_meta_persist() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                compaction_idle_cooldown_s: 0.0,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let filter_bytes = 8;
        let mut bloom_a = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom a");
        bloom_a.add(0x4443_4241).expect("add gram a");
        let inserted_a = store
            .insert_document(
                [0x11; 32],
                8,
                Some(1),
                Some(DEFAULT_BLOOM_HASHES),
                Some(0),
                Some(0),
                filter_bytes,
                &bloom_a.into_bytes(),
                filter_bytes,
                &[],
                None,
            )
            .expect("insert a");
        assert_eq!(inserted_a.doc_id, 1);

        let mut reopened = CandidateStore::open(&root).expect("reopen");
        let mut bloom_b = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom b");
        bloom_b.add(0x5A59_5857).expect("add gram b");
        let inserted_b = reopened
            .insert_document(
                [0x22; 32],
                8,
                Some(1),
                Some(DEFAULT_BLOOM_HASHES),
                Some(0),
                Some(0),
                filter_bytes,
                &bloom_b.into_bytes(),
                filter_bytes,
                &[],
                None,
            )
            .expect("insert b");
        assert_eq!(inserted_b.doc_id, 2);
    }

    #[test]
    fn retired_generation_gc_removes_retired_root_and_updates_manifest() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                compaction_idle_cooldown_s: 0.0,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let filter_bytes = 8;
        let mut bloom = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom");
        bloom.add(0x4443_4241).expect("add gram");
        let bloom_bytes = bloom.into_bytes();

        insert_primary(
            &mut store,
            [0x11; 32],
            8,
            None,
            None,
            filter_bytes,
            &bloom_bytes,
            Some("live".to_owned()),
        )
        .expect("insert live");
        insert_primary(
            &mut store,
            [0x22; 32],
            8,
            None,
            None,
            filter_bytes,
            &bloom_bytes,
            Some("deleted".to_owned()),
        )
        .expect("insert deleted");
        store
            .delete_document(&hex::encode([0x22; 32]))
            .expect("delete");

        let snapshot = store
            .prepare_compaction_snapshot(true)
            .expect("snapshot")
            .expect("snapshot available");
        let compacted_root = compaction_work_root(&root, "test-compact");
        write_compacted_snapshot(&snapshot, &compacted_root).expect("write compacted");
        store
            .apply_compaction_snapshot(&snapshot, &compacted_root)
            .expect("apply compaction")
            .expect("compaction applied");

        let retired_root = retired_generation_root(&root, 1);
        assert!(retired_root.exists());
        assert_eq!(store.stats().retired_generation_count, 1);

        let removed = store
            .garbage_collect_retired_generations()
            .expect("garbage collect retired generations");
        assert_eq!(removed, 1);
        assert!(!retired_root.exists());
        assert_eq!(store.stats().retired_generation_count, 0);

        let reopened = CandidateStore::open(&root).expect("reopen");
        assert_eq!(reopened.stats().retired_generation_count, 0);
        assert_eq!(reopened.stats().compaction_generation, 2);
    }

    #[test]
    fn compaction_manifest_helpers_roundtrip_and_force_init_cleans_retired_roots() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let manifest_path = shard_compaction_manifest_path(&root);
        let retired_root = retired_generation_root(&root, 7);

        let default_manifest = ensure_shard_compaction_manifest(&root).expect("ensure manifest");
        assert_eq!(default_manifest.current_generation, 1);
        assert!(manifest_path.exists());

        let manifest = ShardCompactionManifest {
            current_generation: 7,
            retired_roots: vec![
                retired_root
                    .file_name()
                    .expect("retired file name")
                    .to_string_lossy()
                    .into_owned(),
            ],
        };
        fs::create_dir_all(&retired_root).expect("create retired root");
        write_shard_compaction_manifest(&root, &manifest).expect("write manifest");
        let roundtrip = read_shard_compaction_manifest(&root).expect("read manifest");
        assert_eq!(roundtrip.current_generation, 7);
        assert_eq!(roundtrip.retired_roots, manifest.retired_roots);

        let reopened = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("force init");
        assert_eq!(reopened.stats().compaction_generation, 1);
        assert_eq!(reopened.stats().retired_generation_count, 0);
        assert!(!retired_root.exists());
        let reset_manifest = read_shard_compaction_manifest(&root).expect("read reset manifest");
        assert_eq!(reset_manifest.current_generation, 1);
        assert!(reset_manifest.retired_roots.is_empty());
    }

    #[test]
    fn invalid_compaction_manifest_is_rejected() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let manifest_path = shard_compaction_manifest_path(&root);
        fs::write(&manifest_path, b"{not-json").expect("write invalid manifest");
        let err = read_shard_compaction_manifest(&root).expect_err("invalid manifest should fail");
        assert!(
            err.to_string()
                .contains("Invalid candidate compaction manifest"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn compaction_swap_aborts_when_store_mutates() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                compaction_idle_cooldown_s: 0.0,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let filter_bytes = 8;
        let mut bloom = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom");
        bloom.add(0x4443_4241).expect("add gram");
        let bloom_bytes = bloom.into_bytes();

        insert_primary(
            &mut store,
            [0x11; 32],
            8,
            None,
            None,
            filter_bytes,
            &bloom_bytes,
            None,
        )
        .expect("insert one");
        insert_primary(
            &mut store,
            [0x22; 32],
            8,
            None,
            None,
            filter_bytes,
            &bloom_bytes,
            None,
        )
        .expect("insert two");
        store
            .delete_document(&hex::encode([0x22; 32]))
            .expect("delete two");

        let snapshot = store
            .prepare_compaction_snapshot(true)
            .expect("snapshot")
            .expect("snapshot available");
        let compacted_root = compaction_work_root(&root, "test-compact");
        write_compacted_snapshot(&snapshot, &compacted_root).expect("write compacted");

        insert_primary(
            &mut store,
            [0x33; 32],
            8,
            None,
            None,
            filter_bytes,
            &bloom_bytes,
            None,
        )
        .expect("insert third");

        assert!(
            store
                .apply_compaction_snapshot(&snapshot, &compacted_root)
                .expect("apply compaction")
                .is_none()
        );
        assert_eq!(store.stats().doc_count, 2);
        assert_eq!(store.stats().deleted_doc_count, 1);
        let _ = fs::remove_dir_all(compacted_root);
    }

    #[test]
    fn compaction_snapshot_requires_deleted_docs_and_respects_cooldown() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root,
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                compaction_idle_cooldown_s: 60.0,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let filter_bytes = 8;
        let mut bloom = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom");
        bloom.add(0x4443_4241).expect("add gram");
        let bloom_bytes = bloom.into_bytes();

        assert!(
            store
                .prepare_compaction_snapshot(false)
                .expect("snapshot without deletes")
                .is_none()
        );

        insert_primary(
            &mut store,
            [0x11; 32],
            8,
            None,
            None,
            filter_bytes,
            &bloom_bytes,
            None,
        )
        .expect("insert");
        store
            .delete_document(&hex::encode([0x11; 32]))
            .expect("delete");

        assert!(
            store
                .prepare_compaction_snapshot(false)
                .expect("cooldown snapshot")
                .is_none()
        );
        assert!(
            store
                .prepare_compaction_snapshot(true)
                .expect("forced snapshot")
                .is_some()
        );
    }

    #[test]
    fn target_fp_derives_effective_bloom_hash_count() {
        let tmp = tempdir().expect("tmp");
        let store = CandidateStore::init(
            CandidateConfig {
                root: tmp.path().join("candidate_db"),
                filter_target_fp: Some(0.25),
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");
        let bloom_hashes =
            store.resolve_bloom_hashes_for_document(512 * 1024, Some(100_000), Some(7));
        assert_eq!(bloom_hashes, 16);
        assert_eq!(store.stats().tier1_filter_target_fp, Some(0.25));
        assert_eq!(store.stats().tier2_filter_target_fp, Some(0.25));
    }

    #[test]
    fn external_ids_follow_active_docs() {
        let tmp = tempdir().expect("tmp");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: tmp.path().join("candidate_db"),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let small_filter_bytes = 64 * 1024;
        let large_filter_bytes = 256 * 1024;
        let mut small = BloomFilter::new(small_filter_bytes, 1).expect("small bloom");
        small
            .add(u64::from(u32::from_le_bytes(*b"ABCD")))
            .expect("add small");
        let large = BloomFilter::new(large_filter_bytes, 1).expect("large bloom");

        let sha1 = [0x11; 32];
        let sha2 = [0x22; 32];
        let sha3 = [0x33; 32];

        insert_primary(
            &mut store,
            sha1,
            64 * 1024,
            None,
            None,
            small_filter_bytes,
            &small.clone().into_bytes(),
            Some("doc-small".to_owned()),
        )
        .expect("insert one");
        insert_primary(
            &mut store,
            sha2,
            256 * 1024,
            None,
            None,
            large_filter_bytes,
            &large.clone().into_bytes(),
            Some("doc-large".to_owned()),
        )
        .expect("insert two");
        insert_primary(
            &mut store,
            sha3,
            256 * 1024,
            None,
            None,
            large_filter_bytes,
            &large.into_bytes(),
            Some("doc-deleted".to_owned()),
        )
        .expect("insert three");
        store
            .delete_document(&hex::encode(sha3))
            .expect("delete third");

        let external_ids = store.external_ids_for_sha256(&[
            hex::encode(sha1),
            hex::encode(sha2),
            hex::encode(sha3),
            "ff".repeat(32),
        ]);
        assert_eq!(
            external_ids,
            vec![
                Some("doc-small".to_owned()),
                Some("doc-large".to_owned()),
                None,
                None,
            ]
        );
        let doc_ids = store.doc_ids_for_sha256(&[
            hex::encode(sha1),
            hex::encode(sha2),
            hex::encode(sha3),
            "ff".repeat(32),
        ]);
        assert_eq!(doc_ids, vec![Some(1), Some(2), None, None]);
    }

    #[test]
    fn validation_and_open_error_paths_work() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");

        CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");
        assert!(
            CandidateStore::init(
                CandidateConfig {
                    root: root.clone(),
                    ..CandidateConfig::default()
                },
                false
            )
            .expect_err("existing store")
            .to_string()
            .contains("already exists")
        );

        assert!(
            validate_config(&CandidateConfig {
                root: root.clone(),
                id_source: "filepath".to_owned(),
                ..CandidateConfig::default()
            })
            .expect_err("id source")
            .to_string()
            .contains("id_source")
        );
        assert!(
            validate_config(&CandidateConfig {
                root: root.clone(),
                filter_target_fp: Some(1.0),
                ..CandidateConfig::default()
            })
            .expect_err("target fp")
            .to_string()
            .contains("filter_target_fp")
        );
        assert_eq!(
            normalize_sha256_hex(&format!("  {}  ", "AB".repeat(32))).expect("normalize"),
            "ab".repeat(32)
        );
        assert!(
            normalize_sha256_hex("not-a-sha")
                .expect_err("invalid sha")
                .to_string()
                .contains("64 hexadecimal")
        );

        let open_root = tmp.path().join("open_checks");
        fs::create_dir_all(&open_root).expect("open root");
        fs::write(meta_path(&open_root), b"{").expect("bad meta");
        assert!(
            CandidateStore::open(&open_root)
                .expect_err("invalid meta")
                .to_string()
                .contains("Invalid candidate metadata")
        );

        let bad_version = LegacyStoreMeta {
            version: STORE_VERSION + 1,
            ..LegacyStoreMeta::default()
        };
        fs::write(
            meta_path(&open_root),
            serde_json::to_vec_pretty(&bad_version).expect("version json"),
        )
        .expect("write version");
        assert!(
            CandidateStore::open(&open_root)
                .expect_err("unsupported version")
                .to_string()
                .contains("Unsupported candidate store version")
        );

        fs::write(
            meta_path(&open_root),
            serde_json::to_vec_pretty(&LegacyStoreMeta::default()).expect("meta json"),
        )
        .expect("write good meta");
        let opened = CandidateStore::open(&open_root).expect("open without docs");
        assert_eq!(opened.stats().doc_count, 0);
    }

    #[test]
    fn binary_sidecars_roundtrip_and_reopen() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let file_size = 1234;
        let gram_count = 2;
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(file_size, Some(gram_count))
            .expect("filter bytes");
        let bloom_hashes =
            store.resolve_bloom_hashes_for_document(filter_bytes, Some(gram_count), None);
        let mut bloom_one = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom one");
        bloom_one.add(u64::from(0x0201_u32)).expect("add bloom one");
        let mut bloom_two = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom two");
        bloom_two.add(u64::from(0x0403_u32)).expect("add bloom two");

        insert_primary(
            &mut store,
            [0x11; 32],
            file_size,
            Some(gram_count),
            Some(bloom_hashes),
            filter_bytes,
            &bloom_one.into_bytes(),
            Some("doc-one".to_owned()),
        )
        .expect("insert one");
        insert_primary(
            &mut store,
            [0x22; 32],
            file_size,
            Some(gram_count),
            Some(bloom_hashes),
            filter_bytes,
            &bloom_two.into_bytes(),
            None,
        )
        .expect("insert two");
        store
            .delete_document(&hex::encode([0x22; 32]))
            .expect("delete two");

        let (loaded_docs, loaded_rows, loaded_tier2_rows) =
            load_candidate_binary_store(&root).expect("load binary");
        assert_eq!(loaded_docs.len(), 2);
        assert_eq!(loaded_rows.len(), 2);
        assert_eq!(loaded_tier2_rows.len(), 2);
        assert_eq!(loaded_docs[0].doc_id, 1);
        assert!(loaded_docs[1].deleted);

        let reopened = CandidateStore::open(&root).expect("reopen");
        assert_eq!(
            reopened.external_ids_for_sha256(&[hex::encode([0x11; 32])]),
            vec![Some("doc-one".to_owned())]
        );
    }

    #[test]
    fn binary_sidecars_reject_corrupt_lengths_and_offsets() {
        let tmp = tempdir().expect("tmp");
        let invalid_len_root = tmp.path().join("invalid_len_root");
        let mut invalid_len_store = CandidateStore::init(
            CandidateConfig {
                root: invalid_len_root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init invalid len root");
        let file_size = 1234;
        let gram_count = 2;
        let filter_bytes = invalid_len_store
            .resolve_filter_bytes_for_file_size(file_size, Some(gram_count))
            .expect("filter bytes");
        let bloom_hashes = invalid_len_store.resolve_bloom_hashes_for_document(
            filter_bytes,
            Some(gram_count),
            None,
        );
        let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
        bloom.add(u64::from(10_u32)).expect("add gram");
        insert_primary(
            &mut invalid_len_store,
            [0x11; 32],
            file_size,
            Some(gram_count),
            Some(bloom_hashes),
            filter_bytes,
            &bloom.into_bytes(),
            Some("ok".to_owned()),
        )
        .expect("insert invalid len root");
        fs::write(sha_by_docid_path(&invalid_len_root), [0u8; 31]).expect("truncate sha");
        assert!(
            load_candidate_binary_store(&invalid_len_root)
                .expect_err("invalid binary len")
                .to_string()
                .contains("Invalid candidate binary document state")
        );

        let mismatch_root = tmp.path().join("mismatch_root");
        let mut mismatch_store = CandidateStore::init(
            CandidateConfig {
                root: mismatch_root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init mismatch root");
        let mut mismatch_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("mismatch");
        mismatch_bloom
            .add(u64::from(20_u32))
            .expect("add mismatch gram");
        insert_primary(
            &mut mismatch_store,
            [0x11; 32],
            file_size,
            Some(gram_count),
            Some(bloom_hashes),
            filter_bytes,
            &mismatch_bloom.into_bytes(),
            Some("ok".to_owned()),
        )
        .expect("insert mismatch root");
        fs::write(sha_by_docid_path(&mismatch_root), vec![0u8; 64]).expect("mismatch sha bytes");
        assert!(
            load_candidate_binary_store(&mismatch_root)
                .expect_err("mismatch state")
                .to_string()
                .contains("Mismatched candidate binary document state")
        );

        let invalid_bloom_root = tmp.path().join("invalid_bloom_root");
        let mut invalid_bloom_store = CandidateStore::init(
            CandidateConfig {
                root: invalid_bloom_root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init invalid bloom root");
        let mut invalid_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("invalid");
        invalid_bloom
            .add(u64::from(30_u32))
            .expect("add invalid gram");
        insert_primary(
            &mut invalid_bloom_store,
            [0x11; 32],
            file_size,
            Some(gram_count),
            Some(bloom_hashes),
            filter_bytes,
            &invalid_bloom.into_bytes(),
            Some("ok".to_owned()),
        )
        .expect("insert invalid bloom root");
        let mut row =
            DocMetaRow::decode(&fs::read(doc_meta_path(&invalid_bloom_root)).expect("row"))
                .expect("decode row");
        row.bloom_offset = 1_000_000;
        fs::write(doc_meta_path(&invalid_bloom_root), row.encode()).expect("write bad row");
        fs::write(
            meta_path(&invalid_bloom_root),
            serde_json::to_vec_pretty(&LegacyStoreMeta::default()).expect("bad bloom meta"),
        )
        .expect("write bad bloom meta");
        assert!(
            CandidateStore::open(&invalid_bloom_root)
                .expect_err("invalid bloom offset")
                .to_string()
                .contains("Invalid bloom payload stored")
        );

        let invalid_utf8_root = tmp.path().join("invalid_utf8_root");
        let mut invalid_utf8_store = CandidateStore::init(
            CandidateConfig {
                root: invalid_utf8_root.clone(),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init invalid utf8 root");
        let mut invalid_utf8_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("utf8");
        invalid_utf8_bloom
            .add(u64::from(40_u32))
            .expect("add utf8 gram");
        insert_primary(
            &mut invalid_utf8_store,
            [0x11; 32],
            file_size,
            Some(gram_count),
            Some(bloom_hashes),
            filter_bytes,
            &invalid_utf8_bloom.into_bytes(),
            Some("ok".to_owned()),
        )
        .expect("insert invalid utf8 root");
        fs::write(external_ids_path(&invalid_utf8_root), [0xFF, 0xFE]).expect("write bad utf8");
        fs::write(
            meta_path(&invalid_utf8_root),
            serde_json::to_vec_pretty(&LegacyStoreMeta::default()).expect("bad utf8 meta"),
        )
        .expect("write bad utf8 meta");
        assert!(
            CandidateStore::open(&invalid_utf8_root)
                .expect("open utf8 root")
                .doc_external_id(0)
                .expect_err("invalid external id utf8")
                .to_string()
                .contains("Invalid external_id payload stored")
        );
    }

    #[test]
    fn doc_meta_codec_and_binary_write_helpers_cover_remaining_paths() {
        let row = DocMetaRow {
            file_size: 123,
            filter_bytes: 64,
            flags: DOC_FLAG_DELETED,
            bloom_hashes: 7,
            bloom_offset: 7,
            bloom_len: 8,
            external_id_offset: 21,
            external_id_len: 4,
            metadata_offset: 25,
            metadata_len: 3,
        };
        let encoded = row.encode();
        let decoded = DocMetaRow::decode(&encoded).expect("decode row");
        assert_eq!(decoded.file_size, row.file_size);
        assert_eq!(decoded.filter_bytes, row.filter_bytes);
        assert_eq!(decoded.flags, row.flags);
        assert_eq!(decoded.bloom_offset, row.bloom_offset);
        assert_eq!(decoded.bloom_len, row.bloom_len);
        assert_eq!(decoded.external_id_offset, row.external_id_offset);
        assert_eq!(decoded.external_id_len, row.external_id_len);
        assert!(
            DocMetaRow::decode(&encoded[..encoded.len() - 1])
                .expect_err("short row")
                .to_string()
                .contains("Invalid candidate doc meta row size")
        );

        let tmp = tempdir().expect("tmp");
        let blob_path = tmp.path().join("blob.bin");
        let first = append_blob(blob_path.clone(), b"abc").expect("append blob 1");
        let second = append_blob(blob_path.clone(), b"de").expect("append blob 2");
        assert_eq!(first, 0);
        assert_eq!(second, 3);
        let mut bytes = fs::read(&blob_path).expect("read blob file");
        assert_eq!(
            read_blob(&bytes, 0, 5, "blob", 1).expect("read blob"),
            b"abcde"
        );
        write_at(blob_path.clone(), 1, b"Z").expect("write at");
        bytes = fs::read(&blob_path).expect("re-read blob file");
        assert_eq!(&bytes, b"aZcde");
        assert!(
            read_blob(&bytes, 99, 1, "blob", 1)
                .expect_err("invalid blob range")
                .to_string()
                .contains("Invalid blob payload stored")
        );

        let u32_path = tmp.path().join("u32.bin");
        let offset = append_u32_slice(u32_path.clone(), &[7, 8, 9]).expect("append u32");
        let u32_bytes = fs::read(&u32_path).expect("read u32 file");
        assert_eq!(
            read_u32_vec(&u32_bytes, offset, 3, "grams", 9).expect("read u32 vec"),
            vec![7, 8, 9]
        );
        assert!(
            read_u32_vec(&u32_bytes, 0, 99, "grams", 9)
                .expect_err("invalid u32 range")
                .to_string()
                .contains("Invalid grams payload stored")
        );
    }

    #[test]
    fn sidecar_and_append_helper_paths_work() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).expect("create root");

        let first_blob_path = tmp.path().join("blob_first.bin");
        fs::write(&first_blob_path, b"abcdef").expect("write first blob");
        fs::write(doc_metadata_path(&root), b"meta").expect("write metadata");

        let mut sidecar = BlobSidecar::with_access_mode(
            first_blob_path.clone(),
            BlobSidecarAccessMode::MmapWholeFile,
        );
        sidecar.map_if_exists().expect("map sidecar");
        assert_eq!(
            sidecar
                .read_bytes(1, 3, "blob", 7)
                .expect("mmap read")
                .as_ref(),
            b"bcd"
        );
        assert!(
            sidecar
                .read_bytes(99, 1, "blob", 7)
                .expect_err("invalid range")
                .to_string()
                .contains("Invalid blob payload stored")
        );
        sidecar.invalidate();
        assert_eq!(
            sidecar
                .read_bytes(0, 2, "blob", 7)
                .expect("file read")
                .as_ref(),
            b"ab"
        );

        let other_root = tmp.path().join("other");
        fs::create_dir_all(&other_root).expect("create other root");
        fs::write(doc_metadata_path(&other_root), b"xyz").expect("write other metadata");
        let second_blob_path = tmp.path().join("blob_second.bin");
        fs::write(&second_blob_path, b"xyz").expect("write second blob");
        sidecar.retarget(second_blob_path.clone());
        sidecar.map_if_exists().expect("remap sidecar");
        assert_eq!(
            sidecar
                .read_bytes(0, 3, "blob", 8)
                .expect("retarget read")
                .as_ref(),
            b"xyz"
        );

        let positioned_path = tmp.path().join("blob_positioned.bin");
        fs::write(&positioned_path, b"positioned").expect("write positioned blob");
        let positioned =
            BlobSidecar::with_access_mode(positioned_path, BlobSidecarAccessMode::PositionedRead);
        positioned.map_if_exists().expect("open positioned sidecar");
        assert_eq!(
            positioned
                .read_bytes(1, 4, "blob", 11)
                .expect("positioned read")
                .as_ref(),
            b"osit"
        );
        assert_eq!(
            positioned
                .mmap_slice(0, 4, "blob")
                .expect("positioned mmap slice"),
            None
        );
        assert_eq!(positioned.mapped_bytes(), 0);

        let mut sidecars = StoreSidecars::map_existing(&root).expect("map store sidecars");
        assert_eq!(
            sidecars
                .metadata
                .read_bytes(0, 4, "metadata", 9)
                .expect("metadata read")
                .as_ref(),
            b"meta"
        );
        assert_eq!(sidecars.metadata.mapped_bytes(), 0);
        sidecars.invalidate_all();
        sidecars.retarget_root(&other_root);
        sidecars.refresh_maps().expect("refresh retargeted maps");
        assert_eq!(
            sidecars
                .metadata
                .read_bytes(0, 3, "metadata", 10)
                .expect("retargeted store metadata sidecar")
                .as_ref(),
            b"xyz"
        );

        let append_path = tmp.path().join("append").join("payload.bin");
        let mut append = AppendFile::new(append_path.clone()).expect("new append file");
        assert_eq!(append.append(b"abc").expect("append first"), 0);
        assert_eq!(append.append(b"").expect("append empty"), 3);
        assert_eq!(append.append(b"de").expect("append second"), 3);
        assert_eq!(
            fs::read(&append_path).expect("read append payload"),
            b"abcde"
        );

        let retarget_path = tmp.path().join("retarget").join("payload.bin");
        fs::create_dir_all(retarget_path.parent().expect("retarget parent"))
            .expect("create retarget dir");
        fs::write(&retarget_path, b"pre").expect("seed retarget payload");
        append.retarget(retarget_path.clone());
        assert_eq!(append.append(b"zz").expect("append retarget"), 3);
        assert_eq!(
            fs::read(&retarget_path).expect("read retarget payload"),
            b"prezz"
        );

        let mut writers = StoreAppendWriters::new(&root).expect("append writers");
        writers.retarget_root(&other_root);
        assert_eq!(writers.metadata.path, doc_metadata_path(&other_root));
        assert_eq!(writers.external_ids.path, external_ids_path(&other_root));
    }

    #[test]
    fn insert_restore_delete_and_stats_edge_paths_work() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root,
                filter_target_fp: Some(0.25),
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        assert!(
            store
                .insert_document([0x10; 32], 8, None, None, None, None, 0, &[], 0, &[], None,)
                .expect_err("zero filter bytes")
                .to_string()
                .contains("filter_bytes must be > 0")
        );
        assert!(
            store
                .insert_document(
                    [0x10; 32],
                    8,
                    None,
                    None,
                    None,
                    None,
                    1024,
                    &vec![0u8; 32],
                    0,
                    &[],
                    None,
                )
                .expect_err("length mismatch")
                .to_string()
                .contains("bloom_filter length")
        );

        let inserted = insert_primary(
            &mut store,
            [0x10; 32],
            8,
            None,
            None,
            1024,
            &vec![0u8; 1024],
            Some("first".to_owned()),
        )
        .expect("insert");
        assert_eq!(inserted.status, "inserted");

        let duplicate = insert_primary(
            &mut store,
            [0x10; 32],
            999,
            None,
            None,
            1024,
            &vec![0u8; 1024],
            Some("ignored".to_owned()),
        )
        .expect("duplicate");
        assert_eq!(duplicate.status, "already_exists");
        assert_eq!(duplicate.doc_id, inserted.doc_id);

        let missing = store
            .delete_document(&hex::encode([0x33; 32]))
            .expect("missing delete");
        assert_eq!(missing.status, "missing");
        assert_eq!(missing.doc_id, None);

        let deleted = store
            .delete_document(&hex::encode([0x10; 32]))
            .expect("delete");
        assert_eq!(deleted.status, "deleted");

        let restored = insert_primary(
            &mut store,
            [0x10; 32],
            16,
            None,
            None,
            1024,
            &vec![0xFF; 1024],
            Some("restored".to_owned()),
        )
        .expect("restore");
        assert_eq!(restored.status, "restored");
        assert_eq!(restored.doc_id, inserted.doc_id);

        let stats = store.stats();
        assert_eq!(stats.doc_count, 1);
        assert_eq!(stats.deleted_doc_count, 0);
        assert_eq!(
            store.external_ids_for_sha256(&[hex::encode([0x10; 32])]),
            vec![Some("restored".to_owned())]
        );
    }

    #[test]
    fn query_and_ast_edge_paths_work() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root,
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let filter_bytes = 8;
        let bloom_one = lane_bloom_bytes(filter_bytes, 2, &[1]);
        let bloom_two = lane_bloom_bytes(filter_bytes, 2, &[2]);
        let bloom_one_two = lane_bloom_bytes(filter_bytes, 2, &[1, 2]);

        insert_primary(
            &mut store,
            [0x11; 32],
            8,
            None,
            Some(2),
            filter_bytes,
            &bloom_one,
            None,
        )
        .expect("insert doc one");
        insert_primary(
            &mut store,
            [0x22; 32],
            8,
            None,
            Some(2),
            filter_bytes,
            &bloom_two,
            None,
        )
        .expect("insert doc two");
        insert_primary(
            &mut store,
            [0x33; 32],
            8,
            None,
            Some(2),
            filter_bytes,
            &bloom_one_two,
            None,
        )
        .expect("insert doc three");

        let plan = CompiledQueryPlan {
            patterns: vec![
                PatternPlan {
                    pattern_id: "tier1".to_owned(),
                    alternatives: vec![vec![1]],
                    tier2_alternatives: vec![Vec::new()],
                    anchor_literals: vec![Vec::new()],
                    fixed_literals: vec![Vec::new()],
                    fixed_literal_wide: vec![false],
                    fixed_literal_fullword: vec![false],
                },
                PatternPlan {
                    pattern_id: "tier2".to_owned(),
                    alternatives: vec![vec![2]],
                    tier2_alternatives: vec![Vec::new()],
                    anchor_literals: vec![Vec::new()],
                    fixed_literals: vec![Vec::new()],
                    fixed_literal_wide: vec![false],
                    fixed_literal_fullword: vec![false],
                },
            ],
            root: QueryNode {
                kind: "or".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("tier1".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("tier2".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                ],
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 3.0,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };

        let result = store.query_candidates(&plan, 0, 1).expect("query");
        assert_eq!(result.total_candidates, 3);
        assert_eq!(result.returned_count, 1);
        assert_eq!(result.next_cursor, Some(1));
        assert_eq!(result.tier_used, "tier1");

        let bloom_bytes = lane_bloom_bytes(64, 2, &[1, 2]);
        let doc = CandidateDoc {
            doc_id: 99,
            sha256: hex::encode([0x44; 32]),
            file_size: 42,
            filter_bytes: 64,
            bloom_hashes: 2,
            tier2_filter_bytes: 0,
            tier2_bloom_hashes: 0,
            special_population: false,
            deleted: false,
        };
        let patterns_vec = vec![
            PatternPlan {
                pattern_id: "empty".to_owned(),
                alternatives: vec![Vec::new()],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
            PatternPlan {
                pattern_id: "tier1".to_owned(),
                alternatives: vec![vec![1]],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
            PatternPlan {
                pattern_id: "tier2".to_owned(),
                alternatives: vec![vec![1, 2]],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
            PatternPlan {
                pattern_id: "missing".to_owned(),
                alternatives: vec![vec![99]],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
        ];
        let patterns = patterns_vec
            .iter()
            .cloned()
            .map(|pattern| (pattern.pattern_id.clone(), pattern))
            .collect::<HashMap<_, _>>();
        let eval_plan = CompiledQueryPlan {
            patterns: patterns_vec.clone(),
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("tier1".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 32.0,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };
        let tier2_bloom_bytes = &[][..];
        let mask_cache = build_pattern_mask_cache(
            &patterns_vec,
            &[(64, 2)],
            &[(64, 2)],
            DEFAULT_TIER1_GRAM_SIZE,
            DEFAULT_TIER2_GRAM_SIZE,
        )
        .expect("pattern mask cache");

        let (mut doc_inputs, _load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
        let outcome = evaluate_pattern(
            patterns.get("empty").expect("empty"),
            mask_cache.get("empty").expect("empty masks"),
            &mut doc_inputs,
            &mut load_tier1,
            &mut load_tier2,
            &eval_plan,
        )
        .expect("empty pattern");
        assert!(outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "tier1");

        let no_fallback_plan = CompiledQueryPlan {
            force_tier1_only: false,
            allow_tier2_fallback: false,
            ..eval_plan.clone()
        };
        let complete_doc = doc.clone();
        let (mut doc_inputs, _load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&complete_doc, &[], &bloom_bytes, tier2_bloom_bytes);
        let outcome = evaluate_pattern(
            patterns.get("missing").expect("missing"),
            mask_cache.get("missing").expect("missing masks"),
            &mut doc_inputs,
            &mut load_tier1,
            &mut load_tier2,
            &no_fallback_plan,
        )
        .expect("no match");
        assert!(!outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "none");

        let allow_fallback_plan = CompiledQueryPlan {
            force_tier1_only: false,
            allow_tier2_fallback: true,
            ..eval_plan.clone()
        };
        let (mut doc_inputs, _load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&complete_doc, &[], &bloom_bytes, tier2_bloom_bytes);
        let outcome = evaluate_pattern(
            patterns.get("tier2").expect("tier2"),
            mask_cache.get("tier2").expect("tier2 masks"),
            &mut doc_inputs,
            &mut load_tier1,
            &mut load_tier2,
            &allow_fallback_plan,
        )
        .expect("complete doc should match via bloom path");
        assert!(outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "tier1");

        let no_overlap_doc = doc.clone();
        let (mut doc_inputs, _load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&no_overlap_doc, &[], &bloom_bytes, tier2_bloom_bytes);
        let outcome = evaluate_pattern(
            patterns.get("tier2").expect("tier2"),
            mask_cache.get("tier2").expect("tier2 masks"),
            &mut doc_inputs,
            &mut load_tier1,
            &mut load_tier2,
            &allow_fallback_plan,
        )
        .expect("bloom-only path should match from bloom anchors");
        assert!(outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "tier1");

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
        let outcome = evaluate_node(
            &QueryNode {
                kind: "and".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("tier1".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("missing".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                ],
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("and");
        assert!(!outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "none");

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
        let outcome = evaluate_node(
            &QueryNode {
                kind: "or".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("missing".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("tier2".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                ],
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("or");
        assert!(outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "tier1");

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
        let outcome = evaluate_node(
            &QueryNode {
                kind: "n_of".to_owned(),
                pattern_id: None,
                threshold: Some(2),
                children: vec![
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("tier1".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("tier2".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                ],
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("n_of");
        assert!(outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "tier1");

        assert!(
            {
                let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
                    prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
                evaluate_node(
                    &QueryNode {
                        kind: "n_of".to_owned(),
                        pattern_id: None,
                        threshold: None,
                        children: Vec::new(),
                    },
                    &mut doc_inputs,
                    &mut load_metadata,
                    &mut load_tier1,
                    &mut load_tier2,
                    &patterns,
                    &mask_cache,
                    &eval_plan,
                    0,
                    &mut QueryEvalCache::default(),
                )
            }
            .expect_err("missing threshold")
            .to_string()
            .contains("requires threshold")
        );
        assert!(
            {
                let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
                    prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
                evaluate_node(
                    &QueryNode {
                        kind: "bogus".to_owned(),
                        pattern_id: None,
                        threshold: None,
                        children: Vec::new(),
                    },
                    &mut doc_inputs,
                    &mut load_metadata,
                    &mut load_tier1,
                    &mut load_tier2,
                    &patterns,
                    &mask_cache,
                    &eval_plan,
                    0,
                    &mut QueryEvalCache::default(),
                )
            }
            .expect_err("unsupported kind")
            .to_string()
            .contains("Unsupported ast node kind")
        );

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
        let outcome = evaluate_node(
            &QueryNode {
                kind: "not".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("tier1".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                }],
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("not pattern");
        assert!(outcome.matched);

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
        let outcome = evaluate_node(
            &QueryNode {
                kind: "not".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![QueryNode {
                    kind: "filesize_eq".to_owned(),
                    pattern_id: Some("filesize".to_owned()),
                    threshold: Some(doc.file_size as usize),
                    children: Vec::new(),
                }],
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("not filesize");
        assert!(!outcome.matched);
    }

    #[test]
    fn query_candidates_truncates_when_match_count_exceeds_max_candidates() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root,
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let filter_bytes = 8;
        let bloom_one = lane_bloom_bytes(filter_bytes, 2, &[1]);
        let bloom_two = lane_bloom_bytes(filter_bytes, 2, &[2]);
        let bloom_one_two = lane_bloom_bytes(filter_bytes, 2, &[1, 2]);

        insert_primary(
            &mut store,
            [0x11; 32],
            8,
            None,
            Some(2),
            filter_bytes,
            &bloom_one,
            None,
        )
        .expect("insert doc one");
        insert_primary(
            &mut store,
            [0x22; 32],
            8,
            None,
            Some(2),
            filter_bytes,
            &bloom_two,
            None,
        )
        .expect("insert doc two");
        insert_primary(
            &mut store,
            [0x33; 32],
            8,
            None,
            Some(2),
            filter_bytes,
            &bloom_one_two,
            None,
        )
        .expect("insert doc three");

        let plan = CompiledQueryPlan {
            patterns: vec![
                PatternPlan {
                    pattern_id: "tier1".to_owned(),
                    alternatives: vec![vec![1]],
                    tier2_alternatives: vec![Vec::new()],
                    anchor_literals: vec![Vec::new()],
                    fixed_literals: vec![Vec::new()],
                    fixed_literal_wide: vec![false],
                    fixed_literal_fullword: vec![false],
                },
                PatternPlan {
                    pattern_id: "tier2".to_owned(),
                    alternatives: vec![vec![2]],
                    tier2_alternatives: vec![Vec::new()],
                    anchor_literals: vec![Vec::new()],
                    fixed_literals: vec![Vec::new()],
                    fixed_literal_wide: vec![false],
                    fixed_literal_fullword: vec![false],
                },
            ],
            root: QueryNode {
                kind: "or".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("tier1".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("tier2".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                ],
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 2.0,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };

        let result = store
            .query_candidates(&plan, 0, 8)
            .expect("overflow should truncate");
        assert!(result.truncated);
        assert_eq!(result.truncated_limit, Some(2));
        assert_eq!(result.total_candidates, 2);
        assert_eq!(result.returned_count, 2);
        assert_eq!(result.sha256.len(), 2);
    }

    #[test]
    fn evaluate_node_supports_metadata_and_time_conditions() {
        let tmp = tempdir().expect("tmp");
        let pe_path = tmp.path().join("sample.exe");
        let mut pe = vec![0u8; 512];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        pe[0x88..0x8c].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        pe[0x96..0x98].copy_from_slice(&0x2000u16.to_le_bytes());
        pe[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
        fs::write(&pe_path, &pe).expect("write pe");
        let metadata_bytes = extract_compact_document_metadata(&pe_path).expect("metadata");

        let doc = CandidateDoc {
            doc_id: 1,
            sha256: hex::encode([0x11; 32]),
            file_size: 512,
            filter_bytes: 8,
            bloom_hashes: 2,
            tier2_filter_bytes: 8,
            tier2_bloom_hashes: 2,
            special_population: false,
            deleted: false,
        };
        let patterns = HashMap::<String, PatternPlan>::new();
        let mask_cache = PatternMaskCache::new();
        let eval_plan = CompiledQueryPlan {
            patterns: Vec::new(),
            root: QueryNode {
                kind: "metadata_eq".to_owned(),
                pattern_id: Some("pe.machine".to_owned()),
                threshold: Some(0x14c),
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 32.0,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
        let metadata_outcome = evaluate_node(
            &eval_plan.root,
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("metadata eq");
        assert!(metadata_outcome.matched);

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &[], &[], &[]);
        let unknown_outcome = evaluate_node(
            &QueryNode {
                kind: "metadata_eq".to_owned(),
                pattern_id: Some("elf.machine".to_owned()),
                threshold: Some(62),
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("unknown metadata eq");
        assert!(unknown_outcome.matched);

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
        let time_outcome = evaluate_node(
            &QueryNode {
                kind: "time_now_eq".to_owned(),
                pattern_id: Some("time.now".to_owned()),
                threshold: Some(1234),
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            1234,
            &mut QueryEvalCache::default(),
        )
        .expect("time now eq");
        assert!(time_outcome.matched);

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
        let time_gt_outcome = evaluate_node(
            &QueryNode {
                kind: "time_now_gt".to_owned(),
                pattern_id: Some("time.now".to_owned()),
                threshold: Some(1000),
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            1234,
            &mut QueryEvalCache::default(),
        )
        .expect("time now gt");
        assert!(time_gt_outcome.matched);

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
        let verifier_outcome = evaluate_node(
            &QueryNode {
                kind: "verifier_only_eq".to_owned(),
                pattern_id: Some("uint16(0)==23117".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("verifier only eq");
        assert!(verifier_outcome.matched);

        let numeric_path = tmp.path().join("numeric.bin");
        let numeric_bytes = 0x1122_3344_5566_7788u64.to_le_bytes();
        fs::write(&numeric_path, numeric_bytes).expect("write numeric");
        let numeric_metadata = extract_compact_document_metadata(&numeric_path).expect("metadata");
        let numeric_doc = CandidateDoc {
            file_size: 8,
            ..doc.clone()
        };
        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&numeric_doc, &numeric_metadata, &[], &[]);
        let numeric_true = evaluate_node(
            &QueryNode {
                kind: "verifier_only_eq".to_owned(),
                pattern_id: Some("uint64(0)==1234605616436508552".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("uint64 prefix eq");
        assert!(numeric_true.matched);
        assert_eq!(
            true, numeric_true.matched,
            "uint64(0) prefix shortcut should match the expected decoded value"
        );

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&numeric_doc, &numeric_metadata, &[], &[]);
        let numeric_u32 = evaluate_node(
            &QueryNode {
                kind: "verifier_only_eq".to_owned(),
                pattern_id: Some("uint32(0)==1432778632".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("uint32 prefix eq");
        assert_eq!(
            numeric_u32.matched,
            yara_rule_matches_bytes(
                "rule test { condition: uint32(0) == 1432778632 }",
                &numeric_bytes,
            ),
            "uint32(0) prefix shortcut must match YARA-X semantics"
        );

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&numeric_doc, &numeric_metadata, &[], &[]);
        let numeric_false = evaluate_node(
            &QueryNode {
                kind: "verifier_only_eq".to_owned(),
                pattern_id: Some("int16be(0)==-2".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("int16be prefix eq");
        assert!(!numeric_false.matched);
        assert_eq!(
            numeric_false.matched,
            yara_rule_matches_bytes("rule test { condition: int16be(0) == -2 }", &numeric_bytes,),
            "int16be(0) prefix shortcut must match YARA-X semantics"
        );

        let short_path = tmp.path().join("short.bin");
        let short_bytes = *b"AB";
        fs::write(&short_path, short_bytes).expect("write short");
        let short_metadata = extract_compact_document_metadata(&short_path).expect("metadata");
        let short_doc = CandidateDoc {
            file_size: 2,
            ..doc.clone()
        };
        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&short_doc, &short_metadata, &[], &[]);
        let short_numeric = evaluate_node(
            &QueryNode {
                kind: "verifier_only_eq".to_owned(),
                pattern_id: Some("uint32(0)==0".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("short uint64 prefix eq");
        assert_eq!(
            short_numeric.matched,
            yara_rule_matches_bytes("rule test { condition: uint32(0) == 0 }", &short_bytes),
            "short-file integer prefix shortcut must match YARA-X semantics"
        );

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
        let metadata_ne = evaluate_node(
            &QueryNode {
                kind: "metadata_ne".to_owned(),
                pattern_id: Some("pe.machine".to_owned()),
                threshold: Some(0x8664),
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            200_000_000,
            &mut QueryEvalCache::default(),
        )
        .expect("metadata ne");
        assert!(metadata_ne.matched);

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
        let metadata_time = evaluate_node(
            &QueryNode {
                kind: "metadata_time_lt".to_owned(),
                pattern_id: Some("pe.timestamp".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            400_000_000,
            &mut QueryEvalCache::default(),
        )
        .expect("metadata time lt");
        assert!(metadata_time.matched);

        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
        let metadata_field = evaluate_node(
            &QueryNode {
                kind: "metadata_field_lt".to_owned(),
                pattern_id: Some("pe.subsystem|pe.machine".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("metadata field lt");
        assert!(metadata_field.matched);

        let at_zero_patterns = HashMap::from([(
            "$mz".to_owned(),
            PatternPlan {
                pattern_id: "$mz".to_owned(),
                alternatives: vec![Vec::new()],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![b"MZ".to_vec()],
                fixed_literals: vec![b"MZ".to_vec()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
        )]);
        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
        let at_zero_true = evaluate_node(
            &QueryNode {
                kind: "verifier_only_at".to_owned(),
                pattern_id: Some("$mz@0".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &at_zero_patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("at zero prefix true");
        assert!(at_zero_true.matched);
        assert_eq!(
            at_zero_true.matched,
            yara_rule_matches_bytes(
                "rule test { strings: $mz = \"MZ\" condition: $mz at 0 }",
                &pe,
            ),
            "$str at 0 prefix shortcut must match YARA-X semantics"
        );

        let at_zero_patterns = HashMap::from([(
            "$pk".to_owned(),
            PatternPlan {
                pattern_id: "$pk".to_owned(),
                alternatives: vec![Vec::new()],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![b"PK".to_vec()],
                fixed_literals: vec![b"PK".to_vec()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
        )]);
        let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
            prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
        let at_zero_false = evaluate_node(
            &QueryNode {
                kind: "verifier_only_at".to_owned(),
                pattern_id: Some("$pk@0".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            &mut doc_inputs,
            &mut load_metadata,
            &mut load_tier1,
            &mut load_tier2,
            &at_zero_patterns,
            &mask_cache,
            &eval_plan,
            0,
            &mut QueryEvalCache::default(),
        )
        .expect("at zero prefix false");
        assert!(!at_zero_false.matched);
        assert_eq!(
            at_zero_false.matched,
            yara_rule_matches_bytes(
                "rule test { strings: $pk = \"PK\" condition: $pk at 0 }",
                &pe,
            ),
            "negative $str at 0 prefix shortcut must match YARA-X semantics"
        );
    }

    #[test]
    fn prepared_query_cache_reuses_entries_and_invalidates_on_mutation() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("store");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");
        let sha256 = [0xaa; 32];
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(4, Some(1))
            .expect("primary filter bytes");
        let bloom_hashes = store.resolve_bloom_hashes_for_document(filter_bytes, Some(1), None);
        let mut primary_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("tier1 bloom");
        primary_bloom
            .add(pack_exact_gram(&[1, 2, 3]))
            .expect("add primary gram");
        primary_bloom
            .add(pack_exact_gram(&[2, 3, 4]))
            .expect("add primary gram");
        let tier2_filter_bytes = store
            .resolve_filter_bytes_for_file_size(4, Some(2))
            .expect("tier2 filter bytes");
        let tier2_bloom_hashes =
            store.resolve_bloom_hashes_for_document(tier2_filter_bytes, Some(2), None);
        let mut tier2_bloom =
            BloomFilter::new(tier2_filter_bytes, tier2_bloom_hashes).expect("tier2 bloom");
        tier2_bloom
            .add(pack_exact_gram(&[1, 2, 3, 4]))
            .expect("add tier2 gram");
        store
            .insert_document(
                sha256,
                4,
                Some(1),
                Some(bloom_hashes),
                Some(2),
                Some(tier2_bloom_hashes),
                filter_bytes,
                &primary_bloom.into_bytes(),
                tier2_filter_bytes,
                &tier2_bloom.into_bytes(),
                None,
            )
            .expect("write tier2 sidecars");

        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![pack_exact_gram(&[1, 2, 3, 4])]],
                tier2_alternatives: vec![vec![
                    pack_exact_gram(&[1, 2, 3]),
                    pack_exact_gram(&[2, 3, 4]),
                ]],
                anchor_literals: vec![vec![1, 2, 3, 4]],
                fixed_literals: vec![vec![1, 2, 3, 4]],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 64.0,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };

        let first = store.query_candidates(&plan, 0, 64).expect("first query");
        assert_eq!(store.prepared_query_cache.len(), 1);

        let second = store.query_candidates(&plan, 0, 64).expect("second query");
        assert_eq!(first.total_candidates, second.total_candidates);
        assert_eq!(store.prepared_query_cache.len(), 1);

        let delete = store.delete_document(&hex::encode(sha256)).expect("delete");
        assert_eq!(delete.status, "deleted");
        assert_eq!(store.prepared_query_cache.len(), 0);

        let _third = store.query_candidates(&plan, 0, 64).expect("third query");
        assert_eq!(store.prepared_query_cache.len(), 1);
    }

    #[test]
    fn clear_search_caches_empties_prepared_query_cache() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("store");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(8, None)
            .expect("filter bytes");
        insert_primary(
            &mut store,
            [0x44; 32],
            8,
            None,
            None,
            filter_bytes,
            &lane_bloom_bytes(
                filter_bytes,
                DEFAULT_BLOOM_HASHES,
                &[pack_exact_gram(b"ABC")],
            ),
            None,
        )
        .expect("insert");
        let plan = compile_query_plan_with_gram_sizes_and_identity_source(
            r#"
rule q {
  strings:
    $a = "ABC"
  condition:
    $a
}
"#,
            GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
                .expect("default gram sizes"),
            Some("sha256"),
            8,
            false,
            true,
            100_000,
        )
        .expect("plan");

        let _ = store.query_candidates(&plan, 0, 64).expect("query");
        assert_eq!(store.prepared_query_cache.len(), 1);
        store.clear_search_caches();
        assert_eq!(store.prepared_query_cache.len(), 0);
    }

    #[test]
    fn import_document_batch_wrappers_roundtrip_live_documents() {
        let tmp = tempdir().expect("tmp");
        let src_root = tmp.path().join("src");
        let mut src = CandidateStore::init(
            CandidateConfig {
                root: src_root,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init src");
        let filter_bytes = src
            .resolve_filter_bytes_for_file_size(8, None)
            .expect("filter bytes");
        let bloom = lane_bloom_bytes(
            filter_bytes,
            DEFAULT_BLOOM_HASHES,
            &[pack_exact_gram(b"ABC")],
        );
        insert_primary(
            &mut src,
            [0x61; 32],
            8,
            None,
            None,
            filter_bytes,
            &bloom,
            Some("src-doc".to_owned()),
        )
        .expect("insert source");
        let documents = src.export_live_documents().expect("export");
        assert_eq!(documents.len(), 1);

        let mut dst = CandidateStore::init(
            CandidateConfig {
                root: tmp.path().join("dst"),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init dst");
        let inserted = dst.import_documents_batch(&documents).expect("import");
        assert_eq!(inserted.len(), 1);
        assert_eq!(inserted[0].status, "inserted");
        assert_eq!(dst.stats().doc_count, 1);

        let mut dst_known_new = CandidateStore::init(
            CandidateConfig {
                root: tmp.path().join("dst-known-new"),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init dst known new");
        let inserted_known_new = dst_known_new
            .import_documents_batch_known_new(&documents)
            .expect("import known new");
        assert_eq!(inserted_known_new.len(), 1);
        assert_eq!(inserted_known_new[0].status, "inserted");

        let mut dst_quiet = CandidateStore::init(
            CandidateConfig {
                root: tmp.path().join("dst-quiet"),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init dst quiet");
        dst_quiet
            .import_documents_batch_quiet(&documents)
            .expect("import quiet");
        assert_eq!(dst_quiet.stats().doc_count, 1);

        let mut dst_known_new_quiet = CandidateStore::init(
            CandidateConfig {
                root: tmp.path().join("dst-known-new-quiet"),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init dst known new quiet");
        dst_known_new_quiet
            .import_documents_batch_known_new_quiet(&documents)
            .expect("import known new quiet");
        assert_eq!(dst_known_new_quiet.stats().doc_count, 1);
    }

    #[test]
    fn query_candidates_scans_special_population_when_normal_tree_gate_is_empty() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("store");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root,
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");
        let sha256 = [0x5a; 32];
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(123, None)
            .expect("filter bytes");
        let bloom_hashes = store.resolve_bloom_hashes_for_document(filter_bytes, None, None);
        let gram = pack_exact_gram(&[1, 2, 3, 4]);
        let bloom_bytes = lane_bloom_bytes(filter_bytes, bloom_hashes, &[gram]);
        store
            .insert_document_with_metadata(
                sha256,
                123,
                None,
                None,
                None,
                None,
                filter_bytes,
                &bloom_bytes,
                0,
                &[],
                &[],
                true,
                None,
            )
            .expect("insert special doc");

        assert!(store.tree_tier1_gates.bucket_for_key.is_empty());
        assert_eq!(store.special_doc_positions, vec![0]);

        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "tier1".to_owned(),
                alternatives: vec![vec![gram]],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![vec![1, 2, 3, 4]],
                fixed_literals: vec![vec![1, 2, 3, 4]],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("tier1".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 8.0,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };

        let result = store.query_candidates(&plan, 0, 8).expect("query");
        assert_eq!(result.total_candidates, 1);
        assert_eq!(result.returned_count, 1);
        assert_eq!(result.sha256, vec![hex::encode(sha256)]);
        assert_eq!(result.query_profile.docs_scanned, 1);
        assert_eq!(result.query_profile.tier1_bloom_loads, 1);
    }

    #[test]
    fn query_candidates_tier2_and_metadata_only_scans_docs_without_tier1_loads() {
        let _guard = tier2_and_metadata_only_override(true);
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("store");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root,
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");
        let gram = pack_exact_gram(&[1, 2, 3, 4]);
        for idx in 0..2u8 {
            let sha256 = [idx + 1; 32];
            let filter_bytes = store
                .resolve_filter_bytes_for_file_size(123, None)
                .expect("filter bytes");
            let tier2_filter_bytes = filter_bytes;
            let tier2_bloom_hashes =
                store.resolve_bloom_hashes_for_document(tier2_filter_bytes, None, None);
            let tier2_bloom_bytes = if idx == 0 {
                lane_bloom_bytes(tier2_filter_bytes, tier2_bloom_hashes, &[gram])
            } else {
                vec![0u8; tier2_filter_bytes]
            };
            store
                .insert_document_with_metadata(
                    sha256,
                    123,
                    None,
                    None,
                    None,
                    None,
                    filter_bytes,
                    &vec![0u8; filter_bytes],
                    tier2_filter_bytes,
                    &tier2_bloom_bytes,
                    &[],
                    false,
                    None,
                )
                .expect("insert doc");
        }

        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "tier1".to_owned(),
                alternatives: vec![Vec::new()],
                tier2_alternatives: vec![vec![gram]],
                anchor_literals: vec![vec![1, 2, 3, 4]],
                fixed_literals: vec![vec![1, 2, 3, 4]],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("tier1".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 8.0,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };

        let result = store.query_candidates(&plan, 0, 8).expect("query");
        assert_eq!(result.total_candidates, 1);
        assert_eq!(result.returned_count, 1);
        assert_eq!(result.query_profile.docs_scanned, 2);
        assert_eq!(result.query_profile.tree_gate_passed, 1);
        assert_eq!(result.query_profile.tier1_bloom_loads, 0);
        assert_eq!(result.query_profile.tier2_bloom_loads, 2);
        assert_eq!(result.tier_used, "tier2");
    }
}
