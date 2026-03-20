use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use memmap2::{Mmap, MmapOptions};
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
use crate::candidate::metadata_field_matches_eq;
use crate::candidate::query_plan::{CompiledQueryPlan, PatternPlan, QueryNode};
use crate::perf::{record_counter, record_max, scope};
use crate::{Result, SspryError};

const STORE_VERSION: u32 = 2;
const TIER2_SUPERBLOCKS_SNAPSHOT_VERSION: u32 = 2;
const TREE_BLOOM_GATES_SNAPSHOT_VERSION: u32 = 1;
const DEFAULT_FILTER_BYTES: usize = 2048;
const DEFAULT_BLOOM_HASHES: usize = 7;
const DEFAULT_FILTER_MIN_BYTES: usize = 1;
const DEFAULT_FILTER_MAX_BYTES: usize = 0;
const DEFAULT_TIER2_SUPERBLOCK_DOCS: usize = 32;
pub const DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES: usize = 4096;
const DEFAULT_COMPACTION_IDLE_COOLDOWN_S: f64 = 5.0;
const PREPARED_QUERY_CACHE_CAPACITY: usize = 32;
const DEFAULT_QUERY_SCAN_WORKERS: usize = 4;

#[derive(Clone, Debug)]
pub struct CandidateConfig {
    pub root: PathBuf,
    pub id_source: String,
    pub store_path: bool,
    pub tier2_gram_size: usize,
    pub tier1_gram_size: usize,
    pub tier2_superblock_summary_cap_bytes: usize,
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
            tier2_superblock_summary_cap_bytes: DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES,
            filter_target_fp: Some(0.35),
            compaction_idle_cooldown_s: DEFAULT_COMPACTION_IDLE_COOLDOWN_S,
        }
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
    pub load_tier2_superblocks_ms: u64,
    pub rebuild_tier2_superblocks_ms: u64,
    pub loaded_tier2_superblocks_from_snapshot: bool,
    pub total_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CandidateStoreRebuildProfile {
    sha_index_ms: u64,
    load_tier2_superblocks_ms: u64,
    tier2_superblocks_ms: u64,
    loaded_tier2_superblocks_from_snapshot: bool,
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
    pub metadata_bytes: Vec<u8>,
    pub external_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CandidateQueryResult {
    pub sha256: Vec<String>,
    pub scores: Vec<u32>,
    pub total_candidates: usize,
    pub returned_count: usize,
    pub cursor: usize,
    pub next_cursor: Option<usize>,
    pub tier_used: String,
    pub query_profile: CandidateQueryProfile,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CandidateQueryProfile {
    pub docs_scanned: u64,
    pub superblocks_skipped: u64,
    pub metadata_loads: u64,
    pub metadata_bytes: u64,
    pub tier1_bloom_loads: u64,
    pub tier1_bloom_bytes: u64,
    pub tier2_bloom_loads: u64,
    pub tier2_bloom_bytes: u64,
}

impl CandidateQueryProfile {
    pub(crate) fn merge_from(&mut self, other: &Self) {
        self.docs_scanned = self.docs_scanned.saturating_add(other.docs_scanned);
        self.superblocks_skipped = self
            .superblocks_skipped
            .saturating_add(other.superblocks_skipped);
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

#[derive(Clone, Debug)]
pub struct CandidateStats {
    pub doc_count: usize,
    pub deleted_doc_count: usize,
    pub id_source: String,
    pub store_path: bool,
    pub filter_target_fp: Option<f64>,
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
    pub tier2_superblocks_skipped_total: u64,
    pub tier2_match_ratio: f64,
    pub tier2_superblock_count: usize,
    pub tier2_superblock_docs: usize,
    pub tier2_superblock_summary_bytes: u64,
    pub tier2_superblock_memory_budget_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct StoreMeta {
    version: u32,
    next_doc_id: u64,
    id_source: String,
    store_path: bool,
    tier2_gram_size: usize,
    tier1_gram_size: usize,
    tier2_superblock_summary_cap_bytes: usize,
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

impl Default for StoreMeta {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            next_doc_id: 1,
            id_source: "sha256".to_owned(),
            store_path: false,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
            tier2_superblock_summary_cap_bytes: DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES,
            filter_target_fp: Some(0.35),
            compaction_idle_cooldown_s: DEFAULT_COMPACTION_IDLE_COOLDOWN_S,
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
    deleted: bool,
}

const DOC_META_ROW_BYTES: usize = 56;
const TIER2_DOC_META_ROW_BYTES: usize = 24;
const DEFAULT_TIER2_SUPERBLOCK_MEMORY_BUDGET_DIVISOR: u64 = 4;
const APPEND_PAYLOAD_SYNC_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;
const MIN_TIER2_SUPERBLOCK_MEMORY_BUDGET_BYTES: u64 = 1 * 1024 * 1024;
const DOC_FLAG_DELETED: u8 = 0x02;

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
    tier2_superblocks_skipped_total: u64,
}

#[derive(Debug, Default)]
struct BlobSidecar {
    path: PathBuf,
    mmap: Option<Mmap>,
}

impl BlobSidecar {
    fn new(path: PathBuf) -> Self {
        Self { path, mmap: None }
    }

    fn map_if_exists(&mut self) -> Result<()> {
        self.mmap = None;
        if !self.path.exists() {
            return Ok(());
        }
        let file = fs::File::open(&self.path)?;
        if file.metadata()?.len() == 0 {
            return Ok(());
        }
        let mmap = unsafe { MmapOptions::new().map(&file) }.map_err(|err| {
            SspryError::from(format!("Failed to mmap {}: {err}", self.path.display()))
        })?;
        self.mmap = Some(mmap);
        Ok(())
    }

    fn invalidate(&mut self) {
        self.mmap = None;
    }

    fn retarget(&mut self, path: PathBuf) {
        self.path = path;
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
        if let Some(mmap) = &self.mmap {
            let start = offset as usize;
            let end = start.saturating_add(len);
            if end > mmap.len() {
                return Err(SspryError::from(format!(
                    "Invalid {label} payload stored for doc_id {doc_id}"
                )));
            }
            return Ok(Cow::Borrowed(&mmap[start..end]));
        }

        let mut file = fs::File::open(&self.path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0u8; len];
        file.read_exact(&mut bytes)?;
        Ok(Cow::Owned(bytes))
    }

    fn mmap_slice<'a>(&'a self, offset: u64, len: usize, label: &str) -> Result<Option<&'a [u8]>> {
        if len == 0 {
            return Ok(Some(&[]));
        }
        let Some(mmap) = &self.mmap else {
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
            blooms: BlobSidecar::new(blooms_path(root)),
            tier2_blooms: BlobSidecar::new(tier2_blooms_path(root)),
            metadata: BlobSidecar::new(doc_metadata_path(root)),
            external_ids: BlobSidecar::new(external_ids_path(root)),
        }
    }

    fn map_existing(root: &Path) -> Result<Self> {
        let mut sidecars = Self::new(root);
        sidecars.refresh_maps()?;
        Ok(sidecars)
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

#[derive(Clone, Debug)]
struct Tier2SuperblockIndex {
    docs_per_block: usize,
    keys_per_block: Vec<Vec<(usize, usize)>>,
    bucket_for_key: BTreeMap<(usize, usize), (usize, usize)>,
    summary_bytes_by_bucket: BTreeMap<(usize, usize), usize>,
    masks_by_bucket: BTreeMap<(usize, usize), Vec<Vec<u8>>>,
    summary_memory_bytes: u64,
}

impl Default for Tier2SuperblockIndex {
    fn default() -> Self {
        Self {
            docs_per_block: DEFAULT_TIER2_SUPERBLOCK_DOCS,
            keys_per_block: Vec::new(),
            bucket_for_key: BTreeMap::new(),
            summary_bytes_by_bucket: BTreeMap::new(),
            masks_by_bucket: BTreeMap::new(),
            summary_memory_bytes: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct TreeBloomGateIndex {
    bucket_for_key: BTreeMap<(usize, usize), (usize, usize)>,
    summary_bytes_by_bucket: BTreeMap<(usize, usize), usize>,
    masks_by_bucket: BTreeMap<(usize, usize), Vec<u8>>,
    summary_memory_bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct CandidateCompactionSnapshot {
    root: PathBuf,
    meta: StoreMeta,
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

fn tier2_superblock_summary_bytes(filter_bytes: usize, summary_cap_bytes: usize) -> usize {
    align_filter_bytes(filter_bytes.max(1).min(summary_cap_bytes.max(1)))
}

const TIER2_SUPERBLOCK_FILTER_BUCKETS: &[usize] = &[
    1 << 10,
    2 << 10,
    4 << 10,
    8 << 10,
    12 << 10,
    16 << 10,
    24 << 10,
    32 << 10,
    48 << 10,
    64 << 10,
    96 << 10,
    128 << 10,
    192 << 10,
    256 << 10,
    384 << 10,
    512 << 10,
    768 << 10,
    1 << 20,
];

fn tier2_superblock_filter_bucket(filter_bytes: usize) -> usize {
    let filter_bytes = filter_bytes.max(1);
    for bucket in TIER2_SUPERBLOCK_FILTER_BUCKETS {
        if filter_bytes <= *bucket {
            return *bucket;
        }
    }
    let mut bucket = *TIER2_SUPERBLOCK_FILTER_BUCKETS.last().unwrap_or(&(1 << 20));
    while bucket < filter_bytes {
        bucket = bucket.saturating_mul(2);
        if bucket == usize::MAX {
            break;
        }
    }
    bucket.max(filter_bytes.next_power_of_two())
}

fn tier2_superblock_bucket_key(filter_bytes: usize, bloom_hashes: usize) -> (usize, usize) {
    (tier2_superblock_filter_bucket(filter_bytes), bloom_hashes)
}

fn tier2_superblock_summary_word_stride(filter_bytes: usize, summary_bytes: usize) -> usize {
    let total_words = align_filter_bytes(filter_bytes.max(1)) / 8;
    let summary_words = align_filter_bytes(summary_bytes.max(1)) / 8;
    total_words.div_ceil(summary_words).max(1)
}

fn tier2_superblock_sample_word_index(
    word_idx: usize,
    filter_bytes: usize,
    summary_bytes: usize,
) -> Option<usize> {
    let summary_words = align_filter_bytes(summary_bytes.max(1)) / 8;
    let stride_words = tier2_superblock_summary_word_stride(filter_bytes, summary_bytes);
    if word_idx % stride_words != 0 {
        return None;
    }
    let summary_word_idx = word_idx / stride_words;
    (summary_word_idx < summary_words).then_some(summary_word_idx)
}

fn merge_sampled_bloom_words_into_summary(
    summary: &mut [u8],
    bloom_bytes: &[u8],
    filter_bytes: usize,
) {
    let summary_bytes = align_filter_bytes(summary.len().max(1));
    for (word_idx, chunk) in bloom_bytes.chunks_exact(8).enumerate() {
        let Some(summary_word_idx) =
            tier2_superblock_sample_word_index(word_idx, filter_bytes, summary_bytes)
        else {
            continue;
        };
        let start = summary_word_idx * 8;
        let end = start + 8;
        let src = u64::from_le_bytes(chunk.try_into().expect("word-sized bloom chunk"));
        let dst = u64::from_le_bytes(
            summary[start..end]
                .try_into()
                .expect("word-sized summary chunk"),
        ) | src;
        summary[start..end].copy_from_slice(&dst.to_le_bytes());
    }
}

fn sample_bloom_word_masks_for_superblock(
    required_masks: &[(usize, u64)],
    filter_bytes: usize,
    summary_bytes: usize,
) -> Vec<(usize, u64)> {
    let mut sampled = BTreeMap::<usize, u64>::new();
    for (word_idx, mask) in required_masks {
        let Some(summary_word_idx) =
            tier2_superblock_sample_word_index(*word_idx, filter_bytes, summary_bytes)
        else {
            continue;
        };
        *sampled.entry(summary_word_idx).or_insert(0) |= *mask;
    }
    sampled.into_iter().collect()
}

fn ensure_superblock_capacity_for(
    index: &mut Tier2SuperblockIndex,
    block_idx: usize,
    filter_bytes: usize,
    bloom_hashes: usize,
    summary_cap_bytes: usize,
) {
    let needed_blocks = block_idx + 1;
    if index.keys_per_block.len() < needed_blocks {
        index.keys_per_block.resize_with(needed_blocks, Vec::new);
    }
    let filter_key = (filter_bytes, bloom_hashes);
    let bucket_key = tier2_superblock_bucket_key(filter_bytes, bloom_hashes);
    let summary_bytes = tier2_superblock_summary_bytes(bucket_key.0, summary_cap_bytes);
    index.bucket_for_key.insert(filter_key, bucket_key);
    index
        .summary_bytes_by_bucket
        .insert(bucket_key, summary_bytes);
    let blocks = index
        .masks_by_bucket
        .entry(bucket_key)
        .or_insert_with(Vec::new);
    while blocks.len() < needed_blocks {
        blocks.push(vec![0u8; summary_bytes]);
        index.summary_memory_bytes = index
            .summary_memory_bytes
            .saturating_add(summary_bytes as u64);
    }
    let keys = &mut index.keys_per_block[block_idx];
    if !keys.contains(&filter_key) {
        keys.push(filter_key);
        keys.sort_unstable();
    }
}

fn update_superblocks_for_doc_bytes_inner(
    index: &mut Tier2SuperblockIndex,
    summary_cap_bytes: usize,
    docs_per_block: usize,
    pos: usize,
    filter_bytes: usize,
    bloom_hashes: usize,
    bloom_bytes: &[u8],
) {
    let block_idx = pos / docs_per_block.max(1);
    ensure_superblock_capacity_for(
        index,
        block_idx,
        filter_bytes,
        bloom_hashes,
        summary_cap_bytes,
    );
    let bucket_key = tier2_superblock_bucket_key(filter_bytes, bloom_hashes);
    if let Some(blocks) = index.masks_by_bucket.get_mut(&bucket_key) {
        if let Some(block) = blocks.get_mut(block_idx) {
            merge_sampled_bloom_words_into_summary(block, bloom_bytes, filter_bytes);
        }
    }
}

fn update_superblocks_for_doc_bytes_batch<'a>(
    index: &mut Tier2SuperblockIndex,
    summary_cap_bytes: usize,
    updates: &[(usize, usize, usize, &'a [u8])],
) {
    if updates.is_empty() {
        return;
    }
    let docs_per_block = index.docs_per_block.max(1);
    let mut max_needed_blocks = index.keys_per_block.len();
    let mut keys_by_block = BTreeMap::<usize, Vec<(usize, usize)>>::new();
    let mut max_block_by_bucket = BTreeMap::<(usize, usize), usize>::new();
    let mut aggregated = BTreeMap::<(usize, (usize, usize)), Vec<u8>>::new();

    for (pos, filter_bytes, bloom_hashes, bloom_bytes) in updates {
        let block_idx = *pos / docs_per_block;
        max_needed_blocks = max_needed_blocks.max(block_idx + 1);
        let filter_key = (*filter_bytes, *bloom_hashes);
        let bucket_key = tier2_superblock_bucket_key(*filter_bytes, *bloom_hashes);
        let summary_bytes = tier2_superblock_summary_bytes(bucket_key.0, summary_cap_bytes).max(1);
        keys_by_block.entry(block_idx).or_default().push(filter_key);
        max_block_by_bucket
            .entry(bucket_key)
            .and_modify(|value| *value = (*value).max(block_idx))
            .or_insert(block_idx);
        let folded = aggregated
            .entry((block_idx, filter_key))
            .or_insert_with(|| vec![0u8; summary_bytes]);
        merge_sampled_bloom_words_into_summary(folded, bloom_bytes, *filter_bytes);
    }

    if index.keys_per_block.len() < max_needed_blocks {
        index
            .keys_per_block
            .resize_with(max_needed_blocks, Vec::new);
    }

    for (bucket_key, max_block_idx) in max_block_by_bucket {
        let summary_bytes = tier2_superblock_summary_bytes(bucket_key.0, summary_cap_bytes);
        index
            .summary_bytes_by_bucket
            .insert(bucket_key, summary_bytes);
        let blocks = index
            .masks_by_bucket
            .entry(bucket_key)
            .or_insert_with(Vec::new);
        while blocks.len() <= max_block_idx {
            blocks.push(vec![0u8; summary_bytes]);
            index.summary_memory_bytes = index
                .summary_memory_bytes
                .saturating_add(summary_bytes as u64);
        }
    }

    for (block_idx, mut filter_keys) in keys_by_block {
        filter_keys.sort_unstable();
        filter_keys.dedup();
        let keys = &mut index.keys_per_block[block_idx];
        let before_len = keys.len();
        for filter_key in filter_keys {
            let bucket_key = tier2_superblock_bucket_key(filter_key.0, filter_key.1);
            index.bucket_for_key.insert(filter_key, bucket_key);
            if !keys.contains(&filter_key) {
                keys.push(filter_key);
            }
        }
        if keys.len() != before_len {
            keys.sort_unstable();
        }
    }

    for ((block_idx, filter_key), folded) in aggregated {
        let bucket_key = tier2_superblock_bucket_key(filter_key.0, filter_key.1);
        if let Some(blocks) = index.masks_by_bucket.get_mut(&bucket_key) {
            if let Some(block) = blocks.get_mut(block_idx) {
                for (dst, src) in block.iter_mut().zip(folded.iter()) {
                    *dst |= *src;
                }
            }
        }
    }
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
    let bucket_key = tier2_superblock_bucket_key(filter_bytes, bloom_hashes);
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
    let bucket_key = tier2_superblock_bucket_key(filter_bytes, bloom_hashes);
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
    meta: StoreMeta,
    docs: Vec<CandidateDoc>,
    doc_rows: Vec<DocMetaRow>,
    tier2_doc_rows: Vec<Tier2DocMetaRow>,
    sidecars: StoreSidecars,
    append_writers: StoreAppendWriters,
    sha_to_pos: HashMap<String, usize>,
    mutation_counter: u64,
    compaction_generation: u64,
    retired_generation_roots: Vec<String>,
    last_write_activity_monotonic: Option<Instant>,
    tree_tier1_gates: TreeBloomGateIndex,
    tree_tier2_gates: TreeBloomGateIndex,
    tier2_superblocks: Tier2SuperblockIndex,
    tier2_pattern_superblocks: Tier2SuperblockIndex,
    tier2_telemetry: Tier2Telemetry,
    prepared_query_cache: BoundedCache<String, Arc<PreparedQueryArtifacts>>,
    memory_budget_bytes: u64,
    total_shards: usize,
    tier2_superblock_memory_budget_divisor: u64,
    tier2_superblock_memory_budget_bytes: u64,
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
    score: u32,
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

    fn from_prefetched_tier1(doc: &'a CandidateDoc, tier1_bloom_bytes: Cow<'a, [u8]>) -> Self {
        let mut profile = CandidateQueryProfile::default();
        profile.tier1_bloom_loads = 1;
        profile.tier1_bloom_bytes = tier1_bloom_bytes.len() as u64;
        Self {
            doc,
            metadata_bytes: None,
            tier1_bloom_bytes: Some(tier1_bloom_bytes),
            tier2_bloom_bytes: None,
            profile,
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
    matched_hits: &mut Vec<(String, u32)>,
    max_candidates: usize,
    cursor: usize,
    chunk_size: usize,
) -> (Vec<String>, Vec<u32>, usize, usize, usize, Option<usize>) {
    matched_hits.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    if matched_hits.len() > max_candidates {
        matched_hits.truncate(max_candidates);
    }

    let total = matched_hits.len();
    let start = cursor.min(total);
    let size = chunk_size.max(1);
    let end = (start + size).min(total);
    let page = matched_hits[start..end]
        .iter()
        .map(|(sha256, _)| sha256.clone())
        .collect::<Vec<_>>();
    let page_scores = matched_hits[start..end]
        .iter()
        .map(|(_, score)| *score)
        .collect::<Vec<_>>();
    let next_cursor = if end < total { Some(end) } else { None };

    (page, page_scores, total, start, end, next_cursor)
}

fn tier2_superblock_memory_budget_bytes(
    memory_budget_bytes: u64,
    total_shards: usize,
    budget_divisor: u64,
) -> u64 {
    if memory_budget_bytes == 0 || total_shards == 0 {
        return 0;
    }
    let aggregate_budget = memory_budget_bytes / budget_divisor.max(1);
    let per_shard_budget = aggregate_budget / total_shards as u64;
    per_shard_budget.max(MIN_TIER2_SUPERBLOCK_MEMORY_BUDGET_BYTES)
}

fn scaled_docs_per_block_for_budget(
    current_docs_per_block: usize,
    summary_memory_bytes: u64,
    budget_bytes: u64,
) -> usize {
    let current_docs_per_block = current_docs_per_block.max(1);
    if budget_bytes == 0 || summary_memory_bytes <= budget_bytes {
        return current_docs_per_block;
    }
    let required_scale = summary_memory_bytes.div_ceil(budget_bytes);
    let scale = required_scale.next_power_of_two();
    current_docs_per_block.saturating_mul(usize::try_from(scale).unwrap_or(usize::MAX))
}

impl CandidateStore {
    pub fn init(config: CandidateConfig, force: bool) -> Result<Self> {
        validate_config(&config)?;
        fs::create_dir_all(&config.root)?;
        let compaction_manifest_path = shard_compaction_manifest_path(&config.root);
        let meta_path = meta_path(&config.root);
        let sha_path = sha_by_docid_path(&config.root);
        let doc_meta_path = doc_meta_path(&config.root);
        let tier2_doc_meta_path = tier2_doc_meta_path(&config.root);
        let doc_metadata_path = doc_metadata_path(&config.root);
        let blooms_path = blooms_path(&config.root);
        let tier2_blooms_path = tier2_blooms_path(&config.root);
        let external_ids_path = external_ids_path(&config.root);
        if !force
            && (meta_path.exists()
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
            let _ = fs::remove_file(&sha_path);
            let _ = fs::remove_file(&doc_meta_path);
            let _ = fs::remove_file(&tier2_doc_meta_path);
            let _ = fs::remove_file(&doc_metadata_path);
            let _ = fs::remove_file(&blooms_path);
            let _ = fs::remove_file(&tier2_blooms_path);
            let _ = fs::remove_file(&external_ids_path);
            let _ = fs::remove_file(&tier2_superblocks_path(&config.root));
            let _ = fs::remove_file(&tree_tier1_gates_path(&config.root));
            let _ = fs::remove_file(&tree_tier2_gates_path(&config.root));
        }

        let mut store = Self {
            root: config.root.clone(),
            meta: StoreMeta {
                version: STORE_VERSION,
                next_doc_id: 1,
                id_source: config.id_source.clone(),
                store_path: config.store_path,
                tier2_gram_size: config.tier2_gram_size,
                tier1_gram_size: config.tier1_gram_size,
                tier2_superblock_summary_cap_bytes: config
                    .tier2_superblock_summary_cap_bytes
                    .max(1),
                filter_target_fp: config.filter_target_fp,
                compaction_idle_cooldown_s: config.compaction_idle_cooldown_s.max(0.0),
            },
            docs: Vec::new(),
            doc_rows: Vec::new(),
            tier2_doc_rows: Vec::new(),
            sidecars: StoreSidecars::new(&config.root),
            append_writers: StoreAppendWriters::new(&config.root)?,
            sha_to_pos: HashMap::new(),
            mutation_counter: 0,
            compaction_generation: 1,
            retired_generation_roots: Vec::new(),
            last_write_activity_monotonic: None,
            tree_tier1_gates: TreeBloomGateIndex::default(),
            tree_tier2_gates: TreeBloomGateIndex::default(),
            tier2_superblocks: Tier2SuperblockIndex::default(),
            tier2_pattern_superblocks: Tier2SuperblockIndex::default(),
            tier2_telemetry: Tier2Telemetry::default(),
            prepared_query_cache: BoundedCache::new(PREPARED_QUERY_CACHE_CAPACITY),
            memory_budget_bytes: 0,
            total_shards: 1,
            tier2_superblock_memory_budget_divisor: DEFAULT_TIER2_SUPERBLOCK_MEMORY_BUDGET_DIVISOR,
            tier2_superblock_memory_budget_bytes: 0,
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
        let meta: StoreMeta =
            serde_json::from_slice(&fs::read(meta_path(&root))?).map_err(|_| {
                SspryError::from(format!("Invalid candidate metadata at {}", root.display()))
            })?;
        let meta_ms = meta_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        if meta.version != STORE_VERSION {
            return Err(SspryError::from(format!(
                "Unsupported candidate store version: {}",
                meta.version
            )));
        }
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
            docs,
            doc_rows,
            tier2_doc_rows,
            sidecars: StoreSidecars::map_existing(root.as_path())?,
            append_writers: StoreAppendWriters::new(root.as_path())?,
            sha_to_pos: HashMap::new(),
            mutation_counter: 0,
            compaction_generation: compaction_manifest.current_generation,
            retired_generation_roots: compaction_manifest.retired_roots,
            last_write_activity_monotonic: None,
            tree_tier1_gates: TreeBloomGateIndex::default(),
            tree_tier2_gates: TreeBloomGateIndex::default(),
            tier2_superblocks: Tier2SuperblockIndex::default(),
            tier2_pattern_superblocks: Tier2SuperblockIndex::default(),
            tier2_telemetry: Tier2Telemetry::default(),
            prepared_query_cache: BoundedCache::new(PREPARED_QUERY_CACHE_CAPACITY),
            memory_budget_bytes: 0,
            total_shards: 1,
            tier2_superblock_memory_budget_divisor: DEFAULT_TIER2_SUPERBLOCK_MEMORY_BUDGET_DIVISOR,
            tier2_superblock_memory_budget_bytes: 0,
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
        if store.meta.next_doc_id != normalized_next_doc_id {
            store.meta.next_doc_id = normalized_next_doc_id;
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
            load_tier2_superblocks_ms: rebuild_profile.load_tier2_superblocks_ms,
            rebuild_tier2_superblocks_ms: rebuild_profile.tier2_superblocks_ms,
            loaded_tier2_superblocks_from_snapshot: rebuild_profile
                .loaded_tier2_superblocks_from_snapshot,
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
        tier2_superblock_memory_budget_divisor: u64,
    ) -> Result<()> {
        self.memory_budget_bytes = memory_budget_bytes;
        self.total_shards = total_shards.max(1);
        self.tier2_superblock_memory_budget_divisor = tier2_superblock_memory_budget_divisor.max(1);
        self.tier2_superblock_memory_budget_bytes = tier2_superblock_memory_budget_bytes(
            memory_budget_bytes,
            self.total_shards,
            self.tier2_superblock_memory_budget_divisor,
        );
        self.maybe_rebalance_tier2_superblocks()
    }

    pub fn config(&self) -> CandidateConfig {
        CandidateConfig {
            root: self.root.clone(),
            id_source: self.meta.id_source.clone(),
            store_path: self.meta.store_path,
            tier2_gram_size: self.meta.tier2_gram_size,
            tier1_gram_size: self.meta.tier1_gram_size,
            tier2_superblock_summary_cap_bytes: self.meta.tier2_superblock_summary_cap_bytes,
            filter_target_fp: self.meta.filter_target_fp,
            compaction_idle_cooldown_s: self.meta.compaction_idle_cooldown_s,
        }
    }

    pub fn retarget_root(&mut self, root: impl AsRef<Path>) {
        let root = root.as_ref();
        self.root = root.to_path_buf();
        self.sidecars.retarget_root(root);
        self.append_writers.retarget_root(root);
    }

    fn mark_write_activity(&mut self) {
        self.mutation_counter = self.mutation_counter.saturating_add(1);
        self.last_write_activity_monotonic = Some(Instant::now());
        self.prepared_query_cache.clear();
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
        if let Err(err) = reopened.apply_runtime_limits(
            self.memory_budget_bytes,
            self.total_shards,
            self.tier2_superblock_memory_budget_divisor,
        ) {
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

    fn resolve_filter_bytes_for_file_size(
        &self,
        file_size: u64,
        bloom_item_estimate: Option<usize>,
    ) -> Result<usize> {
        choose_filter_bytes_for_file_size(
            file_size,
            DEFAULT_FILTER_BYTES,
            Some(DEFAULT_FILTER_MIN_BYTES),
            Some(DEFAULT_FILTER_MAX_BYTES),
            self.meta.filter_target_fp,
            bloom_item_estimate,
        )
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
        external_id: Option<String>,
    ) -> Result<CandidateInsertResult> {
        let mut total_scope = scope("candidate.insert_document");
        total_scope.add_bytes(file_size);
        if filter_bytes == 0 {
            return Err(SspryError::from("filter_bytes must be > 0"));
        }
        let expected_filter_bytes =
            self.resolve_filter_bytes_for_file_size(file_size, bloom_item_estimate)?;
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
            self.resolve_filter_bytes_for_file_size(file_size, tier2_bloom_item_estimate)?;
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
                existing.deleted = false;
                existing.clone()
            };
            let row = self.build_doc_row(
                snapshot.file_size,
                snapshot.filter_bytes,
                snapshot.bloom_hashes,
                snapshot.deleted,
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
            self.update_tree_tier1_gates_for_doc_bytes_inner(existing_pos, bloom_filter)?;
            self.update_tree_tier2_gates_for_doc_bytes_inner(existing_pos, tier2_bloom_filter)?;
            self.update_tier2_superblocks_for_doc_bytes_inner(existing_pos, bloom_filter)?;
            self.update_tier2_pattern_superblocks_for_doc_bytes_inner(
                existing_pos,
                tier2_bloom_filter,
            )?;
            self.maybe_rebalance_tier2_superblocks()?;
        } else {
            doc_id = self.meta.next_doc_id;
            self.meta.next_doc_id += 1;
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
                deleted: false,
            };
            {
                let _scope = scope("candidate.insert_document.persist");
                let row = self.build_doc_row(
                    doc.file_size,
                    doc.filter_bytes,
                    doc.bloom_hashes,
                    doc.deleted,
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
            self.sha_to_pos
                .insert(sha256_hex.clone(), self.docs.len() - 1);
            self.update_tree_tier1_gates_for_doc_bytes_inner(self.docs.len() - 1, bloom_filter)?;
            self.update_tree_tier2_gates_for_doc_bytes_inner(
                self.docs.len() - 1,
                tier2_bloom_filter,
            )?;
            self.update_tier2_superblocks_for_doc_bytes_inner(self.docs.len() - 1, bloom_filter)?;
            self.update_tier2_pattern_superblocks_for_doc_bytes_inner(
                self.docs.len() - 1,
                tier2_bloom_filter,
            )?;
            self.maybe_rebalance_tier2_superblocks()?;
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
                external_id,
            ) = document;
            total_scope.add_bytes(*file_size);
            if *filter_bytes == 0 {
                return Err(SspryError::from("filter_bytes must be > 0"));
            }
            let expected_filter_bytes =
                self.resolve_filter_bytes_for_file_size(*file_size, *bloom_item_estimate)?;
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
            let expected_tier2_filter_bytes =
                self.resolve_filter_bytes_for_file_size(*file_size, *tier2_bloom_item_estimate)?;
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
                    existing.deleted = false;
                    existing.clone()
                };
                let row = self.build_doc_row(
                    snapshot.file_size,
                    snapshot.filter_bytes,
                    snapshot.bloom_hashes,
                    snapshot.deleted,
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
                tier2_updates.push((
                    existing_pos,
                    *filter_bytes,
                    expected_bloom_hashes,
                    bloom_filter,
                ));
                if !tier2_bloom_filter.is_empty() {
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
            let doc_id = self.meta.next_doc_id;
            self.meta.next_doc_id += 1;
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
                insert_profile.install_docs_us = insert_profile
                    .install_docs_us
                    .saturating_add(elapsed_us(install_docs_started));
                tier2_updates.push((
                    pos,
                    pending.doc.filter_bytes,
                    pending.doc.bloom_hashes,
                    pending.bloom_filter,
                ));
                if !pending.tier2_bloom_filter.is_empty() {
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
            self.update_tier2_superblocks_for_doc_bytes_batch(&tier2_updates)?;
            self.update_tier2_pattern_superblocks_for_doc_bytes_batch(&tier2_pattern_updates)?;
            insert_profile.tier2_update_us = insert_profile
                .tier2_update_us
                .saturating_add(elapsed_us(tier2_update_started));
            if meta_dirty {
                self.mark_meta_dirty();
            }
            let rebalance_tier2_started = Instant::now();
            self.maybe_rebalance_tier2_superblocks()?;
            insert_profile.rebalance_tier2_us = insert_profile
                .rebalance_tier2_us
                .saturating_add(elapsed_us(rebalance_tier2_started));
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
            self.rebuild_tier2_superblocks()?;
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
                        existing.deleted = false;
                        existing.clone()
                    };
                    let row = self.build_doc_row(
                        snapshot.file_size,
                        snapshot.filter_bytes,
                        snapshot.bloom_hashes,
                        snapshot.deleted,
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
                    self.update_tier2_superblocks_for_doc_bytes_inner(
                        existing_pos,
                        &document.bloom_filter,
                    )?;
                    self.update_tier2_pattern_superblocks_for_doc_bytes_inner(
                        existing_pos,
                        &document.tier2_bloom_filter,
                    )?;
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

            let doc_id = self.meta.next_doc_id;
            self.meta.next_doc_id += 1;
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
                    flags: 0,
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
                tier2_updates.push((pos, filter_bytes, bloom_hashes, bloom_filter));
                if !tier2_bloom_filter.is_empty() {
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
            self.update_tier2_superblocks_for_doc_bytes_batch(&tier2_updates)?;
            self.update_tier2_pattern_superblocks_for_doc_bytes_batch(&tier2_pattern_updates)?;
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
            let rebalance_tier2_started = Instant::now();
            self.maybe_rebalance_tier2_superblocks()?;
            import_profile.rebalance_tier2_ms = rebalance_tier2_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
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
                scores: Vec::new(),
                total_candidates: 0,
                returned_count: 0,
                cursor: 0,
                next_cursor: None,
                tier_used: "none".to_owned(),
                query_profile: CandidateQueryProfile::default(),
            });
        }
        let (mut matched_hits, used_tiers, query_profile) = self.scan_query_hits(plan, prepared)?;
        let (page, page_scores, total, start, end, next_cursor) =
            paginate_query_hits(&mut matched_hits, plan.max_candidates, cursor, chunk_size);
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
            "candidate.query_candidates_superblocks_skipped_total",
            query_profile.superblocks_skipped,
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
        self.record_query_metrics(
            query_profile.docs_scanned,
            matched_hits.len() as u64,
            query_profile.superblocks_skipped,
        );

        Ok(CandidateQueryResult {
            sha256: page,
            scores: page_scores,
            total_candidates: total,
            returned_count: end.saturating_sub(start),
            cursor: start,
            next_cursor,
            tier_used: used_tiers.as_label(),
            query_profile,
        })
    }

    fn scan_query_hits(
        &self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
    ) -> Result<(Vec<(String, u32)>, TierFlags, CandidateQueryProfile)> {
        let allow_block_skip = !plan.force_tier1_only && plan.allow_tier2_fallback;
        if !tree_maybe_matches_node(
            &plan.root,
            &prepared.mask_cache,
            &self.tree_tier1_gates,
            &self.tree_tier2_gates,
            allow_block_skip,
        )? {
            return Ok((
                Vec::new(),
                TierFlags::default(),
                CandidateQueryProfile::default(),
            ));
        }
        let docs_per_block = self.tier2_superblocks.docs_per_block.max(1);
        let block_count = self.tier2_superblocks.keys_per_block.len();
        if block_count == 0 {
            return Ok((
                Vec::new(),
                TierFlags::default(),
                CandidateQueryProfile::default(),
            ));
        }
        let prefetch_tier1_by_block = query_node_uses_pattern_blooms(&plan.root);
        let query_now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let worker_count = query_scan_worker_count(block_count);

        if worker_count <= 1 {
            return self.scan_query_hits_worker(
                plan,
                prepared,
                docs_per_block,
                block_count,
                allow_block_skip,
                prefetch_tier1_by_block,
                query_now_unix,
                None,
            );
        }

        let next_block = AtomicUsize::new(0);
        let partials = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let next_block = &next_block;
                handles.push(scope.spawn(move || {
                    self.scan_query_hits_worker(
                        plan,
                        prepared,
                        docs_per_block,
                        block_count,
                        allow_block_skip,
                        prefetch_tier1_by_block,
                        query_now_unix,
                        Some(next_block),
                    )
                }));
            }

            let mut merged = Vec::with_capacity(handles.len());
            for handle in handles {
                let partial = handle
                    .join()
                    .map_err(|_| SspryError::from("Candidate query worker panicked."))??;
                merged.push(partial);
            }
            Ok::<Vec<(Vec<(String, u32)>, TierFlags, CandidateQueryProfile)>, SspryError>(merged)
        })?;

        let mut matched_hits = Vec::<(String, u32)>::new();
        let mut used_tiers = TierFlags::default();
        let mut query_profile = CandidateQueryProfile::default();
        for (hits, tiers, profile) in partials {
            matched_hits.extend(hits);
            used_tiers.merge(tiers);
            query_profile.merge_from(&profile);
        }

        Ok((matched_hits, used_tiers, query_profile))
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_query_hits_worker(
        &self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
        docs_per_block: usize,
        block_count: usize,
        allow_block_skip: bool,
        prefetch_tier1_by_block: bool,
        query_now_unix: u64,
        next_block: Option<&AtomicUsize>,
    ) -> Result<(Vec<(String, u32)>, TierFlags, CandidateQueryProfile)> {
        let mut matched_hits = Vec::<(String, u32)>::new();
        let mut used_tiers = TierFlags::default();
        let mut query_profile = CandidateQueryProfile::default();

        let mut next_sequential_block = 0usize;
        loop {
            let block_idx = if let Some(next_block) = next_block {
                let idx = next_block.fetch_add(1, Ordering::Relaxed);
                if idx >= block_count {
                    break;
                }
                idx
            } else {
                if next_sequential_block >= block_count {
                    break;
                }
                let idx = next_sequential_block;
                next_sequential_block += 1;
                idx
            };
            if allow_block_skip
                && !block_maybe_matches_node(
                    block_idx,
                    &plan.root,
                    &prepared.mask_cache,
                    &self.tier2_superblocks,
                    &self.tier2_pattern_superblocks,
                    true,
                )?
            {
                query_profile.superblocks_skipped =
                    query_profile.superblocks_skipped.saturating_add(1);
                continue;
            }
            let start = block_idx * docs_per_block;
            let end = (start + docs_per_block).min(self.docs.len());
            let mut prefetched_tier1 = if prefetch_tier1_by_block {
                self.prefetch_block_tier1_blooms(start, end)?
            } else {
                Vec::new()
            };
            for pos in start..end {
                let doc = &self.docs[pos];
                if doc.deleted {
                    continue;
                }
                query_profile.docs_scanned = query_profile.docs_scanned.saturating_add(1);
                let mut doc_inputs = if prefetch_tier1_by_block {
                    let prefetched = prefetched_tier1
                        .get_mut(pos - start)
                        .and_then(Option::take)
                        .unwrap_or_else(|| Cow::Borrowed(&[]));
                    LazyDocQueryInputs::from_prefetched_tier1(doc, prefetched)
                } else {
                    LazyDocQueryInputs::new(doc)
                };
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
                    matched_hits.push((doc.sha256.clone(), outcome.score));
                    used_tiers.merge(outcome.tiers);
                }
                query_profile.merge_from(&doc_inputs.into_profile());
            }
        }

        Ok((matched_hits, used_tiers, query_profile))
    }

    pub fn stats(&self) -> CandidateStats {
        let doc_count = self.docs.iter().filter(|doc| !doc.deleted).count();
        let deleted_doc_count = self.docs.iter().filter(|doc| doc.deleted).count();
        let cooldown_remaining = self.compaction_cooldown_remaining_s();
        let tier2_match_ratio = if self.tier2_telemetry.tier2_scanned_docs_total > 0 {
            self.tier2_telemetry.tier2_docs_matched_total as f64
                / self.tier2_telemetry.tier2_scanned_docs_total as f64
        } else {
            0.0
        };
        CandidateStats {
            doc_count,
            deleted_doc_count,
            id_source: self.meta.id_source.clone(),
            store_path: self.meta.store_path,
            filter_target_fp: self.meta.filter_target_fp,
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
            tier2_superblocks_skipped_total: self.tier2_telemetry.tier2_superblocks_skipped_total,
            tier2_match_ratio,
            tier2_superblock_count: self.tier2_superblocks.keys_per_block.len(),
            tier2_superblock_docs: self.tier2_superblocks.docs_per_block,
            tier2_superblock_summary_bytes: self
                .tier2_superblocks
                .summary_memory_bytes
                .saturating_add(self.tier2_pattern_superblocks.summary_memory_bytes),
            tier2_superblock_memory_budget_bytes: self.tier2_superblock_memory_budget_bytes,
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

    pub(crate) fn tier1_superblock_filter_keys(&self) -> Vec<(usize, usize)> {
        self.tier2_superblocks
            .bucket_for_key
            .keys()
            .copied()
            .collect::<Vec<_>>()
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

    fn prefetch_block_tier1_blooms<'a>(
        &'a self,
        start: usize,
        end: usize,
    ) -> Result<Vec<Option<Cow<'a, [u8]>>>> {
        let mut total_len = 0usize;
        let mut span_start = u64::MAX;
        let mut span_end = 0u64;
        let mut has_live = false;
        for pos in start..end {
            if self.docs[pos].deleted {
                continue;
            }
            let row = self.doc_rows[pos];
            if row.bloom_len == 0 {
                continue;
            }
            has_live = true;
            total_len = total_len.saturating_add(row.bloom_len as usize);
            span_start = span_start.min(row.bloom_offset);
            span_end = span_end.max(row.bloom_offset.saturating_add(row.bloom_len as u64));
        }
        if has_live && span_start < span_end {
            let span_len = span_end.saturating_sub(span_start) as usize;
            let dense_enough = span_len <= total_len.saturating_mul(2).saturating_add(64 * 1024);
            if dense_enough {
                if let Some(span) = self
                    .sidecars
                    .blooms
                    .mmap_slice(span_start, span_len, "bloom")?
                {
                    let mut out = Vec::with_capacity(end.saturating_sub(start));
                    for pos in start..end {
                        if self.docs[pos].deleted {
                            out.push(None);
                            continue;
                        }
                        let row = self.doc_rows[pos];
                        let rel_start = row.bloom_offset.saturating_sub(span_start) as usize;
                        let rel_end = rel_start.saturating_add(row.bloom_len as usize);
                        out.push(Some(Cow::Borrowed(&span[rel_start..rel_end])));
                    }
                    return Ok(out);
                }
            }
        }
        let mut out = Vec::with_capacity(end.saturating_sub(start));
        for pos in start..end {
            if self.docs[pos].deleted {
                out.push(None);
            } else {
                out.push(Some(self.doc_bloom_bytes(pos)?));
            }
        }
        Ok(out)
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
        write_json(meta_path(&self.root), &self.meta)?;
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
                flags: u8::from(deleted) * DOC_FLAG_DELETED,
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
            flags: u8::from(deleted) * DOC_FLAG_DELETED,
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

    fn tier2_superblock_summary_bytes(&self, filter_bytes: usize) -> usize {
        tier2_superblock_summary_bytes(filter_bytes, self.meta.tier2_superblock_summary_cap_bytes)
    }

    fn update_tree_tier1_gates_for_doc_bytes_inner(
        &mut self,
        pos: usize,
        bloom_bytes: &[u8],
    ) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted {
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
        update_tree_gate_for_doc_bytes_batch(&mut self.tree_tier1_gates, updates);
        Ok(())
    }

    fn update_tree_tier2_gates_for_doc_bytes_inner(
        &mut self,
        pos: usize,
        bloom_bytes: &[u8],
    ) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted {
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
        update_tree_gate_for_doc_bytes_batch(&mut self.tree_tier2_gates, updates);
        Ok(())
    }

    fn update_tier2_superblocks_for_doc_bytes_inner(
        &mut self,
        pos: usize,
        bloom_bytes: &[u8],
    ) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted {
            return Ok(());
        }
        let filter_bytes = self.docs[pos].filter_bytes;
        let bloom_hashes = self.docs[pos].bloom_hashes;
        let docs_per_block = self.tier2_superblocks.docs_per_block;
        update_superblocks_for_doc_bytes_inner(
            &mut self.tier2_superblocks,
            self.meta.tier2_superblock_summary_cap_bytes,
            docs_per_block,
            pos,
            filter_bytes,
            bloom_hashes,
            bloom_bytes,
        );
        Ok(())
    }

    fn update_tier2_superblocks_for_doc_bytes_batch(
        &mut self,
        updates: &[(usize, usize, usize, &[u8])],
    ) -> Result<()> {
        update_superblocks_for_doc_bytes_batch(
            &mut self.tier2_superblocks,
            self.meta.tier2_superblock_summary_cap_bytes,
            updates,
        );
        Ok(())
    }

    fn update_tier2_pattern_superblocks_for_doc_bytes_inner(
        &mut self,
        pos: usize,
        bloom_bytes: &[u8],
    ) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted {
            return Ok(());
        }
        let filter_bytes = self.docs[pos].tier2_filter_bytes;
        let bloom_hashes = self.docs[pos].tier2_bloom_hashes;
        if filter_bytes == 0 || bloom_hashes == 0 || bloom_bytes.is_empty() {
            return Ok(());
        }
        let docs_per_block = self.tier2_pattern_superblocks.docs_per_block;
        update_superblocks_for_doc_bytes_inner(
            &mut self.tier2_pattern_superblocks,
            self.meta.tier2_superblock_summary_cap_bytes,
            docs_per_block,
            pos,
            filter_bytes,
            bloom_hashes,
            bloom_bytes,
        );
        Ok(())
    }

    fn update_tier2_pattern_superblocks_for_doc_bytes_batch(
        &mut self,
        updates: &[(usize, usize, usize, &[u8])],
    ) -> Result<()> {
        update_superblocks_for_doc_bytes_batch(
            &mut self.tier2_pattern_superblocks,
            self.meta.tier2_superblock_summary_cap_bytes,
            updates,
        );
        Ok(())
    }

    fn update_tier2_superblocks_for_doc_inner(&mut self, pos: usize) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted {
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
        self.update_tier2_superblocks_for_doc_bytes_inner(pos, &owned_bloom_bytes)
    }

    fn update_tier2_pattern_superblocks_for_doc_inner(&mut self, pos: usize) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted {
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
        self.update_tier2_pattern_superblocks_for_doc_bytes_inner(pos, &owned_bloom_bytes)
    }

    fn update_tree_tier1_gates_for_doc_inner(&mut self, pos: usize) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted {
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
        if pos >= self.docs.len() || self.docs[pos].deleted {
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
        for pos in 0..self.docs.len() {
            self.update_tree_tier1_gates_for_doc_inner(pos)?;
            self.update_tree_tier2_gates_for_doc_inner(pos)?;
        }
        Ok(())
    }

    fn rebuild_tier2_superblocks_with_docs_per_block(
        &mut self,
        docs_per_block: usize,
    ) -> Result<()> {
        self.tier2_superblocks = Tier2SuperblockIndex {
            docs_per_block: docs_per_block.max(1),
            ..Tier2SuperblockIndex::default()
        };
        self.tier2_pattern_superblocks = Tier2SuperblockIndex {
            docs_per_block: docs_per_block.max(1),
            ..Tier2SuperblockIndex::default()
        };
        for pos in 0..self.docs.len() {
            self.update_tier2_superblocks_for_doc_inner(pos)?;
            self.update_tier2_pattern_superblocks_for_doc_inner(pos)?;
        }
        Ok(())
    }

    fn maybe_rebalance_tier2_superblocks(&mut self) -> Result<()> {
        let budget_bytes = self.tier2_superblock_memory_budget_bytes;
        let current_bytes = self
            .tier2_superblocks
            .summary_memory_bytes
            .saturating_add(self.tier2_pattern_superblocks.summary_memory_bytes);
        if budget_bytes == 0 || current_bytes <= budget_bytes {
            return Ok(());
        }
        let target_docs_per_block = scaled_docs_per_block_for_budget(
            self.tier2_superblocks.docs_per_block,
            current_bytes,
            budget_bytes,
        );
        if target_docs_per_block <= self.tier2_superblocks.docs_per_block {
            return Ok(());
        }
        self.rebuild_tier2_superblocks_with_docs_per_block(target_docs_per_block)
    }

    fn rebuild_tier2_superblocks(&mut self) -> Result<()> {
        self.rebuild_tier2_superblocks_with_docs_per_block(self.tier2_superblocks.docs_per_block)
    }

    fn record_query_metrics(
        &mut self,
        tier2_scanned_docs: u64,
        tier2_docs_matched: u64,
        tier2_superblocks_skipped: u64,
    ) {
        self.tier2_telemetry.query_count = self.tier2_telemetry.query_count.saturating_add(1);
        self.tier2_telemetry.tier2_scanned_docs_total = self
            .tier2_telemetry
            .tier2_scanned_docs_total
            .saturating_add(tier2_scanned_docs);
        self.tier2_telemetry.tier2_docs_matched_total = self
            .tier2_telemetry
            .tier2_docs_matched_total
            .saturating_add(tier2_docs_matched);
        self.tier2_telemetry.tier2_superblocks_skipped_total = self
            .tier2_telemetry
            .tier2_superblocks_skipped_total
            .saturating_add(tier2_superblocks_skipped);
    }

    fn rebuild_indexes_profiled(&mut self) -> Result<CandidateStoreRebuildProfile> {
        let started_total = Instant::now();
        self.sha_to_pos.clear();
        let sha_started = Instant::now();
        for (index, doc) in self.docs.iter_mut().enumerate() {
            if doc.bloom_hashes == 0 {
                doc.bloom_hashes = DEFAULT_BLOOM_HASHES;
                if let Some(row) = self.doc_rows.get_mut(index) {
                    row.bloom_hashes = DEFAULT_BLOOM_HASHES.min(u8::MAX as usize) as u8;
                }
            }
            self.sha_to_pos.insert(doc.sha256.clone(), index);
        }
        let sha_index_ms = sha_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let load_tier2_started = Instant::now();
        let expected_active_doc_count = self.docs.iter().filter(|doc| !doc.deleted).count();
        let maybe_tree_tier1_snapshot = self
            .load_tree_gate_snapshot(
                &tree_tier1_gates_path(&self.root),
                self.docs.len(),
                expected_active_doc_count,
            )
            .ok()
            .flatten();
        let maybe_tree_tier2_snapshot = self
            .load_tree_gate_snapshot(
                &tree_tier2_gates_path(&self.root),
                self.docs.len(),
                expected_active_doc_count,
            )
            .ok()
            .flatten();
        if let (Some(tree_tier1_snapshot), Some(tree_tier2_snapshot)) =
            (maybe_tree_tier1_snapshot, maybe_tree_tier2_snapshot)
        {
            self.tree_tier1_gates = tree_tier1_snapshot;
            self.tree_tier2_gates = tree_tier2_snapshot;
        } else {
            self.rebuild_tree_gates()?;
        }
        let maybe_snapshot = self
            .load_tier2_superblocks_snapshot(self.docs.len(), expected_active_doc_count)
            .ok()
            .flatten();
        let load_tier2_superblocks_ms = load_tier2_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let (loaded_tier2_superblocks_from_snapshot, tier2_superblocks_ms) =
            if let Some(snapshot) = maybe_snapshot {
                self.tier2_superblocks = snapshot;
                let tier2_started = Instant::now();
                self.tier2_pattern_superblocks = Tier2SuperblockIndex {
                    docs_per_block: self.tier2_superblocks.docs_per_block,
                    ..Tier2SuperblockIndex::default()
                };
                for pos in 0..self.docs.len() {
                    self.update_tier2_pattern_superblocks_for_doc_inner(pos)?;
                }
                let tier2_superblocks_ms = tier2_started
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX);
                (true, tier2_superblocks_ms)
            } else {
                let tier2_started = Instant::now();
                self.rebuild_tier2_superblocks()?;
                let tier2_superblocks_ms = tier2_started
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX);
                (false, tier2_superblocks_ms)
            };
        Ok(CandidateStoreRebuildProfile {
            sha_index_ms,
            load_tier2_superblocks_ms,
            tier2_superblocks_ms,
            loaded_tier2_superblocks_from_snapshot,
            total_ms: started_total
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        })
    }

    pub(crate) fn persist_tier2_superblocks_snapshot(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        let path = tier2_superblocks_path(&self.root);
        let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
        let mut payload = Vec::<u8>::new();
        append_u32(&mut payload, TIER2_SUPERBLOCKS_SNAPSHOT_VERSION);
        append_u64(&mut payload, self.docs.len() as u64);
        append_u64(
            &mut payload,
            self.docs.iter().filter(|doc| !doc.deleted).count() as u64,
        );
        append_u64(&mut payload, self.tier2_superblocks.docs_per_block as u64);
        append_u64(
            &mut payload,
            self.tier2_superblocks.keys_per_block.len() as u64,
        );
        for keys in &self.tier2_superblocks.keys_per_block {
            append_u64(&mut payload, keys.len() as u64);
            for (filter_bytes, bloom_hashes) in keys {
                append_u64(&mut payload, *filter_bytes as u64);
                append_u64(&mut payload, *bloom_hashes as u64);
            }
        }
        append_u64(
            &mut payload,
            self.tier2_superblocks.masks_by_bucket.len() as u64,
        );
        for ((filter_bucket, bloom_hashes), blocks) in &self.tier2_superblocks.masks_by_bucket {
            append_u64(&mut payload, *filter_bucket as u64);
            append_u64(&mut payload, *bloom_hashes as u64);
            let summary_bytes = self
                .tier2_superblocks
                .summary_bytes_by_bucket
                .get(&(*filter_bucket, *bloom_hashes))
                .copied()
                .unwrap_or_else(|| self.tier2_superblock_summary_bytes(*filter_bucket));
            append_u64(&mut payload, summary_bytes as u64);
            append_u64(&mut payload, blocks.len() as u64);
            for block in blocks {
                append_u64(&mut payload, block.len() as u64);
                payload.extend_from_slice(block);
            }
        }
        fs::write(&tmp_path, payload)?;
        fs::rename(tmp_path, path)?;
        Ok(())
    }

    fn load_tier2_superblocks_snapshot(
        &self,
        expected_doc_count: usize,
        expected_active_doc_count: usize,
    ) -> Result<Option<Tier2SuperblockIndex>> {
        let path = tier2_superblocks_path(&self.root);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        let mut cursor = 0usize;
        let version = read_u32(&bytes, &mut cursor)?;
        if version != TIER2_SUPERBLOCKS_SNAPSHOT_VERSION {
            return Ok(None);
        }
        let stored_doc_count = read_u64(&bytes, &mut cursor)? as usize;
        let stored_active_doc_count = read_u64(&bytes, &mut cursor)? as usize;
        if stored_doc_count != expected_doc_count
            || stored_active_doc_count != expected_active_doc_count
        {
            return Ok(None);
        }
        let docs_per_block = read_u64(&bytes, &mut cursor)? as usize;
        let block_count = read_u64(&bytes, &mut cursor)? as usize;
        let mut keys_per_block = Vec::with_capacity(block_count);
        let mut bucket_for_key = BTreeMap::new();
        for _ in 0..block_count {
            let key_count = read_u64(&bytes, &mut cursor)? as usize;
            let mut keys = Vec::with_capacity(key_count);
            for _ in 0..key_count {
                let filter_bytes = read_u64(&bytes, &mut cursor)? as usize;
                let bloom_hashes = read_u64(&bytes, &mut cursor)? as usize;
                keys.push((filter_bytes, bloom_hashes));
                bucket_for_key.insert(
                    (filter_bytes, bloom_hashes),
                    tier2_superblock_bucket_key(filter_bytes, bloom_hashes),
                );
            }
            keys_per_block.push(keys);
        }
        let bucket_count = read_u64(&bytes, &mut cursor)? as usize;
        let mut summary_bytes_by_bucket = BTreeMap::new();
        let mut masks_by_bucket = BTreeMap::new();
        let mut summary_memory_bytes = 0u64;
        for _ in 0..bucket_count {
            let filter_bucket = read_u64(&bytes, &mut cursor)? as usize;
            let bloom_hashes = read_u64(&bytes, &mut cursor)? as usize;
            let summary_bytes = read_u64(&bytes, &mut cursor)? as usize;
            let expected_summary_bytes = self.tier2_superblock_summary_bytes(filter_bucket);
            if summary_bytes != expected_summary_bytes {
                return Ok(None);
            }
            let blocks_len = read_u64(&bytes, &mut cursor)? as usize;
            let mut blocks = Vec::with_capacity(blocks_len);
            for _ in 0..blocks_len {
                let block_len = read_u64(&bytes, &mut cursor)? as usize;
                if block_len != summary_bytes {
                    return Ok(None);
                }
                let end = cursor.saturating_add(block_len);
                if end > bytes.len() {
                    return Ok(None);
                }
                blocks.push(bytes[cursor..end].to_vec());
                cursor = end;
            }
            summary_memory_bytes = summary_memory_bytes
                .saturating_add((summary_bytes as u64).saturating_mul(blocks_len as u64));
            summary_bytes_by_bucket.insert((filter_bucket, bloom_hashes), summary_bytes);
            masks_by_bucket.insert((filter_bucket, bloom_hashes), blocks);
        }
        for keys in &keys_per_block {
            for (filter_bytes, bloom_hashes) in keys {
                let bucket_key = tier2_superblock_bucket_key(*filter_bytes, *bloom_hashes);
                if !masks_by_bucket.contains_key(&bucket_key) {
                    return Ok(None);
                }
            }
        }
        if cursor != bytes.len() {
            return Ok(None);
        }
        Ok(Some(Tier2SuperblockIndex {
            docs_per_block: docs_per_block.max(1),
            keys_per_block,
            bucket_for_key,
            summary_bytes_by_bucket,
            masks_by_bucket,
            summary_memory_bytes,
        }))
    }

    pub(crate) fn persist_tree_gate_snapshots(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        self.persist_tree_gate_snapshot(
            &tree_tier1_gates_path(&self.root),
            &self.tree_tier1_gates,
        )?;
        self.persist_tree_gate_snapshot(
            &tree_tier2_gates_path(&self.root),
            &self.tree_tier2_gates,
        )?;
        Ok(())
    }

    fn persist_tree_gate_snapshot(&self, path: &Path, index: &TreeBloomGateIndex) -> Result<()> {
        let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
        let mut payload = Vec::<u8>::new();
        append_u32(&mut payload, TREE_BLOOM_GATES_SNAPSHOT_VERSION);
        append_u64(&mut payload, self.docs.len() as u64);
        append_u64(
            &mut payload,
            self.docs.iter().filter(|doc| !doc.deleted).count() as u64,
        );
        append_u64(&mut payload, index.bucket_for_key.len() as u64);
        for ((filter_bytes, bloom_hashes), (filter_bucket, bucket_hashes)) in &index.bucket_for_key
        {
            append_u64(&mut payload, *filter_bytes as u64);
            append_u64(&mut payload, *bloom_hashes as u64);
            append_u64(&mut payload, *filter_bucket as u64);
            append_u64(&mut payload, *bucket_hashes as u64);
        }
        append_u64(&mut payload, index.masks_by_bucket.len() as u64);
        for ((filter_bucket, bloom_hashes), mask) in &index.masks_by_bucket {
            append_u64(&mut payload, *filter_bucket as u64);
            append_u64(&mut payload, *bloom_hashes as u64);
            append_u64(&mut payload, mask.len() as u64);
            payload.extend_from_slice(mask);
        }
        fs::write(&tmp_path, payload)?;
        fs::rename(tmp_path, path)?;
        Ok(())
    }

    fn load_tree_gate_snapshot(
        &self,
        path: &Path,
        expected_doc_count: usize,
        expected_active_doc_count: usize,
    ) -> Result<Option<TreeBloomGateIndex>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        let mut cursor = 0usize;
        let version = read_u32(&bytes, &mut cursor)?;
        if version != TREE_BLOOM_GATES_SNAPSHOT_VERSION {
            return Ok(None);
        }
        let stored_doc_count = read_u64(&bytes, &mut cursor)? as usize;
        let stored_active_doc_count = read_u64(&bytes, &mut cursor)? as usize;
        if stored_doc_count != expected_doc_count
            || stored_active_doc_count != expected_active_doc_count
        {
            return Ok(None);
        }
        let key_count = read_u64(&bytes, &mut cursor)? as usize;
        let mut bucket_for_key = BTreeMap::new();
        for _ in 0..key_count {
            let filter_bytes = read_u64(&bytes, &mut cursor)? as usize;
            let bloom_hashes = read_u64(&bytes, &mut cursor)? as usize;
            let filter_bucket = read_u64(&bytes, &mut cursor)? as usize;
            let bucket_hashes = read_u64(&bytes, &mut cursor)? as usize;
            let expected_bucket = tier2_superblock_bucket_key(filter_bytes, bloom_hashes);
            if expected_bucket != (filter_bucket, bucket_hashes) {
                return Ok(None);
            }
            bucket_for_key.insert((filter_bytes, bloom_hashes), expected_bucket);
        }
        let bucket_count = read_u64(&bytes, &mut cursor)? as usize;
        let mut summary_bytes_by_bucket = BTreeMap::new();
        let mut masks_by_bucket = BTreeMap::new();
        let mut summary_memory_bytes = 0u64;
        for _ in 0..bucket_count {
            let filter_bucket = read_u64(&bytes, &mut cursor)? as usize;
            let bloom_hashes = read_u64(&bytes, &mut cursor)? as usize;
            let mask_len = read_u64(&bytes, &mut cursor)? as usize;
            let expected_len = align_filter_bytes(filter_bucket.max(1));
            if mask_len != expected_len {
                return Ok(None);
            }
            let end = cursor.saturating_add(mask_len);
            if end > bytes.len() {
                return Ok(None);
            }
            let bucket_key = (filter_bucket, bloom_hashes);
            masks_by_bucket.insert(bucket_key, bytes[cursor..end].to_vec());
            summary_bytes_by_bucket.insert(bucket_key, mask_len);
            summary_memory_bytes = summary_memory_bytes.saturating_add(mask_len as u64);
            cursor = end;
        }
        for bucket_key in bucket_for_key.values() {
            if !masks_by_bucket.contains_key(bucket_key) {
                return Ok(None);
            }
        }
        if cursor != bytes.len() {
            return Ok(None);
        }
        Ok(Some(TreeBloomGateIndex {
            bucket_for_key,
            summary_bytes_by_bucket,
            masks_by_bucket,
            summary_memory_bytes,
        }))
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
            &self.tier1_superblock_filter_keys(),
            &self.tier2_doc_filter_keys(),
            self.meta.tier2_superblock_summary_cap_bytes,
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

    let mut meta = snapshot.meta.clone();
    meta.next_doc_id = snapshot.live_docs.len() as u64 + 1;
    write_json(meta_path(compacted_root), &meta)?;
    Ok(())
}

fn meta_path(root: &Path) -> PathBuf {
    root.join("meta.json")
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

fn tier2_superblocks_path(root: &Path) -> PathBuf {
    root.join("tier2_superblocks.bin")
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

fn append_u32(payload: &mut Vec<u8>, value: u32) {
    payload.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(payload: &mut Vec<u8>, value: u64) {
    payload.extend_from_slice(&value.to_le_bytes());
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let end = cursor.saturating_add(4);
    if end > bytes.len() {
        return Err(SspryError::from("Invalid tier2 superblocks snapshot"));
    }
    let value = u32::from_le_bytes(bytes[*cursor..end].try_into().expect("u32 slice"));
    *cursor = end;
    Ok(value)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let end = cursor.saturating_add(8);
    if end > bytes.len() {
        return Err(SspryError::from("Invalid tier2 superblocks snapshot"));
    }
    let value = u64::from_le_bytes(bytes[*cursor..end].try_into().expect("u64 slice"));
    *cursor = end;
    Ok(value)
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
    GramSizes::new(config.tier2_gram_size, config.tier1_gram_size)
        .map_err(|err| SspryError::from(format!("invalid gram size pair: {err}")))?;
    if config.tier2_superblock_summary_cap_bytes == 0 {
        return Err(SspryError::from(
            "tier2_superblock_summary_cap_bytes must be > 0",
        ));
    }
    if !config.compaction_idle_cooldown_s.is_finite() || config.compaction_idle_cooldown_s < 0.0 {
        return Err(SspryError::from(
            "compaction_idle_cooldown_s must be finite and >= 0",
        ));
    }
    if let Some(value) = config.filter_target_fp {
        if !(0.0 < value && value < 1.0) {
            return Err(SspryError::from("filter_target_fp must be in range (0, 1)"));
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

type RequiredMasksByKey = BTreeMap<(usize, usize), Vec<(usize, u64)>>;

#[derive(Clone, Debug, Default)]
struct ShiftedRequiredMasks {
    shifts: Vec<RequiredMasksByKey>,
}

impl ShiftedRequiredMasks {
    fn is_empty(&self) -> bool {
        self.shifts.iter().all(BTreeMap::is_empty)
    }
}

#[derive(Clone, Debug, Default)]
struct PreparedPatternMasks {
    tier1: Vec<ShiftedRequiredMasks>,
    tier1_superblocks: Vec<ShiftedRequiredMasks>,
    tier2: Vec<ShiftedRequiredMasks>,
    tier2_superblocks: Vec<ShiftedRequiredMasks>,
}

type PatternMaskCache = HashMap<String, PreparedPatternMasks>;

const MAX_LANE_POSITION_VARIANTS: usize = 64;

fn lane_position_variants_for_pattern(
    values: &[u64],
    fixed_literal: &[u8],
    gram_size: usize,
    lane_count: usize,
) -> Vec<Vec<usize>> {
    let mut positions_per_gram = Vec::<Vec<usize>>::with_capacity(values.len());
    if !fixed_literal.is_empty() && fixed_literal.len() >= gram_size {
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
    } else {
        for gram_idx in 0..values.len() {
            positions_per_gram.push(vec![gram_idx]);
        }
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

fn merge_cached_lane_bloom_word_masks(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
    lanes: &[usize],
    lane_count: usize,
    cache: &mut HashMap<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>,
) -> Result<Vec<(usize, u64)>> {
    let mut merged = BTreeMap::<usize, u64>::new();
    for (gram_idx, value) in values.iter().enumerate() {
        let lane = lanes
            .get(gram_idx)
            .copied()
            .unwrap_or(gram_idx % lane_count.max(1));
        let key = (*value, size_bytes, hash_count, lane, lane_count);
        let cached = if let Some(entry) = cache.get(&key) {
            entry.clone()
        } else {
            let entry =
                bloom_word_masks_in_lane(&[*value], size_bytes, hash_count, lane, lane_count)?;
            cache.insert(key, entry.clone());
            entry
        };
        for (word_idx, mask) in cached {
            *merged.entry(word_idx).or_insert(0) |= mask;
        }
    }
    Ok(merged.into_iter().collect())
}

fn node_structurally_impossible(node: &QueryNode) -> bool {
    match node.kind.as_str() {
        "pattern" => false,
        "verifier_only_eq" => false,
        "filesize_eq" => false,
        "metadata_eq" => false,
        "time_now_eq" => false,
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
        "and" | "or" | "n_of" => node.children.iter().any(query_node_uses_pattern_blooms),
        _ => false,
    }
}

fn build_pattern_mask_cache(
    patterns: &[PatternPlan],
    tier1_filter_keys: &[(usize, usize)],
    tier2_filter_keys: &[(usize, usize)],
    tier1_gram_size: usize,
    tier2_gram_size: usize,
    tier2_superblock_summary_cap_bytes: usize,
) -> Result<PatternMaskCache> {
    let mut out = HashMap::with_capacity(patterns.len());
    let mut tier1_gram_cache =
        HashMap::<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>::new();
    let mut tier2_gram_cache =
        HashMap::<(u64, usize, usize, usize, usize), Vec<(usize, u64)>>::new();
    for pattern in patterns {
        let mut tier1_masks = Vec::with_capacity(pattern.alternatives.len());
        let mut tier1_superblock_masks = Vec::with_capacity(pattern.alternatives.len());
        for (alt_index, alternative) in pattern.alternatives.iter().enumerate() {
            let fixed_literal = pattern
                .fixed_literals
                .get(alt_index)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let lane_variants = lane_position_variants_for_pattern(
                alternative,
                fixed_literal,
                tier1_gram_size,
                DEFAULT_BLOOM_POSITION_LANES,
            );
            let mut shifted_tier1 = ShiftedRequiredMasks {
                shifts: Vec::with_capacity(lane_variants.len()),
            };
            let mut shifted_tier1_superblocks = ShiftedRequiredMasks {
                shifts: Vec::with_capacity(lane_variants.len()),
            };
            for lanes in &lane_variants {
                let mut by_key = RequiredMasksByKey::new();
                let mut superblock_by_key = RequiredMasksByKey::new();
                for (filter_bytes, bloom_hashes) in tier1_filter_keys {
                    let required = merge_cached_lane_bloom_word_masks(
                        alternative,
                        *filter_bytes,
                        *bloom_hashes,
                        lanes,
                        DEFAULT_BLOOM_POSITION_LANES,
                        &mut tier1_gram_cache,
                    )?;
                    let summary_bucket = tier2_superblock_bucket_key(*filter_bytes, *bloom_hashes);
                    let summary_bytes = tier2_superblock_summary_bytes(
                        summary_bucket.0,
                        tier2_superblock_summary_cap_bytes,
                    );
                    superblock_by_key.insert(
                        (*filter_bytes, *bloom_hashes),
                        sample_bloom_word_masks_for_superblock(
                            &required,
                            *filter_bytes,
                            summary_bytes,
                        ),
                    );
                    by_key.insert((*filter_bytes, *bloom_hashes), required);
                }
                shifted_tier1.shifts.push(by_key);
                shifted_tier1_superblocks.shifts.push(superblock_by_key);
            }
            tier1_masks.push(shifted_tier1);
            tier1_superblock_masks.push(shifted_tier1_superblocks);
        }

        let mut tier2_masks = Vec::with_capacity(pattern.tier2_alternatives.len());
        let mut tier2_superblock_masks = Vec::with_capacity(pattern.tier2_alternatives.len());
        for (alt_index, alternative) in pattern.tier2_alternatives.iter().enumerate() {
            let fixed_literal = pattern
                .fixed_literals
                .get(alt_index)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let lane_variants = lane_position_variants_for_pattern(
                alternative,
                fixed_literal,
                tier2_gram_size,
                DEFAULT_BLOOM_POSITION_LANES,
            );
            let mut shifted_tier2 = ShiftedRequiredMasks {
                shifts: Vec::with_capacity(lane_variants.len()),
            };
            let mut shifted_tier2_superblocks = ShiftedRequiredMasks {
                shifts: Vec::with_capacity(lane_variants.len()),
            };
            for lanes in &lane_variants {
                let mut by_key = RequiredMasksByKey::new();
                let mut superblock_by_key = RequiredMasksByKey::new();
                for (filter_bytes, bloom_hashes) in tier2_filter_keys {
                    let required = merge_cached_lane_bloom_word_masks(
                        alternative,
                        *filter_bytes,
                        *bloom_hashes,
                        lanes,
                        DEFAULT_BLOOM_POSITION_LANES,
                        &mut tier2_gram_cache,
                    )?;
                    let summary_bucket = tier2_superblock_bucket_key(*filter_bytes, *bloom_hashes);
                    let summary_bytes = tier2_superblock_summary_bytes(
                        summary_bucket.0,
                        tier2_superblock_summary_cap_bytes,
                    );
                    superblock_by_key.insert(
                        (*filter_bytes, *bloom_hashes),
                        sample_bloom_word_masks_for_superblock(
                            &required,
                            *filter_bytes,
                            summary_bytes,
                        ),
                    );
                    by_key.insert((*filter_bytes, *bloom_hashes), required);
                }
                shifted_tier2.shifts.push(by_key);
                shifted_tier2_superblocks.shifts.push(superblock_by_key);
            }
            tier2_masks.push(shifted_tier2);
            tier2_superblock_masks.push(shifted_tier2_superblocks);
        }

        out.insert(
            pattern.pattern_id.clone(),
            PreparedPatternMasks {
                tier1: tier1_masks,
                tier1_superblocks: tier1_superblock_masks,
                tier2: tier2_masks,
                tier2_superblocks: tier2_superblock_masks,
            },
        );
    }
    Ok(out)
}

pub(crate) fn build_prepared_query_artifacts(
    plan: &CompiledQueryPlan,
    tier1_filter_keys: &[(usize, usize)],
    tier2_filter_keys: &[(usize, usize)],
    tier2_superblock_summary_cap_bytes: usize,
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
        tier2_superblock_summary_cap_bytes,
    )?;
    Ok(Arc::new(PreparedQueryArtifacts {
        patterns,
        mask_cache,
        impossible_query: node_structurally_impossible(&plan.root),
    }))
}

fn block_matches_required_masks(
    block_idx: usize,
    by_key: &RequiredMasksByKey,
    superblocks: &Tier2SuperblockIndex,
) -> bool {
    if by_key.is_empty() {
        return true;
    }
    let Some(keys) = superblocks.keys_per_block.get(block_idx) else {
        return false;
    };
    keys.iter().any(|filter_key| {
        let Some(required) = by_key.get(filter_key) else {
            return false;
        };
        let Some(bucket_key) = superblocks.bucket_for_key.get(filter_key) else {
            return false;
        };
        let Some(blocks) = superblocks.masks_by_bucket.get(bucket_key) else {
            return false;
        };
        let Some(block) = blocks.get(block_idx) else {
            return false;
        };
        raw_filter_matches_word_masks(block, required)
    })
}

fn tree_gate_matches_required_masks(
    by_key: &RequiredMasksByKey,
    gates: &TreeBloomGateIndex,
) -> bool {
    if by_key.is_empty() {
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
    pattern_masks
        .tier1
        .iter()
        .enumerate()
        .any(|(alt_index, tier1_by_key)| {
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
        "verifier_only_eq" | "filesize_eq" | "metadata_eq" | "time_now_eq" => Ok(true),
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

fn block_matches_shifted_required_masks(
    block_idx: usize,
    shifted: &ShiftedRequiredMasks,
    superblocks: &Tier2SuperblockIndex,
) -> bool {
    shifted
        .shifts
        .iter()
        .any(|by_key| block_matches_required_masks(block_idx, by_key, superblocks))
}

fn block_matches_pattern(
    block_idx: usize,
    pattern_id: &str,
    mask_cache: &PatternMaskCache,
    tier1_superblocks: &Tier2SuperblockIndex,
    tier2_superblocks: &Tier2SuperblockIndex,
    allow_tier2: bool,
) -> bool {
    let Some(pattern_masks) = mask_cache.get(pattern_id) else {
        return false;
    };
    pattern_masks
        .tier1_superblocks
        .iter()
        .enumerate()
        .any(|(alt_index, tier1_by_key)| {
            if !block_matches_shifted_required_masks(block_idx, tier1_by_key, tier1_superblocks) {
                return false;
            }
            let Some(tier2_by_key) = pattern_masks.tier2_superblocks.get(alt_index) else {
                return true;
            };
            if !allow_tier2 || tier2_by_key.is_empty() {
                return true;
            }
            block_matches_shifted_required_masks(block_idx, tier2_by_key, tier2_superblocks)
        })
}

fn block_maybe_matches_node(
    block_idx: usize,
    node: &QueryNode,
    mask_cache: &PatternMaskCache,
    tier1_superblocks: &Tier2SuperblockIndex,
    tier2_superblocks: &Tier2SuperblockIndex,
    allow_tier2: bool,
) -> Result<bool> {
    match node.kind.as_str() {
        "pattern" => {
            let pattern_id = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| SspryError::from("pattern node requires pattern_id"))?;
            Ok(block_matches_pattern(
                block_idx,
                pattern_id,
                mask_cache,
                tier1_superblocks,
                tier2_superblocks,
                allow_tier2,
            ))
        }
        "verifier_only_eq" => Ok(true),
        "filesize_eq" => Ok(true),
        "metadata_eq" => Ok(true),
        "time_now_eq" => Ok(true),
        "and" => {
            for child in &node.children {
                if !block_maybe_matches_node(
                    block_idx,
                    child,
                    mask_cache,
                    tier1_superblocks,
                    tier2_superblocks,
                    allow_tier2,
                )? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        "or" => {
            for child in &node.children {
                if block_maybe_matches_node(
                    block_idx,
                    child,
                    mask_cache,
                    tier1_superblocks,
                    tier2_superblocks,
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
                if block_maybe_matches_node(
                    block_idx,
                    child,
                    mask_cache,
                    tier1_superblocks,
                    tier2_superblocks,
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

fn query_scan_worker_count(block_count: usize) -> usize {
    if block_count < 64 {
        return 1;
    }
    thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1)
        .min(DEFAULT_QUERY_SCAN_WORKERS)
        .min(block_count.max(1))
        .max(1)
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
    for (alt_index, alternative) in pattern.alternatives.iter().enumerate() {
        if alternative.is_empty() {
            return Ok(MatchOutcome {
                matched: true,
                tiers: TierFlags {
                    used_tier1: true,
                    used_tier2: false,
                },
                score: 10_000,
            });
        }
        let doc = doc_inputs.doc;
        let bloom_bytes = doc_inputs.tier1_bloom_bytes(load_tier1)?;
        let primary_match = pattern_masks.tier1.get(alt_index).is_some_and(|shifted| {
            shifted.shifts.iter().any(|by_key| {
                by_key
                    .get(&(doc.filter_bytes, doc.bloom_hashes))
                    .is_some_and(|required| raw_filter_matches_word_masks(bloom_bytes, required))
            })
        });
        if !primary_match {
            continue;
        }
        let tier2_alternative = pattern
            .tier2_alternatives
            .get(alt_index)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut used_tier2 = false;
        if allow_tier2
            && !tier2_alternative.is_empty()
            && doc.tier2_filter_bytes > 0
            && doc.tier2_bloom_hashes > 0
        {
            let tier2_bloom_bytes = doc_inputs.tier2_bloom_bytes(load_tier2)?;
            if tier2_bloom_bytes.is_empty() {
                continue;
            }
            let tier2_match = pattern_masks.tier2.get(alt_index).is_some_and(|shifted| {
                shifted.shifts.iter().any(|by_key| {
                    by_key
                        .get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                        .is_some_and(|required| {
                            raw_filter_matches_word_masks(tier2_bloom_bytes, required)
                        })
                })
            });
            if !tier2_match {
                continue;
            }
            used_tier2 = true;
        }
        return Ok(MatchOutcome {
            matched: true,
            tiers: TierFlags {
                used_tier1: true,
                used_tier2,
            },
            score: 1_000u32
                .saturating_add((alternative.len() as u32).saturating_mul(16))
                .saturating_add(
                    tier2_alternative
                        .len()
                        .saturating_mul(8)
                        .try_into()
                        .unwrap_or(u32::MAX),
                ),
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
        "verifier_only_eq" => Ok(MatchOutcome {
            matched: true,
            tiers: TierFlags::default(),
            score: 0,
        }),
        "filesize_eq" => {
            let expected_size = node
                .threshold
                .ok_or_else(|| SspryError::from("filesize_eq node requires threshold"))?
                as u64;
            Ok(MatchOutcome {
                matched: doc_inputs.doc.file_size == expected_size,
                tiers: TierFlags::default(),
                score: 0,
            })
        }
        "metadata_eq" => {
            let field = node
                .pattern_id
                .as_deref()
                .ok_or_else(|| SspryError::from("metadata_eq node requires pattern_id"))?;
            let expected = node
                .threshold
                .ok_or_else(|| SspryError::from("metadata_eq node requires threshold"))?
                as u64;
            let metadata_bytes = doc_inputs.metadata_bytes(load_metadata)?;
            let matched =
                metadata_field_matches_eq(metadata_bytes, field, expected)?.unwrap_or(true);
            Ok(MatchOutcome {
                matched,
                tiers: TierFlags::default(),
                score: 0,
            })
        }
        "time_now_eq" => {
            let expected = node
                .threshold
                .ok_or_else(|| SspryError::from("time_now_eq node requires threshold"))?
                as u64;
            Ok(MatchOutcome {
                matched: query_now_unix == expected,
                tiers: TierFlags::default(),
                score: 0,
            })
        }
        "and" => {
            let mut merged = TierFlags::default();
            let mut score = 0u32;
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
                score = score.saturating_add(outcome.score);
            }
            Ok(MatchOutcome {
                matched: true,
                tiers: merged,
                score,
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
            let mut score = 0u32;
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
                    score = score.saturating_add(outcome.score);
                    if matched_count >= threshold {
                        return Ok(MatchOutcome {
                            matched: true,
                            tiers: merged,
                            score,
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
                score: if matched_count >= threshold { score } else { 0 },
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

    use crate::candidate::BloomFilter;
    use crate::candidate::bloom::DEFAULT_BLOOM_POSITION_LANES;
    use crate::candidate::{
        DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes,
        extract_compact_document_metadata, pack_exact_gram,
        query_plan::compile_query_plan_with_gram_sizes,
    };

    use super::*;

    fn borrowed_bytes<'a>(bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        Ok(Cow::Borrowed(bytes))
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

    fn dir_size(root: &Path) -> u64 {
        fn walk(path: &Path) -> u64 {
            let Ok(metadata) = fs::metadata(path) else {
                return 0;
            };
            if metadata.is_file() {
                return metadata.len();
            }
            let Ok(entries) = fs::read_dir(path) else {
                return 0;
            };
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| walk(&entry.path()))
                .sum()
        }
        walk(root)
    }

    #[test]
    fn insert_query_delete_roundtrip() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
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
            &lane_bloom_bytes(filter_bytes, bloom_hashes, &[0x4443_4241]),
            Some("doc-1".to_owned()),
        )
        .expect("insert");
        assert_eq!(result.status, "inserted");

        let plan = compile_query_plan_with_gram_sizes(
            r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
            GramSizes::new(DEFAULT_TIER2_GRAM_SIZE, DEFAULT_TIER1_GRAM_SIZE)
                .expect("default gram sizes"),
            8,
            false,
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
    fn compaction_reclaims_deleted_docs_and_storage() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
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
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");
        let bloom_hashes =
            store.resolve_bloom_hashes_for_document(512 * 1024, Some(100_000), Some(7));
        assert_eq!(bloom_hashes, 16);
        assert_eq!(store.stats().filter_target_fp, Some(0.25));
    }

    #[test]
    fn external_ids_follow_active_docs() {
        let tmp = tempdir().expect("tmp");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: tmp.path().join("candidate_db"),
                filter_target_fp: None,
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

        let bad_version = StoreMeta {
            version: STORE_VERSION + 1,
            ..StoreMeta::default()
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
            serde_json::to_vec_pretty(&StoreMeta::default()).expect("meta json"),
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
            serde_json::to_vec_pretty(&StoreMeta::default()).expect("bad bloom meta"),
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
            serde_json::to_vec_pretty(&StoreMeta::default()).expect("bad utf8 meta"),
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

        let mut sidecar = BlobSidecar::new(first_blob_path.clone());
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

        let mut sidecars = StoreSidecars::map_existing(&root).expect("map store sidecars");
        assert_eq!(
            sidecars
                .metadata
                .read_bytes(0, 4, "metadata", 9)
                .expect("metadata read")
                .as_ref(),
            b"meta"
        );
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
                    fixed_literals: vec![Vec::new()],
                },
                PatternPlan {
                    pattern_id: "tier2".to_owned(),
                    alternatives: vec![vec![2]],
                    tier2_alternatives: vec![Vec::new()],
                    fixed_literals: vec![Vec::new()],
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
            max_candidates: 2,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };

        let result = store.query_candidates(&plan, 0, 1).expect("query");
        assert_eq!(result.total_candidates, 2);
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
            deleted: false,
        };
        let patterns_vec = vec![
            PatternPlan {
                pattern_id: "empty".to_owned(),
                alternatives: vec![Vec::new()],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
            },
            PatternPlan {
                pattern_id: "tier1".to_owned(),
                alternatives: vec![vec![1]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
            },
            PatternPlan {
                pattern_id: "tier2".to_owned(),
                alternatives: vec![vec![1, 2]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
            },
            PatternPlan {
                pattern_id: "missing".to_owned(),
                alternatives: vec![vec![99]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
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
            max_candidates: 32,
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
            DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES,
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
        assert!(outcome.score > 0);

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
        assert_eq!(outcome.score, 0);

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
        assert!(outcome.score > 0);

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
        assert!(outcome.score > 0);

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
        assert_eq!(outcome.score, 0);

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
        assert!(outcome.score > 0);

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
        assert!(outcome.score > 0);

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
        fs::write(&pe_path, pe).expect("write pe");
        let metadata_bytes = extract_compact_document_metadata(&pe_path).expect("metadata");

        let doc = CandidateDoc {
            doc_id: 1,
            sha256: hex::encode([0x11; 32]),
            file_size: 512,
            filter_bytes: 8,
            bloom_hashes: 2,
            tier2_filter_bytes: 8,
            tier2_bloom_hashes: 2,
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
            max_candidates: 32,
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
        let verifier_outcome = evaluate_node(
            &QueryNode {
                kind: "verifier_only_eq".to_owned(),
                pattern_id: Some("uint32(0)==332".to_owned()),
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
                fixed_literals: vec![vec![1, 2, 3, 4]],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 64,
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
    fn sampled_superblock_masks_preserve_selected_words() {
        let required = vec![
            (0usize, 0b0000_0011u64),
            (4usize, 0b0000_0100u64),
            (7usize, 0b1000_0000u64),
        ];
        let sampled = sample_bloom_word_masks_for_superblock(&required, 64, 16);
        let sampled_map = sampled.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(sampled_map.get(&0).copied(), Some(0b0000_0011));
        assert_eq!(sampled_map.get(&1).copied(), Some(0b0000_0100));
        assert!(!sampled_map.contains_key(&7));
    }

    #[test]
    fn tier2_superblocks_use_bounded_summary_bytes() {
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
        let sha256 = [0x11; 32];
        let file_size = 64 * 1024 * 1024u64;
        let bloom_item_estimate = 1_000_000usize;
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(file_size, Some(bloom_item_estimate))
            .expect("large primary filter bytes");
        assert!(filter_bytes > DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES);
        let bloom_hashes =
            store.resolve_bloom_hashes_for_document(filter_bytes, Some(bloom_item_estimate), None);
        let mut primary_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("tier1 bloom");
        primary_bloom
            .add(pack_exact_gram(&[1, 2, 3]))
            .expect("add primary gram");
        let tier2_filter_bytes = store
            .resolve_filter_bytes_for_file_size(file_size, Some(2))
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
                file_size,
                Some(bloom_item_estimate),
                Some(bloom_hashes),
                Some(2),
                Some(tier2_bloom_hashes),
                filter_bytes,
                &primary_bloom.into_bytes(),
                tier2_filter_bytes,
                &tier2_bloom.into_bytes(),
                None,
            )
            .expect("insert");

        let key = (filter_bytes, bloom_hashes);
        let bucket_key = tier2_superblock_bucket_key(filter_bytes, bloom_hashes);
        assert_eq!(
            store.tier2_superblocks.bucket_for_key.get(&key).copied(),
            Some(bucket_key)
        );
        assert_eq!(
            store
                .tier2_superblocks
                .summary_bytes_by_bucket
                .get(&bucket_key)
                .copied(),
            Some(DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES)
        );
        let blocks = store
            .tier2_superblocks
            .masks_by_bucket
            .get(&bucket_key)
            .expect("superblock masks");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES);
    }

    #[test]
    fn tier2_superblocks_respect_custom_summary_cap() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("store");
        let cap_bytes = 8 * 1024;
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                tier2_superblock_summary_cap_bytes: cap_bytes,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");
        let sha256 = [0x22; 32];
        let file_size = 64 * 1024 * 1024u64;
        let bloom_item_estimate = 1_000_000usize;
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(file_size, Some(bloom_item_estimate))
            .expect("large primary filter bytes");
        assert!(filter_bytes > cap_bytes);
        let bloom_hashes =
            store.resolve_bloom_hashes_for_document(filter_bytes, Some(bloom_item_estimate), None);
        let mut primary_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("tier1 bloom");
        primary_bloom
            .add(pack_exact_gram(&[9, 8, 7]))
            .expect("add primary gram");
        let tier2_filter_bytes = store
            .resolve_filter_bytes_for_file_size(file_size, Some(2))
            .expect("tier2 filter bytes");
        let tier2_bloom_hashes =
            store.resolve_bloom_hashes_for_document(tier2_filter_bytes, Some(2), None);
        let mut tier2_bloom =
            BloomFilter::new(tier2_filter_bytes, tier2_bloom_hashes).expect("tier2 bloom");
        tier2_bloom
            .add(pack_exact_gram(&[9, 8, 7, 6]))
            .expect("add tier2 gram");
        store
            .insert_document(
                sha256,
                file_size,
                Some(bloom_item_estimate),
                Some(bloom_hashes),
                Some(2),
                Some(tier2_bloom_hashes),
                filter_bytes,
                &primary_bloom.into_bytes(),
                tier2_filter_bytes,
                &tier2_bloom.into_bytes(),
                None,
            )
            .expect("insert");

        let bucket_key = tier2_superblock_bucket_key(filter_bytes, bloom_hashes);
        let blocks = store
            .tier2_superblocks
            .masks_by_bucket
            .get(&bucket_key)
            .expect("superblock masks");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), cap_bytes);
        assert_eq!(store.config().tier2_superblock_summary_cap_bytes, cap_bytes);
    }

    #[test]
    fn tier2_superblock_memory_budget_respects_memory_budget_and_divisor() {
        assert_eq!(
            tier2_superblock_memory_budget_bytes(16 * 1024 * 1024 * 1024, 256, 4),
            16 * 1024 * 1024
        );
        assert_eq!(tier2_superblock_memory_budget_bytes(0, 256, 4), 0);
        assert_eq!(
            tier2_superblock_memory_budget_bytes(512 * 1024 * 1024, 256, 4),
            MIN_TIER2_SUPERBLOCK_MEMORY_BUDGET_BYTES
        );
    }

    #[test]
    fn scaled_docs_per_block_grows_only_when_needed() {
        assert_eq!(
            scaled_docs_per_block_for_budget(128, 8 * 1024 * 1024, 0),
            128
        );
        assert_eq!(
            scaled_docs_per_block_for_budget(128, 8 * 1024 * 1024, 8 * 1024 * 1024),
            128
        );
        assert_eq!(
            scaled_docs_per_block_for_budget(128, 32 * 1024 * 1024, 16 * 1024 * 1024),
            256
        );
        assert_eq!(
            scaled_docs_per_block_for_budget(128, 80 * 1024 * 1024, 16 * 1024 * 1024),
            1024
        );
    }

    #[test]
    fn apply_runtime_limits_updates_tier2_budget_stats() {
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

        store
            .apply_runtime_limits(16 * 1024 * 1024 * 1024, 256, 4)
            .expect("apply runtime limits");

        let stats = store.stats();
        assert_eq!(stats.tier2_superblock_memory_budget_bytes, 16 * 1024 * 1024);
        assert_eq!(stats.tier2_superblock_summary_bytes, 0);
    }

    #[test]
    fn tier2_superblocks_snapshot_roundtrips_on_open() {
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

        let sha256 = [0x41; 32];
        let file_size = 4096u64;
        let grams_received = [pack_exact_gram(&[1, 2, 3]), pack_exact_gram(&[2, 3, 4])];
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(file_size, Some(grams_received.len()))
            .expect("primary filter bytes");
        let bloom_hashes =
            store.resolve_bloom_hashes_for_document(filter_bytes, Some(grams_received.len()), None);
        let mut primary_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("primary");
        for gram in grams_received {
            primary_bloom.add(gram).expect("add primary gram");
        }
        let tier2_filter_bytes = store
            .resolve_filter_bytes_for_file_size(file_size, Some(1))
            .expect("tier2 filter bytes");
        let tier2_bloom_hashes =
            store.resolve_bloom_hashes_for_document(tier2_filter_bytes, Some(1), None);
        let mut tier2_bloom =
            BloomFilter::new(tier2_filter_bytes, tier2_bloom_hashes).expect("tier2 bloom");
        tier2_bloom
            .add(pack_exact_gram(&[1, 2, 3, 4]))
            .expect("add tier2 gram");

        store
            .insert_document(
                sha256,
                file_size,
                Some(grams_received.len()),
                Some(bloom_hashes),
                Some(1),
                Some(tier2_bloom_hashes),
                filter_bytes,
                &primary_bloom.into_bytes(),
                tier2_filter_bytes,
                &tier2_bloom.into_bytes(),
                None,
            )
            .expect("insert");
        let expected_summary_bytes = store.tier2_superblocks.summary_memory_bytes;
        store
            .persist_tier2_superblocks_snapshot()
            .expect("persist snapshot");

        let (reopened, profile) = CandidateStore::open_profiled(&root).expect("reopen");
        assert!(profile.loaded_tier2_superblocks_from_snapshot);
        assert_eq!(profile.rebuild_tier2_superblocks_ms, 0);
        assert_eq!(
            reopened.tier2_superblocks.summary_memory_bytes,
            expected_summary_bytes
        );
    }

    #[test]
    fn stale_tier2_superblocks_snapshot_falls_back_to_rebuild() {
        fn make_doc(
            store: &CandidateStore,
            file_size: u64,
            sha_byte: u8,
            gram: u64,
        ) -> ([u8; 32], Vec<u64>, usize, usize, Vec<u8>) {
            let grams = vec![gram];
            let filter_bytes = store
                .resolve_filter_bytes_for_file_size(file_size, Some(grams.len()))
                .expect("filter bytes");
            let bloom_hashes =
                store.resolve_bloom_hashes_for_document(filter_bytes, Some(grams.len()), None);
            let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
            for value in &grams {
                bloom.add(*value).expect("add gram");
            }
            (
                [sha_byte; 32],
                grams,
                filter_bytes,
                bloom_hashes,
                bloom.into_bytes(),
            )
        }

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

        let file_size = 4096u64;
        let (sha_one, grams_one, filter_bytes, bloom_hashes, bloom_one) =
            make_doc(&store, file_size, 0x51, pack_exact_gram(&[1, 2, 3, 4]));
        store
            .insert_document(
                sha_one,
                file_size,
                Some(grams_one.len()),
                Some(bloom_hashes),
                Some(1),
                Some(bloom_hashes),
                filter_bytes,
                &bloom_one,
                filter_bytes,
                &bloom_one,
                None,
            )
            .expect("insert first");
        store
            .persist_tier2_superblocks_snapshot()
            .expect("persist snapshot");

        let (sha_two, grams_two, _, _, bloom_two) =
            make_doc(&store, file_size, 0x52, pack_exact_gram(&[2, 3, 4, 5]));
        store
            .insert_document(
                sha_two,
                file_size,
                Some(grams_two.len()),
                Some(bloom_hashes),
                Some(1),
                Some(bloom_hashes),
                filter_bytes,
                &bloom_two,
                filter_bytes,
                &bloom_two,
                None,
            )
            .expect("insert second");

        let (reopened, profile) = CandidateStore::open_profiled(&root).expect("reopen");
        assert!(!profile.loaded_tier2_superblocks_from_snapshot);
        assert!(reopened.tier2_superblocks.summary_memory_bytes > 0);
    }
}
