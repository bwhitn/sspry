use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hashbrown::{HashMap as FastHashMap, hash_map::Entry as FastEntry};
use memmap2::{Mmap, MmapOptions};
use serde::{Deserialize, Serialize};

use crate::candidate::bloom::{bloom_byte_masks, raw_filter_matches_masks};
use crate::candidate::cache::BoundedCache;
use crate::candidate::features::scale_tier1_gram_budget;
use crate::candidate::filter_policy::{
    choose_filter_bytes_for_file_size, derive_document_bloom_hash_count,
};
use crate::candidate::grams::{DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes};
use crate::candidate::query_plan::{CompiledQueryPlan, PatternPlan, QueryNode};
use crate::perf::{record_counter, record_max, scope};
use crate::{Result, TgsError};

const STORE_VERSION: u32 = 1;
const TIER2_SUPERBLOCKS_SNAPSHOT_VERSION: u32 = 1;
const DEFAULT_FILTER_BYTES: usize = 2048;
const DEFAULT_BLOOM_HASHES: usize = 7;
const DEFAULT_FILTER_MIN_BYTES: usize = 1;
const DEFAULT_FILTER_MAX_BYTES: usize = 0;
const DEFAULT_FILTER_SIZE_DIVISOR: usize = 1;
const DEFAULT_DF_MIN: usize = 1;
const DEFAULT_DF_MAX: usize = 0;
const DEFAULT_TIER1_GRAM_BUDGET: usize = 4096;
const DEFAULT_TIER1_GRAM_HASH_SEED: u64 = 1337;
const DEFAULT_TIER2_SUPERBLOCK_DOCS: usize = 128;
const MAX_TIER2_SUPERBLOCK_SUMMARY_BYTES: usize = 4096;
const DEFAULT_COMPACTION_IDLE_COOLDOWN_S: f64 = 5.0;
const PREPARED_QUERY_CACHE_CAPACITY: usize = 32;

#[derive(Debug, Default)]
struct DfCountsState {
    gram_bytes: usize,
    snapshot: Option<Mmap>,
    snapshot_rows: usize,
    delta: FastHashMap<u64, i64>,
}

impl DfCountsState {
    fn load(root: &Path, gram_bytes: usize) -> Result<Self> {
        let snapshot_path = df_counts_path(root);
        let snapshot = if snapshot_path.exists() {
            let file = fs::File::open(&snapshot_path)?;
            let len = file.metadata()?.len() as usize;
            let row_bytes = gram_bytes + 4;
            if len % row_bytes != 0 {
                return Err(TgsError::from(format!(
                    "Invalid df_counts snapshot at {}",
                    snapshot_path.display()
                )));
            }
            if len == 0 {
                None
            } else {
                Some(unsafe { MmapOptions::new().map(&file) }.map_err(|err| {
                    TgsError::from(format!("Failed to mmap {}: {err}", snapshot_path.display()))
                })?)
            }
        } else {
            None
        };

        let mut state = Self {
            gram_bytes,
            snapshot_rows: snapshot
                .as_ref()
                .map(|mmap| mmap.len() / (gram_bytes + 4))
                .unwrap_or(0),
            snapshot,
            delta: FastHashMap::new(),
        };
        state.load_delta(root)?;
        Ok(state)
    }

    fn load_delta(&mut self, root: &Path) -> Result<()> {
        let delta_path = df_counts_delta_path(root);
        if delta_path.exists() {
            let bytes = fs::read(&delta_path)?;
            let row_bytes = self.gram_bytes + 4;
            if bytes.len() % row_bytes != 0 {
                return Err(TgsError::from(format!(
                    "Invalid df_counts delta at {}",
                    delta_path.display()
                )));
            }
            for chunk in bytes.chunks_exact(row_bytes) {
                let gram = decode_packed_exact_gram(&chunk[..self.gram_bytes]);
                let change = i32::from_le_bytes(
                    chunk[self.gram_bytes..self.gram_bytes + 4]
                        .try_into()
                        .expect("df delta value"),
                );
                *self.delta.entry(gram).or_insert(0) += i64::from(change);
            }
        }
        let unit_delta_path = df_counts_unit_delta_path(root);
        if unit_delta_path.exists() {
            let bytes = fs::read(&unit_delta_path)?;
            if self.gram_bytes == 0 || bytes.len() % self.gram_bytes != 0 {
                return Err(TgsError::from(format!(
                    "Invalid df_counts unit delta at {}",
                    unit_delta_path.display()
                )));
            }
            self.delta.reserve(bytes.len() / self.gram_bytes);
            for chunk in bytes.chunks_exact(self.gram_bytes) {
                match self.delta.entry(decode_packed_exact_gram(chunk)) {
                    FastEntry::Occupied(mut entry) => {
                        let next = *entry.get() + 1;
                        if next == 0 {
                            entry.remove();
                        } else {
                            *entry.get_mut() = next;
                        }
                    }
                    FastEntry::Vacant(entry) => {
                        entry.insert(1);
                    }
                }
            }
        }
        self.delta.retain(|_, value| *value != 0);
        Ok(())
    }

    fn snapshot_count(&self, gram: u64) -> usize {
        let Some(snapshot) = &self.snapshot else {
            return 0;
        };
        let row_bytes = self.gram_bytes + 4;
        let mut left = 0usize;
        let mut right = self.snapshot_rows;
        while left < right {
            let mid = left + (right - left) / 2;
            let start = mid * row_bytes;
            let candidate = decode_packed_exact_gram(&snapshot[start..start + self.gram_bytes]);
            if candidate == gram {
                return u32::from_le_bytes(
                    snapshot[start + self.gram_bytes..start + row_bytes]
                        .try_into()
                        .expect("df count"),
                ) as usize;
            }
            if candidate < gram {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        0
    }

    fn get(&self, gram: u64) -> usize {
        let base = self.snapshot_count(gram) as i64;
        let delta = self.delta.get(&gram).copied().unwrap_or(0);
        (base + delta).max(0) as usize
    }

    fn get_many(&self, grams: &[u64]) -> HashMap<u64, usize> {
        let mut out = HashMap::with_capacity(grams.len());
        for gram in grams {
            let count = self.get(*gram);
            if count > 0 {
                out.insert(*gram, count);
            }
        }
        out
    }

    fn get_many_sorted_counts(&self, grams: &[u64]) -> Vec<usize> {
        if grams.is_empty() {
            return Vec::new();
        }
        let mut counts = Vec::with_capacity(grams.len());
        let row_bytes = self.gram_bytes + 4;
        let mut snapshot_idx = 0usize;
        let snapshot = self.snapshot.as_deref().unwrap_or(&[]);
        for gram in grams {
            while snapshot_idx < self.snapshot_rows {
                let start = snapshot_idx * row_bytes;
                let candidate = decode_packed_exact_gram(&snapshot[start..start + self.gram_bytes]);
                if candidate < *gram {
                    snapshot_idx += 1;
                    continue;
                }
                break;
            }
            let base = if snapshot_idx < self.snapshot_rows {
                let start = snapshot_idx * row_bytes;
                let candidate = decode_packed_exact_gram(&snapshot[start..start + self.gram_bytes]);
                if candidate == *gram {
                    u32::from_le_bytes(
                        snapshot[start + self.gram_bytes..start + row_bytes]
                            .try_into()
                            .expect("df count"),
                    ) as usize
                } else {
                    0
                }
            } else {
                0
            };
            let delta = self.delta.get(gram).copied().unwrap_or(0);
            counts.push((base as i64 + delta).max(0) as usize);
        }
        counts
    }

    fn materialize(&self) -> HashMap<u64, usize> {
        let mut counts =
            HashMap::<u64, usize>::with_capacity(self.snapshot_rows + self.delta.len());
        if let Some(snapshot) = &self.snapshot {
            let row_bytes = self.gram_bytes + 4;
            for chunk in snapshot.chunks_exact(row_bytes) {
                let gram = decode_packed_exact_gram(&chunk[..self.gram_bytes]);
                let count = u32::from_le_bytes(
                    chunk[self.gram_bytes..row_bytes]
                        .try_into()
                        .expect("df count"),
                ) as usize;
                if count > 0 {
                    counts.insert(gram, count);
                }
            }
        }
        for (gram, delta) in &self.delta {
            let next = counts.get(gram).copied().unwrap_or(0) as i64 + *delta;
            if next > 0 {
                counts.insert(*gram, next as usize);
            } else {
                counts.remove(gram);
            }
        }
        counts
    }

    fn apply_deltas(&mut self, deltas: &[(u64, i32)]) {
        self.delta.reserve(deltas.len());
        for (gram, delta) in deltas {
            let delta = i64::from(*delta);
            if delta == 0 {
                continue;
            }
            match self.delta.entry(*gram) {
                FastEntry::Occupied(mut entry) => {
                    let next = *entry.get() + delta;
                    if next == 0 {
                        entry.remove();
                    } else {
                        *entry.get_mut() = next;
                    }
                }
                FastEntry::Vacant(entry) => {
                    entry.insert(delta);
                }
            }
        }
    }

    fn apply_unit_deltas(&mut self, grams: &[u64]) {
        self.delta.reserve(grams.len());
        for gram in grams {
            match self.delta.entry(*gram) {
                FastEntry::Occupied(mut entry) => {
                    *entry.get_mut() += 1;
                }
                FastEntry::Vacant(entry) => {
                    entry.insert(1);
                }
            }
        }
    }

    fn refresh_snapshot(&mut self, root: &Path) -> Result<()> {
        let fresh = Self::load(root, self.gram_bytes)?;
        self.snapshot = fresh.snapshot;
        self.snapshot_rows = fresh.snapshot_rows;
        self.delta = fresh.delta;
        Ok(())
    }

    fn unique_count_hint(&self) -> usize {
        self.snapshot_rows + self.delta.len()
    }
}

fn is_strictly_sorted_unique(values: &[u64]) -> bool {
    let mut prev = None;
    for value in values {
        if prev.is_some_and(|prior| *value <= prior) {
            return false;
        }
        prev = Some(*value);
    }
    true
}

#[derive(Clone, Debug)]
pub struct CandidateConfig {
    pub root: PathBuf,
    pub id_source: String,
    pub store_path: bool,
    pub tier2_gram_size: usize,
    pub tier1_gram_size: usize,
    pub filter_target_fp: Option<f64>,
    pub df_min: usize,
    pub df_max: usize,
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
            filter_target_fp: Some(0.35),
            df_min: DEFAULT_DF_MIN,
            df_max: DEFAULT_DF_MAX,
            compaction_idle_cooldown_s: DEFAULT_COMPACTION_IDLE_COOLDOWN_S,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CandidateInsertResult {
    pub status: String,
    pub doc_id: u64,
    pub sha256: String,
    pub grams_received: usize,
    pub grams_indexed: usize,
    pub grams_complete: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CandidateInsertBatchProfile {
    pub classify_us: u64,
    pub apply_df_counts_us: u64,
    pub append_sidecars_us: u64,
    pub append_sidecar_payloads_us: u64,
    pub append_bloom_payload_us: u64,
    pub append_grams_received_payload_us: u64,
    pub append_grams_indexed_payload_us: u64,
    pub append_external_id_payload_us: u64,
    pub append_tier2_bloom_payload_us: u64,
    pub append_bloom_payload_bytes: u64,
    pub append_grams_received_payload_bytes: u64,
    pub append_grams_indexed_payload_bytes: u64,
    pub append_external_id_payload_bytes: u64,
    pub append_tier2_bloom_payload_bytes: u64,
    pub append_doc_records_us: u64,
    pub write_existing_us: u64,
    pub install_docs_us: u64,
    pub tier2_update_us: u64,
    pub persist_meta_us: u64,
    pub append_df_delta_us: u64,
    pub compact_df_counts_us: u64,
    pub rebalance_tier2_us: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CandidateImportBatchProfile {
    pub classify_ms: u64,
    pub apply_df_counts_ms: u64,
    pub build_payloads_ms: u64,
    pub append_sidecars_ms: u64,
    pub append_sidecar_payloads_ms: u64,
    pub append_doc_records_ms: u64,
    pub install_docs_ms: u64,
    pub tier2_update_ms: u64,
    pub persist_meta_ms: u64,
    pub append_df_delta_ms: u64,
    pub compact_df_counts_ms: u64,
    pub rebalance_tier2_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CandidateDocRowPayloadProfile {
    bloom_us: u64,
    grams_received_us: u64,
    grams_indexed_us: u64,
    external_id_us: u64,
    tier2_bloom_us: u64,
    bloom_bytes: u64,
    grams_received_bytes: u64,
    grams_indexed_bytes: u64,
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
    pub rebuild_df_counts_ms: u64,
    pub rebuild_sha_index_ms: u64,
    pub load_tier2_superblocks_ms: u64,
    pub rebuild_tier2_superblocks_ms: u64,
    pub loaded_tier2_superblocks_from_snapshot: bool,
    pub total_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CandidateStoreRebuildProfile {
    df_counts_ms: u64,
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
    pub grams_received_bytes: Vec<u8>,
    pub grams_received_count: usize,
    pub grams_indexed_bytes: Vec<u8>,
    pub grams_indexed_count: usize,
    pub grams_complete: bool,
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
}

#[derive(Clone, Debug)]
pub struct CandidateStats {
    pub doc_count: usize,
    pub deleted_doc_count: usize,
    pub tier1_incomplete_doc_count: usize,
    pub id_source: String,
    pub store_path: bool,
    pub filter_target_fp: Option<f64>,
    pub tier2_gram_size: usize,
    pub tier1_gram_size: usize,
    pub df_min: usize,
    pub df_max: usize,
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
    pub df_counts_delta_bytes: u64,
    pub df_counts_delta_entries: usize,
    pub df_counts_delta_compact_threshold_bytes: u64,
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
    filter_target_fp: Option<f64>,
    df_min: usize,
    df_max: usize,
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
            filter_target_fp: Some(0.35),
            df_min: DEFAULT_DF_MIN,
            df_max: DEFAULT_DF_MAX,
            compaction_idle_cooldown_s: DEFAULT_COMPACTION_IDLE_COOLDOWN_S,
        }
    }
}

impl StoreMeta {
    fn exact_gram_bytes(&self) -> usize {
        if self.tier1_gram_size <= 4 { 4 } else { 8 }
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
    grams_complete: bool,
    deleted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyCandidateDoc {
    doc_id: u64,
    sha256: String,
    file_size: u64,
    filter_bytes: usize,
    #[serde(default)]
    bloom_hashes: usize,
    bloom_hex: String,
    #[serde(default)]
    tier2_filter_bytes: usize,
    #[serde(default)]
    tier2_bloom_hashes: usize,
    #[serde(default)]
    tier2_bloom_hex: String,
    grams_received: Vec<u32>,
    grams_indexed: Vec<u32>,
    grams_complete: bool,
    deleted: bool,
    external_id: Option<String>,
}

const DOC_META_ROW_BYTES: usize = 64;
const TIER2_DOC_META_ROW_BYTES: usize = 24;
const DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES: u64 = 64 * 1024 * 1024;
const MIN_DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES: u64 = 32 * 1024 * 1024;
const DF_COUNTS_DELTA_MEMORY_BUDGET_DIVISOR: u64 = 16;
const DEFAULT_TIER2_SUPERBLOCK_MEMORY_BUDGET_DIVISOR: u64 = 4;
const MIN_TIER2_SUPERBLOCK_MEMORY_BUDGET_BYTES: u64 = 1 * 1024 * 1024;
const DOC_FLAG_GRAMS_COMPLETE: u8 = 0x01;
const DOC_FLAG_DELETED: u8 = 0x02;

#[derive(Clone, Copy, Debug, Default)]
struct DocMetaRow {
    file_size: u64,
    filter_bytes: u32,
    flags: u8,
    bloom_hashes: u8,
    bloom_offset: u64,
    bloom_len: u32,
    grams_received_offset: u64,
    grams_received_count: u32,
    grams_indexed_offset: u64,
    grams_indexed_count: u32,
    external_id_offset: u64,
    external_id_len: u32,
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
            return Err(TgsError::from("Invalid candidate doc meta5 row size"));
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
        out[28..36].copy_from_slice(&self.grams_received_offset.to_le_bytes());
        out[36..40].copy_from_slice(&self.grams_received_count.to_le_bytes());
        out[40..48].copy_from_slice(&self.grams_indexed_offset.to_le_bytes());
        out[48..52].copy_from_slice(&self.grams_indexed_count.to_le_bytes());
        out[52..60].copy_from_slice(&self.external_id_offset.to_le_bytes());
        out[60..64].copy_from_slice(&self.external_id_len.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DOC_META_ROW_BYTES {
            return Err(TgsError::from("Invalid candidate doc meta row size"));
        }
        Ok(Self {
            file_size: u64::from_le_bytes(bytes[0..8].try_into().expect("file_size")),
            filter_bytes: u32::from_le_bytes(bytes[8..12].try_into().expect("filter_bytes")),
            flags: bytes[12],
            bloom_hashes: bytes[13],
            bloom_offset: u64::from_le_bytes(bytes[16..24].try_into().expect("bloom_offset")),
            bloom_len: u32::from_le_bytes(bytes[24..28].try_into().expect("bloom_len")),
            grams_received_offset: u64::from_le_bytes(
                bytes[28..36].try_into().expect("grams_received_offset"),
            ),
            grams_received_count: u32::from_le_bytes(
                bytes[36..40].try_into().expect("grams_received_count"),
            ),
            grams_indexed_offset: u64::from_le_bytes(
                bytes[40..48].try_into().expect("grams_indexed_offset"),
            ),
            grams_indexed_count: u32::from_le_bytes(
                bytes[48..52].try_into().expect("grams_indexed_count"),
            ),
            external_id_offset: u64::from_le_bytes(
                bytes[52..60].try_into().expect("external_id_offset"),
            ),
            external_id_len: u32::from_le_bytes(bytes[60..64].try_into().expect("external_id_len")),
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
            TgsError::from(format!("Failed to mmap {}: {err}", self.path.display()))
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
                return Err(TgsError::from(format!(
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
}

#[derive(Debug)]
struct StoreSidecars {
    blooms: BlobSidecar,
    tier2_blooms: BlobSidecar,
    grams_received: BlobSidecar,
    grams_indexed: BlobSidecar,
    external_ids: BlobSidecar,
}

impl StoreSidecars {
    fn new(root: &Path) -> Self {
        Self {
            blooms: BlobSidecar::new(blooms_path(root)),
            tier2_blooms: BlobSidecar::new(tier2_blooms_path(root)),
            grams_received: BlobSidecar::new(grams_received_path(root)),
            grams_indexed: BlobSidecar::new(grams_indexed_path(root)),
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
        self.grams_received.map_if_exists()?;
        self.grams_indexed.map_if_exists()?;
        self.external_ids.map_if_exists()?;
        Ok(())
    }

    fn invalidate_all(&mut self) {
        self.blooms.invalidate();
        self.tier2_blooms.invalidate();
        self.grams_received.invalidate();
        self.grams_indexed.invalidate();
        self.external_ids.invalidate();
    }

    fn retarget_root(&mut self, root: &Path) {
        self.blooms.retarget(blooms_path(root));
        self.tier2_blooms.retarget(tier2_blooms_path(root));
        self.grams_received.retarget(grams_received_path(root));
        self.grams_indexed.retarget(grams_indexed_path(root));
        self.external_ids.retarget(external_ids_path(root));
    }
}

#[derive(Debug)]
struct AppendFile {
    path: PathBuf,
    handle: Option<fs::File>,
    offset: u64,
}

impl AppendFile {
    fn new(path: PathBuf) -> Result<Self> {
        let offset = fs::metadata(&path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Ok(Self {
            path,
            handle: None,
            offset,
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
            .ok_or_else(|| TgsError::from("append handle unexpectedly unavailable"))?;
        handle.write_all(bytes)?;
        self.offset = self.offset.saturating_add(bytes.len() as u64);
        Ok(offset)
    }

    fn retarget(&mut self, path: PathBuf) {
        self.path = path;
    }
}

#[derive(Debug)]
struct StoreAppendWriters {
    blooms: AppendFile,
    tier2_blooms: AppendFile,
    grams_received: AppendFile,
    grams_indexed: AppendFile,
    external_ids: AppendFile,
    sha_by_docid: AppendFile,
    doc_meta: AppendFile,
    tier2_doc_meta: AppendFile,
    df_counts_delta: AppendFile,
    df_counts_unit_delta: AppendFile,
}

impl StoreAppendWriters {
    fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            blooms: AppendFile::new(blooms_path(root))?,
            tier2_blooms: AppendFile::new(tier2_blooms_path(root))?,
            grams_received: AppendFile::new(grams_received_path(root))?,
            grams_indexed: AppendFile::new(grams_indexed_path(root))?,
            external_ids: AppendFile::new(external_ids_path(root))?,
            sha_by_docid: AppendFile::new(sha_by_docid_path(root))?,
            doc_meta: AppendFile::new(doc_meta_path(root))?,
            tier2_doc_meta: AppendFile::new(tier2_doc_meta_path(root))?,
            df_counts_delta: AppendFile::new(df_counts_delta_path(root))?,
            df_counts_unit_delta: AppendFile::new(df_counts_unit_delta_path(root))?,
        })
    }

    fn retarget_root(&mut self, root: &Path) {
        self.blooms.retarget(blooms_path(root));
        self.tier2_blooms.retarget(tier2_blooms_path(root));
        self.grams_received.retarget(grams_received_path(root));
        self.grams_indexed.retarget(grams_indexed_path(root));
        self.external_ids.retarget(external_ids_path(root));
        self.sha_by_docid.retarget(sha_by_docid_path(root));
        self.doc_meta.retarget(doc_meta_path(root));
        self.tier2_doc_meta.retarget(tier2_doc_meta_path(root));
        self.df_counts_delta.retarget(df_counts_delta_path(root));
        self.df_counts_unit_delta
            .retarget(df_counts_unit_delta_path(root));
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

#[derive(Clone, Debug)]
pub(crate) struct CandidateCompactionSnapshot {
    root: PathBuf,
    meta: StoreMeta,
    exact_gram_bytes: usize,
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
    grams_complete: bool,
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

#[derive(Clone, Copy, Debug)]
struct Tier1DfEntry {
    gram: u64,
    projected_df: usize,
    commonness: f64,
    tie_breaker: u64,
}

fn stable_tier1_tie_breaker(gram: u64, hash_seed: u64) -> u64 {
    let mixed = gram.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mixed.rotate_left(17) ^ hash_seed.rotate_right(7)
}

fn split_weighted_quota(total: usize, weights: &[usize]) -> Vec<usize> {
    if total == 0 {
        return vec![0; weights.len()];
    }
    let weight_total: usize = weights.iter().sum();
    let mut quotas = vec![0usize; weights.len()];
    let mut remainders = Vec::<(usize, usize)>::with_capacity(weights.len());
    let mut assigned = 0usize;
    for (index, weight) in weights.iter().copied().enumerate() {
        let numerator = total.saturating_mul(weight);
        let quota = numerator / weight_total.max(1);
        quotas[index] = quota;
        assigned = assigned.saturating_add(quota);
        remainders.push((numerator % weight_total.max(1), index));
    }
    remainders.sort_unstable_by(|left, right| right.cmp(left));
    for (_, index) in remainders.into_iter().take(total.saturating_sub(assigned)) {
        quotas[index] = quotas[index].saturating_add(1);
    }
    quotas
}

fn tier2_superblock_summary_bytes(filter_bytes: usize) -> usize {
    filter_bytes.max(1).min(MAX_TIER2_SUPERBLOCK_SUMMARY_BYTES)
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

fn fold_bloom_masks(required_masks: &[(usize, u8)], summary_bytes: usize) -> Vec<(usize, u8)> {
    let mut folded = BTreeMap::<usize, u8>::new();
    let summary_bytes = summary_bytes.max(1);
    for (byte_idx, mask) in required_masks {
        *folded.entry(*byte_idx % summary_bytes).or_insert(0) |= *mask;
    }
    folded.into_iter().collect()
}

fn median_value(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let middle = values.len() / 2;
    let cmp =
        |left: &f64, right: &f64| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal);
    if values.len() % 2 == 0 {
        let (left, right) = values.split_at_mut(middle);
        let (_, upper, _) = right.select_nth_unstable_by(0, cmp);
        let upper_value = *upper;
        let lower_value = left.iter().copied().max_by(cmp).unwrap_or(upper_value);
        (lower_value + upper_value) / 2.0
    } else {
        let (_, median, _) = values.select_nth_unstable_by(middle, cmp);
        *median
    }
}

fn tier1_budget_multiplier(effective_diversity: f64, commonness: f64) -> f64 {
    let diversity = effective_diversity.clamp(0.0, 1.0);
    let df = commonness.clamp(0.0, 1.0);
    if diversity >= 0.67 && df < 0.33 {
        0.80
    } else if diversity >= 0.67 && df >= 0.67 {
        0.90
    } else if diversity < 0.33 && df >= 0.67 {
        1.25
    } else if diversity < 0.33 && df < 0.33 {
        1.00
    } else {
        (1.0 + (df - 0.5) * 0.25 - (diversity - 0.5) * 0.15).clamp(0.85, 1.15)
    }
}

fn tier1_df_bin(commonness: f64) -> usize {
    if commonness < 0.25 {
        0
    } else if commonness < 0.50 {
        1
    } else if commonness < 0.75 {
        2
    } else {
        3
    }
}

fn tier1_df_bin_weights(effective_diversity: f64, commonness: f64) -> [usize; 4] {
    let diversity = effective_diversity.clamp(0.0, 1.0);
    let df = commonness.clamp(0.0, 1.0);
    if diversity >= 0.67 && df < 0.33 {
        [55, 28, 14, 3]
    } else if diversity >= 0.67 && df >= 0.67 {
        [48, 30, 17, 5]
    } else if diversity < 0.33 && df >= 0.67 {
        [35, 30, 20, 15]
    } else {
        [45, 30, 20, 5]
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
    df_counts: DfCountsState,
    mutation_counter: u64,
    compaction_generation: u64,
    retired_generation_roots: Vec<String>,
    last_write_activity_monotonic: Option<Instant>,
    tier2_superblocks: Tier2SuperblockIndex,
    tier2_telemetry: Tier2Telemetry,
    prepared_query_cache: BoundedCache<String, Arc<PreparedQueryArtifacts>>,
    memory_budget_bytes: u64,
    total_shards: usize,
    tier2_superblock_memory_budget_divisor: u64,
    tier2_superblock_memory_budget_bytes: u64,
    df_counts_delta_compact_threshold_bytes: u64,
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

fn df_counts_delta_compact_threshold_bytes(memory_budget_bytes: u64, total_shards: usize) -> u64 {
    if memory_budget_bytes == 0 || total_shards == 0 {
        return DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES;
    }
    let aggregate_budget = memory_budget_bytes / DF_COUNTS_DELTA_MEMORY_BUDGET_DIVISOR;
    let per_shard_budget = aggregate_budget / total_shards as u64;
    per_shard_budget.clamp(
        MIN_DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES,
        MAX_DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES,
    )
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
        let docs_path = docs_path(&config.root);
        let docs_log_path = docs_log_path(&config.root);
        let sha_path = sha_by_docid_path(&config.root);
        let doc_meta_path = doc_meta_path(&config.root);
        let tier2_doc_meta_path = tier2_doc_meta_path(&config.root);
        let blooms_path = blooms_path(&config.root);
        let tier2_blooms_path = tier2_blooms_path(&config.root);
        let grams_received_path = grams_received_path(&config.root);
        let grams_indexed_path = grams_indexed_path(&config.root);
        let external_ids_path = external_ids_path(&config.root);
        let df_counts_path = df_counts_path(&config.root);
        let df_delta_path = df_counts_delta_path(&config.root);
        let df_unit_delta_path = df_counts_unit_delta_path(&config.root);
        if !force
            && (meta_path.exists()
                || docs_path.exists()
                || docs_log_path.exists()
                || sha_path.exists()
                || doc_meta_path.exists()
                || tier2_doc_meta_path.exists()
                || blooms_path.exists()
                || tier2_blooms_path.exists()
                || grams_received_path.exists()
                || grams_indexed_path.exists()
                || external_ids_path.exists()
                || df_counts_path.exists()
                || df_delta_path.exists()
                || df_unit_delta_path.exists())
        {
            return Err(TgsError::from(format!(
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
            let _ = fs::remove_file(&docs_path);
            let _ = fs::remove_file(&docs_log_path);
            let _ = fs::remove_file(&sha_path);
            let _ = fs::remove_file(&doc_meta_path);
            let _ = fs::remove_file(&tier2_doc_meta_path);
            let _ = fs::remove_file(&blooms_path);
            let _ = fs::remove_file(&tier2_blooms_path);
            let _ = fs::remove_file(&grams_received_path);
            let _ = fs::remove_file(&grams_indexed_path);
            let _ = fs::remove_file(&external_ids_path);
            let _ = fs::remove_file(&df_counts_path);
            let _ = fs::remove_file(&df_delta_path);
            let _ = fs::remove_file(&df_unit_delta_path);
            let _ = fs::remove_file(&tier2_superblocks_path(&config.root));
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
                filter_target_fp: config.filter_target_fp,
                df_min: config.df_min,
                df_max: config.df_max,
                compaction_idle_cooldown_s: config.compaction_idle_cooldown_s.max(0.0),
            },
            docs: Vec::new(),
            doc_rows: Vec::new(),
            tier2_doc_rows: Vec::new(),
            sidecars: StoreSidecars::new(&config.root),
            append_writers: StoreAppendWriters::new(&config.root)?,
            sha_to_pos: HashMap::new(),
            df_counts: DfCountsState::default(),
            mutation_counter: 0,
            compaction_generation: 1,
            retired_generation_roots: Vec::new(),
            last_write_activity_monotonic: None,
            tier2_superblocks: Tier2SuperblockIndex::default(),
            tier2_telemetry: Tier2Telemetry::default(),
            prepared_query_cache: BoundedCache::new(PREPARED_QUERY_CACHE_CAPACITY),
            memory_budget_bytes: 0,
            total_shards: 1,
            tier2_superblock_memory_budget_divisor: DEFAULT_TIER2_SUPERBLOCK_MEMORY_BUDGET_DIVISOR,
            tier2_superblock_memory_budget_bytes: 0,
            df_counts_delta_compact_threshold_bytes: DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES,
            meta_persist_dirty: false,
            last_insert_batch_profile: CandidateInsertBatchProfile::default(),
            last_import_batch_profile: CandidateImportBatchProfile::default(),
        };
        store.df_counts = DfCountsState::load(&config.root, store.meta.exact_gram_bytes())?;
        store.persist_meta()?;
        store.persist_df_counts_snapshot()?;
        store.df_counts.refresh_snapshot(&config.root)?;
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
                TgsError::from(format!("Invalid candidate metadata at {}", root.display()))
            })?;
        let meta_ms = meta_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        if meta.version != STORE_VERSION {
            return Err(TgsError::from(format!(
                "Unsupported candidate store version: {}",
                meta.version
            )));
        }
        let load_state_started = Instant::now();
        let (docs, doc_rows, tier2_doc_rows) = load_candidate_store_state(&root, &meta)?;
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
            df_counts: DfCountsState::default(),
            mutation_counter: 0,
            compaction_generation: compaction_manifest.current_generation,
            retired_generation_roots: compaction_manifest.retired_roots,
            last_write_activity_monotonic: None,
            tier2_superblocks: Tier2SuperblockIndex::default(),
            tier2_telemetry: Tier2Telemetry::default(),
            prepared_query_cache: BoundedCache::new(PREPARED_QUERY_CACHE_CAPACITY),
            memory_budget_bytes: 0,
            total_shards: 1,
            tier2_superblock_memory_budget_divisor: DEFAULT_TIER2_SUPERBLOCK_MEMORY_BUDGET_DIVISOR,
            tier2_superblock_memory_budget_bytes: 0,
            df_counts_delta_compact_threshold_bytes: DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES,
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
            rebuild_df_counts_ms: rebuild_profile.df_counts_ms,
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
        self.df_counts_delta_compact_threshold_bytes =
            df_counts_delta_compact_threshold_bytes(memory_budget_bytes, self.total_shards);
        self.maybe_compact_df_counts()?;
        self.maybe_rebalance_tier2_superblocks()
    }

    pub fn config(&self) -> CandidateConfig {
        CandidateConfig {
            root: self.root.clone(),
            id_source: self.meta.id_source.clone(),
            store_path: self.meta.store_path,
            tier2_gram_size: self.meta.tier2_gram_size,
            tier1_gram_size: self.meta.tier1_gram_size,
            filter_target_fp: self.meta.filter_target_fp,
            df_min: self.meta.df_min,
            df_max: self.meta.df_max,
            compaction_idle_cooldown_s: self.meta.compaction_idle_cooldown_s,
        }
    }

    pub fn retarget_root(&mut self, root: impl AsRef<Path>) {
        let root = root.as_ref();
        self.root = root.to_path_buf();
        self.sidecars.retarget_root(root);
        self.append_writers.retarget_root(root);
    }

    pub fn df_counts(&self) -> HashMap<u64, usize> {
        let _scope = scope("candidate.df_counts");
        record_counter("candidate.df_counts_docs_total", self.docs.len() as u64);
        record_counter(
            "candidate.df_counts_unique_grams_total",
            self.df_counts.unique_count_hint() as u64,
        );
        self.df_counts.materialize()
    }

    pub fn df_counts_for(&self, grams: &[u64]) -> HashMap<u64, usize> {
        self.df_counts.get_many(grams)
    }

    fn mark_write_activity(&mut self) {
        self.mutation_counter = self.mutation_counter.saturating_add(1);
        self.last_write_activity_monotonic = Some(Instant::now());
        self.prepared_query_cache.clear();
    }

    pub fn deleted_storage_bytes(&self) -> u64 {
        let gram_bytes = self.meta.exact_gram_bytes() as u64;
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
                .saturating_add(row.grams_received_count as u64 * gram_bytes)
                .saturating_add(row.grams_indexed_count as u64 * gram_bytes)
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
                grams_complete: doc.grams_complete,
                row: *row,
                tier2_row: *tier2_row,
            });
        }

        Ok(Some(CandidateCompactionSnapshot {
            root: self.root.clone(),
            meta: self.meta.clone(),
            exact_gram_bytes: self.meta.exact_gram_bytes(),
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
        gram_count_estimate: Option<usize>,
    ) -> Result<usize> {
        choose_filter_bytes_for_file_size(
            file_size,
            DEFAULT_FILTER_BYTES,
            Some(DEFAULT_FILTER_MIN_BYTES),
            Some(DEFAULT_FILTER_MAX_BYTES),
            DEFAULT_FILTER_SIZE_DIVISOR,
            self.meta.filter_target_fp,
            gram_count_estimate,
        )
    }

    fn resolve_bloom_hashes_for_document(
        &self,
        filter_bytes: usize,
        gram_count_estimate: Option<usize>,
        bloom_hashes: Option<usize>,
    ) -> usize {
        derive_document_bloom_hash_count(
            filter_bytes,
            gram_count_estimate,
            bloom_hashes.unwrap_or(DEFAULT_BLOOM_HASHES),
        )
    }

    fn select_indexed_grams(
        &self,
        dedup_received: &[u64],
        gram_count_estimate: Option<usize>,
        effective_diversity: Option<f64>,
    ) -> (Vec<u64>, bool) {
        self.select_indexed_grams_with_active_docs(
            dedup_received,
            gram_count_estimate,
            effective_diversity,
            self.docs.iter().filter(|doc| !doc.deleted).count(),
        )
    }

    fn select_indexed_grams_with_active_docs(
        &self,
        dedup_received: &[u64],
        gram_count_estimate: Option<usize>,
        effective_diversity: Option<f64>,
        active_docs: usize,
    ) -> (Vec<u64>, bool) {
        if dedup_received.is_empty() {
            return (Vec::new(), false);
        }

        let base_budget = match gram_count_estimate {
            Some(estimate) if DEFAULT_TIER1_GRAM_BUDGET > 0 => {
                scale_tier1_gram_budget(DEFAULT_TIER1_GRAM_BUDGET, estimate)
            }
            _ => DEFAULT_TIER1_GRAM_BUDGET,
        };
        let mut eligible = Vec::<Tier1DfEntry>::new();
        let mut commonness_values = Vec::<f64>::new();
        let mut complete = true;
        let active_docs = active_docs.max(1);
        let projected = if is_strictly_sorted_unique(dedup_received) {
            self.df_counts.get_many_sorted_counts(dedup_received)
        } else {
            dedup_received
                .iter()
                .map(|gram| self.df_counts.get(*gram))
                .collect()
        };
        let df_log_denominator = ((active_docs as f64) + 1.0).ln().max(1.0);
        for (gram, current_df) in dedup_received.iter().zip(projected.into_iter()) {
            let projected_df = current_df + 1;
            if projected_df < self.meta.df_min
                || (self.meta.df_max != 0 && projected_df > self.meta.df_max)
            {
                complete = false;
                continue;
            }
            let commonness =
                ((((projected_df as f64) + 1.0).ln()) / df_log_denominator).clamp(0.0, 1.0);
            commonness_values.push(commonness);
            eligible.push(Tier1DfEntry {
                gram: *gram,
                projected_df,
                commonness,
                tie_breaker: stable_tier1_tie_breaker(*gram, DEFAULT_TIER1_GRAM_HASH_SEED),
            });
        }
        if eligible.len() == dedup_received.len() && DEFAULT_TIER1_GRAM_BUDGET == 0 {
            let mut grams = eligible
                .into_iter()
                .map(|entry| entry.gram)
                .collect::<Vec<_>>();
            grams.sort_unstable();
            return (grams, complete);
        }
        if eligible.is_empty() {
            return (Vec::new(), false);
        }

        let doc_diversity = effective_diversity.unwrap_or(0.5).clamp(0.0, 1.0);
        let min_adjusted_budget = if base_budget == 0 {
            eligible.len()
        } else {
            ((base_budget as f64) * 0.80).floor() as usize
        };
        if min_adjusted_budget >= eligible.len() {
            let mut grams = eligible
                .into_iter()
                .map(|entry| entry.gram)
                .collect::<Vec<_>>();
            grams.sort_unstable();
            return (grams, complete);
        }
        let doc_commonness = median_value(&mut commonness_values);
        let adjusted_budget = if base_budget == 0 {
            eligible.len()
        } else {
            ((base_budget as f64) * tier1_budget_multiplier(doc_diversity, doc_commonness))
                .round()
                .max(1.0) as usize
        };
        if adjusted_budget >= eligible.len() {
            let mut grams = eligible
                .into_iter()
                .map(|entry| entry.gram)
                .collect::<Vec<_>>();
            grams.sort_unstable();
            return (grams, complete);
        }

        let weights = tier1_df_bin_weights(doc_diversity, doc_commonness);
        let quotas = split_weighted_quota(adjusted_budget, &weights);
        let mut bins = [
            Vec::<Tier1DfEntry>::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ];
        for entry in eligible {
            bins[tier1_df_bin(entry.commonness)].push(entry);
        }
        for bin in &mut bins {
            bin.sort_unstable_by_key(|entry| (entry.projected_df, entry.tie_breaker, entry.gram));
        }

        let mut selected = Vec::<u64>::new();
        let mut leftovers = Vec::<Tier1DfEntry>::new();
        for (bin, quota) in bins.iter_mut().zip(quotas.into_iter()) {
            let take = quota.min(bin.len());
            for entry in bin.drain(..take) {
                selected.push(entry.gram);
            }
            leftovers.extend(bin.drain(..));
        }
        if selected.len() < adjusted_budget && !leftovers.is_empty() {
            leftovers
                .sort_unstable_by_key(|entry| (entry.projected_df, entry.tie_breaker, entry.gram));
            for entry in leftovers.into_iter().take(adjusted_budget - selected.len()) {
                selected.push(entry.gram);
            }
        }
        selected.sort_unstable();
        (selected, false)
    }

    pub fn insert_document(
        &mut self,
        sha256: [u8; 32],
        file_size: u64,
        gram_count_estimate: Option<usize>,
        bloom_hashes: Option<usize>,
        tier2_gram_count_estimate: Option<usize>,
        tier2_bloom_hashes: Option<usize>,
        filter_bytes: usize,
        bloom_filter: &[u8],
        tier2_filter_bytes: usize,
        tier2_bloom_filter: &[u8],
        grams_received: &[u64],
        grams_complete: bool,
        effective_diversity: Option<f64>,
        external_id: Option<String>,
        grams_sorted_unique: bool,
    ) -> Result<CandidateInsertResult> {
        let mut total_scope = scope("candidate.insert_document");
        total_scope.add_bytes(file_size);
        if filter_bytes == 0 {
            return Err(TgsError::from("filter_bytes must be > 0"));
        }
        let expected_filter_bytes =
            self.resolve_filter_bytes_for_file_size(file_size, gram_count_estimate)?;
        let expected_bloom_hashes = self.resolve_bloom_hashes_for_document(
            expected_filter_bytes,
            gram_count_estimate,
            bloom_hashes,
        );
        if filter_bytes != expected_filter_bytes {
            return Err(TgsError::from(format!(
                "filter_bytes must equal expected filter size ({expected_filter_bytes})"
            )));
        }
        if bloom_filter.len() != expected_filter_bytes {
            return Err(TgsError::from(format!(
                "bloom_filter length must equal filter_bytes ({expected_filter_bytes})"
            )));
        }
        let expected_tier2_filter_bytes =
            self.resolve_filter_bytes_for_file_size(file_size, tier2_gram_count_estimate)?;
        let expected_tier2_bloom_hashes = self.resolve_bloom_hashes_for_document(
            expected_tier2_filter_bytes,
            tier2_gram_count_estimate,
            tier2_bloom_hashes,
        );
        if !tier2_bloom_filter.is_empty() {
            if tier2_filter_bytes != expected_tier2_filter_bytes {
                return Err(TgsError::from(format!(
                    "tier2_filter_bytes must equal expected filter size ({expected_tier2_filter_bytes})"
                )));
            }
            if tier2_bloom_filter.len() != expected_tier2_filter_bytes {
                return Err(TgsError::from(format!(
                    "tier2_bloom_filter length must equal tier2_filter_bytes ({expected_tier2_filter_bytes})"
                )));
            }
        }
        let sha256_hex = hex::encode(sha256);

        let dedup_received = if grams_sorted_unique {
            let mut ordered = Vec::with_capacity(grams_received.len());
            let mut prev = None;
            let mut valid = true;
            for gram in grams_received {
                if prev.is_some_and(|value| *gram <= value) {
                    valid = false;
                    break;
                }
                ordered.push(*gram);
                prev = Some(*gram);
            }
            if valid {
                ordered
            } else {
                let mut dedup: Vec<u64> = grams_received
                    .iter()
                    .copied()
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                dedup.sort_unstable();
                dedup
            }
        } else {
            let mut dedup: Vec<u64> = grams_received
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            dedup.sort_unstable();
            dedup
        };

        let (indexed, selection_complete) =
            self.select_indexed_grams(&dedup_received, gram_count_estimate, effective_diversity);
        let complete =
            grams_complete && selection_complete && indexed.len() == dedup_received.len();

        let status;
        let doc_id;
        let mut df_unit_delta_payload =
            Vec::with_capacity(dedup_received.len() * self.meta.exact_gram_bytes());
        extend_unit_df_payload_from_values(
            &mut df_unit_delta_payload,
            &dedup_received,
            self.meta.exact_gram_bytes(),
        );
        if let Some(existing_pos) = self.sha_to_pos.get(&sha256_hex).copied() {
            if !self.docs[existing_pos].deleted {
                let existing = &self.docs[existing_pos];
                let existing_row = self.doc_rows[existing_pos];
                return Ok(CandidateInsertResult {
                    status: "already_exists".to_owned(),
                    doc_id: existing.doc_id,
                    sha256: existing.sha256.clone(),
                    grams_received: existing_row.grams_received_count as usize,
                    grams_indexed: existing_row.grams_indexed_count as usize,
                    grams_complete: existing.grams_complete,
                });
            }
            self.df_counts.apply_unit_deltas(&dedup_received);
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
                existing.grams_complete = complete;
                existing.deleted = false;
                existing.clone()
            };
            let row = self.build_doc_row(
                snapshot.file_size,
                snapshot.filter_bytes,
                snapshot.bloom_hashes,
                snapshot.grams_complete,
                snapshot.deleted,
                external_id.as_deref(),
                bloom_filter,
                &dedup_received,
                &indexed,
            )?;
            let tier2_row = self.build_doc_row5(
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
                self.write_doc_row5(snapshot.doc_id, tier2_row)?;
            }
            self.update_tier2_superblocks_for_doc_bytes_inner(existing_pos, bloom_filter)?;
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
                grams_complete: complete,
                deleted: false,
            };
            self.df_counts.apply_unit_deltas(&dedup_received);
            {
                let _scope = scope("candidate.insert_document.persist");
                let row = self.build_doc_row(
                    doc.file_size,
                    doc.filter_bytes,
                    doc.bloom_hashes,
                    doc.grams_complete,
                    doc.deleted,
                    external_id.as_deref(),
                    bloom_filter,
                    &dedup_received,
                    &indexed,
                )?;
                let tier2_row = self.build_doc_row5(
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
            self.update_tier2_superblocks_for_doc_bytes_inner(self.docs.len() - 1, bloom_filter)?;
            self.maybe_rebalance_tier2_superblocks()?;
            status = "inserted".to_owned();
        }

        append_df_count_unit_payload_with_writer(
            &mut self.append_writers.df_counts_unit_delta,
            &df_unit_delta_payload,
        )?;
        self.maybe_compact_df_counts()?;
        self.sidecars.invalidate_all();

        self.mark_write_activity();
        total_scope.add_items(dedup_received.len() as u64);
        record_counter(
            "candidate.insert_document_received_grams_total",
            dedup_received.len() as u64,
        );
        record_counter(
            "candidate.insert_document_indexed_grams_total",
            indexed.len() as u64,
        );
        record_max(
            "candidate.insert_document_max_received_grams",
            dedup_received.len() as u64,
        );
        record_max(
            "candidate.insert_document_max_indexed_grams",
            indexed.len() as u64,
        );
        Ok(CandidateInsertResult {
            status,
            doc_id,
            sha256: sha256_hex,
            grams_received: dedup_received.len(),
            grams_indexed: indexed.len(),
            grams_complete: complete,
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
            Vec<u64>,
            bool,
            Option<f64>,
            Option<String>,
            bool,
        )],
    ) -> Result<Vec<CandidateInsertResult>> {
        fn elapsed_us(started: Instant) -> u64 {
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
        }

        struct PendingNewInsert<'a> {
            sha256: [u8; 32],
            sha256_hex: String,
            doc: CandidateDoc,
            external_id: Option<&'a str>,
            bloom_filter: &'a [u8],
            tier2_bloom_filter: &'a [u8],
            dedup_received: Vec<u64>,
            indexed: Vec<u64>,
        }

        let mut total_scope = scope("candidate.insert_documents_batch");
        let mut results = Vec::with_capacity(documents.len());
        let mut aggregate_df_unit_delta_payload = Vec::<u8>::new();
        let mut modified = false;
        let mut meta_dirty = false;
        let mut insert_profile = CandidateInsertBatchProfile::default();
        let mut received_grams_total = 0u64;
        let mut indexed_grams_total = 0u64;
        let mut max_received_grams = 0u64;
        let mut max_indexed_grams = 0u64;
        let mut active_docs = self.docs.iter().filter(|doc| !doc.deleted).count();
        let mut tier2_updates = Vec::<(usize, usize, usize, &[u8])>::with_capacity(documents.len());
        let mut pending_new_inserts = Vec::<PendingNewInsert<'_>>::new();

        for document in documents {
            let (
                sha256,
                file_size,
                gram_count_estimate,
                bloom_hashes,
                tier2_gram_count_estimate,
                tier2_bloom_hashes,
                filter_bytes,
                bloom_filter,
                tier2_filter_bytes,
                tier2_bloom_filter,
                grams_received,
                grams_complete,
                effective_diversity,
                external_id,
                grams_sorted_unique,
            ) = document;
            total_scope.add_bytes(*file_size);
            if *filter_bytes == 0 {
                return Err(TgsError::from("filter_bytes must be > 0"));
            }
            let expected_filter_bytes =
                self.resolve_filter_bytes_for_file_size(*file_size, *gram_count_estimate)?;
            let expected_bloom_hashes = self.resolve_bloom_hashes_for_document(
                expected_filter_bytes,
                *gram_count_estimate,
                *bloom_hashes,
            );
            if *filter_bytes != expected_filter_bytes {
                self.last_insert_batch_profile = insert_profile;
                return Err(TgsError::from(format!(
                    "filter_bytes must equal expected filter size ({expected_filter_bytes})"
                )));
            }
            if bloom_filter.len() != expected_filter_bytes {
                self.last_insert_batch_profile = insert_profile;
                return Err(TgsError::from(format!(
                    "bloom_filter length must equal filter_bytes ({expected_filter_bytes})"
                )));
            }
            let expected_tier2_filter_bytes =
                self.resolve_filter_bytes_for_file_size(*file_size, *tier2_gram_count_estimate)?;
            let expected_tier2_bloom_hashes = self.resolve_bloom_hashes_for_document(
                expected_tier2_filter_bytes,
                *tier2_gram_count_estimate,
                *tier2_bloom_hashes,
            );
            if !tier2_bloom_filter.is_empty() {
                if *tier2_filter_bytes != expected_tier2_filter_bytes {
                    self.last_insert_batch_profile = insert_profile;
                    return Err(TgsError::from(format!(
                        "tier2_filter_bytes must equal expected filter size ({expected_tier2_filter_bytes})"
                    )));
                }
                if tier2_bloom_filter.len() != expected_tier2_filter_bytes {
                    self.last_insert_batch_profile = insert_profile;
                    return Err(TgsError::from(format!(
                        "tier2_bloom_filter length must equal tier2_filter_bytes ({expected_tier2_filter_bytes})"
                    )));
                }
            }

            let classify_started = Instant::now();
            let sha256_hex = hex::encode(sha256);
            let dedup_received = if *grams_sorted_unique {
                let mut ordered = Vec::with_capacity(grams_received.len());
                let mut prev = None;
                let mut valid = true;
                for gram in grams_received {
                    if prev.is_some_and(|value| *gram <= value) {
                        valid = false;
                        break;
                    }
                    ordered.push(*gram);
                    prev = Some(*gram);
                }
                if valid {
                    ordered
                } else {
                    let mut dedup: Vec<u64> = grams_received
                        .iter()
                        .copied()
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect();
                    dedup.sort_unstable();
                    dedup
                }
            } else {
                let mut dedup: Vec<u64> = grams_received
                    .iter()
                    .copied()
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                dedup.sort_unstable();
                dedup
            };

            let (indexed, selection_complete) = self.select_indexed_grams_with_active_docs(
                &dedup_received,
                *gram_count_estimate,
                *effective_diversity,
                active_docs,
            );
            let complete =
                *grams_complete && selection_complete && indexed.len() == dedup_received.len();
            let received_len = dedup_received.len() as u64;
            let indexed_len = indexed.len() as u64;
            received_grams_total = received_grams_total.saturating_add(received_len);
            indexed_grams_total = indexed_grams_total.saturating_add(indexed_len);
            max_received_grams = max_received_grams.max(received_len);
            max_indexed_grams = max_indexed_grams.max(indexed_len);
            extend_unit_df_payload_from_values(
                &mut aggregate_df_unit_delta_payload,
                &dedup_received,
                self.meta.exact_gram_bytes(),
            );

            if let Some(existing_pos) = self.sha_to_pos.get(&sha256_hex).copied() {
                if !self.docs[existing_pos].deleted {
                    let existing = &self.docs[existing_pos];
                    let existing_row = self.doc_rows[existing_pos];
                    results.push(CandidateInsertResult {
                        status: "already_exists".to_owned(),
                        doc_id: existing.doc_id,
                        sha256: existing.sha256.clone(),
                        grams_received: existing_row.grams_received_count as usize,
                        grams_indexed: existing_row.grams_indexed_count as usize,
                        grams_complete: existing.grams_complete,
                    });
                    insert_profile.classify_us = insert_profile
                        .classify_us
                        .saturating_add(elapsed_us(classify_started));
                    continue;
                }

                insert_profile.classify_us = insert_profile
                    .classify_us
                    .saturating_add(elapsed_us(classify_started));
                let apply_df_counts_started = Instant::now();
                self.df_counts.apply_unit_deltas(&dedup_received);
                insert_profile.apply_df_counts_us = insert_profile
                    .apply_df_counts_us
                    .saturating_add(elapsed_us(apply_df_counts_started));
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
                    existing.grams_complete = complete;
                    existing.deleted = false;
                    existing.clone()
                };
                let row = self.build_doc_row(
                    snapshot.file_size,
                    snapshot.filter_bytes,
                    snapshot.bloom_hashes,
                    snapshot.grams_complete,
                    snapshot.deleted,
                    external_id.as_deref(),
                    bloom_filter,
                    &dedup_received,
                    &indexed,
                )?;
                let tier2_row = self.build_doc_row5(
                    snapshot.tier2_filter_bytes,
                    snapshot.tier2_bloom_hashes,
                    tier2_bloom_filter,
                )?;
                self.doc_rows[existing_pos] = row;
                self.tier2_doc_rows[existing_pos] = tier2_row;
                self.write_doc_row(snapshot.doc_id, row)?;
                self.write_doc_row5(snapshot.doc_id, tier2_row)?;
                insert_profile.write_existing_us = insert_profile
                    .write_existing_us
                    .saturating_add(elapsed_us(write_existing_started));
                tier2_updates.push((
                    existing_pos,
                    *filter_bytes,
                    expected_bloom_hashes,
                    bloom_filter,
                ));
                modified = true;
                results.push(CandidateInsertResult {
                    status: "restored".to_owned(),
                    doc_id: snapshot.doc_id,
                    sha256: sha256_hex,
                    grams_received: dedup_received.len(),
                    grams_indexed: indexed.len(),
                    grams_complete: complete,
                });
                active_docs = active_docs.saturating_add(1);
                continue;
            }

            insert_profile.classify_us = insert_profile
                .classify_us
                .saturating_add(elapsed_us(classify_started));
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
                grams_complete: complete,
                deleted: false,
            };
            let apply_df_counts_started = Instant::now();
            self.df_counts.apply_unit_deltas(&dedup_received);
            insert_profile.apply_df_counts_us = insert_profile
                .apply_df_counts_us
                .saturating_add(elapsed_us(apply_df_counts_started));
            modified = true;
            meta_dirty = true;
            results.push(CandidateInsertResult {
                status: "inserted".to_owned(),
                doc_id,
                sha256: sha256_hex,
                grams_received: dedup_received.len(),
                grams_indexed: indexed.len(),
                grams_complete: complete,
            });
            pending_new_inserts.push(PendingNewInsert {
                sha256: *sha256,
                sha256_hex: doc.sha256.clone(),
                doc,
                external_id: external_id.as_deref(),
                bloom_filter,
                tier2_bloom_filter,
                dedup_received,
                indexed,
            });
            active_docs = active_docs.saturating_add(1);
        }

        if !pending_new_inserts.is_empty() {
            let append_sidecars_started = Instant::now();
            let bloom_base = self.append_writers.blooms.offset;
            let tier2_bloom_base = self.append_writers.tier2_blooms.offset;
            let mut blooms_payload = Vec::<u8>::new();
            let mut tier2_blooms_payload = Vec::<u8>::new();
            let mut bloom_offsets = Vec::<u64>::with_capacity(pending_new_inserts.len());
            let mut tier2_bloom_offsets = Vec::<u64>::with_capacity(pending_new_inserts.len());
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
            let append_bloom_started = Instant::now();
            self.append_writers.blooms.append(&blooms_payload)?;
            insert_profile.append_bloom_payload_us = insert_profile
                .append_bloom_payload_us
                .saturating_add(elapsed_us(append_bloom_started));
            insert_profile.append_bloom_payload_bytes = insert_profile
                .append_bloom_payload_bytes
                .saturating_add(blooms_payload.len() as u64);
            let append_tier2_bloom_started = Instant::now();
            self.append_writers
                .tier2_blooms
                .append(&tier2_blooms_payload)?;
            insert_profile.append_tier2_bloom_payload_us = insert_profile
                .append_tier2_bloom_payload_us
                .saturating_add(elapsed_us(append_tier2_bloom_started));
            insert_profile.append_tier2_bloom_payload_bytes = insert_profile
                .append_tier2_bloom_payload_bytes
                .saturating_add(tier2_blooms_payload.len() as u64);

            for ((pending, bloom_offset), tier2_bloom_offset) in pending_new_inserts
                .into_iter()
                .zip(bloom_offsets.into_iter())
                .zip(tier2_bloom_offsets.into_iter())
            {
                let (row, row_profile) = self.build_doc_row_with_bloom_offset_profile(
                    pending.doc.file_size,
                    pending.doc.filter_bytes,
                    pending.doc.bloom_hashes,
                    pending.doc.grams_complete,
                    pending.doc.deleted,
                    pending.external_id,
                    bloom_offset,
                    pending.bloom_filter.len(),
                    &pending.dedup_received,
                    &pending.indexed,
                )?;
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
                insert_profile.append_grams_received_payload_us = insert_profile
                    .append_grams_received_payload_us
                    .saturating_add(row_profile.grams_received_us);
                insert_profile.append_grams_received_payload_bytes = insert_profile
                    .append_grams_received_payload_bytes
                    .saturating_add(row_profile.grams_received_bytes);
                insert_profile.append_grams_indexed_payload_us = insert_profile
                    .append_grams_indexed_payload_us
                    .saturating_add(row_profile.grams_indexed_us);
                insert_profile.append_grams_indexed_payload_bytes = insert_profile
                    .append_grams_indexed_payload_bytes
                    .saturating_add(row_profile.grams_indexed_bytes);
                insert_profile.append_external_id_payload_us = insert_profile
                    .append_external_id_payload_us
                    .saturating_add(row_profile.external_id_us);
                insert_profile.append_external_id_payload_bytes = insert_profile
                    .append_external_id_payload_bytes
                    .saturating_add(row_profile.external_id_bytes);
                let append_doc_records_started = Instant::now();
                self.append_new_doc(&pending.sha256, row, tier2_row)?;
                insert_profile.append_doc_records_us = insert_profile
                    .append_doc_records_us
                    .saturating_add(elapsed_us(append_doc_records_started));
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
            }
            insert_profile.append_sidecar_payloads_us =
                insert_profile.append_sidecar_payloads_us.saturating_add(
                    insert_profile
                        .append_bloom_payload_us
                        .saturating_add(insert_profile.append_grams_received_payload_us)
                        .saturating_add(insert_profile.append_grams_indexed_payload_us)
                        .saturating_add(insert_profile.append_external_id_payload_us)
                        .saturating_add(insert_profile.append_tier2_bloom_payload_us),
                );
            insert_profile.append_sidecars_us = insert_profile
                .append_sidecars_us
                .saturating_add(elapsed_us(append_sidecars_started));
        }

        if modified {
            let tier2_update_started = Instant::now();
            self.update_tier2_superblocks_for_doc_bytes_batch(&tier2_updates)?;
            insert_profile.tier2_update_us = insert_profile
                .tier2_update_us
                .saturating_add(elapsed_us(tier2_update_started));
            if meta_dirty {
                self.mark_meta_dirty();
            }
            let append_df_delta_started = Instant::now();
            append_df_count_unit_payload_with_writer(
                &mut self.append_writers.df_counts_unit_delta,
                &aggregate_df_unit_delta_payload,
            )?;
            insert_profile.append_df_delta_us = insert_profile
                .append_df_delta_us
                .saturating_add(elapsed_us(append_df_delta_started));
            let compact_df_counts_started = Instant::now();
            self.maybe_compact_df_counts()?;
            insert_profile.compact_df_counts_us = insert_profile
                .compact_df_counts_us
                .saturating_add(elapsed_us(compact_df_counts_started));
            let rebalance_tier2_started = Instant::now();
            self.maybe_rebalance_tier2_superblocks()?;
            insert_profile.rebalance_tier2_us = insert_profile
                .rebalance_tier2_us
                .saturating_add(elapsed_us(rebalance_tier2_started));
            self.sidecars.invalidate_all();
            self.mark_write_activity();
            total_scope.add_items(received_grams_total);
            record_counter(
                "candidate.insert_document_received_grams_total",
                received_grams_total,
            );
            record_counter(
                "candidate.insert_document_indexed_grams_total",
                indexed_grams_total,
            );
            record_max(
                "candidate.insert_document_max_received_grams",
                max_received_grams,
            );
            record_max(
                "candidate.insert_document_max_indexed_grams",
                max_indexed_grams,
            );
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
            let grams_received = self.doc_grams_received(pos)?;
            let df_deltas = grams_received
                .iter()
                .map(|gram| (*gram, -1))
                .collect::<Vec<_>>();
            self.df_counts.apply_deltas(&df_deltas);
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
            self.rebuild_tier2_superblocks()?;
            append_df_count_deltas_with_writer(
                &mut self.append_writers.df_counts_delta,
                self.meta.exact_gram_bytes(),
                &df_deltas,
            )?;
            self.maybe_compact_df_counts()?;
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
                grams_received_bytes: self.doc_received_bytes(pos)?.into_owned(),
                grams_received_count: self.doc_rows[pos].grams_received_count as usize,
                grams_indexed_bytes: self.doc_indexed_bytes(pos)?.into_owned(),
                grams_indexed_count: self.doc_rows[pos].grams_indexed_count as usize,
                grams_complete: doc.grams_complete,
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
        let mut aggregate_df_unit_delta_payload = Vec::<u8>::new();
        let mut pending_inserts = Vec::<PendingImportedInsert<'_>>::new();
        let mut modified = false;
        let mut meta_dirty = false;
        let mut received_grams_total = 0u64;
        let mut indexed_grams_total = 0u64;
        let mut max_received_grams = 0u64;
        let mut max_indexed_grams = 0u64;
        let gram_bytes = self.meta.exact_gram_bytes();
        let mut import_profile = CandidateImportBatchProfile::default();

        let classify_started = Instant::now();
        for document in documents {
            total_scope.add_bytes(document.file_size);
            let sha256_hex = document.sha256_hex.clone();
            let received_len = document.grams_received_count as u64;
            let indexed_len = document.grams_indexed_count as u64;
            received_grams_total = received_grams_total.saturating_add(received_len);
            indexed_grams_total = indexed_grams_total.saturating_add(indexed_len);
            max_received_grams = max_received_grams.max(received_len);
            max_indexed_grams = max_indexed_grams.max(indexed_len);
            extend_unit_df_payload_from_packed(
                &mut aggregate_df_unit_delta_payload,
                &document.grams_received_bytes,
                gram_bytes,
            )?;

            if !assume_new {
                if let Some(existing_pos) = self.sha_to_pos.get(&sha256_hex).copied() {
                    if !self.docs[existing_pos].deleted {
                        let existing = &self.docs[existing_pos];
                        let existing_row = self.doc_rows[existing_pos];
                        if collect_results {
                            results.push(CandidateInsertResult {
                                status: "already_exists".to_owned(),
                                doc_id: existing.doc_id,
                                sha256: existing.sha256.clone(),
                                grams_received: existing_row.grams_received_count as usize,
                                grams_indexed: existing_row.grams_indexed_count as usize,
                                grams_complete: existing.grams_complete,
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
                        existing.grams_complete = document.grams_complete;
                        existing.deleted = false;
                        existing.clone()
                    };
                    let row = self.build_doc_row(
                        snapshot.file_size,
                        snapshot.filter_bytes,
                        snapshot.bloom_hashes,
                        snapshot.grams_complete,
                        snapshot.deleted,
                        document.external_id.as_deref(),
                        &document.bloom_filter,
                        &decode_exact_gram_vec(&document.grams_received_bytes, gram_bytes)?,
                        &decode_exact_gram_vec(&document.grams_indexed_bytes, gram_bytes)?,
                    )?;
                    let tier2_row = self.build_doc_row5(
                        snapshot.tier2_filter_bytes,
                        snapshot.tier2_bloom_hashes,
                        &document.tier2_bloom_filter,
                    )?;
                    self.doc_rows[existing_pos] = row;
                    self.tier2_doc_rows[existing_pos] = tier2_row;
                    self.write_doc_row(snapshot.doc_id, row)?;
                    self.write_doc_row5(snapshot.doc_id, tier2_row)?;
                    self.update_tier2_superblocks_for_doc_bytes_inner(
                        existing_pos,
                        &document.bloom_filter,
                    )?;
                    modified = true;
                    if collect_results {
                        results.push(CandidateInsertResult {
                            status: "restored".to_owned(),
                            doc_id: snapshot.doc_id,
                            sha256: sha256_hex,
                            grams_received: document.grams_received_count,
                            grams_indexed: document.grams_indexed_count,
                            grams_complete: document.grams_complete,
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
        import_profile.classify_ms = classify_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);

        if !pending_inserts.is_empty() {
            let bloom_base = self.append_writers.blooms.offset;
            let grams_received_base = self.append_writers.grams_received.offset;
            let grams_indexed_base = self.append_writers.grams_indexed.offset;
            let external_ids_base = self.append_writers.external_ids.offset;
            let tier2_blooms_base = self.append_writers.tier2_blooms.offset;
            let mut blooms_payload = Vec::<u8>::new();
            let mut grams_received_payload = Vec::<u8>::new();
            let mut grams_indexed_payload = Vec::<u8>::new();
            let mut external_ids_payload = Vec::<u8>::new();
            let mut tier2_blooms_payload = Vec::<u8>::new();
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
                bool,
            )>::with_capacity(pending_inserts.len());

            let build_payloads_started = Instant::now();
            for pending in pending_inserts {
                let document = pending.document;
                let bloom_offset = bloom_base + blooms_payload.len() as u64;
                blooms_payload.extend_from_slice(&document.bloom_filter);

                let grams_received_offset =
                    grams_received_base + grams_received_payload.len() as u64;
                grams_received_payload.extend_from_slice(&document.grams_received_bytes);

                let grams_indexed_offset = grams_indexed_base + grams_indexed_payload.len() as u64;
                grams_indexed_payload.extend_from_slice(&document.grams_indexed_bytes);

                let (external_id_offset, external_id_len) =
                    if let Some(external_id) = document.external_id.as_deref() {
                        let bytes = external_id.as_bytes();
                        let offset = external_ids_base + external_ids_payload.len() as u64;
                        external_ids_payload.extend_from_slice(bytes);
                        (offset, bytes.len() as u32)
                    } else {
                        (0, 0)
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
                    flags: u8::from(document.grams_complete) * DOC_FLAG_GRAMS_COMPLETE,
                    bloom_hashes: document.bloom_hashes.min(u8::MAX as usize) as u8,
                    bloom_offset,
                    bloom_len: document.bloom_filter.len() as u32,
                    grams_received_offset,
                    grams_received_count: document.grams_received_count as u32,
                    grams_indexed_offset,
                    grams_indexed_count: document.grams_indexed_count as u32,
                    external_id_offset,
                    external_id_len,
                };

                let doc = CandidateDoc {
                    doc_id: pending.doc_id,
                    sha256: pending.sha256_hex.clone(),
                    file_size: document.file_size,
                    filter_bytes: document.filter_bytes,
                    bloom_hashes: document.bloom_hashes,
                    tier2_filter_bytes: document.tier2_filter_bytes,
                    tier2_bloom_hashes: document.tier2_bloom_hashes,
                    grams_complete: document.grams_complete,
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
                    document.grams_received_count,
                    document.grams_indexed_count,
                    document.grams_complete,
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
                .grams_received
                .append(&grams_received_payload)?;
            self.append_writers
                .grams_indexed
                .append(&grams_indexed_payload)?;
            self.append_writers
                .external_ids
                .append(&external_ids_payload)?;
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
            let install_docs_started = Instant::now();
            for (
                doc,
                row,
                tier2_row,
                sha256_hex,
                filter_bytes,
                bloom_hashes,
                bloom_filter,
                grams_received_len,
                grams_indexed_len,
                grams_complete,
            ) in prepared
            {
                self.doc_rows.push(row);
                self.tier2_doc_rows.push(tier2_row);
                let pos = self.docs.len();
                self.docs.push(doc.clone());
                self.sha_to_pos.insert(sha256_hex.clone(), pos);
                tier2_updates.push((pos, filter_bytes, bloom_hashes, bloom_filter));
                if collect_results {
                    results.push(CandidateInsertResult {
                        status: "inserted".to_owned(),
                        doc_id: doc.doc_id,
                        sha256: sha256_hex,
                        grams_received: grams_received_len,
                        grams_indexed: grams_indexed_len,
                        grams_complete,
                    });
                }
            }
            import_profile.install_docs_ms = install_docs_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            let tier2_update_started = Instant::now();
            self.update_tier2_superblocks_for_doc_bytes_batch(&tier2_updates)?;
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
            let append_df_delta_started = Instant::now();
            append_df_count_unit_payload_with_writer(
                &mut self.append_writers.df_counts_unit_delta,
                &aggregate_df_unit_delta_payload,
            )?;
            import_profile.append_df_delta_ms = append_df_delta_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            let rebalance_tier2_started = Instant::now();
            self.maybe_rebalance_tier2_superblocks()?;
            import_profile.rebalance_tier2_ms = rebalance_tier2_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            self.sidecars.invalidate_all();
            self.mark_write_activity();
            total_scope.add_items(received_grams_total);
            record_counter(
                "candidate.insert_document_received_grams_total",
                received_grams_total,
            );
            record_counter(
                "candidate.insert_document_indexed_grams_total",
                indexed_grams_total,
            );
            record_max(
                "candidate.insert_document_max_received_grams",
                max_received_grams,
            );
            record_max(
                "candidate.insert_document_max_indexed_grams",
                max_indexed_grams,
            );
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
            });
        }
        let (mut matched_hits, used_tiers, docs_scanned, superblocks_skipped) =
            self.scan_query_hits(plan, prepared)?;
        let (page, page_scores, total, start, end, next_cursor) =
            paginate_query_hits(&mut matched_hits, plan.max_candidates, cursor, chunk_size);
        total_scope.add_items(docs_scanned);
        record_counter(
            "candidate.query_candidates_docs_scanned_total",
            docs_scanned,
        );
        record_counter(
            "candidate.query_candidates_matches_total",
            matched_hits.len() as u64,
        );
        record_counter(
            "candidate.query_candidates_superblocks_skipped_total",
            superblocks_skipped,
        );
        record_max(
            "candidate.query_candidates_max_matches",
            matched_hits.len() as u64,
        );
        self.record_query_metrics(docs_scanned, matched_hits.len() as u64, superblocks_skipped);

        Ok(CandidateQueryResult {
            sha256: page,
            scores: page_scores,
            total_candidates: total,
            returned_count: end.saturating_sub(start),
            cursor: start,
            next_cursor,
            tier_used: used_tiers.as_label(),
        })
    }

    fn scan_query_hits(
        &self,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
    ) -> Result<(Vec<(String, u32)>, TierFlags, u64, u64)> {
        let mut matched_hits = Vec::<(String, u32)>::new();
        let mut used_tiers = TierFlags::default();
        let mut docs_scanned = 0u64;
        let mut superblocks_skipped = 0u64;
        let docs_per_block = self.tier2_superblocks.docs_per_block.max(1);
        let block_count = self.tier2_superblocks.keys_per_block.len();
        let allow_block_skip = !plan.force_tier1_only && plan.allow_tier2_fallback;

        for block_idx in 0..block_count {
            if allow_block_skip
                && !block_maybe_matches_node(
                    block_idx,
                    &plan.root,
                    &prepared.mask_cache,
                    &self.tier2_superblocks,
                )?
            {
                superblocks_skipped = superblocks_skipped.saturating_add(1);
                continue;
            }
            let start = block_idx * docs_per_block;
            let end = (start + docs_per_block).min(self.docs.len());
            for pos in start..end {
                let doc = &self.docs[pos];
                if doc.deleted {
                    continue;
                }
                docs_scanned += 1;
                let indexed_bytes = self.doc_indexed_bytes(pos)?;
                let tier1_bloom_bytes = self.doc_bloom_bytes(pos)?;
                let tier2_bloom_bytes = self.doc_tier2_bloom_bytes(pos)?;
                let mut eval_cache = QueryEvalCache::default();
                let outcome = evaluate_node(
                    &plan.root,
                    doc,
                    indexed_bytes.as_ref(),
                    tier1_bloom_bytes.as_ref(),
                    tier2_bloom_bytes.as_ref(),
                    &prepared.patterns,
                    &prepared.mask_cache,
                    plan,
                    &mut eval_cache,
                )?;
                if outcome.matched {
                    matched_hits.push((doc.sha256.clone(), outcome.score));
                    used_tiers.merge(outcome.tiers);
                }
            }
        }

        Ok((matched_hits, used_tiers, docs_scanned, superblocks_skipped))
    }

    pub fn stats(&self) -> CandidateStats {
        let doc_count = self.docs.iter().filter(|doc| !doc.deleted).count();
        let deleted_doc_count = self.docs.iter().filter(|doc| doc.deleted).count();
        let tier1_incomplete_doc_count = self
            .docs
            .iter()
            .filter(|doc| !doc.deleted && !doc.grams_complete)
            .count();
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
            tier1_incomplete_doc_count,
            id_source: self.meta.id_source.clone(),
            store_path: self.meta.store_path,
            filter_target_fp: self.meta.filter_target_fp,
            tier2_gram_size: self.meta.tier2_gram_size,
            tier1_gram_size: self.meta.tier1_gram_size,
            df_min: self.meta.df_min,
            df_max: self.meta.df_max,
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
            tier2_superblock_summary_bytes: self.tier2_superblocks.summary_memory_bytes,
            tier2_superblock_memory_budget_bytes: self.tier2_superblock_memory_budget_bytes,
            df_counts_delta_bytes: current_df_counts_delta_bytes(&self.root),
            df_counts_delta_entries: self.df_counts.delta.len(),
            df_counts_delta_compact_threshold_bytes: self.df_counts_delta_compact_threshold_bytes,
        }
    }

    pub fn filter_bucket_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::<String, usize>::new();
        for doc in self.docs.iter().filter(|doc| !doc.deleted) {
            *counts.entry(doc.filter_bytes.to_string()).or_insert(0) += 1;
        }
        counts
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

    pub(crate) fn tier2_filter_keys(&self) -> Vec<(usize, usize)> {
        self.tier2_superblocks
            .bucket_for_key
            .keys()
            .copied()
            .collect::<Vec<_>>()
    }

    pub(crate) fn secondary_filter_keys(&self) -> Vec<(usize, usize)> {
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

    fn doc_grams_received(&self, pos: usize) -> Result<Vec<u64>> {
        let doc = &self.docs[pos];
        let row = self.doc_rows[pos];
        read_exact_gram_vec_from_sidecar(
            &self.sidecars.grams_received,
            row.grams_received_offset,
            row.grams_received_count,
            self.meta.exact_gram_bytes(),
            "grams_received",
            doc.doc_id,
        )
    }

    fn doc_received_bytes<'a>(&'a self, pos: usize) -> Result<Cow<'a, [u8]>> {
        let doc = &self.docs[pos];
        let row = self.doc_rows[pos];
        self.sidecars.grams_received.read_bytes(
            row.grams_received_offset,
            row.grams_received_count as usize * self.meta.exact_gram_bytes(),
            "grams_received",
            doc.doc_id,
        )
    }

    fn doc_indexed_bytes<'a>(&'a self, pos: usize) -> Result<Cow<'a, [u8]>> {
        let doc = &self.docs[pos];
        let row = self.doc_rows[pos];
        self.sidecars.grams_indexed.read_bytes(
            row.grams_indexed_offset,
            row.grams_indexed_count as usize * self.meta.exact_gram_bytes(),
            "grams_indexed",
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
                TgsError::from(format!(
                    "Invalid external_id payload stored for doc_id {}",
                    doc.doc_id
                ))
            },
        )?))
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

    pub(crate) fn persist_df_counts_snapshot(&self) -> Result<()> {
        persist_df_counts_snapshot_to_root(
            &self.root,
            &self.df_counts.materialize(),
            self.meta.exact_gram_bytes(),
        )
    }

    pub(crate) fn seal_df_counts_snapshot_from_disk(&mut self) -> Result<()> {
        self.df_counts.refresh_snapshot(&self.root)?;
        self.persist_df_counts_snapshot()?;
        self.df_counts.refresh_snapshot(&self.root)?;
        self.append_writers.df_counts_delta = AppendFile::new(df_counts_delta_path(&self.root))?;
        self.append_writers.df_counts_unit_delta =
            AppendFile::new(df_counts_unit_delta_path(&self.root))?;
        Ok(())
    }

    fn maybe_compact_df_counts(&mut self) -> Result<()> {
        let len = current_df_counts_delta_bytes(&self.root);
        if len >= self.df_counts_delta_compact_threshold_bytes {
            self.persist_df_counts_snapshot()?;
            self.df_counts.refresh_snapshot(&self.root)?;
            self.append_writers.df_counts_delta =
                AppendFile::new(df_counts_delta_path(&self.root))?;
            self.append_writers.df_counts_unit_delta =
                AppendFile::new(df_counts_unit_delta_path(&self.root))?;
        }
        Ok(())
    }

    fn build_doc_row(
        &mut self,
        file_size: u64,
        filter_bytes: usize,
        bloom_hashes: usize,
        grams_complete: bool,
        deleted: bool,
        external_id: Option<&str>,
        bloom_filter: &[u8],
        grams_received: &[u64],
        grams_indexed: &[u64],
    ) -> Result<DocMetaRow> {
        Ok(self
            .build_doc_row_profile(
                file_size,
                filter_bytes,
                bloom_hashes,
                grams_complete,
                deleted,
                external_id,
                bloom_filter,
                grams_received,
                grams_indexed,
            )?
            .0)
    }

    fn build_doc_row_with_bloom_offset_profile(
        &mut self,
        file_size: u64,
        filter_bytes: usize,
        bloom_hashes: usize,
        grams_complete: bool,
        deleted: bool,
        external_id: Option<&str>,
        bloom_offset: u64,
        bloom_len: usize,
        grams_received: &[u64],
        grams_indexed: &[u64],
    ) -> Result<(DocMetaRow, CandidateDocRowPayloadProfile)> {
        fn elapsed_us(started: Instant) -> u64 {
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
        }

        let gram_bytes = self.meta.exact_gram_bytes();
        let mut profile = CandidateDocRowPayloadProfile::default();
        let grams_received_started = Instant::now();
        let grams_received_offset = append_exact_gram_slice_with_writer(
            &mut self.append_writers.grams_received,
            grams_received,
            gram_bytes,
        )?;
        profile.grams_received_us = elapsed_us(grams_received_started);
        profile.grams_received_bytes = (grams_received.len() * gram_bytes) as u64;
        let grams_indexed_started = Instant::now();
        let grams_indexed_offset = append_exact_gram_slice_with_writer(
            &mut self.append_writers.grams_indexed,
            grams_indexed,
            gram_bytes,
        )?;
        profile.grams_indexed_us = elapsed_us(grams_indexed_started);
        profile.grams_indexed_bytes = (grams_indexed.len() * gram_bytes) as u64;
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
                flags: (u8::from(grams_complete) * DOC_FLAG_GRAMS_COMPLETE)
                    | (u8::from(deleted) * DOC_FLAG_DELETED),
                bloom_hashes: bloom_hashes.min(u8::MAX as usize) as u8,
                bloom_offset,
                bloom_len: bloom_len as u32,
                grams_received_offset,
                grams_received_count: grams_received.len() as u32,
                grams_indexed_offset,
                grams_indexed_count: grams_indexed.len() as u32,
                external_id_offset,
                external_id_len,
            },
            profile,
        ))
    }

    fn build_doc_row_profile(
        &mut self,
        file_size: u64,
        filter_bytes: usize,
        bloom_hashes: usize,
        grams_complete: bool,
        deleted: bool,
        external_id: Option<&str>,
        bloom_filter: &[u8],
        grams_received: &[u64],
        grams_indexed: &[u64],
    ) -> Result<(DocMetaRow, CandidateDocRowPayloadProfile)> {
        fn elapsed_us(started: Instant) -> u64 {
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
        }

        let gram_bytes = self.meta.exact_gram_bytes();
        let mut profile = CandidateDocRowPayloadProfile::default();
        let bloom_started = Instant::now();
        let bloom_offset = self.append_writers.blooms.append(bloom_filter)?;
        profile.bloom_us = elapsed_us(bloom_started);
        profile.bloom_bytes = bloom_filter.len() as u64;
        let grams_received_started = Instant::now();
        let grams_received_offset = append_exact_gram_slice_with_writer(
            &mut self.append_writers.grams_received,
            grams_received,
            gram_bytes,
        )?;
        profile.grams_received_us = elapsed_us(grams_received_started);
        profile.grams_received_bytes = (grams_received.len() * gram_bytes) as u64;
        let grams_indexed_started = Instant::now();
        let grams_indexed_offset = append_exact_gram_slice_with_writer(
            &mut self.append_writers.grams_indexed,
            grams_indexed,
            gram_bytes,
        )?;
        profile.grams_indexed_us = elapsed_us(grams_indexed_started);
        profile.grams_indexed_bytes = (grams_indexed.len() * gram_bytes) as u64;
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
            flags: (u8::from(grams_complete) * DOC_FLAG_GRAMS_COMPLETE)
                | (u8::from(deleted) * DOC_FLAG_DELETED),
            bloom_hashes: bloom_hashes.min(u8::MAX as usize) as u8,
            bloom_offset,
            bloom_len: bloom_filter.len() as u32,
            grams_received_offset,
            grams_received_count: grams_received.len() as u32,
            grams_indexed_offset,
            grams_indexed_count: grams_indexed.len() as u32,
            external_id_offset,
            external_id_len,
        };
        Ok((row, profile))
    }

    fn build_doc_row5(
        &mut self,
        tier2_filter_bytes: usize,
        tier2_bloom_hashes: usize,
        tier2_bloom_filter: &[u8],
    ) -> Result<Tier2DocMetaRow> {
        Ok(self
            .build_doc_row5_profile(tier2_filter_bytes, tier2_bloom_hashes, tier2_bloom_filter)?
            .0)
    }

    fn build_doc_row5_profile(
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
            return Err(TgsError::from("doc_id must be positive"));
        }
        write_at(
            doc_meta_path(&self.root),
            (doc_id - 1) * DOC_META_ROW_BYTES as u64,
            &row.encode(),
        )
    }

    fn write_doc_row5(&self, doc_id: u64, row: Tier2DocMetaRow) -> Result<()> {
        if doc_id == 0 {
            return Err(TgsError::from("doc_id must be positive"));
        }
        write_at(
            tier2_doc_meta_path(&self.root),
            (doc_id - 1) * TIER2_DOC_META_ROW_BYTES as u64,
            &row.encode(),
        )
    }

    fn ensure_tier2_superblock_capacity(
        &mut self,
        block_idx: usize,
        filter_bytes: usize,
        bloom_hashes: usize,
    ) {
        let needed_blocks = block_idx + 1;
        if self.tier2_superblocks.keys_per_block.len() < needed_blocks {
            self.tier2_superblocks
                .keys_per_block
                .resize_with(needed_blocks, Vec::new);
        }
        let filter_key = (filter_bytes, bloom_hashes);
        let bucket_key = tier2_superblock_bucket_key(filter_bytes, bloom_hashes);
        let summary_bytes = tier2_superblock_summary_bytes(bucket_key.0);
        self.tier2_superblocks
            .bucket_for_key
            .insert(filter_key, bucket_key);
        self.tier2_superblocks
            .summary_bytes_by_bucket
            .insert(bucket_key, summary_bytes);
        let blocks = self
            .tier2_superblocks
            .masks_by_bucket
            .entry(bucket_key)
            .or_insert_with(Vec::new);
        while blocks.len() < needed_blocks {
            blocks.push(vec![0u8; summary_bytes]);
            self.tier2_superblocks.summary_memory_bytes = self
                .tier2_superblocks
                .summary_memory_bytes
                .saturating_add(summary_bytes as u64);
        }
        let keys = &mut self.tier2_superblocks.keys_per_block[block_idx];
        if !keys.contains(&filter_key) {
            keys.push(filter_key);
            keys.sort_unstable();
        }
    }

    fn update_tier2_superblocks_for_doc_bytes_inner(
        &mut self,
        pos: usize,
        bloom_bytes: &[u8],
    ) -> Result<()> {
        if pos >= self.docs.len() || self.docs[pos].deleted {
            return Ok(());
        }
        let block_idx = pos / self.tier2_superblocks.docs_per_block.max(1);
        let filter_bytes = self.docs[pos].filter_bytes;
        let bloom_hashes = self.docs[pos].bloom_hashes;
        self.ensure_tier2_superblock_capacity(block_idx, filter_bytes, bloom_hashes);
        let bucket_key = tier2_superblock_bucket_key(filter_bytes, bloom_hashes);
        if let Some(blocks) = self.tier2_superblocks.masks_by_bucket.get_mut(&bucket_key) {
            if let Some(block) = blocks.get_mut(block_idx) {
                let summary_bytes = block.len().max(1);
                for (source_idx, src) in bloom_bytes.iter().copied().enumerate() {
                    let folded_idx = source_idx % summary_bytes;
                    block[folded_idx] |= src;
                }
            }
        }
        Ok(())
    }

    fn update_tier2_superblocks_for_doc_bytes_batch(
        &mut self,
        updates: &[(usize, usize, usize, &[u8])],
    ) -> Result<()> {
        if updates.is_empty() {
            return Ok(());
        }
        let docs_per_block = self.tier2_superblocks.docs_per_block.max(1);
        let mut max_needed_blocks = self.tier2_superblocks.keys_per_block.len();
        let mut keys_by_block = BTreeMap::<usize, Vec<(usize, usize)>>::new();
        let mut max_block_by_bucket = BTreeMap::<(usize, usize), usize>::new();
        let mut aggregated = BTreeMap::<(usize, (usize, usize)), Vec<u8>>::new();

        for (pos, filter_bytes, bloom_hashes, bloom_bytes) in updates {
            let block_idx = *pos / docs_per_block;
            max_needed_blocks = max_needed_blocks.max(block_idx + 1);
            let filter_key = (*filter_bytes, *bloom_hashes);
            let bucket_key = tier2_superblock_bucket_key(*filter_bytes, *bloom_hashes);
            let summary_bytes = tier2_superblock_summary_bytes(bucket_key.0).max(1);
            keys_by_block.entry(block_idx).or_default().push(filter_key);
            max_block_by_bucket
                .entry(bucket_key)
                .and_modify(|value| *value = (*value).max(block_idx))
                .or_insert(block_idx);
            let folded = aggregated
                .entry((block_idx, filter_key))
                .or_insert_with(|| vec![0u8; summary_bytes]);
            for (source_idx, src) in bloom_bytes.iter().copied().enumerate() {
                let folded_idx = source_idx % summary_bytes;
                folded[folded_idx] |= src;
            }
        }

        if self.tier2_superblocks.keys_per_block.len() < max_needed_blocks {
            self.tier2_superblocks
                .keys_per_block
                .resize_with(max_needed_blocks, Vec::new);
        }

        for (bucket_key, max_block_idx) in max_block_by_bucket {
            let summary_bytes = tier2_superblock_summary_bytes(bucket_key.0);
            self.tier2_superblocks
                .summary_bytes_by_bucket
                .insert(bucket_key, summary_bytes);
            let blocks = self
                .tier2_superblocks
                .masks_by_bucket
                .entry(bucket_key)
                .or_insert_with(Vec::new);
            while blocks.len() <= max_block_idx {
                blocks.push(vec![0u8; summary_bytes]);
                self.tier2_superblocks.summary_memory_bytes = self
                    .tier2_superblocks
                    .summary_memory_bytes
                    .saturating_add(summary_bytes as u64);
            }
        }

        for (block_idx, mut filter_keys) in keys_by_block {
            filter_keys.sort_unstable();
            filter_keys.dedup();
            let keys = &mut self.tier2_superblocks.keys_per_block[block_idx];
            let before_len = keys.len();
            for filter_key in filter_keys {
                let bucket_key = tier2_superblock_bucket_key(filter_key.0, filter_key.1);
                self.tier2_superblocks
                    .bucket_for_key
                    .insert(filter_key, bucket_key);
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
            if let Some(blocks) = self.tier2_superblocks.masks_by_bucket.get_mut(&bucket_key) {
                if let Some(block) = blocks.get_mut(block_idx) {
                    for (dst, src) in block.iter_mut().zip(folded.iter()) {
                        *dst |= *src;
                    }
                }
            }
        }

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

    fn rebuild_tier2_superblocks_with_docs_per_block(
        &mut self,
        docs_per_block: usize,
    ) -> Result<()> {
        self.tier2_superblocks = Tier2SuperblockIndex {
            docs_per_block: docs_per_block.max(1),
            ..Tier2SuperblockIndex::default()
        };
        for pos in 0..self.docs.len() {
            self.update_tier2_superblocks_for_doc_inner(pos)?;
        }
        Ok(())
    }

    fn maybe_rebalance_tier2_superblocks(&mut self) -> Result<()> {
        let budget_bytes = self.tier2_superblock_memory_budget_bytes;
        let current_bytes = self.tier2_superblocks.summary_memory_bytes;
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
        let df_started = Instant::now();
        self.df_counts = DfCountsState::load(&self.root, self.meta.exact_gram_bytes())?;
        let df_counts_ms = df_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
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
                (true, 0)
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
            df_counts_ms,
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
                .unwrap_or_else(|| tier2_superblock_summary_bytes(*filter_bucket));
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
            let expected_summary_bytes = tier2_superblock_summary_bytes(filter_bucket);
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

    fn prepared_query_cache_key(plan: &CompiledQueryPlan) -> Result<String> {
        serde_json::to_string(plan).map_err(TgsError::from)
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
            &self.tier2_filter_keys(),
            &self.secondary_filter_keys(),
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
        blooms_path(compacted_root),
        tier2_blooms_path(compacted_root),
        grams_received_path(compacted_root),
        grams_indexed_path(compacted_root),
        external_ids_path(compacted_root),
    ];
    for path in &paths {
        let _ = fs::remove_file(path);
    }

    let mut counts = HashMap::<u64, usize>::new();
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
        let grams_received = read_exact_gram_vec_from_path(
            &grams_received_path(&snapshot.root),
            doc.row.grams_received_offset,
            doc.row.grams_received_count,
            snapshot.exact_gram_bytes,
            "grams_received",
            0,
        )?;
        let grams_indexed = read_exact_gram_vec_from_path(
            &grams_indexed_path(&snapshot.root),
            doc.row.grams_indexed_offset,
            doc.row.grams_indexed_count,
            snapshot.exact_gram_bytes,
            "grams_indexed",
            0,
        )?;
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
                TgsError::from("Invalid UTF-8 external_id payload during compaction.")
            })?)
        };

        for gram in &grams_received {
            *counts.entry(*gram).or_insert(0) += 1;
        }

        let row = DocMetaRow {
            file_size: doc.file_size,
            filter_bytes: doc.filter_bytes as u32,
            flags: u8::from(doc.grams_complete) * DOC_FLAG_GRAMS_COMPLETE,
            bloom_hashes: doc.bloom_hashes.min(u8::MAX as usize) as u8,
            bloom_offset: append_blob(blooms_path(compacted_root), &bloom_bytes)?,
            bloom_len: bloom_bytes.len() as u32,
            grams_received_offset: append_exact_gram_slice(
                grams_received_path(compacted_root),
                &grams_received,
                snapshot.exact_gram_bytes,
            )?,
            grams_received_count: grams_received.len() as u32,
            grams_indexed_offset: append_exact_gram_slice(
                grams_indexed_path(compacted_root),
                &grams_indexed,
                snapshot.exact_gram_bytes,
            )?,
            grams_indexed_count: grams_indexed.len() as u32,
            external_id_offset: if let Some(external_id) = &external_id {
                append_blob(external_ids_path(compacted_root), external_id.as_bytes())?
            } else {
                0
            },
            external_id_len: external_id
                .as_ref()
                .map(|value| value.len() as u32)
                .unwrap_or(0),
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
    persist_df_counts_snapshot_to_root(compacted_root, &counts, snapshot.exact_gram_bytes)?;
    Ok(())
}

fn meta_path(root: &Path) -> PathBuf {
    root.join("meta.json")
}

fn docs_path(root: &Path) -> PathBuf {
    root.join("docs.json")
}

fn docs_log_path(root: &Path) -> PathBuf {
    root.join("docs.jsonl")
}

fn sha_by_docid_path(root: &Path) -> PathBuf {
    root.join("sha256_by_docid.dat")
}

fn doc_meta_path(root: &Path) -> PathBuf {
    root.join("doc_meta.bin")
}

fn tier2_doc_meta_path(root: &Path) -> PathBuf {
    root.join("doc_meta5.bin")
}

fn blooms_path(root: &Path) -> PathBuf {
    root.join("blooms.bin")
}

fn tier2_blooms_path(root: &Path) -> PathBuf {
    root.join("tier2_blooms.bin")
}

fn grams_received_path(root: &Path) -> PathBuf {
    root.join("grams_received.bin")
}

fn grams_indexed_path(root: &Path) -> PathBuf {
    root.join("grams_indexed.bin")
}

fn external_ids_path(root: &Path) -> PathBuf {
    root.join("external_ids.dat")
}

fn tier2_superblocks_path(root: &Path) -> PathBuf {
    root.join("tier2_superblocks.bin")
}

fn df_counts_path(root: &Path) -> PathBuf {
    root.join("df_counts.bin")
}

fn df_counts_delta_path(root: &Path) -> PathBuf {
    root.join("df_counts.delta.bin")
}

fn df_counts_unit_delta_path(root: &Path) -> PathBuf {
    root.join("df_counts.unit.delta.bin")
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
        TgsError::from(format!(
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
        TgsError::from(format!(
            "Invalid candidate shard manifest at {}",
            path.display()
        ))
    })?;
    let count = raw
        .get("candidate_shards")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| {
            TgsError::from(format!(
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
        TgsError::from(format!(
            "Failed to read {label} payload for doc_id {doc_id} from {}: {err}",
            path.display()
        ))
    })?;
    Ok(bytes)
}

fn append_exact_gram_slice(path: PathBuf, values: &[u64], gram_bytes: usize) -> Result<u64> {
    let mut payload = Vec::with_capacity(values.len() * gram_bytes);
    for value in values {
        let encoded = value.to_le_bytes();
        payload.extend_from_slice(&encoded[..gram_bytes]);
    }
    append_blob(path, &payload)
}

fn append_exact_gram_slice_with_writer(
    writer: &mut AppendFile,
    values: &[u64],
    gram_bytes: usize,
) -> Result<u64> {
    let mut payload = Vec::with_capacity(values.len() * gram_bytes);
    for value in values {
        let encoded = value.to_le_bytes();
        payload.extend_from_slice(&encoded[..gram_bytes]);
    }
    writer.append(&payload)
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

fn legacy_docs_to_docs(docs: &[LegacyCandidateDoc]) -> Vec<CandidateDoc> {
    let mut out = Vec::with_capacity(docs.len());
    for doc in docs {
        out.push(CandidateDoc {
            doc_id: doc.doc_id,
            sha256: doc.sha256.clone(),
            file_size: doc.file_size,
            filter_bytes: doc.filter_bytes,
            bloom_hashes: doc.bloom_hashes.max(1),
            tier2_filter_bytes: doc.tier2_filter_bytes,
            tier2_bloom_hashes: doc.tier2_bloom_hashes,
            grams_complete: doc.grams_complete,
            deleted: doc.deleted,
        });
    }
    out
}

fn persist_df_counts_snapshot_for_docs(
    root: &Path,
    docs: &[CandidateDoc],
    legacy_docs: &[LegacyCandidateDoc],
    gram_bytes: usize,
) -> Result<()> {
    let mut counts = HashMap::<u64, usize>::new();
    for (doc, legacy) in docs.iter().zip(legacy_docs.iter()) {
        if doc.deleted {
            continue;
        }
        for gram in &legacy.grams_received {
            *counts.entry(u64::from(*gram)).or_insert(0) += 1;
        }
    }
    persist_df_counts_snapshot_to_root(root, &counts, gram_bytes)
}

fn persist_df_counts_snapshot_to_root(
    root: &Path,
    counts: &HashMap<u64, usize>,
    gram_bytes: usize,
) -> Result<()> {
    fs::create_dir_all(root)?;
    let mut ordered = counts
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(gram, count)| (*gram, *count))
        .collect::<Vec<_>>();
    ordered.sort_unstable_by_key(|(gram, _)| *gram);

    let snapshot_path = df_counts_path(root);
    let tmp_path = PathBuf::from(format!("{}.tmp", snapshot_path.display()));
    let mut payload = Vec::with_capacity(ordered.len() * (gram_bytes + 4));
    for (gram, count) in ordered {
        payload.extend_from_slice(&gram.to_le_bytes()[..gram_bytes]);
        payload.extend_from_slice(&(count.min(u32::MAX as usize) as u32).to_le_bytes());
    }
    fs::write(&tmp_path, payload)?;
    fs::rename(tmp_path, snapshot_path)?;
    fs::write(df_counts_delta_path(root), [])?;
    fs::write(df_counts_unit_delta_path(root), [])?;
    Ok(())
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
        return Err(TgsError::from("Invalid tier2 superblocks snapshot"));
    }
    let value = u32::from_le_bytes(bytes[*cursor..end].try_into().expect("u32 slice"));
    *cursor = end;
    Ok(value)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let end = cursor.saturating_add(8);
    if end > bytes.len() {
        return Err(TgsError::from("Invalid tier2 superblocks snapshot"));
    }
    let value = u64::from_le_bytes(bytes[*cursor..end].try_into().expect("u64 slice"));
    *cursor = end;
    Ok(value)
}

fn current_df_counts_delta_bytes(root: &Path) -> u64 {
    fs::metadata(df_counts_delta_path(root))
        .map(|metadata| metadata.len())
        .unwrap_or(0)
        .saturating_add(
            fs::metadata(df_counts_unit_delta_path(root))
                .map(|metadata| metadata.len())
                .unwrap_or(0),
        )
}

fn append_df_count_deltas_with_writer(
    writer: &mut AppendFile,
    gram_bytes: usize,
    deltas: &[(u64, i32)],
) -> Result<()> {
    if deltas.is_empty() {
        return Ok(());
    }
    let mut payload = Vec::with_capacity(deltas.len() * (gram_bytes + 4));
    for (gram, delta) in deltas {
        payload.extend_from_slice(&gram.to_le_bytes()[..gram_bytes]);
        payload.extend_from_slice(&delta.to_le_bytes());
    }
    writer.append(&payload)?;
    Ok(())
}

fn append_df_count_unit_payload_with_writer(writer: &mut AppendFile, payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    writer.append(payload)?;
    Ok(())
}

fn extend_unit_df_payload_from_packed(
    payload: &mut Vec<u8>,
    packed_grams: &[u8],
    gram_bytes: usize,
) -> Result<()> {
    if gram_bytes == 0 || packed_grams.len() % gram_bytes != 0 {
        return Err(TgsError::from("Invalid packed exact gram payload."));
    }
    payload.reserve(packed_grams.len());
    payload.extend_from_slice(packed_grams);
    Ok(())
}

fn extend_unit_df_payload_from_values(payload: &mut Vec<u8>, grams: &[u64], gram_bytes: usize) {
    payload.reserve(grams.len() * gram_bytes);
    for gram in grams {
        payload.extend_from_slice(&gram.to_le_bytes()[..gram_bytes]);
    }
}

#[cfg(test)]
fn append_u32_slice(path: PathBuf, values: &[u32]) -> Result<u64> {
    let widened = values
        .iter()
        .map(|value| u64::from(*value))
        .collect::<Vec<_>>();
    append_exact_gram_slice(path, &widened, 4)
}

fn load_candidate_store_state(
    root: &Path,
    meta: &StoreMeta,
) -> Result<(Vec<CandidateDoc>, Vec<DocMetaRow>, Vec<Tier2DocMetaRow>)> {
    if binary_store_exists(root) {
        return load_candidate_binary_store(root);
    }
    let log_path = docs_log_path(root);
    if log_path.exists() {
        let docs = load_candidate_docs_log(&log_path)?;
        let (rows, tier2_rows) = persist_docs_as_binary(root, &docs, meta.exact_gram_bytes())?;
        let _ = fs::remove_file(log_path);
        let _ = fs::remove_file(docs_path(root));
        return Ok((legacy_docs_to_docs(&docs), rows, tier2_rows));
    }
    let legacy_path = docs_path(root);
    if !legacy_path.exists() {
        return Ok((Vec::new(), Vec::new(), Vec::new()));
    }
    let docs = serde_json::from_slice::<Vec<LegacyCandidateDoc>>(&fs::read(&legacy_path)?)
        .map_err(|_| {
            TgsError::from(format!(
                "Invalid candidate document state at {}",
                root.display()
            ))
        })?;
    let (rows, tier2_rows) = persist_docs_as_binary(root, &docs, meta.exact_gram_bytes())?;
    let _ = fs::remove_file(legacy_path);
    Ok((legacy_docs_to_docs(&docs), rows, tier2_rows))
}

fn load_candidate_docs_log(path: &Path) -> Result<Vec<LegacyCandidateDoc>> {
    let handle = fs::File::open(path)?;
    let reader = BufReader::new(handle);
    let mut docs_by_id = BTreeMap::<u64, LegacyCandidateDoc>::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let doc = serde_json::from_str::<LegacyCandidateDoc>(&line).map_err(|_| {
            TgsError::from(format!(
                "Invalid candidate document log at {}:{}",
                path.display(),
                line_no + 1
            ))
        })?;
        docs_by_id.insert(doc.doc_id, doc);
    }
    Ok(docs_by_id.into_values().collect())
}

fn binary_store_exists(root: &Path) -> bool {
    sha_by_docid_path(root).exists()
        || doc_meta_path(root).exists()
        || tier2_doc_meta_path(root).exists()
}

fn persist_docs_as_binary(
    root: &Path,
    docs: &[LegacyCandidateDoc],
    gram_bytes: usize,
) -> Result<(Vec<DocMetaRow>, Vec<Tier2DocMetaRow>)> {
    fs::create_dir_all(root)?;
    let paths = [
        sha_by_docid_path(root),
        doc_meta_path(root),
        tier2_doc_meta_path(root),
        blooms_path(root),
        tier2_blooms_path(root),
        grams_received_path(root),
        grams_indexed_path(root),
        external_ids_path(root),
    ];
    for path in &paths {
        let _ = fs::remove_file(path);
    }
    let mut rows = Vec::with_capacity(docs.len());
    let mut tier2_rows = Vec::with_capacity(docs.len());
    let mut ordered_docs = docs.to_vec();
    ordered_docs.sort_by_key(|doc| doc.doc_id);
    for doc in &ordered_docs {
        let bloom_bytes = hex::decode(&doc.bloom_hex).map_err(|_| {
            TgsError::from(format!("Invalid bloom payload stored for {}", doc.sha256))
        })?;
        let tier2_bloom_bytes = if doc.tier2_bloom_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(&doc.tier2_bloom_hex).map_err(|_| {
                TgsError::from(format!(
                    "Invalid tier2_bloom payload stored for {}",
                    doc.sha256
                ))
            })?
        };
        let row = DocMetaRow {
            file_size: doc.file_size,
            filter_bytes: doc.filter_bytes as u32,
            flags: (u8::from(doc.grams_complete) * DOC_FLAG_GRAMS_COMPLETE)
                | (u8::from(doc.deleted) * DOC_FLAG_DELETED),
            bloom_hashes: doc.bloom_hashes.min(u8::MAX as usize) as u8,
            bloom_offset: append_blob(blooms_path(root), &bloom_bytes)?,
            bloom_len: bloom_bytes.len() as u32,
            grams_received_offset: append_exact_gram_slice(
                grams_received_path(root),
                &doc.grams_received
                    .iter()
                    .map(|value| u64::from(*value))
                    .collect::<Vec<_>>(),
                gram_bytes,
            )?,
            grams_received_count: doc.grams_received.len() as u32,
            grams_indexed_offset: append_exact_gram_slice(
                grams_indexed_path(root),
                &doc.grams_indexed
                    .iter()
                    .map(|value| u64::from(*value))
                    .collect::<Vec<_>>(),
                gram_bytes,
            )?,
            grams_indexed_count: doc.grams_indexed.len() as u32,
            external_id_offset: if let Some(external_id) = &doc.external_id {
                append_blob(external_ids_path(root), external_id.as_bytes())?
            } else {
                0
            },
            external_id_len: doc
                .external_id
                .as_ref()
                .map(|value| value.len() as u32)
                .unwrap_or(0),
        };
        let tier2_row = if tier2_bloom_bytes.is_empty() {
            Tier2DocMetaRow::default()
        } else {
            Tier2DocMetaRow {
                filter_bytes: doc.tier2_filter_bytes as u32,
                bloom_hashes: doc.tier2_bloom_hashes.min(u8::MAX as usize) as u8,
                bloom_offset: append_blob(tier2_blooms_path(root), &tier2_bloom_bytes)?,
                bloom_len: tier2_bloom_bytes.len() as u32,
            }
        };
        append_blob(sha_by_docid_path(root), &hex::decode(&doc.sha256)?)?;
        append_blob(doc_meta_path(root), &row.encode())?;
        append_blob(tier2_doc_meta_path(root), &tier2_row.encode())?;
        rows.push(row);
        tier2_rows.push(tier2_row);
    }
    let docs_view = legacy_docs_to_docs(docs);
    persist_df_counts_snapshot_for_docs(root, &docs_view, docs, gram_bytes)?;
    Ok((rows, tier2_rows))
}

fn load_candidate_binary_store(
    root: &Path,
) -> Result<(Vec<CandidateDoc>, Vec<DocMetaRow>, Vec<Tier2DocMetaRow>)> {
    let sha_bytes = fs::read(sha_by_docid_path(root))?;
    let row_bytes = fs::read(doc_meta_path(root))?;
    let row5_bytes = fs::read(tier2_doc_meta_path(root)).unwrap_or_default();
    if sha_bytes.len() % 32 != 0 || row_bytes.len() % DOC_META_ROW_BYTES != 0 {
        return Err(TgsError::from(format!(
            "Invalid candidate binary document state at {}",
            root.display()
        )));
    }
    let doc_count = sha_bytes.len() / 32;
    if doc_count != row_bytes.len() / DOC_META_ROW_BYTES {
        return Err(TgsError::from(format!(
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
        let tier2_row = if row5_bytes.len() >= (index + 1) * TIER2_DOC_META_ROW_BYTES {
            Tier2DocMetaRow::decode(
                &row5_bytes
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
            grams_complete: (row.flags & DOC_FLAG_GRAMS_COMPLETE) != 0,
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
        return Err(TgsError::from(format!(
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

fn read_exact_gram_vec_from_sidecar(
    sidecar: &BlobSidecar,
    offset: u64,
    count: u32,
    gram_bytes: usize,
    label: &str,
    doc_id: u64,
) -> Result<Vec<u64>> {
    let bytes = sidecar.read_bytes(offset, count as usize * gram_bytes, label, doc_id)?;
    let mut out = Vec::with_capacity(count as usize);
    for chunk in bytes.chunks_exact(gram_bytes) {
        out.push(decode_packed_exact_gram(chunk));
    }
    Ok(out)
}

fn read_exact_gram_vec_from_path(
    path: &Path,
    offset: u64,
    count: u32,
    gram_bytes: usize,
    label: &str,
    doc_id: u64,
) -> Result<Vec<u64>> {
    let bytes = read_blob_from_path(path, offset, count as usize * gram_bytes, label, doc_id)?;
    let mut out = Vec::with_capacity(count as usize);
    for chunk in bytes.chunks_exact(gram_bytes) {
        out.push(decode_packed_exact_gram(chunk));
    }
    Ok(out)
}

fn decode_exact_gram_vec(bytes: &[u8], gram_bytes: usize) -> Result<Vec<u64>> {
    if gram_bytes == 0 || bytes.len() % gram_bytes != 0 {
        return Err(TgsError::from("Invalid packed exact gram payload."));
    }
    let mut out = Vec::with_capacity(bytes.len() / gram_bytes);
    for chunk in bytes.chunks_exact(gram_bytes) {
        out.push(decode_packed_exact_gram(chunk));
    }
    Ok(out)
}

fn decode_packed_exact_gram(bytes: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    out[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(out)
}

fn exact_gram_bytes_contains_all(bytes: &[u8], required: &[u64], gram_bytes: usize) -> bool {
    if required.is_empty() {
        return true;
    }
    let count = bytes.len() / gram_bytes;
    for needle in required {
        let mut left = 0usize;
        let mut right = count;
        let mut found = false;
        while left < right {
            let mid = left + (right - left) / 2;
            let start = mid * gram_bytes;
            let value = decode_packed_exact_gram(&bytes[start..start + gram_bytes]);
            if value == *needle {
                found = true;
                break;
            }
            if value < *needle {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

fn validate_config(config: &CandidateConfig) -> Result<()> {
    if config.df_min == 0 {
        return Err(TgsError::from("candidate config values must be positive"));
    }
    if config.df_max != 0 && config.df_max < config.df_min {
        return Err(TgsError::from("df_max must be >= df_min"));
    }
    if !matches!(
        config.id_source.as_str(),
        "sha256" | "md5" | "sha1" | "sha512"
    ) {
        return Err(TgsError::from(
            "id_source must be one of sha256, md5, sha1, sha512",
        ));
    }
    GramSizes::new(config.tier2_gram_size, config.tier1_gram_size)
        .map_err(|err| TgsError::from(format!("invalid gram size pair: {err}")))?;
    if !config.compaction_idle_cooldown_s.is_finite() || config.compaction_idle_cooldown_s < 0.0 {
        return Err(TgsError::from(
            "compaction_idle_cooldown_s must be finite and >= 0",
        ));
    }
    if let Some(value) = config.filter_target_fp {
        if !(0.0 < value && value < 1.0) {
            return Err(TgsError::from("filter_target_fp must be in range (0, 1)"));
        }
    }
    Ok(())
}

fn normalize_sha256_hex(value: &str) -> Result<String> {
    let text = value.trim().to_ascii_lowercase();
    if text.len() != 64 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(TgsError::from(
            "sha256 must be exactly 64 hexadecimal characters.",
        ));
    }
    Ok(text)
}

#[derive(Clone, Debug, Default)]
struct PreparedPatternMasks {
    tier1: Vec<BTreeMap<(usize, usize), Vec<(usize, u8)>>>,
    tier1_superblocks: Vec<BTreeMap<(usize, usize), Vec<(usize, u8)>>>,
    tier2: Vec<BTreeMap<(usize, usize), Vec<(usize, u8)>>>,
}

type PatternMaskCache = HashMap<String, PreparedPatternMasks>;

fn merge_cached_bloom_masks(
    values: &[u64],
    size_bytes: usize,
    hash_count: usize,
    cache: &mut HashMap<(u64, usize, usize), Vec<(usize, u8)>>,
) -> Result<Vec<(usize, u8)>> {
    let mut merged = BTreeMap::<usize, u8>::new();
    for value in values {
        let key = (*value, size_bytes, hash_count);
        let cached = if let Some(entry) = cache.get(&key) {
            entry.clone()
        } else {
            let entry = bloom_byte_masks(&[*value], size_bytes, hash_count)?;
            cache.insert(key, entry.clone());
            entry
        };
        for (byte_idx, mask) in cached {
            *merged.entry(byte_idx).or_insert(0) |= mask;
        }
    }
    Ok(merged.into_iter().collect())
}

fn node_structurally_impossible(node: &QueryNode) -> bool {
    match node.kind.as_str() {
        "pattern" => false,
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

fn build_pattern_mask_cache(
    patterns: &[PatternPlan],
    tier1_filter_keys: &[(usize, usize)],
    tier2_filter_keys: &[(usize, usize)],
) -> Result<PatternMaskCache> {
    let mut out = HashMap::with_capacity(patterns.len());
    let mut tier1_gram_cache = HashMap::<(u64, usize, usize), Vec<(usize, u8)>>::new();
    let mut tier2_gram_cache = HashMap::<(u64, usize, usize), Vec<(usize, u8)>>::new();
    for pattern in patterns {
        let mut tier1_masks = Vec::with_capacity(pattern.alternatives.len());
        let mut tier1_superblock_masks = Vec::with_capacity(pattern.alternatives.len());
        for alternative in &pattern.alternatives {
            let mut by_key = BTreeMap::<(usize, usize), Vec<(usize, u8)>>::new();
            let mut superblock_by_key = BTreeMap::<(usize, usize), Vec<(usize, u8)>>::new();
            for (filter_bytes, bloom_hashes) in tier1_filter_keys {
                let required = merge_cached_bloom_masks(
                    alternative,
                    *filter_bytes,
                    *bloom_hashes,
                    &mut tier1_gram_cache,
                )?;
                let summary_bucket = tier2_superblock_bucket_key(*filter_bytes, *bloom_hashes);
                superblock_by_key.insert(
                    (*filter_bytes, *bloom_hashes),
                    fold_bloom_masks(&required, tier2_superblock_summary_bytes(summary_bucket.0)),
                );
                by_key.insert((*filter_bytes, *bloom_hashes), required);
            }
            tier1_masks.push(by_key);
            tier1_superblock_masks.push(superblock_by_key);
        }

        let mut tier2_masks = Vec::with_capacity(pattern.tier2_alternatives.len());
        for alternative in &pattern.tier2_alternatives {
            let mut by_key = BTreeMap::<(usize, usize), Vec<(usize, u8)>>::new();
            for (filter_bytes, bloom_hashes) in tier2_filter_keys {
                by_key.insert(
                    (*filter_bytes, *bloom_hashes),
                    merge_cached_bloom_masks(
                        alternative,
                        *filter_bytes,
                        *bloom_hashes,
                        &mut tier2_gram_cache,
                    )?,
                );
            }
            tier2_masks.push(by_key);
        }

        out.insert(
            pattern.pattern_id.clone(),
            PreparedPatternMasks {
                tier1: tier1_masks,
                tier1_superblocks: tier1_superblock_masks,
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
    let mask_cache =
        build_pattern_mask_cache(&plan.patterns, tier1_filter_keys, tier2_filter_keys)?;
    Ok(Arc::new(PreparedQueryArtifacts {
        patterns,
        mask_cache,
        impossible_query: node_structurally_impossible(&plan.root),
    }))
}

fn block_matches_pattern(
    block_idx: usize,
    pattern_id: &str,
    mask_cache: &PatternMaskCache,
    superblocks: &Tier2SuperblockIndex,
) -> bool {
    let Some(pattern_masks) = mask_cache.get(pattern_id) else {
        return false;
    };
    let Some(keys) = superblocks.keys_per_block.get(block_idx) else {
        return false;
    };
    pattern_masks.tier1_superblocks.iter().any(|by_key| {
        if by_key.is_empty() {
            return true;
        }
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
            raw_filter_matches_masks(block, required)
        })
    })
}

fn block_maybe_matches_node(
    block_idx: usize,
    node: &QueryNode,
    mask_cache: &PatternMaskCache,
    superblocks: &Tier2SuperblockIndex,
) -> Result<bool> {
    match node.kind.as_str() {
        "pattern" => {
            let pattern_id = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| TgsError::from("pattern node requires pattern_id"))?;
            Ok(block_matches_pattern(
                block_idx,
                pattern_id,
                mask_cache,
                superblocks,
            ))
        }
        "and" => {
            for child in &node.children {
                if !block_maybe_matches_node(block_idx, child, mask_cache, superblocks)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        "or" => {
            for child in &node.children {
                if block_maybe_matches_node(block_idx, child, mask_cache, superblocks)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        "n_of" => {
            let threshold = node
                .threshold
                .ok_or_else(|| TgsError::from("n_of node requires threshold"))?;
            let mut matched = 0usize;
            for child in &node.children {
                if block_maybe_matches_node(block_idx, child, mask_cache, superblocks)? {
                    matched += 1;
                    if matched >= threshold {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        other => Err(TgsError::from(format!(
            "Unsupported ast node kind: {other}"
        ))),
    }
}

fn evaluate_pattern(
    pattern: &PatternPlan,
    pattern_masks: &PreparedPatternMasks,
    doc: &CandidateDoc,
    indexed_bytes: &[u8],
    bloom_bytes: &[u8],
    tier2_bloom_bytes: &[u8],
    plan: &CompiledQueryPlan,
) -> Result<MatchOutcome> {
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
        let exact_gram_bytes = if plan.tier1_gram_size <= 4 { 4 } else { 8 };
        if exact_gram_bytes_contains_all(indexed_bytes, alternative, exact_gram_bytes) {
            return Ok(MatchOutcome {
                matched: true,
                tiers: TierFlags {
                    used_tier1: true,
                    used_tier2: false,
                },
                score: 10_000u32
                    .saturating_add((alternative.len() as u32).saturating_mul(32))
                    .saturating_add(
                        pattern
                            .tier2_alternatives
                            .get(alt_index)
                            .map(|grams| grams.len() as u32)
                            .unwrap_or(0)
                            .saturating_mul(16),
                    ),
            });
        }
        if !doc.grams_complete && allow_tier2 {
            let primary_match = pattern_masks
                .tier1
                .get(alt_index)
                .and_then(|by_key| by_key.get(&(doc.filter_bytes, doc.bloom_hashes)))
                .is_some_and(|required| raw_filter_matches_masks(bloom_bytes, required));
            if !primary_match {
                continue;
            }
            let tier2_alternative = pattern
                .tier2_alternatives
                .get(alt_index)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if !tier2_alternative.is_empty()
                && doc.tier2_filter_bytes > 0
                && doc.tier2_bloom_hashes > 0
                && !tier2_bloom_bytes.is_empty()
            {
                let tier2_match = pattern_masks
                    .tier2
                    .get(alt_index)
                    .and_then(|by_key| {
                        by_key.get(&(doc.tier2_filter_bytes, doc.tier2_bloom_hashes))
                    })
                    .is_some_and(|required| raw_filter_matches_masks(tier2_bloom_bytes, required));
                if !tier2_match {
                    continue;
                }
            }
            return Ok(MatchOutcome {
                matched: true,
                tiers: TierFlags {
                    used_tier1: false,
                    used_tier2: true,
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
    }
    Ok(MatchOutcome::default())
}

fn evaluate_node(
    node: &QueryNode,
    doc: &CandidateDoc,
    indexed_bytes: &[u8],
    bloom_bytes: &[u8],
    tier2_bloom_bytes: &[u8],
    patterns: &HashMap<String, PatternPlan>,
    mask_cache: &PatternMaskCache,
    plan: &CompiledQueryPlan,
    eval_cache: &mut QueryEvalCache,
) -> Result<MatchOutcome> {
    match node.kind.as_str() {
        "pattern" => {
            let pattern_id = node
                .pattern_id
                .as_ref()
                .ok_or_else(|| TgsError::from("pattern node requires pattern_id"))?;
            if let Some(outcome) = eval_cache.pattern_outcomes.get(pattern_id).copied() {
                return Ok(outcome);
            }
            let pattern = patterns
                .get(pattern_id)
                .ok_or_else(|| TgsError::from(format!("Unknown pattern id: {pattern_id}")))?;
            let pattern_masks = mask_cache
                .get(pattern_id)
                .ok_or_else(|| TgsError::from(format!("Unknown pattern id: {pattern_id}")))?;
            let outcome = evaluate_pattern(
                pattern,
                pattern_masks,
                doc,
                indexed_bytes,
                bloom_bytes,
                tier2_bloom_bytes,
                plan,
            )?;
            eval_cache
                .pattern_outcomes
                .insert(pattern_id.clone(), outcome);
            Ok(outcome)
        }
        "and" => {
            let mut merged = TierFlags::default();
            let mut score = 0u32;
            for child in &node.children {
                let outcome = evaluate_node(
                    child,
                    doc,
                    indexed_bytes,
                    bloom_bytes,
                    tier2_bloom_bytes,
                    patterns,
                    mask_cache,
                    plan,
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
                    doc,
                    indexed_bytes,
                    bloom_bytes,
                    tier2_bloom_bytes,
                    patterns,
                    mask_cache,
                    plan,
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
                .ok_or_else(|| TgsError::from("n_of node requires threshold"))?;
            let mut matched_count = 0usize;
            let mut merged = TierFlags::default();
            let mut score = 0u32;
            for child in &node.children {
                let outcome = evaluate_node(
                    child,
                    doc,
                    indexed_bytes,
                    bloom_bytes,
                    tier2_bloom_bytes,
                    patterns,
                    mask_cache,
                    plan,
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
        other => Err(TgsError::from(format!(
            "Unsupported ast node kind: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::candidate::BloomFilter;
    use crate::candidate::{
        DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, pack_exact_gram,
        query_plan::compile_query_plan,
    };

    use super::*;

    fn bloom_hex(filter_bytes: usize, bloom_hashes: usize, grams: &[u32]) -> String {
        let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
        for gram in grams {
            bloom.add(u64::from(*gram)).expect("add gram");
        }
        hex::encode(bloom.into_bytes())
    }

    fn legacy_doc(
        doc_id: u64,
        sha_byte: u8,
        filter_bytes: usize,
        bloom_hashes: usize,
        indexed: &[u32],
        bloom_grams: &[u32],
        grams_complete: bool,
        deleted: bool,
        external_id: Option<&str>,
    ) -> LegacyCandidateDoc {
        LegacyCandidateDoc {
            doc_id,
            sha256: hex::encode([sha_byte; 32]),
            file_size: 1234,
            filter_bytes,
            bloom_hashes,
            bloom_hex: bloom_hex(filter_bytes, bloom_hashes, bloom_grams),
            tier2_filter_bytes: 0,
            tier2_bloom_hashes: 0,
            tier2_bloom_hex: String::new(),
            grams_received: indexed.to_vec(),
            grams_indexed: indexed.to_vec(),
            grams_complete,
            deleted,
            external_id: external_id.map(str::to_owned),
        }
    }

    fn u32_bytes(values: &[u32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(values.len() * 4);
        for value in values {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    fn insert_primary(
        store: &mut CandidateStore,
        sha256: [u8; 32],
        file_size: u64,
        gram_count_estimate: Option<usize>,
        bloom_hashes: Option<usize>,
        filter_bytes: usize,
        bloom_filter: &[u8],
        grams_received: &[u64],
        grams_complete: bool,
        external_id: Option<String>,
        grams_sorted_unique: bool,
    ) -> Result<CandidateInsertResult> {
        store.insert_document(
            sha256,
            file_size,
            gram_count_estimate,
            bloom_hashes,
            None,
            None,
            filter_bytes,
            bloom_filter,
            0,
            &[],
            grams_received,
            grams_complete,
            None,
            external_id,
            grams_sorted_unique,
        )
    }

    fn default_test_meta() -> StoreMeta {
        StoreMeta::default()
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
            &{
                let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
                bloom.add(0x4443_4241).expect("add gram");
                bloom.into_bytes()
            },
            &[0x4443_4241],
            true,
            Some("doc-1".to_owned()),
            true,
        )
        .expect("insert");
        assert_eq!(result.status, "inserted");

        let plan = compile_query_plan(
            r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
            Some(&store.df_counts()),
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
            &[0x4443_4241],
            true,
            Some("live".to_owned()),
            true,
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
            &[0x4443_4241],
            true,
            Some("deleted".to_owned()),
            true,
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
                &[0x4443_4241],
                true,
                None,
                None,
                true,
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
                &[0x5A59_5857],
                true,
                None,
                None,
                true,
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
            &[0x4443_4241],
            true,
            Some("live".to_owned()),
            true,
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
            &[0x4443_4241],
            true,
            Some("deleted".to_owned()),
            true,
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
            &[0x4443_4241],
            true,
            None,
            true,
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
            &[0x4443_4241],
            true,
            None,
            true,
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
            &[0x4443_4241],
            true,
            None,
            true,
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
            &[0x4443_4241],
            true,
            None,
            true,
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
    fn df_min_suppresses_first_occurrence() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root,
                filter_target_fp: None,
                df_min: 2,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");

        let first = insert_primary(
            &mut store,
            [0xAA; 32],
            32,
            None,
            None,
            32,
            &[0u8; 32],
            &[0x0102_0304],
            true,
            None,
            true,
        )
        .expect("insert");
        assert_eq!(first.grams_indexed, 0);
        assert!(!first.grams_complete);

        let second = insert_primary(
            &mut store,
            [0xBB; 32],
            32,
            None,
            None,
            32,
            &[0u8; 32],
            &[0x0102_0304],
            true,
            None,
            true,
        )
        .expect("insert");
        assert_eq!(second.grams_indexed, 1);
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
    fn filter_bucket_counts_and_external_ids_follow_active_docs() {
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
            &[],
            false,
            Some("doc-small".to_owned()),
            true,
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
            &[],
            false,
            Some("doc-large".to_owned()),
            true,
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
            &[],
            false,
            Some("doc-deleted".to_owned()),
            true,
        )
        .expect("insert three");
        store
            .delete_document(&hex::encode(sha3))
            .expect("delete third");

        let counts = store.filter_bucket_counts();
        assert_eq!(counts.get("65536"), Some(&1));
        assert_eq!(counts.get("262144"), Some(&1));

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
                df_min: 0,
                ..CandidateConfig::default()
            })
            .expect_err("positive config")
            .to_string()
            .contains("must be positive")
        );
        assert!(
            validate_config(&CandidateConfig {
                root: root.clone(),
                df_min: 2,
                df_max: 1,
                ..CandidateConfig::default()
            })
            .expect_err("df order")
            .to_string()
            .contains("df_max")
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

        fs::write(docs_path(&open_root), b"{").expect("bad docs");
        assert!(
            CandidateStore::open(&open_root)
                .expect_err("invalid docs")
                .to_string()
                .contains("Invalid candidate document state")
        );
    }

    #[test]
    fn binary_sidecars_roundtrip_and_legacy_sources_migrate() {
        let tmp = tempdir().expect("tmp");
        let docs = vec![
            legacy_doc(2, 0x22, 64, 7, &[2, 3, 4], &[2, 3, 4], false, true, None),
            legacy_doc(
                1,
                0x11,
                64,
                7,
                &[1, 2],
                &[1, 2],
                true,
                false,
                Some("legacy-one"),
            ),
        ];

        let binary_root = tmp.path().join("binary_root");
        let (rows, tier2_rows) =
            persist_docs_as_binary(&binary_root, &docs, 4).expect("persist binary");
        assert_eq!(rows.len(), 2);
        assert_eq!(tier2_rows.len(), 2);
        assert!(binary_store_exists(&binary_root));
        let (loaded_docs, loaded_rows, loaded_rows5) =
            load_candidate_binary_store(&binary_root).expect("load binary");
        assert_eq!(loaded_docs.len(), 2);
        assert_eq!(loaded_rows.len(), 2);
        assert_eq!(loaded_rows5.len(), 2);
        assert_eq!(loaded_docs[0].doc_id, 1);
        assert!(loaded_docs[1].deleted);
        fs::write(
            meta_path(&binary_root),
            serde_json::to_vec_pretty(&StoreMeta::default()).expect("binary meta"),
        )
        .expect("write binary meta");
        let opened_binary = CandidateStore::open(&binary_root).expect("open binary store");
        assert_eq!(
            opened_binary.external_ids_for_sha256(&[hex::encode([0x11; 32])]),
            vec![Some("legacy-one".to_owned())]
        );

        let legacy_json_root = tmp.path().join("legacy_json_root");
        fs::create_dir_all(&legacy_json_root).expect("legacy json root");
        fs::write(
            docs_path(&legacy_json_root),
            serde_json::to_vec_pretty(&docs).expect("legacy docs json"),
        )
        .expect("write legacy json");
        let (migrated_docs, migrated_rows, migrated_rows5) =
            load_candidate_store_state(&legacy_json_root, &default_test_meta())
                .expect("migrate json");
        assert_eq!(migrated_docs.len(), 2);
        assert_eq!(migrated_rows.len(), 2);
        assert_eq!(migrated_rows5.len(), 2);
        assert_eq!(migrated_docs[0].doc_id, 2);
        assert!(!docs_path(&legacy_json_root).exists());
        assert!(binary_store_exists(&legacy_json_root));
        let (reopened_migrated_docs, reopened_migrated_rows, reopened_migrated_rows5) =
            load_candidate_binary_store(&legacy_json_root).expect("reload migrated json");
        assert_eq!(reopened_migrated_docs.len(), 2);
        assert_eq!(reopened_migrated_rows.len(), 2);
        assert_eq!(reopened_migrated_rows5.len(), 2);
        assert_eq!(reopened_migrated_docs[0].doc_id, 1);

        let legacy_log_root = tmp.path().join("legacy_log_root");
        fs::create_dir_all(&legacy_log_root).expect("legacy log root");
        let mut log = fs::File::create(docs_log_path(&legacy_log_root)).expect("create log");
        writeln!(
            log,
            "{}",
            serde_json::to_string(&docs[0]).expect("log doc 0")
        )
        .expect("write log doc 0");
        writeln!(log).expect("blank line");
        writeln!(
            log,
            "{}",
            serde_json::to_string(&docs[1]).expect("log doc 1")
        )
        .expect("write log doc 1");
        let (migrated_log_docs, migrated_log_rows, migrated_log_rows5) =
            load_candidate_store_state(&legacy_log_root, &default_test_meta())
                .expect("migrate log");
        assert_eq!(migrated_log_docs.len(), 2);
        assert_eq!(migrated_log_rows.len(), 2);
        assert_eq!(migrated_log_rows5.len(), 2);
        assert_eq!(migrated_log_docs[0].doc_id, 1);
        assert!(!docs_log_path(&legacy_log_root).exists());
        assert!(binary_store_exists(&legacy_log_root));

        let invalid_log = tmp.path().join("invalid_log.jsonl");
        fs::write(&invalid_log, b"{\n").expect("write invalid log");
        assert!(
            load_candidate_docs_log(&invalid_log)
                .expect_err("invalid log")
                .to_string()
                .contains("Invalid candidate document log")
        );
    }

    #[test]
    fn binary_sidecars_reject_corrupt_lengths_and_offsets() {
        let tmp = tempdir().expect("tmp");
        let docs = vec![legacy_doc(
            1,
            0x11,
            64,
            7,
            &[10, 20],
            &[10, 20],
            true,
            false,
            Some("ok"),
        )];

        let invalid_len_root = tmp.path().join("invalid_len_root");
        persist_docs_as_binary(&invalid_len_root, &docs, 4).expect("persist invalid len root");
        fs::write(sha_by_docid_path(&invalid_len_root), [0u8; 31]).expect("truncate sha");
        assert!(
            load_candidate_binary_store(&invalid_len_root)
                .expect_err("invalid binary len")
                .to_string()
                .contains("Invalid candidate binary document state")
        );

        let mismatch_root = tmp.path().join("mismatch_root");
        persist_docs_as_binary(&mismatch_root, &docs, 4).expect("persist mismatch root");
        fs::write(sha_by_docid_path(&mismatch_root), vec![0u8; 64]).expect("mismatch sha bytes");
        assert!(
            load_candidate_binary_store(&mismatch_root)
                .expect_err("mismatch state")
                .to_string()
                .contains("Mismatched candidate binary document state")
        );

        let invalid_bloom_root = tmp.path().join("invalid_bloom_root");
        persist_docs_as_binary(&invalid_bloom_root, &docs, 4).expect("persist invalid bloom root");
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
        persist_docs_as_binary(&invalid_utf8_root, &docs, 4).expect("persist invalid utf8 root");
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
            flags: DOC_FLAG_GRAMS_COMPLETE | DOC_FLAG_DELETED,
            bloom_hashes: 7,
            bloom_offset: 7,
            bloom_len: 8,
            grams_received_offset: 9,
            grams_received_count: 2,
            grams_indexed_offset: 17,
            grams_indexed_count: 1,
            external_id_offset: 21,
            external_id_len: 4,
        };
        let encoded = row.encode();
        let decoded = DocMetaRow::decode(&encoded).expect("decode row");
        assert_eq!(decoded.file_size, row.file_size);
        assert_eq!(decoded.filter_bytes, row.filter_bytes);
        assert_eq!(decoded.flags, row.flags);
        assert_eq!(decoded.bloom_offset, row.bloom_offset);
        assert_eq!(decoded.bloom_len, row.bloom_len);
        assert_eq!(decoded.grams_received_offset, row.grams_received_offset);
        assert_eq!(decoded.grams_received_count, row.grams_received_count);
        assert_eq!(decoded.grams_indexed_offset, row.grams_indexed_offset);
        assert_eq!(decoded.grams_indexed_count, row.grams_indexed_count);
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
                .insert_document(
                    [0x10; 32],
                    8,
                    None,
                    None,
                    None,
                    None,
                    0,
                    &[],
                    0,
                    &[],
                    &[],
                    true,
                    None,
                    None,
                    true,
                )
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
                    &[],
                    true,
                    None,
                    None,
                    true,
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
            &[5, 6, 6],
            true,
            Some("first".to_owned()),
            false,
        )
        .expect("insert");
        assert_eq!(inserted.status, "inserted");
        assert_eq!(inserted.grams_received, 2);

        let duplicate = insert_primary(
            &mut store,
            [0x10; 32],
            999,
            None,
            None,
            1024,
            &vec![0u8; 1024],
            &[99],
            false,
            Some("ignored".to_owned()),
            true,
        )
        .expect("duplicate");
        assert_eq!(duplicate.status, "already_exists");
        assert_eq!(duplicate.doc_id, inserted.doc_id);
        assert_eq!(duplicate.grams_received, 2);

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
            &[7],
            false,
            Some("restored".to_owned()),
            true,
        )
        .expect("restore");
        assert_eq!(restored.status, "restored");
        assert_eq!(restored.doc_id, inserted.doc_id);
        assert!(!restored.grams_complete);

        let stats = store.stats();
        assert_eq!(stats.doc_count, 1);
        assert_eq!(stats.deleted_doc_count, 0);
        assert_eq!(stats.tier1_incomplete_doc_count, 1);
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
        let mut bloom_one = BloomFilter::new(filter_bytes, 2).expect("bloom one");
        bloom_one.add(1).expect("add gram");
        let mut bloom_two = BloomFilter::new(filter_bytes, 2).expect("bloom two");
        bloom_two.add(2).expect("add gram");
        let mut bloom_one_two = BloomFilter::new(filter_bytes, 2).expect("bloom one two");
        bloom_one_two.add(1).expect("add gram");
        bloom_one_two.add(2).expect("add gram");

        insert_primary(
            &mut store,
            [0x11; 32],
            8,
            None,
            Some(2),
            filter_bytes,
            &bloom_one.into_bytes(),
            &[1],
            true,
            None,
            true,
        )
        .expect("insert doc one");
        insert_primary(
            &mut store,
            [0x22; 32],
            8,
            None,
            Some(2),
            filter_bytes,
            &bloom_two.into_bytes(),
            &[2],
            false,
            None,
            true,
        )
        .expect("insert doc two");
        insert_primary(
            &mut store,
            [0x33; 32],
            8,
            None,
            Some(2),
            filter_bytes,
            &bloom_one_two.into_bytes(),
            &[1],
            false,
            None,
            true,
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

        let mut bloom = BloomFilter::new(64, 2).expect("bloom");
        bloom.add(1).expect("add gram");
        bloom.add(2).expect("add gram");
        let doc = CandidateDoc {
            doc_id: 99,
            sha256: hex::encode([0x44; 32]),
            file_size: 42,
            filter_bytes: 64,
            bloom_hashes: 2,
            tier2_filter_bytes: 0,
            tier2_bloom_hashes: 0,
            grams_complete: false,
            deleted: false,
        };
        let indexed = u32_bytes(&[1]);
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
        let bloom_bytes = bloom.into_bytes();
        let tier2_bloom_bytes = &[][..];
        let mask_cache = build_pattern_mask_cache(&patterns_vec, &[(64, 2)], &[(64, 2)])
            .expect("pattern mask cache");

        let outcome = evaluate_pattern(
            patterns.get("empty").expect("empty"),
            mask_cache.get("empty").expect("empty masks"),
            &doc,
            &indexed,
            &bloom_bytes,
            tier2_bloom_bytes,
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
        let complete_doc = CandidateDoc {
            grams_complete: true,
            ..doc.clone()
        };
        let empty_indexed = Vec::new();
        let outcome = evaluate_pattern(
            patterns.get("missing").expect("missing"),
            mask_cache.get("missing").expect("missing masks"),
            &complete_doc,
            &empty_indexed,
            &bloom_bytes,
            tier2_bloom_bytes,
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
        let outcome = evaluate_pattern(
            patterns.get("tier2").expect("tier2"),
            mask_cache.get("tier2").expect("tier2 masks"),
            &complete_doc,
            &empty_indexed,
            &bloom_bytes,
            tier2_bloom_bytes,
            &allow_fallback_plan,
        )
        .expect("complete doc should not tier2 fallback");
        assert!(!outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "none");
        assert_eq!(outcome.score, 0);

        let no_overlap_doc = CandidateDoc {
            grams_complete: false,
            ..doc.clone()
        };
        let no_overlap_indexed = u32_bytes(&[3]);
        let outcome = evaluate_pattern(
            patterns.get("tier2").expect("tier2"),
            mask_cache.get("tier2").expect("tier2 masks"),
            &no_overlap_doc,
            &no_overlap_indexed,
            &bloom_bytes,
            tier2_bloom_bytes,
            &allow_fallback_plan,
        )
        .expect("incomplete doc without indexed overlap should still tier2 fallback");
        assert!(outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "tier2");
        assert!(outcome.score > 0);

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
            &doc,
            &indexed,
            &bloom_bytes,
            tier2_bloom_bytes,
            &patterns,
            &mask_cache,
            &eval_plan,
            &mut QueryEvalCache::default(),
        )
        .expect("and");
        assert!(!outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "none");
        assert_eq!(outcome.score, 0);

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
            &doc,
            &indexed,
            &bloom_bytes,
            tier2_bloom_bytes,
            &patterns,
            &mask_cache,
            &eval_plan,
            &mut QueryEvalCache::default(),
        )
        .expect("or");
        assert!(outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "tier2");
        assert!(outcome.score > 0);

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
            &doc,
            &indexed,
            &bloom_bytes,
            tier2_bloom_bytes,
            &patterns,
            &mask_cache,
            &eval_plan,
            &mut QueryEvalCache::default(),
        )
        .expect("n_of");
        assert!(outcome.matched);
        assert_eq!(outcome.tiers.as_label(), "tier1+tier2");
        assert!(outcome.score > 0);

        assert!(
            evaluate_node(
                &QueryNode {
                    kind: "n_of".to_owned(),
                    pattern_id: None,
                    threshold: None,
                    children: Vec::new(),
                },
                &doc,
                &indexed,
                &bloom_bytes,
                tier2_bloom_bytes,
                &patterns,
                &mask_cache,
                &eval_plan,
                &mut QueryEvalCache::default(),
            )
            .expect_err("missing threshold")
            .to_string()
            .contains("requires threshold")
        );
        assert!(
            evaluate_node(
                &QueryNode {
                    kind: "bogus".to_owned(),
                    pattern_id: None,
                    threshold: None,
                    children: Vec::new(),
                },
                &doc,
                &indexed,
                &bloom_bytes,
                tier2_bloom_bytes,
                &patterns,
                &mask_cache,
                &eval_plan,
                &mut QueryEvalCache::default(),
            )
            .expect_err("unsupported kind")
            .to_string()
            .contains("Unsupported ast node kind")
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
        let mut primary_bloom =
            BloomFilter::new(filter_bytes, bloom_hashes).expect("primary bloom");
        primary_bloom
            .add(pack_exact_gram(&[1, 2, 3]))
            .expect("add primary gram");
        primary_bloom
            .add(pack_exact_gram(&[2, 3, 4]))
            .expect("add primary gram");
        let tier2_filter_bytes = store
            .resolve_filter_bytes_for_file_size(4, Some(2))
            .expect("secondary filter bytes");
        let tier2_bloom_hashes =
            store.resolve_bloom_hashes_for_document(tier2_filter_bytes, Some(2), None);
        let mut secondary_bloom =
            BloomFilter::new(tier2_filter_bytes, tier2_bloom_hashes).expect("secondary bloom");
        secondary_bloom
            .add(pack_exact_gram(&[1, 2, 3, 4]))
            .expect("add secondary gram");
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
                &secondary_bloom.into_bytes(),
                &[pack_exact_gram(&[1, 2, 3, 4])],
                false,
                None,
                None,
                true,
            )
            .expect("write secondary sidecars");

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
    fn folded_superblock_masks_preserve_required_bits() {
        let required = vec![
            (0usize, 0b0000_0011),
            (4096usize, 0b0000_0100),
            (8193usize, 0b1000_0000),
        ];
        let folded = fold_bloom_masks(&required, 4096);
        let folded_map = folded.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(folded_map.get(&0).copied(), Some(0b0000_0111));
        assert_eq!(folded_map.get(&1).copied(), Some(0b1000_0000));
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
        let gram_count_estimate = 1_000_000usize;
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(file_size, Some(gram_count_estimate))
            .expect("large primary filter bytes");
        assert!(filter_bytes > MAX_TIER2_SUPERBLOCK_SUMMARY_BYTES);
        let bloom_hashes =
            store.resolve_bloom_hashes_for_document(filter_bytes, Some(gram_count_estimate), None);
        let mut primary_bloom =
            BloomFilter::new(filter_bytes, bloom_hashes).expect("primary bloom");
        primary_bloom
            .add(pack_exact_gram(&[1, 2, 3]))
            .expect("add primary gram");
        let tier2_filter_bytes = store
            .resolve_filter_bytes_for_file_size(file_size, Some(2))
            .expect("secondary filter bytes");
        let tier2_bloom_hashes =
            store.resolve_bloom_hashes_for_document(tier2_filter_bytes, Some(2), None);
        let mut secondary_bloom =
            BloomFilter::new(tier2_filter_bytes, tier2_bloom_hashes).expect("secondary bloom");
        secondary_bloom
            .add(pack_exact_gram(&[1, 2, 3, 4]))
            .expect("add secondary gram");
        store
            .insert_document(
                sha256,
                file_size,
                Some(gram_count_estimate),
                Some(bloom_hashes),
                Some(2),
                Some(tier2_bloom_hashes),
                filter_bytes,
                &primary_bloom.into_bytes(),
                tier2_filter_bytes,
                &secondary_bloom.into_bytes(),
                &[pack_exact_gram(&[1, 2, 3, 4])],
                false,
                None,
                None,
                true,
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
            Some(MAX_TIER2_SUPERBLOCK_SUMMARY_BYTES)
        );
        let blocks = store
            .tier2_superblocks
            .masks_by_bucket
            .get(&bucket_key)
            .expect("superblock masks");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), MAX_TIER2_SUPERBLOCK_SUMMARY_BYTES);
    }

    #[test]
    fn df_counts_delta_compaction_threshold_respects_memory_budget_and_shards() {
        assert_eq!(
            df_counts_delta_compact_threshold_bytes(16 * 1024 * 1024 * 1024, 256),
            4 * 1024 * 1024
        );
        assert_eq!(
            df_counts_delta_compact_threshold_bytes(0, 0),
            DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES
        );
        assert_eq!(
            df_counts_delta_compact_threshold_bytes(1024 * 1024 * 1024, 256),
            MIN_DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES
        );
        assert_eq!(
            df_counts_delta_compact_threshold_bytes(512 * 1024 * 1024 * 1024, 1),
            MAX_DF_COUNTS_DELTA_COMPACT_THRESHOLD_BYTES
        );
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
    fn apply_runtime_limits_updates_df_counts_threshold_and_stats() {
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
        assert_eq!(stats.df_counts_delta_entries, 0);
        assert_eq!(stats.df_counts_delta_bytes, 0);
        assert_eq!(
            stats.df_counts_delta_compact_threshold_bytes,
            4 * 1024 * 1024
        );
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
                &grams_received,
                true,
                None,
                None,
                true,
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
                &grams_one,
                true,
                None,
                None,
                true,
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
                &grams_two,
                true,
                None,
                None,
                true,
            )
            .expect("insert second");

        let (reopened, profile) = CandidateStore::open_profiled(&root).expect("reopen");
        assert!(!profile.loaded_tier2_superblocks_from_snapshot);
        assert!(reopened.tier2_superblocks.summary_memory_bytes > 0);
    }
}
