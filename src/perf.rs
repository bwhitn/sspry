use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::{Result, SspryError};

#[derive(Clone, Debug, Default)]
struct StageStats {
    calls: u64,
    total_ns: u128,
    max_ns: u128,
    total_bytes: u64,
    total_items: u64,
}

#[derive(Clone, Debug)]
struct SampleRow {
    stage: String,
    label: String,
    elapsed_ms: f64,
    bytes: u64,
    items: u64,
}

#[derive(Clone, Debug)]
struct PerfState {
    enabled: bool,
    report_path: Option<PathBuf>,
    stdout: bool,
    started_unix_ms: u64,
    started_at: Instant,
    stages: BTreeMap<String, StageStats>,
    counters: BTreeMap<String, u64>,
    maxima: BTreeMap<String, u64>,
    samples: Vec<SampleRow>,
}

impl Default for PerfState {
    fn default() -> Self {
        Self {
            enabled: false,
            report_path: None,
            stdout: false,
            started_unix_ms: now_unix_ms(),
            started_at: Instant::now(),
            stages: BTreeMap::new(),
            counters: BTreeMap::new(),
            maxima: BTreeMap::new(),
            samples: Vec::new(),
        }
    }
}

pub struct Scope {
    name: &'static str,
    started_at: Option<Instant>,
    bytes: u64,
    items: u64,
}

impl Scope {
    pub fn add_bytes(&mut self, value: u64) {
        self.bytes = self.bytes.saturating_add(value);
    }

    pub fn add_items(&mut self, value: u64) {
        self.items = self.items.saturating_add(value);
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let Some(started_at) = self.started_at.take() else {
            return;
        };
        let elapsed = started_at.elapsed().as_nanos();
        let Ok(mut state) = state().lock() else {
            return;
        };
        if !state.enabled {
            return;
        }
        let entry = state.stages.entry(self.name.to_owned()).or_default();
        entry.calls = entry.calls.saturating_add(1);
        entry.total_ns = entry.total_ns.saturating_add(elapsed);
        entry.max_ns = entry.max_ns.max(elapsed);
        entry.total_bytes = entry.total_bytes.saturating_add(self.bytes);
        entry.total_items = entry.total_items.saturating_add(self.items);
    }
}

fn truthy_env(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

fn initial_state() -> PerfState {
    let report_path = env::var_os("TGSDB_PERF_REPORT").map(PathBuf::from);
    let stdout = truthy_env("TGSDB_PERF_STDOUT");
    let enabled = report_path.is_some() || stdout;
    PerfState {
        enabled,
        report_path,
        stdout,
        ..PerfState::default()
    }
}

fn state() -> &'static Mutex<PerfState> {
    static STATE: OnceLock<Mutex<PerfState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(initial_state()))
}

#[cfg(test)]
pub(crate) fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn configure(report_path: Option<PathBuf>, stdout: bool) {
    let mut state = state().lock().expect("perf lock poisoned");
    state.report_path = report_path;
    state.stdout = stdout;
    state.enabled = state.report_path.is_some() || state.stdout;
    state.started_unix_ms = now_unix_ms();
    state.started_at = Instant::now();
    state.stages.clear();
    state.counters.clear();
    state.maxima.clear();
    state.samples.clear();
}

pub fn is_enabled() -> bool {
    state().lock().map(|value| value.enabled).unwrap_or(false)
}

pub fn scope(name: &'static str) -> Scope {
    if !is_enabled() {
        return Scope {
            name,
            started_at: None,
            bytes: 0,
            items: 0,
        };
    }
    Scope {
        name,
        started_at: Some(Instant::now()),
        bytes: 0,
        items: 0,
    }
}

pub fn record_counter(name: &'static str, delta: u64) {
    let Ok(mut state) = state().lock() else {
        return;
    };
    if !state.enabled {
        return;
    }
    *state.counters.entry(name.to_owned()).or_insert(0) = state
        .counters
        .get(name)
        .copied()
        .unwrap_or(0)
        .saturating_add(delta);
}

pub fn record_max(name: &'static str, value: u64) {
    let Ok(mut state) = state().lock() else {
        return;
    };
    if !state.enabled {
        return;
    }
    let entry = state.maxima.entry(name.to_owned()).or_insert(0);
    *entry = (*entry).max(value);
}

pub fn record_sample(
    stage: &'static str,
    label: impl Into<String>,
    elapsed_ns: u128,
    bytes: u64,
    items: u64,
) {
    let Ok(mut state) = state().lock() else {
        return;
    };
    if !state.enabled {
        return;
    }
    state.samples.push(SampleRow {
        stage: stage.to_owned(),
        label: label.into(),
        elapsed_ms: elapsed_ns as f64 / 1_000_000.0,
        bytes,
        items,
    });
}

fn build_report_value(state: &PerfState, exit_code: i32) -> Value {
    let finished_unix_ms = now_unix_ms();
    let elapsed_ms = state.started_at.elapsed().as_secs_f64() * 1000.0;
    let mut stages = Map::new();
    for (name, stats) in &state.stages {
        let total_ms = stats.total_ns as f64 / 1_000_000.0;
        let max_ms = stats.max_ns as f64 / 1_000_000.0;
        let avg_ms = if stats.calls == 0 {
            0.0
        } else {
            total_ms / stats.calls as f64
        };
        stages.insert(
            name.clone(),
            json!({
                "calls": stats.calls,
                "total_ms": total_ms,
                "avg_ms": avg_ms,
                "max_ms": max_ms,
                "total_bytes": stats.total_bytes,
                "total_items": stats.total_items,
            }),
        );
    }

    json!({
        "started_unix_ms": state.started_unix_ms,
        "finished_unix_ms": finished_unix_ms,
        "elapsed_ms": elapsed_ms,
        "exit_code": exit_code,
        "stages": stages,
        "counters": state.counters,
        "maxima": state.maxima,
        "samples": state.samples.iter().map(|row| json!({
            "stage": row.stage,
            "label": row.label,
            "elapsed_ms": row.elapsed_ms,
            "bytes": row.bytes,
            "items": row.items,
        })).collect::<Vec<_>>(),
    })
}

pub fn report_value(exit_code: i32) -> Option<Value> {
    let Ok(state) = state().lock() else {
        return None;
    };
    if !state.enabled {
        return None;
    }
    Some(build_report_value(&state, exit_code))
}

pub fn write_report(exit_code: i32) -> Result<()> {
    let (report_path, stdout, value) = {
        let state = state()
            .lock()
            .map_err(|_| SspryError::from("perf lock poisoned"))?;
        if !state.enabled {
            return Ok(());
        }
        (
            state.report_path.clone(),
            state.stdout,
            build_report_value(&state, exit_code),
        )
    };

    if let Some(path) = report_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, format!("{}\n", serde_json::to_string_pretty(&value)?))?;
    }
    if stdout {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::thread;
    use std::time::Duration;

    use serde_json::Value;
    use tempfile::tempdir;

    use super::{
        build_report_value, configure, initial_state, is_enabled, record_counter, record_max,
        record_sample, report_value, scope, test_lock, truthy_env, write_report,
    };

    #[test]
    fn perf_scope_records_stage_counters_and_maxima() {
        let _guard = test_lock().lock().expect("perf lock");
        configure(None, true);
        {
            let mut stage = scope("test.scope");
            stage.add_bytes(12);
            stage.add_items(3);
            thread::sleep(Duration::from_millis(1));
        }
        record_counter("rows_total", 7);
        record_counter("rows_total", 5);
        record_max("largest_row", 9);
        record_max("largest_row", 3);
        record_sample("test.sample", "alpha.bin", 2_500_000, 99, 4);

        let report = report_value(0).expect("perf report");
        assert_eq!(report.get("exit_code").and_then(Value::as_i64), Some(0));
        let scope_stats = report
            .get("stages")
            .and_then(Value::as_object)
            .and_then(|map| map.get("test.scope"))
            .and_then(Value::as_object)
            .expect("scope stats");
        assert_eq!(scope_stats.get("calls").and_then(Value::as_u64), Some(1));
        assert_eq!(
            scope_stats.get("total_bytes").and_then(Value::as_u64),
            Some(12)
        );
        assert_eq!(
            scope_stats.get("total_items").and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(
            report
                .get("counters")
                .and_then(Value::as_object)
                .and_then(|map| map.get("rows_total"))
                .and_then(Value::as_u64),
            Some(12)
        );
        assert_eq!(
            report
                .get("maxima")
                .and_then(Value::as_object)
                .and_then(|map| map.get("largest_row"))
                .and_then(Value::as_u64),
            Some(9)
        );
        let samples = report
            .get("samples")
            .and_then(Value::as_array)
            .expect("samples");
        assert_eq!(samples.len(), 1);
        assert_eq!(
            samples[0].get("stage").and_then(Value::as_str),
            Some("test.sample")
        );
        assert_eq!(
            samples[0].get("label").and_then(Value::as_str),
            Some("alpha.bin")
        );
    }

    #[test]
    fn env_helpers_and_disabled_state_cover_remaining_perf_paths() {
        let _guard = test_lock().lock().expect("perf lock");
        configure(None, false);
        assert!(!is_enabled());
        record_counter("ignored_counter", 5);
        record_max("ignored_max", 11);
        record_sample("ignored.sample", "ignored", 1, 2, 3);
        let report = super::report_value(0);
        assert!(report.is_none());

        let report_path = tempdir().expect("tmp").path().join("report.json");
        // SAFETY: tests only read these variables within this process.
        unsafe { env::set_var("TGSDB_PERF_REPORT", &report_path) };
        // SAFETY: tests only read these variables within this process.
        unsafe { env::set_var("TGSDB_PERF_STDOUT", "yes") };
        let initial = initial_state();
        assert!(initial.enabled);
        assert_eq!(initial.report_path, Some(report_path));
        assert!(initial.stdout);
        assert!(truthy_env("TGSDB_PERF_STDOUT"));
        // SAFETY: tests only mutate these variables within this process.
        unsafe { env::remove_var("TGSDB_PERF_REPORT") };
        // SAFETY: tests only mutate these variables within this process.
        unsafe { env::remove_var("TGSDB_PERF_STDOUT") };
        assert!(!truthy_env("TGSDB_PERF_STDOUT"));

        let disabled = build_report_value(&super::PerfState::default(), 7);
        assert_eq!(disabled.get("exit_code").and_then(Value::as_i64), Some(7));
    }

    #[test]
    fn write_report_writes_file_and_parent_dirs() {
        let _guard = test_lock().lock().expect("perf lock");
        let tmp = tempdir().expect("tmp");
        let report_path = tmp.path().join("nested").join("perf.json");
        configure(Some(report_path.clone()), false);
        {
            let mut stage = scope("write.report.scope");
            stage.add_bytes(5);
            stage.add_items(1);
        }
        write_report(3).expect("write perf report");
        let raw = fs::read_to_string(&report_path).expect("read perf report");
        let value: Value = serde_json::from_str(&raw).expect("parse perf report");
        assert_eq!(value.get("exit_code").and_then(Value::as_i64), Some(3));
        assert!(
            value
                .get("stages")
                .and_then(Value::as_object)
                .is_some_and(|map| map.contains_key("write.report.scope"))
        );
    }
}
