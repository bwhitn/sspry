#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN=${BIN:-"$ROOT_DIR/target/debug/sspry"}

ADDR=
ROOT=
OUT=
RULE_MANIFEST=
BUNDLE_RULE=
MODE_LABEL=default
SEARCH_WORKERS=0
READY_TIMEOUT_S=180
SEARCH_TIMEOUT_S=86400
SAMPLE_INTERVAL_S=1
SKIP_INDIVIDUAL=0
SKIP_BUNDLE=0
SERVER_EXTRA_ARGS=()
SEARCH_EXTRA_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  ./scripts/server_search_bench.sh --root <db-root> --addr <host:port> --out <dir> [options]

Required:
  --root <path>             Candidate DB root to serve.
  --addr <host:port>        Server bind address and client target.
  --out <dir>               Output directory for logs, metrics, and summaries.

Search selection:
  --rule-manifest <path>    Newline-delimited rule list for sequential individual runs.
  --bundle-rule <path>      Bundle file for the bundled search run.
  --skip-individual         Skip the sequential per-rule phase.
  --skip-bundle             Skip the bundled phase.

Server and search options:
  --search-workers <n>      Passed to `sspry serve --search-workers`.
  --server-extra-arg <arg>  Extra arg forwarded to `sspry serve`. Repeatable.
  --search-extra-arg <arg>  Extra arg forwarded to `sspry search`. Repeatable.
  --ready-timeout <sec>     Wait time for server readiness. Default: 180.
  --search-timeout <sec>    Passed to `sspry search --timeout`. Default: 86400.
  --sample-interval <sec>   `/proc` sample interval for server metrics. Default: 1.
  --mode-label <text>       Label stored in summary rows. Default: default.

Outputs:
  phase_summary.tsv         Per-phase wall, CPU, and memory summary.
  server_samples.tsv        Timestamped server `/proc` samples.
  individual_summary.tsv    Per-rule client timings for individual runs.
  bundle.time               Client timing metrics for the bundled run.
  run.log                   High-level execution log.

Captured server metrics:
  - CPU time from `/proc/<pid>/stat`
  - VmRSS, RssAnon, VmSwap from `/proc/<pid>/status`
  - Pss_Anon, Private_Clean, Private_Dirty from `/proc/<pid>/smaps_rollup`

Captured client metrics:
  - elapsed wall time
  - user CPU time
  - system CPU time
  - average CPU percent
  - max RSS
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

timestamp_now() {
  date +%s.%N
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || die "missing file: $path"
}

status_field_kb() {
  local pid="$1"
  local field="$2"
  awk -v key="${field}:" '$1 == key { print $2; found = 1 } END { if (!found) print 0 }' \
    "/proc/$pid/status"
}

status_field_text() {
  local pid="$1"
  local field="$2"
  awk -v key="${field}:" '$1 == key { print $2; found = 1 } END { if (!found) print "NA" }' \
    "/proc/$pid/status"
}

read_server_ticks() {
  local pid="$1"
  awk '{ print $14, $15 }' "/proc/$pid/stat"
}

read_smaps_rollup_kb() {
  local pid="$1"
  if [[ ! -r "/proc/$pid/smaps_rollup" ]]; then
    echo "0 0 0"
    return
  fi
  awk '
    $1 == "Pss_Anon:" { pss_anon = $2 }
    $1 == "Private_Clean:" { private_clean = $2 }
    $1 == "Private_Dirty:" { private_dirty = $2 }
    END { print pss_anon + 0, private_clean + 0, private_dirty + 0 }
  ' "/proc/$pid/smaps_rollup"
}

sample_server_proc() {
  local pid="$1"
  local ts state vmrss rssanon vmswap utime stime pss_anon private_clean private_dirty

  [[ -r "/proc/$pid/status" && -r "/proc/$pid/stat" ]] || return 1

  ts=$(timestamp_now)
  state=$(status_field_text "$pid" "State")
  vmrss=$(status_field_kb "$pid" "VmRSS")
  rssanon=$(status_field_kb "$pid" "RssAnon")
  vmswap=$(status_field_kb "$pid" "VmSwap")
  read -r utime stime < <(read_server_ticks "$pid")
  read -r pss_anon private_clean private_dirty < <(read_smaps_rollup_kb "$pid")

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$ts" "$state" "$utime" "$stime" "$vmrss" "$rssanon" "$vmswap" \
    "$pss_anon" "$private_clean" "$private_dirty"
}

monitor_server() {
  local pid="$1"
  local sample_file="$2"
  local interval="$3"

  printf 'timestamp_s\tstate\tutime_ticks\tstime_ticks\tvmrss_kb\trssanon_kb\tvmswap_kb\tpss_anon_kb\tprivate_clean_kb\tprivate_dirty_kb\n' \
    > "$sample_file"

  while kill -0 "$pid" 2>/dev/null; do
    sample_server_proc "$pid" >> "$sample_file" || true
    sleep "$interval"
  done
  sample_server_proc "$pid" >> "$sample_file" || true
}

capture_server_snapshot() {
  local pid="$1"
  local ts utime stime
  ts=$(timestamp_now)
  read -r utime stime < <(read_server_ticks "$pid")
  printf '%s\t%s\t%s\n' "$ts" "$utime" "$stime"
}

metric_value() {
  local path="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print $2; found = 1 } END { if (!found) exit 1 }' "$path"
}

sum_metric_key() {
  local files=("$@")
  if [[ ${#files[@]} -eq 0 ]]; then
    echo "0"
    return
  fi
  awk -F= '
    $1 == "elapsed_s" { elapsed += $2 }
    $1 == "user_s" { user += $2 }
    $1 == "system_s" { system += $2 }
    $1 == "max_rss_kb" { if ($2 > max_rss) max_rss = $2 }
    END {
      printf "elapsed_s=%.6f\n", elapsed + 0
      printf "user_s=%.6f\n", user + 0
      printf "system_s=%.6f\n", system + 0
      printf "max_rss_kb=%d\n", max_rss + 0
    }
  ' "${files[@]}"
}

wait_ready() {
  local pid="$1"
  local waited=0
  while (( waited < READY_TIMEOUT_S )); do
    if "$BIN" info --addr "$ADDR" --timeout 5 >/dev/null 2>&1; then
      echo "$waited"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
    kill -0 "$pid" 2>/dev/null || return 1
  done
  return 1
}

record_phase_summary() {
  local phase="$1"
  local phase_start_ts="$2"
  local phase_end_ts="$3"
  local start_utime="$4"
  local start_stime="$5"
  local end_utime="$6"
  local end_stime="$7"
  local client_elapsed_s="$8"
  local client_user_s="$9"
  local client_system_s="${10}"
  local client_max_rss_kb="${11}"

  local sample_metrics wall_s server_cpu_s client_cpu_s client_avg_cpu_pct server_avg_cpu_pct
  local sample_count max_vmrss_kb max_rssanon_kb max_vmswap_kb max_pss_anon_kb
  local max_private_clean_kb max_private_dirty_kb

  read -r sample_count max_vmrss_kb max_rssanon_kb max_vmswap_kb max_pss_anon_kb \
    max_private_clean_kb max_private_dirty_kb < <(
      awk -F'\t' -v start="$phase_start_ts" -v end="$phase_end_ts" '
        NR == 1 { next }
        ($1 + 0) >= (start + 0) && ($1 + 0) <= (end + 0) {
          count += 1
          if (($5 + 0) > max_vmrss) max_vmrss = $5 + 0
          if (($6 + 0) > max_rssanon) max_rssanon = $6 + 0
          if (($7 + 0) > max_vmswap) max_vmswap = $7 + 0
          if (($8 + 0) > max_pss_anon) max_pss_anon = $8 + 0
          if (($9 + 0) > max_private_clean) max_private_clean = $9 + 0
          if (($10 + 0) > max_private_dirty) max_private_dirty = $10 + 0
        }
        END {
          printf "%d %d %d %d %d %d %d\n",
            count + 0,
            max_vmrss + 0,
            max_rssanon + 0,
            max_vmswap + 0,
            max_pss_anon + 0,
            max_private_clean + 0,
            max_private_dirty + 0
        }
      ' "$OUT/server_samples.tsv"
    )

  wall_s=$(awk -v start="$phase_start_ts" -v end="$phase_end_ts" \
    'BEGIN { printf "%.6f", (end + 0) - (start + 0) }')
  server_cpu_s=$(awk -v hz="$CLOCK_TICKS" \
    -v start_u="$start_utime" -v start_s="$start_stime" \
    -v end_u="$end_utime" -v end_s="$end_stime" \
    'BEGIN { printf "%.6f", ((end_u + end_s) - (start_u + start_s)) / hz }')
  client_cpu_s=$(awk -v user="$client_user_s" -v system="$client_system_s" \
    'BEGIN { printf "%.6f", user + system }')
  client_avg_cpu_pct=$(awk -v cpu="$client_cpu_s" -v wall="$client_elapsed_s" '
    BEGIN {
      if (wall <= 0) printf "0.00";
      else printf "%.2f", (cpu / wall) * 100.0;
    }')
  server_avg_cpu_pct=$(awk -v cpu="$server_cpu_s" -v wall="$wall_s" '
    BEGIN {
      if (wall <= 0) printf "0.00";
      else printf "%.2f", (cpu / wall) * 100.0;
    }')

  printf '%s\t%s\t%.6f\t%.6f\t%.6f\t%.6f\t%s\t%.6f\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n' \
    "$MODE_LABEL" "$phase" "$client_elapsed_s" "$client_user_s" "$client_system_s" \
    "$client_cpu_s" "$client_avg_cpu_pct" "$server_cpu_s" "$server_avg_cpu_pct" \
    "$max_vmrss_kb" "$max_rssanon_kb" "$max_vmswap_kb" "$max_pss_anon_kb" \
    "$max_private_clean_kb" "$max_private_dirty_kb" "$sample_count" \
    >> "$OUT/phase_summary.tsv"
}

run_search() {
  local label="$1"
  local rule_path="$2"
  local metrics_path="$OUT/${label}.time"
  local stderr_path="$OUT/${label}.stderr"

  /usr/bin/time -f 'elapsed_s=%e\nuser_s=%U\nsystem_s=%S\ncpu_pct=%P\nmax_rss_kb=%M' \
    -o "$metrics_path" \
    "$BIN" search --addr "$ADDR" --timeout "$SEARCH_TIMEOUT_S" --rule "$rule_path" \
    "${SEARCH_EXTRA_ARGS[@]}" >/dev/null 2>"$stderr_path"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT="$2"
      shift 2
      ;;
    --addr)
      ADDR="$2"
      shift 2
      ;;
    --out)
      OUT="$2"
      shift 2
      ;;
    --rule-manifest)
      RULE_MANIFEST="$2"
      shift 2
      ;;
    --bundle-rule)
      BUNDLE_RULE="$2"
      shift 2
      ;;
    --search-workers)
      SEARCH_WORKERS="$2"
      shift 2
      ;;
    --server-extra-arg)
      SERVER_EXTRA_ARGS+=("$2")
      shift 2
      ;;
    --search-extra-arg)
      SEARCH_EXTRA_ARGS+=("$2")
      shift 2
      ;;
    --ready-timeout)
      READY_TIMEOUT_S="$2"
      shift 2
      ;;
    --search-timeout)
      SEARCH_TIMEOUT_S="$2"
      shift 2
      ;;
    --sample-interval)
      SAMPLE_INTERVAL_S="$2"
      shift 2
      ;;
    --mode-label)
      MODE_LABEL="$2"
      shift 2
      ;;
    --skip-individual)
      SKIP_INDIVIDUAL=1
      shift
      ;;
    --skip-bundle)
      SKIP_BUNDLE=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$ROOT" ]] || die "--root is required"
[[ -n "$ADDR" ]] || die "--addr is required"
[[ -n "$OUT" ]] || die "--out is required"
[[ -x "$BIN" ]] || die "binary not found or not executable: $BIN"
(( SKIP_INDIVIDUAL == 0 || SKIP_BUNDLE == 0 )) || die "cannot skip both phases"

if (( SKIP_INDIVIDUAL == 0 )); then
  [[ -n "$RULE_MANIFEST" ]] || die "--rule-manifest is required unless --skip-individual is set"
  require_file "$RULE_MANIFEST"
fi
if (( SKIP_BUNDLE == 0 )); then
  [[ -n "$BUNDLE_RULE" ]] || die "--bundle-rule is required unless --skip-bundle is set"
  require_file "$BUNDLE_RULE"
fi

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
ROOT=$(cd "$ROOT" && pwd)
CLOCK_TICKS=$(getconf CLK_TCK)

printf 'mode_label\tphase\tclient_elapsed_s\tclient_user_s\tclient_system_s\tclient_cpu_s\tclient_avg_cpu_pct\tserver_cpu_s\tserver_avg_cpu_pct\tserver_max_vmrss_kb\tserver_max_rssanon_kb\tserver_max_vmswap_kb\tserver_max_pss_anon_kb\tserver_max_private_clean_kb\tserver_max_private_dirty_kb\tsample_count\n' \
  > "$OUT/phase_summary.tsv"
printf 'rule\telapsed_s\tuser_s\tsystem_s\tcpu_pct\tmax_rss_kb\n' > "$OUT/individual_summary.tsv"

{
  echo "started_at=$(date -u +%FT%TZ)"
  echo "mode_label=$MODE_LABEL"
  echo "bin=$BIN"
  echo "root=$ROOT"
  echo "addr=$ADDR"
  echo "search_workers=$SEARCH_WORKERS"
  echo "ready_timeout_s=$READY_TIMEOUT_S"
  echo "search_timeout_s=$SEARCH_TIMEOUT_S"
  echo "sample_interval_s=$SAMPLE_INTERVAL_S"
} > "$OUT/run.log"

cleanup() {
  if [[ -n "${MONITOR_PID:-}" ]]; then
    kill "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    "$BIN" shutdown --addr "$ADDR" --timeout 30 >/dev/null 2>"$OUT/server_shutdown.stderr" || true
    sleep 1
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "[$(date -u +%FT%TZ)] server start" >> "$OUT/run.log"
"$BIN" serve --root "$ROOT" --addr "$ADDR" --search-workers "$SEARCH_WORKERS" \
  "${SERVER_EXTRA_ARGS[@]}" >"$OUT/server.stdout" 2>"$OUT/server.stderr" &
SERVER_PID=$!
echo "server_pid=$SERVER_PID" >> "$OUT/run.log"

READY_WAITED=$(wait_ready "$SERVER_PID") || die "server failed before readiness"
echo "server_ready_after_s=$READY_WAITED" >> "$OUT/run.log"

monitor_server "$SERVER_PID" "$OUT/server_samples.tsv" "$SAMPLE_INTERVAL_S" &
MONITOR_PID=$!
echo "monitor_pid=$MONITOR_PID" >> "$OUT/run.log"

if (( SKIP_INDIVIDUAL == 0 )); then
  echo "[$(date -u +%FT%TZ)] individual phase start" >> "$OUT/run.log"
  read -r INDIVIDUAL_START_TS INDIVIDUAL_START_UTIME INDIVIDUAL_START_STIME \
    < <(capture_server_snapshot "$SERVER_PID")
  INDIVIDUAL_FILES=()
  while IFS= read -r rule || [[ -n "$rule" ]]; do
    [[ -n "$rule" ]] || continue
    require_file "$rule"
    RULE_NAME=$(basename "$rule" .yar)
    LABEL="individual_${RULE_NAME}"
    run_search "$LABEL" "$rule"
    INDIVIDUAL_FILES+=("$OUT/${LABEL}.time")
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$RULE_NAME" \
      "$(metric_value "$OUT/${LABEL}.time" elapsed_s)" \
      "$(metric_value "$OUT/${LABEL}.time" user_s)" \
      "$(metric_value "$OUT/${LABEL}.time" system_s)" \
      "$(metric_value "$OUT/${LABEL}.time" cpu_pct)" \
      "$(metric_value "$OUT/${LABEL}.time" max_rss_kb)" \
      >> "$OUT/individual_summary.tsv"
    echo "[$(date -u +%FT%TZ)] individual rule done rule=$RULE_NAME" >> "$OUT/run.log"
  done < "$RULE_MANIFEST"
  read -r INDIVIDUAL_END_TS INDIVIDUAL_END_UTIME INDIVIDUAL_END_STIME \
    < <(capture_server_snapshot "$SERVER_PID")
  eval "$(sum_metric_key "${INDIVIDUAL_FILES[@]}")"
  record_phase_summary \
    "individual" \
    "$INDIVIDUAL_START_TS" "$INDIVIDUAL_END_TS" \
    "$INDIVIDUAL_START_UTIME" "$INDIVIDUAL_START_STIME" \
    "$INDIVIDUAL_END_UTIME" "$INDIVIDUAL_END_STIME" \
    "$elapsed_s" "$user_s" "$system_s" "$max_rss_kb"
  echo "[$(date -u +%FT%TZ)] individual phase done elapsed_s=$elapsed_s" >> "$OUT/run.log"
fi

if (( SKIP_BUNDLE == 0 )); then
  echo "[$(date -u +%FT%TZ)] bundle phase start" >> "$OUT/run.log"
  read -r BUNDLE_START_TS BUNDLE_START_UTIME BUNDLE_START_STIME \
    < <(capture_server_snapshot "$SERVER_PID")
  run_search "bundle" "$BUNDLE_RULE"
  read -r BUNDLE_END_TS BUNDLE_END_UTIME BUNDLE_END_STIME \
    < <(capture_server_snapshot "$SERVER_PID")
  BUNDLE_ELAPSED=$(metric_value "$OUT/bundle.time" elapsed_s)
  BUNDLE_USER=$(metric_value "$OUT/bundle.time" user_s)
  BUNDLE_SYSTEM=$(metric_value "$OUT/bundle.time" system_s)
  BUNDLE_MAX_RSS=$(metric_value "$OUT/bundle.time" max_rss_kb)
  record_phase_summary \
    "bundle" \
    "$BUNDLE_START_TS" "$BUNDLE_END_TS" \
    "$BUNDLE_START_UTIME" "$BUNDLE_START_STIME" \
    "$BUNDLE_END_UTIME" "$BUNDLE_END_STIME" \
    "$BUNDLE_ELAPSED" "$BUNDLE_USER" "$BUNDLE_SYSTEM" "$BUNDLE_MAX_RSS"
  echo "[$(date -u +%FT%TZ)] bundle phase done elapsed_s=$BUNDLE_ELAPSED" >> "$OUT/run.log"
fi

echo "[$(date -u +%FT%TZ)] server shutdown requested" >> "$OUT/run.log"
"$BIN" shutdown --addr "$ADDR" --timeout 30 >/dev/null 2>"$OUT/server_shutdown.stderr" || true
wait "$SERVER_PID" || true
kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true
echo "finished_at=$(date -u +%FT%TZ)" >> "$OUT/run.log"
