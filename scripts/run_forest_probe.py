#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

TEMPORARY_SEARCH_MARKERS = (
    'Resource temporarily unavailable',
    'busy during query scan; retry later',
    'busy during document frequency lookup; retry later',
)


def run(cmd, **kwargs):
    return subprocess.run(cmd, text=True, **kwargs)


def wait_for_server(sspry: Path, addr: str, out_path: Path, attempts: int = 300) -> None:
    for _ in range(attempts):
        proc = run([str(sspry), 'info', '--addr', addr, '--light'], capture_output=True)
        if proc.returncode == 0 and proc.stdout.strip():
            out_path.write_text(proc.stdout)
            return
        time.sleep(0.2)
    raise RuntimeError(f'server did not start on {addr}')


def wait_for_publish(sspry: Path, addr: str, out_path: Path, attempts: int = 1800, sleep_s: float = 2.0) -> dict:
    last = None
    for _ in range(attempts):
        proc = run([str(sspry), 'info', '--addr', addr, '--light'], capture_output=True)
        if proc.returncode == 0 and proc.stdout.strip():
            out_path.write_text(proc.stdout)
            last = json.loads(proc.stdout)
            publish = last.get('publish', {})
            if (
                publish.get('publish_runs_total', 0) >= 1
                and not last.get('work_dirty', True)
                and not last.get('index_session', {}).get('active', False)
                and last.get('active_mutations', 0) == 0
                and last.get('published_tier2_snapshot_seal', {}).get('pending_shards', 0) == 0
                and not last.get('published_tier2_snapshot_seal', {}).get('in_progress', False)
            ):
                return last
        time.sleep(sleep_s)
    raise RuntimeError(f'publish did not complete on {addr}')


def shutdown_server(sspry: Path, addr: str, proc: subprocess.Popen, run_dir: Path) -> None:
    try:
        run([str(sspry), 'shutdown', '--addr', addr], capture_output=True, timeout=10)
    except Exception:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def dir_stats(root: Path) -> dict:
    out = {}
    for name in ('current', 'work_a', 'work_b', 'retired', '.'):
        target = root if name == '.' else root / name
        total = 0
        largest = 0
        if target.exists():
            for path, _, files in os.walk(target):
                for file_name in files:
                    file_path = os.path.join(path, file_name)
                    try:
                        size = os.path.getsize(file_path)
                    except FileNotFoundError:
                        continue
                    total += size
                    largest = max(largest, size)
        key = 'db' if name == '.' else name
        out[f'{key}_bytes'] = total
        out[f'{key}_largest_file_bytes'] = largest
    return out


def parse_index_metrics(stderr_text: str) -> dict:
    out = {}
    for key in (
        'verbose.index.total_ms',
        'verbose.index.submit_ms',
        'verbose.index.server_current_rss_kb',
        'verbose.index.server_peak_rss_kb',
        'verbose.index.server_disk_usage_bytes',
    ):
        m = re.search(rf'^{re.escape(key)}: ([0-9.]+)$', stderr_text, re.M)
        if m:
            out[key.replace('.', '_')] = float(m.group(1))
    return out


def parse_search_result(rule: Path, proc: subprocess.CompletedProcess, elapsed_ms_wall: float) -> dict:
    record = {
        'rule': rule.name,
        'exit_code': proc.returncode,
        'elapsed_ms_wall': elapsed_ms_wall,
    }
    m = re.search(r'^candidates: (\d+)$', proc.stdout or '', re.M)
    if m:
        record['candidates'] = int(m.group(1))
    m = re.search(r'^tier_used: (.+)$', proc.stdout or '', re.M)
    if m:
        record['tier_used'] = m.group(1).strip()
    for key in (
        'verbose.search.total_ms',
        'verbose.search.plan_ms',
        'verbose.search.query_ms',
        'verbose.search.verify_ms',
        'verbose.search.verified_checked',
        'verbose.search.verified_matched',
        'verbose.search.verified_skipped',
        'verbose.search.docs_scanned',
        'verbose.search.superblocks_skipped',
        'verbose.search.metadata_loads',
        'verbose.search.metadata_bytes',
        'verbose.search.tier1_bloom_loads',
        'verbose.search.tier1_bloom_bytes',
        'verbose.search.tier2_bloom_loads',
        'verbose.search.tier2_bloom_bytes',
        'verbose.search.server_current_rss_kb',
        'verbose.search.server_peak_rss_kb',
    ):
        m = re.search(rf'^{re.escape(key)}: ([0-9.]+)$', proc.stderr or '', re.M)
        if m:
            record[key.replace('.', '_')] = float(m.group(1))
    if proc.returncode != 0:
        first = ((proc.stdout or '').strip().splitlines() or (proc.stderr or '').strip().splitlines() or [''])[0]
        record['error'] = first
    return record


def parse_meminfo() -> dict:
    out = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        number = value.strip().split()[0]
        try:
            out[key] = int(number)
        except ValueError:
            continue
    return out


def parse_vmstat() -> dict:
    wanted = {
        'nr_dirty',
        'nr_writeback',
        'nr_dirtied',
        'nr_written',
        'nr_writeback_temp',
    }
    out = {}
    for line in Path('/proc/vmstat').read_text().splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[0] not in wanted:
            continue
        try:
            out[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return out


def parse_pressure(kind: str) -> dict:
    path = Path('/proc/pressure') / kind
    out = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if not parts:
            continue
        bucket = parts[0]
        metrics = {}
        for item in parts[1:]:
            if '=' not in item:
                continue
            key, value = item.split('=', 1)
            try:
                metrics[key] = float(value)
            except ValueError:
                continue
        out[bucket] = metrics
    return out


def system_snapshot() -> dict:
    meminfo = parse_meminfo()
    vmstat = parse_vmstat()
    io_pressure = parse_pressure('io')
    return {
        'timestamp_unix_s': time.time(),
        'dirty_kb': meminfo.get('Dirty', 0),
        'writeback_kb': meminfo.get('Writeback', 0),
        'mem_available_kb': meminfo.get('MemAvailable', 0),
        'active_anon_kb': meminfo.get('Active(anon)', 0),
        'inactive_anon_kb': meminfo.get('Inactive(anon)', 0),
        'active_file_kb': meminfo.get('Active(file)', 0),
        'inactive_file_kb': meminfo.get('Inactive(file)', 0),
        'cached_kb': meminfo.get('Cached', 0),
        'nr_dirty_pages': vmstat.get('nr_dirty', 0),
        'nr_writeback_pages': vmstat.get('nr_writeback', 0),
        'nr_dirtied_pages': vmstat.get('nr_dirtied', 0),
        'nr_written_pages': vmstat.get('nr_written', 0),
        'nr_writeback_temp_pages': vmstat.get('nr_writeback_temp', 0),
        'io_pressure': io_pressure,
        'io_some_avg10': io_pressure.get('some', {}).get('avg10', 0.0),
        'io_full_avg10': io_pressure.get('full', {}).get('avg10', 0.0),
    }


def write_snapshot(path: Path, snapshot: dict) -> dict:
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True))
    return snapshot


def drain_writeback(
    run_dir: Path,
    max_seconds: int,
    sleep_s: float,
    max_dirty_pages: int,
    max_writeback_pages: int,
    do_sync: bool,
) -> dict:
    started = time.time()
    sync_rc = None
    if do_sync:
        sync_rc = run(['sync']).returncode
    samples = []
    while True:
        snapshot = system_snapshot()
        samples.append(snapshot)
        if (
            snapshot.get('nr_dirty_pages', 0) <= max_dirty_pages
            and snapshot.get('nr_writeback_pages', 0) <= max_writeback_pages
        ):
            break
        if time.time() - started >= max_seconds:
            break
        time.sleep(sleep_s)
    summary = {
        'started_unix_s': started,
        'finished_unix_s': time.time(),
        'duration_s': time.time() - started,
        'sync_rc': sync_rc,
        'max_seconds': max_seconds,
        'sleep_s': sleep_s,
        'max_dirty_pages': max_dirty_pages,
        'max_writeback_pages': max_writeback_pages,
        'samples': samples,
        'completed': bool(samples)
        and samples[-1].get('nr_dirty_pages', 0) <= max_dirty_pages
        and samples[-1].get('nr_writeback_pages', 0) <= max_writeback_pages,
    }
    run_dir.write_text(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def run_search_one(sspry: Path, addr: str, rule: Path, timeout_s: int) -> tuple[subprocess.CompletedProcess, float]:
    started = time.time()
    attempts = 0
    proc = None
    while True:
        attempts += 1
        try:
            proc = run(
                [
                    str(sspry),
                    'search',
                    '--addr',
                    addr,
                    '--timeout',
                    str(timeout_s),
                    '--rule',
                    str(rule),
                    '--verbose',
                ],
                capture_output=True,
                timeout=timeout_s + 30,
            )
        except subprocess.TimeoutExpired as e:
            proc = subprocess.CompletedProcess(e.cmd, 124, e.stdout or '', (e.stderr or '') + '\nTIMEOUT')
        combined = (proc.stdout or '') + '\n' + (proc.stderr or '')
        if proc.returncode == 0:
            break
        if attempts >= 5 or not any(marker in combined for marker in TEMPORARY_SEARCH_MARKERS):
            break
        time.sleep(2)
    return proc, (time.time() - started) * 1000.0


def aggregate_rule_results(rule: Path, tree_results: list[dict], elapsed_ms_parallel: float) -> dict:
    out = {
        'rule': rule.name,
        'elapsed_ms_wall_parallel': elapsed_ms_parallel,
        'elapsed_ms_wall_sum': sum(item.get('elapsed_ms_wall', 0.0) for item in tree_results),
        'tree_results': tree_results,
        'successful_trees': sum(1 for item in tree_results if item['exit_code'] == 0),
    }
    if all(item['exit_code'] == 0 for item in tree_results):
        out['exit_code'] = 0
        out['candidates'] = sum(int(item.get('candidates', 0)) for item in tree_results)
        out['docs_scanned'] = sum(int(item.get('verbose_search_docs_scanned', 0)) for item in tree_results)
        out['superblocks_skipped'] = sum(int(item.get('verbose_search_superblocks_skipped', 0)) for item in tree_results)
        out['tier1_bloom_bytes'] = sum(int(item.get('verbose_search_tier1_bloom_bytes', 0)) for item in tree_results)
        out['tier2_bloom_bytes'] = sum(int(item.get('verbose_search_tier2_bloom_bytes', 0)) for item in tree_results)
        out['verbose_search_total_ms_sum'] = sum(float(item.get('verbose_search_total_ms', 0.0)) for item in tree_results)
        out['verbose_search_total_ms_max'] = max(float(item.get('verbose_search_total_ms', 0.0)) for item in tree_results)
        tiers = sorted({item.get('tier_used', 'unknown') for item in tree_results})
        out['tier_used'] = '+'.join(tiers)
    else:
        first_error = next((item.get('error') for item in tree_results if item['exit_code'] != 0), '')
        out['exit_code'] = next((item['exit_code'] for item in tree_results if item['exit_code'] != 0), 1)
        out['error'] = first_error
    return out


def split_manifest(
    dataset: Path,
    manifests_dir: Path,
    chunk_size: int,
    chunk_count: int | None,
    balance_bytes: bool,
) -> list[dict]:
    manifests_dir.mkdir(parents=True, exist_ok=True)
    lines = [line.strip() for line in dataset.read_text().splitlines() if line.strip()]
    if not balance_bytes:
        out = []
        for idx in range(0, len(lines), chunk_size):
            chunk_lines = lines[idx: idx + chunk_size]
            path = manifests_dir / f'chunk_{idx // chunk_size:02d}.txt'
            path.write_text(''.join(line + '\n' for line in chunk_lines))
            out.append({
                'path': path,
                'files': len(chunk_lines),
                'bytes': 0,
            })
        return out
    if chunk_count is None:
        chunk_count = max(1, math.ceil(len(lines) / max(chunk_size, 1)))
    indexed = []
    for idx, line in enumerate(lines):
        try:
            size = os.path.getsize(line)
        except OSError:
            size = 0
        indexed.append((idx, line, size))
    out = []
    buckets = [{'items': [], 'bytes': 0} for _ in range(chunk_count)]
    for item in sorted(indexed, key=lambda entry: entry[2], reverse=True):
        bucket_idx = min(
            range(len(buckets)),
            key=lambda idx: (buckets[idx]['bytes'], len(buckets[idx]['items'])),
        )
        buckets[bucket_idx]['items'].append(item)
        buckets[bucket_idx]['bytes'] += item[2]
    for idx, bucket in enumerate(buckets):
        if not bucket['items']:
            continue
        bucket['items'].sort(key=lambda item: item[0])
        path = manifests_dir / f'chunk_{idx:02d}.txt'
        path.write_text(''.join(item[1] + '\n' for item in bucket['items']))
        out.append({
            'path': path,
            'files': len(bucket['items']),
            'bytes': bucket['bytes'],
        })
    return out


def resolve_dataset_manifest(dataset: Path) -> Path:
    if dataset.suffix != '.json':
        return dataset
    payload = json.loads(dataset.read_text())
    if isinstance(payload, dict) and isinstance(payload.get('source_manifest'), str):
        return Path(payload['source_manifest'])
    raise RuntimeError(f'unsupported dataset descriptor at {dataset}')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', required=True)
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--rules-dir', required=True)
    parser.add_argument('--sspry', required=True)
    parser.add_argument('--result-base', required=True)
    parser.add_argument('--db-base', required=True)
    parser.add_argument('--base-port', type=int, default=18920)
    parser.add_argument('--chunk-size', type=int, default=25000)
    parser.add_argument('--chunk-count', type=int)
    parser.add_argument('--balance-bytes', action='store_true')
    parser.add_argument('--summary-cap-kib', type=int, default=32)
    parser.add_argument('--memory-budget-gb', type=int, default=16)
    parser.add_argument('--shards', type=int)
    parser.add_argument('--set-fp', type=float)
    parser.add_argument('--tier1-set-fp', type=float)
    parser.add_argument('--tier2-set-fp', type=float)
    parser.add_argument('--search-workers', type=int, default=1)
    parser.add_argument('--search-timeout-s', type=int, default=240)
    parser.add_argument('--search-server-start-attempts', type=int, default=1200)
    parser.add_argument('--drain-between-trees', action='store_true')
    parser.add_argument('--drain-sync', action='store_true')
    parser.add_argument('--drain-max-seconds', type=int, default=900)
    parser.add_argument('--drain-sleep-s', type=float, default=2.0)
    parser.add_argument('--drain-max-dirty-pages', type=int, default=131072)
    parser.add_argument('--drain-max-writeback-pages', type=int, default=8192)
    args = parser.parse_args()

    sspry = Path(args.sspry)
    dataset = Path(args.dataset)
    dataset_manifest = resolve_dataset_manifest(dataset)
    rules_dir = Path(args.rules_dir)
    result_base = Path(args.result_base)
    db_base = Path(args.db_base)
    run_dir = result_base / args.name
    manifests_dir = run_dir / 'manifests'
    trees_dir = run_dir / 'trees'
    searches_dir = run_dir / 'search'

    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(db_base, ignore_errors=True)
    db_base.mkdir(parents=True, exist_ok=True)

    manifests = split_manifest(
        dataset_manifest,
        manifests_dir,
        args.chunk_size,
        args.chunk_count,
        args.balance_bytes,
    )
    forest_summary = {
        'name': args.name,
        'dataset': str(dataset),
        'dataset_manifest': str(dataset_manifest),
        'chunk_size': args.chunk_size,
        'chunk_count': args.chunk_count,
        'balance_bytes': args.balance_bytes,
        'tree_count': len(manifests),
        'summary_cap_kib': args.summary_cap_kib,
        'candidate_shards': args.shards,
        'search_workers_per_tree': args.search_workers,
        'drain_between_trees': args.drain_between_trees,
        'trees': [],
    }

    total_index_wall_s = 0.0
    for idx, manifest in enumerate(manifests):
        tree_name = f'tree_{idx:02d}'
        tree_run_dir = trees_dir / tree_name
        tree_run_dir.mkdir(parents=True, exist_ok=True)
        db_root = db_base / tree_name
        addr = f'127.0.0.1:{args.base_port + idx}'
        before_index = write_snapshot(tree_run_dir / 'system.before_index.json', system_snapshot())
        print(
            f"index.start tree={tree_name} addr={addr} manifest={manifest['path']} "
            f"files={manifest['files']} bytes={manifest['bytes']}",
            flush=True,
        )
        fp_args = []
        if args.set_fp is not None:
            fp_args.extend(['--set-fp', str(args.set_fp)])
        if args.tier1_set_fp is not None:
            fp_args.extend(['--tier1-set-fp', str(args.tier1_set_fp)])
        if args.tier2_set_fp is not None:
            fp_args.extend(['--tier2-set-fp', str(args.tier2_set_fp)])
        server = subprocess.Popen(
            [
                str(sspry), 'serve', '--addr', addr, '--root', str(db_root), '--store-path',
                '--memory-budget-gb', str(args.memory_budget_gb),
                '--tier2-superblock-summary-cap-kib', str(args.summary_cap_kib),
                '--search-workers', str(args.search_workers),
                *fp_args,
                *(['--shards', str(args.shards)] if args.shards else []),
            ],
            stdout=(tree_run_dir / 'server.stdout').open('w'),
            stderr=(tree_run_dir / 'server.stderr').open('w'),
        )
        try:
            wait_for_server(sspry, addr, tree_run_dir / 'start.info.light.json')
            started = time.monotonic()
            proc = run(
                [
                    str(sspry), '--perf-report', str(tree_run_dir / 'index.perf.json'),
                    'index', '--addr', addr, '--path-list', str(manifest['path']), '--batch-size', '64', '--verbose',
                ],
                stdout=(tree_run_dir / 'index.stdout').open('w'),
                stderr=(tree_run_dir / 'index.stderr').open('w'),
            )
            elapsed_s = time.monotonic() - started
            total_index_wall_s += elapsed_s
            (tree_run_dir / 'index.exit_code.txt').write_text(str(proc.returncode))
            (tree_run_dir / 'index.wall_seconds.txt').write_text(f'{elapsed_s:.6f}\n')
            if proc.returncode != 0:
                raise RuntimeError(f'index failed for {tree_name} with exit {proc.returncode}')
            post_publish = wait_for_publish(sspry, addr, tree_run_dir / 'post_publish.info.light.json')
            after_publish = write_snapshot(tree_run_dir / 'system.after_publish.json', system_snapshot())
            (tree_run_dir / 'final.dir_stats.json').write_text(json.dumps(dir_stats(db_root), indent=2, sort_keys=True))
            index_metrics = parse_index_metrics((tree_run_dir / 'index.stderr').read_text())
            tree_record = {
                'tree': tree_name,
                'addr': addr,
                'manifest': str(manifest['path']),
                'index_wall_seconds': elapsed_s,
                'files': manifest['files'],
                'manifest_bytes': manifest['bytes'],
                'index_files_per_minute': ((manifest['files'] / elapsed_s) * 60.0) if elapsed_s > 0 else 0.0,
                'index_metrics': index_metrics,
                'post_publish_info': post_publish,
                'dir_stats': json.loads((tree_run_dir / 'final.dir_stats.json').read_text()),
                'system_before_index': before_index,
                'system_after_publish': after_publish,
            }
            if args.drain_between_trees and idx + 1 < len(manifests):
                drain = drain_writeback(
                    tree_run_dir / 'system.drain.json',
                    args.drain_max_seconds,
                    args.drain_sleep_s,
                    args.drain_max_dirty_pages,
                    args.drain_max_writeback_pages,
                    args.drain_sync,
                )
                tree_record['drain'] = drain
            forest_summary['trees'].append(tree_record)
            print(
                f"index.done tree={tree_name} files={tree_record['files']} bytes={tree_record['manifest_bytes']} "
                f"wall_s={elapsed_s:.3f} files_per_min={tree_record['index_files_per_minute']:.3f} "
                f"db_bytes={tree_record['dir_stats']['db_bytes']} dirty_pages={after_publish['nr_dirty_pages']} "
                f"writeback_pages={after_publish['nr_writeback_pages']}",
                flush=True,
            )
        finally:
            shutdown_server(sspry, addr, server, tree_run_dir)

    search_servers = []
    try:
        for idx, manifest in enumerate(manifests):
            tree_name = f'tree_{idx:02d}'
            tree_run_dir = trees_dir / tree_name
            db_root = db_base / tree_name
            addr = f'127.0.0.1:{args.base_port + idx}'
            fp_args = []
            if args.set_fp is not None:
                fp_args.extend(['--set-fp', str(args.set_fp)])
            if args.tier1_set_fp is not None:
                fp_args.extend(['--tier1-set-fp', str(args.tier1_set_fp)])
            if args.tier2_set_fp is not None:
                fp_args.extend(['--tier2-set-fp', str(args.tier2_set_fp)])
            server = subprocess.Popen(
                [
                    str(sspry), 'serve', '--addr', addr, '--root', str(db_root),
                    '--search-workers', str(args.search_workers),
                    *fp_args,
                    *(['--shards', str(args.shards)] if args.shards else []),
                ],
                stdout=(tree_run_dir / 'search.server.stdout').open('w'),
                stderr=(tree_run_dir / 'search.server.stderr').open('w'),
            )
            wait_for_server(
                sspry,
                addr,
                tree_run_dir / 'search.start.info.light.json',
                attempts=args.search_server_start_attempts,
            )
            search_servers.append((addr, server, tree_run_dir))

        searches_dir.mkdir(parents=True, exist_ok=True)
        search_summary = []
        print(f'search.start trees={len(search_servers)}', flush=True)
        for rule in sorted(rules_dir.glob('*.yar')):
            started = time.time()
            per_tree = []
            print(f'search.rule.start rule={rule.name}', flush=True)
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(search_servers)) as pool:
                future_map = {
                    pool.submit(run_search_one, sspry, addr, rule, args.search_timeout_s): (addr, tree_run_dir)
                    for addr, _, tree_run_dir in search_servers
                }
                for future in concurrent.futures.as_completed(future_map):
                    addr, tree_run_dir = future_map[future]
                    proc, elapsed_ms = future.result()
                    tree_dir = searches_dir / rule.stem
                    tree_dir.mkdir(parents=True, exist_ok=True)
                    safe_addr = addr.replace(':', '_').replace('.', '_')
                    (tree_dir / f'{safe_addr}.stdout').write_text(proc.stdout or '')
                    (tree_dir / f'{safe_addr}.stderr').write_text(proc.stderr or '')
                    record = parse_search_result(rule, proc, elapsed_ms)
                    record['addr'] = addr
                    record['tree'] = tree_run_dir.name
                    per_tree.append(record)
            per_tree.sort(key=lambda item: item['tree'])
            aggregated = aggregate_rule_results(rule, per_tree, (time.time() - started) * 1000.0)
            search_summary.append(aggregated)
            print(
                f"search.rule.done rule={rule.name} exit={aggregated['exit_code']} "
                f"wall_ms={aggregated['elapsed_ms_wall_parallel']:.3f}",
                flush=True,
            )
        (run_dir / 'search_summary.json').write_text(json.dumps(search_summary, indent=2, sort_keys=True))
    finally:
        for addr, server, tree_run_dir in search_servers:
            shutdown_server(sspry, addr, server, tree_run_dir)

    forest_summary['total_index_wall_seconds'] = total_index_wall_s
    forest_summary['avg_index_files_per_minute'] = (
        (sum(tree['files'] for tree in forest_summary['trees']) / total_index_wall_s) * 60.0
        if total_index_wall_s > 0 else 0.0
    )
    forest_summary['combined_db_bytes'] = sum(tree['dir_stats']['db_bytes'] for tree in forest_summary['trees'])
    forest_summary['max_tree_peak_rss_kb'] = max(
        int(tree['post_publish_info'].get('peak_rss_kb', 0)) for tree in forest_summary['trees']
    ) if forest_summary['trees'] else 0
    (run_dir / 'forest_summary.json').write_text(json.dumps(forest_summary, indent=2, sort_keys=True))
    print(
        f"forest.done trees={forest_summary['tree_count']} total_index_wall_s={total_index_wall_s:.3f} "
        f"avg_files_per_min={forest_summary['avg_index_files_per_minute']:.3f}",
        flush=True,
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
