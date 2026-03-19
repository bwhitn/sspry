#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
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


def run_search_one(sspry: Path, addr: str, rule: Path, timeout_s: int) -> tuple[subprocess.CompletedProcess, float]:
    started = time.time()
    attempts = 0
    proc = None
    while True:
        attempts += 1
        try:
            proc = run(
                [str(sspry), 'search', '--addr', addr, '--rule', str(rule), '--verbose'],
                capture_output=True,
                timeout=timeout_s,
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


def split_manifest(dataset: Path, manifests_dir: Path, chunk_size: int) -> list[Path]:
    manifests_dir.mkdir(parents=True, exist_ok=True)
    lines = [line.strip() for line in dataset.read_text().splitlines() if line.strip()]
    out = []
    for idx in range(0, len(lines), chunk_size):
        chunk = lines[idx: idx + chunk_size]
        path = manifests_dir / f'chunk_{idx // chunk_size:02d}.txt'
        path.write_text(''.join(line + '\n' for line in chunk))
        out.append(path)
    return out


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
    parser.add_argument('--summary-cap-kib', type=int, default=32)
    parser.add_argument('--memory-budget-gb', type=int, default=16)
    parser.add_argument('--search-workers', type=int, default=1)
    parser.add_argument('--search-timeout-s', type=int, default=240)
    args = parser.parse_args()

    sspry = Path(args.sspry)
    dataset = Path(args.dataset)
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

    manifests = split_manifest(dataset, manifests_dir, args.chunk_size)
    forest_summary = {
        'name': args.name,
        'dataset': str(dataset),
        'chunk_size': args.chunk_size,
        'tree_count': len(manifests),
        'summary_cap_kib': args.summary_cap_kib,
        'search_workers_per_tree': args.search_workers,
        'trees': [],
    }

    total_index_wall_s = 0.0
    for idx, manifest in enumerate(manifests):
        tree_name = f'tree_{idx:02d}'
        tree_run_dir = trees_dir / tree_name
        tree_run_dir.mkdir(parents=True, exist_ok=True)
        db_root = db_base / tree_name
        addr = f'127.0.0.1:{args.base_port + idx}'
        server = subprocess.Popen(
            [
                str(sspry), 'serve', '--addr', addr, '--root', str(db_root), '--store-path',
                '--memory-budget-gb', str(args.memory_budget_gb),
                '--tier2-superblock-summary-cap-kib', str(args.summary_cap_kib),
                '--search-workers', str(args.search_workers),
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
                    'index', '--addr', addr, '--path-list', str(manifest), '--batch-size', '64', '--verbose',
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
            (tree_run_dir / 'final.dir_stats.json').write_text(json.dumps(dir_stats(db_root), indent=2, sort_keys=True))
            index_metrics = parse_index_metrics((tree_run_dir / 'index.stderr').read_text())
            tree_record = {
                'tree': tree_name,
                'addr': addr,
                'manifest': str(manifest),
                'index_wall_seconds': elapsed_s,
                'files': sum(1 for _ in manifest.open()),
                'index_metrics': index_metrics,
                'post_publish_info': post_publish,
                'dir_stats': json.loads((tree_run_dir / 'final.dir_stats.json').read_text()),
            }
            forest_summary['trees'].append(tree_record)
        finally:
            shutdown_server(sspry, addr, server, tree_run_dir)

    search_servers = []
    try:
        for idx, manifest in enumerate(manifests):
            tree_name = f'tree_{idx:02d}'
            tree_run_dir = trees_dir / tree_name
            db_root = db_base / tree_name
            addr = f'127.0.0.1:{args.base_port + idx}'
            server = subprocess.Popen(
                [
                    str(sspry), 'serve', '--addr', addr, '--root', str(db_root),
                    '--search-workers', str(args.search_workers),
                ],
                stdout=(tree_run_dir / 'search.server.stdout').open('w'),
                stderr=(tree_run_dir / 'search.server.stderr').open('w'),
            )
            wait_for_server(sspry, addr, tree_run_dir / 'search.start.info.light.json')
            search_servers.append((addr, server, tree_run_dir))

        searches_dir.mkdir(parents=True, exist_ok=True)
        search_summary = []
        for rule in sorted(rules_dir.glob('*.yar')):
            started = time.time()
            per_tree = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(search_servers)) as pool:
                future_map = {
                    pool.submit(run_search_one, sspry, addr, rule, args.search_timeout_s): (addr, tree_run_dir)
                    for addr, _, tree_run_dir in search_servers
                }
                for future in concurrent.futures.as_completed(future_map):
                    addr, tree_run_dir = future_map[future]
                    proc, elapsed_ms = future.result()
                    tree_prefix = searches_dir / rule.stem / addr.replace(':', '_')
                    tree_prefix.parent.mkdir(parents=True, exist_ok=True)
                    tree_prefix.with_suffix('.stdout').write_text(proc.stdout or '')
                    tree_prefix.with_suffix('.stderr').write_text(proc.stderr or '')
                    record = parse_search_result(rule, proc, elapsed_ms)
                    record['addr'] = addr
                    record['tree'] = tree_run_dir.name
                    per_tree.append(record)
            per_tree.sort(key=lambda item: item['tree'])
            search_summary.append(aggregate_rule_results(rule, per_tree, (time.time() - started) * 1000.0))
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
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
