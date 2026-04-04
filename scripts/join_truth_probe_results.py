#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Join probe search summaries with rule-truth output.'
    )
    parser.add_argument('--sample-bytes', type=int, required=True)
    parser.add_argument('--truth-json', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument(
        '--config',
        action='append',
        required=True,
        help='Config in the form "label=/abs/path/to/run_dir"',
    )
    return parser.parse_args()


def load_truth_counts(path: Path) -> dict[str, dict]:
    rows = json.loads(path.read_text())
    out = {}
    for row in rows:
        identities = set()
        for matches in row.get('matches', {}).values():
            identities.update(matches)
        out[row['rule_file']] = {
            'true_positives': len(identities),
            'compile_error': row.get('compile_error'),
            'scan_errors': len(row.get('scan_errors', [])),
        }
    return out


def parse_config(value: str) -> tuple[str, Path]:
    if '=' not in value:
        raise SystemExit(f'invalid --config value: {value!r}')
    label, path = value.split('=', 1)
    run_dir = Path(path)
    if not run_dir.exists():
        raise SystemExit(f'run dir does not exist: {run_dir}')
    return label, run_dir


def pick_number(record: dict, *keys: str, default=0):
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return default


def main() -> int:
    args = parse_args()
    truth_counts = load_truth_counts(args.truth_json)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    configs = []
    for item in args.config:
        label, run_dir = parse_config(item)
        forest = json.loads((run_dir / 'forest_summary.json').read_text())
        search = json.loads((run_dir / 'search_summary.json').read_text())

        total_candidates = 0
        total_tp = 0
        total_docs = 0
        total_wall = 0.0
        per_rule = []
        for record in search:
            rule = record['rule']
            tp = truth_counts[rule]['true_positives']
            candidates = int(pick_number(record, 'candidates', 'verbose_search_candidates', default=0))
            docs_scanned = int(pick_number(record, 'docs_scanned', 'verbose_search_docs_scanned', default=0))
            wall_ms = float(pick_number(record, 'elapsed_ms_wall_parallel', 'elapsed_ms_wall', 'verbose_search_total_ms', default=0.0))
            total_candidates += candidates
            total_tp += tp
            total_docs += docs_scanned
            total_wall += wall_ms
            per_rule.append(
                {
                    'rule': rule,
                    'candidates': candidates,
                    'true_positives': tp,
                    'false_positive_candidates': candidates - tp,
                    'docs_scanned': docs_scanned,
                    'wall_ms': wall_ms,
                }
            )

        count = len(search)
        configs.append(
            {
                'config': label,
                'run_dir': str(run_dir),
                'index_files_per_minute': forest['avg_index_files_per_minute'],
                'db_bytes': forest['combined_db_bytes'],
                'db_to_sample_ratio': forest['combined_db_bytes'] / args.sample_bytes,
                'max_tree_peak_rss_kb': forest['max_tree_peak_rss_kb'],
                'search_workers_per_tree': forest['search_workers_per_tree'],
                'total_candidates': total_candidates,
                'total_true_positives': total_tp,
                'false_positive_candidates': total_candidates - total_tp,
                'pooled_candidates_per_true_positive': (
                    total_candidates / total_tp if total_tp else None
                ),
                'candidate_precision': (total_tp / total_candidates) if total_candidates else None,
                'avg_candidates': total_candidates / count if count else 0.0,
                'avg_true_positives': total_tp / count if count else 0.0,
                'avg_docs_scanned': total_docs / count if count else 0.0,
                'total_docs_scanned': total_docs,
                'avg_wall_ms': total_wall / count if count else 0.0,
                'per_rule': per_rule,
            }
        )

    summary = {
        'sample_bytes': args.sample_bytes,
        'truth_path': str(args.truth_json),
        'configs': configs,
    }
    (args.output_dir / 'summary.json').write_text(json.dumps(summary, indent=2))

    with (args.output_dir / 'per_rule.csv').open('w', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                'config',
                'rule',
                'candidates',
                'true_positives',
                'false_positive_candidates',
                'docs_scanned',
                'wall_ms',
            ]
        )
        for cfg in configs:
            for row in cfg['per_rule']:
                writer.writerow(
                    [
                        cfg['config'],
                        row['rule'],
                        row['candidates'],
                        row['true_positives'],
                        row['false_positive_candidates'],
                        row['docs_scanned'],
                        f"{row['wall_ms']:.3f}",
                    ]
                )

    lines = []
    lines.append('# Candidates vs Truth Comparison')
    lines.append('')
    lines.append(f'- sample bytes: `{args.sample_bytes}`')
    lines.append(f'- truth: [{args.truth_json.name}]({args.truth_json})')
    lines.append('')
    lines.append('## Cost / Footprint')
    lines.append('')
    lines.append('| config | index files/min | DB bytes | DB/sample ratio | peak RSS |')
    lines.append('|---|---:|---:|---:|---:|')
    for cfg in configs:
        lines.append(
            f"| `{cfg['config']}` | `{cfg['index_files_per_minute']:.1f}` | "
            f"`{cfg['db_bytes']}` | `{cfg['db_to_sample_ratio']:.3f}x` | "
            f"`{cfg['max_tree_peak_rss_kb']} KB` |"
        )
    lines.append('')
    lines.append('## Search / Truth')
    lines.append('')
    lines.append(
        '| config | total candidates | total true positives | false-positive candidates | pooled cand/tp | candidate precision |'
    )
    lines.append('|---|---:|---:|---:|---:|---:|')
    for cfg in sorted(configs, key=lambda item: item['pooled_candidates_per_true_positive']):
        lines.append(
            f"| `{cfg['config']}` | `{cfg['total_candidates']}` | "
            f"`{cfg['total_true_positives']}` | `{cfg['false_positive_candidates']}` | "
            f"`{cfg['pooled_candidates_per_true_positive']:.3f}` | "
            f"`{cfg['candidate_precision'] * 100:.1f}%` |"
        )
    lines.append('')
    lines.append('## Pruning / Search Work')
    lines.append('')
    lines.append('| config | avg docs scanned | total docs scanned | avg wall ms |')
    lines.append('|---|---:|---:|---:|')
    for cfg in sorted(configs, key=lambda item: item['avg_docs_scanned']):
        lines.append(
            f"| `{cfg['config']}` | `{cfg['avg_docs_scanned']:.1f}` | "
            f"`{cfg['total_docs_scanned']}` | `{cfg['avg_wall_ms']:.1f}` |"
        )
    lines.append('')
    lines.append('## Notes')
    lines.append('')
    lines.append('- pooled `cand/tp` is the main precision comparison')
    lines.append(f"- per-rule details: [{(args.output_dir / 'per_rule.csv').name}]({args.output_dir / 'per_rule.csv'})")
    (args.output_dir / 'comparison_report.md').write_text('\n'.join(lines) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
