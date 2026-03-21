#!/usr/bin/env python3
import argparse
import concurrent.futures
import csv
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from run_forest_probe import parse_search_result


RULE_DECL_RE = re.compile(
    r"(?m)^(?P<indent>\s*)(?P<mods>(?:(?:private|global)\s+)*)rule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
IMPORT_RE = re.compile(r'(?m)^\s*import\s+"[^"]+"\s*$')
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class RuleBlock:
    name: str
    is_private: bool
    text: str


def run(cmd, **kwargs):
    return subprocess.run(cmd, text=True, **kwargs)


def start_server(sspry: Path, addr: str, db_root: Path, run_dir: Path) -> subprocess.Popen:
    stderr_path = run_dir / "server.stderr"
    stdout_path = run_dir / "server.stdout"
    stderr_fh = stderr_path.open("w")
    stdout_fh = stdout_path.open("w")
    return subprocess.Popen(
        [
            str(sspry),
            "serve",
            "--addr",
            addr,
            "--root",
            str(db_root),
        ],
        stdout=stdout_fh,
        stderr=stderr_fh,
        cwd=db_root,
    )


def wait_for_server(sspry: Path, addr: str, out_path: Path, attempts: int = 300) -> None:
    for _ in range(attempts):
        proc = run([str(sspry), "info", "--addr", addr, "--light"], capture_output=True)
        if proc.returncode == 0 and proc.stdout.strip():
            out_path.write_text(proc.stdout)
            return
        time.sleep(0.2)
    raise RuntimeError(f"server did not start on {addr}")


def shutdown_server(sspry: Path, addr: str, proc: subprocess.Popen) -> None:
    try:
        run([str(sspry), "shutdown", "--addr", addr], capture_output=True, timeout=10)
    except Exception:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def match_brace_span(text: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    in_string = False
    in_regex = False
    regex_class = False
    escaped = False
    in_line_comment = False
    in_block_comment = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if in_regex:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "[":
                regex_class = True
            elif ch == "]" and regex_class:
                regex_class = False
            elif ch == "/" and not regex_class:
                in_regex = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == "/":
            in_regex = True
            regex_class = False
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise RuntimeError(f"unclosed rule block at offset {open_idx}")


def parse_rule_blocks(text: str) -> list[RuleBlock]:
    blocks = []
    for match in RULE_DECL_RE.finditer(text):
        name = match.group("name")
        mods = match.group("mods") or ""
        open_idx = text.find("{", match.end())
        if open_idx < 0:
            raise RuntimeError(f"missing opening brace for rule {name}")
        end_idx = match_brace_span(text, open_idx)
        blocks.append(
            RuleBlock(
                name=name,
                is_private="private" in mods.split(),
                text=text[match.start() : end_idx].strip() + "\n",
            )
        )
    return blocks


def collect_imports(text: str) -> list[str]:
    imports = []
    seen = set()
    for match in IMPORT_RE.finditer(text):
        line = match.group(0).strip()
        if line in seen:
            continue
        seen.add(line)
        imports.append(line)
    return imports


def make_private_rule_text(rule_text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        indent = match.group("indent") or ""
        mods = match.group("mods") or ""
        tokens = mods.split()
        if "private" in tokens:
            return match.group(0)
        prefix = " ".join(["private", *tokens]).strip()
        if prefix:
            prefix += " "
        return f"{indent}{prefix}rule {match.group('name')}"

    return RULE_DECL_RE.sub(repl, rule_text, count=1)


def extract_public_rules(rule_path: Path, out_dir: Path) -> list[dict]:
    text = rule_path.read_text(errors="ignore")
    imports = collect_imports(text)
    blocks = parse_rule_blocks(text)
    emitted = []
    for target in blocks:
        if target.is_private:
            continue
        parts = []
        if imports:
            parts.append("\n".join(imports))
        parts.append(target.text.strip())
        for helper in blocks:
            if helper.name == target.name and helper.text == target.text:
                continue
            parts.append(make_private_rule_text(helper.text).strip())
        source = "\n\n".join(part for part in parts if part).strip() + "\n"
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", target.name)
        temp_path = out_dir / f"{safe_name}.yar"
        temp_path.write_text(source)
        emitted.append(
            {
                "rule_name": target.name,
                "temp_rule_path": str(temp_path),
            }
        )
    return emitted


def parse_candidate_hashes(stdout: str) -> list[str]:
    out = []
    for line in stdout.splitlines():
        stripped = line.strip().lower()
        if HEX64_RE.fullmatch(stripped):
            out.append(stripped)
    return out


def unique_rule_key(rule_file: str, rule_name: str) -> str:
    return f"{rule_file}::{rule_name}"


def choose_run_dir(base: Path) -> Path:
    if not base.exists():
        base.mkdir(parents=True)
        return base
    idx = 2
    while True:
        candidate = Path(f"{base}_r{idx}")
        if not candidate.exists():
            candidate.mkdir(parents=True)
            return candidate
        idx += 1


def load_or_build_extracted_rules(
    run_dir: Path, triage_records: list[dict], limit_files: int | None
) -> tuple[list[tuple[str, str]], list[dict]]:
    extracted_path = run_dir / "extracted_rules.json"
    if extracted_path.exists():
        extracted_rules = json.loads(extracted_path.read_text())
        source_files = sorted(
            {
                (item["path"], item["rule_file"])
                for item in extracted_rules
                if item.get("path") and item.get("rule_file")
            }
        )
        return source_files, extracted_rules

    temp_rule_root = run_dir / "temp_rules"
    temp_rule_root.mkdir(parents=True, exist_ok=True)
    source_files = sorted(
        {
            (item["path"], item["rule_file"])
            for item in triage_records
            if item.get("final_bucket") == "good_rule"
        }
    )
    if limit_files:
        source_files = source_files[:limit_files]

    ground_truth_input = []
    extracted_rules = []
    for index, (path_text, rule_file) in enumerate(source_files, start=1):
        path = Path(path_text)
        per_file_dir = temp_rule_root / f"{index:04d}"
        per_file_dir.mkdir(parents=True, exist_ok=True)
        try:
            public_rules = extract_public_rules(path, per_file_dir)
        except Exception as err:
            extracted_rules.append(
                {
                    "rule_file": rule_file,
                    "path": str(path),
                    "rule_name": None,
                    "rule_key": None,
                    "extract_error": str(err),
                }
            )
            continue
        ground_truth_input.append({"path": str(path), "rule_file": rule_file})
        for rule in public_rules:
            extracted_rules.append(
                {
                    "rule_file": rule_file,
                    "path": str(path),
                    "rule_name": rule["rule_name"],
                    "rule_key": unique_rule_key(rule_file, rule["rule_name"]),
                    "temp_rule_path": rule["temp_rule_path"],
                }
            )

    (run_dir / "ground_truth_input.json").write_text(json.dumps(ground_truth_input, indent=2))
    extracted_path.write_text(json.dumps(extracted_rules, indent=2))
    return source_files, extracted_rules


def run_single_search(item: dict, sspry: Path, addr: str, max_candidates: int) -> dict:
    rule_path = Path(item["temp_rule_path"])
    cmd = [
        str(sspry),
        "search",
        "--addr",
        addr,
        "--rule",
        str(rule_path),
        "--max-candidates",
        str(max_candidates),
        "--verbose",
    ]
    started = time.time()
    proc = run(cmd, cwd=Path(item["path"]).parent, capture_output=True)
    elapsed_ms = (time.time() - started) * 1000.0
    parsed = parse_search_result(rule_path, proc, elapsed_ms)
    parsed["candidate_sha256"] = sorted(set(parse_candidate_hashes(proc.stdout)))
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit per-rule recall against the real DB root.")
    parser.add_argument("--sspry", type=Path, default=Path("/root/pertest/repos/yaya/target/release/sspry"))
    parser.add_argument(
        "--triage-records",
        type=Path,
        default=Path("/root/pertest/results/rule_breakdown_3322_20260321_r1/triage_records.json"),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("/root/pertest/results/sspry_dataset_20260228_20260306_20260320/source_manifest.txt"),
    )
    parser.add_argument("--db-root", type=Path, default=Path("/root/pertest/db/tree_00"))
    parser.add_argument("--addr", default="127.0.0.1:19331")
    parser.add_argument("--workers", type=int, default=max(1, min(os.cpu_count() or 1, 8)))
    parser.add_argument("--search-jobs", type=int, default=1)
    parser.add_argument("--max-candidates", type=int, default=10000)
    parser.add_argument("--limit-files", type=int)
    parser.add_argument("--limit-rules", type=int)
    parser.add_argument("--resume-dir", type=Path)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("/root/pertest/results/per_rule_recall_3322_20260321_r1"),
    )
    args = parser.parse_args()

    run_dir = args.resume_dir if args.resume_dir else choose_run_dir(args.out_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    triage_records = json.loads(args.triage_records.read_text())
    source_files, extracted_rules = load_or_build_extracted_rules(
        run_dir, triage_records, args.limit_files
    )
    searchable_rules = [item for item in extracted_rules if item.get("rule_key")]
    if args.limit_rules:
        searchable_rules = searchable_rules[: args.limit_rules]

    ground_truth_path = run_dir / "ground_truth.json"
    if not ground_truth_path.exists():
        truth_cmd = [
            "cargo",
            "run",
            "--release",
            "--quiet",
            "--bin",
            "rule_truth",
            "--",
            "--manifest",
            str(args.manifest),
            "--files-json",
            str(run_dir / "ground_truth_input.json"),
            "--output-json",
            str(ground_truth_path),
            "--workers",
            str(args.workers),
        ]
        truth_proc = run(truth_cmd, cwd="/root/pertest/repos/yaya", capture_output=True)
        (run_dir / "ground_truth.stdout").write_text(truth_proc.stdout)
        (run_dir / "ground_truth.stderr").write_text(truth_proc.stderr)
        if truth_proc.returncode != 0:
            print("ground truth generation failed", file=sys.stderr)
            return truth_proc.returncode

    ground_truth_records = json.loads(ground_truth_path.read_text())
    truth_map = {}
    truth_compile_errors = []
    for record in ground_truth_records:
        if record.get("compile_error"):
            truth_compile_errors.append(record)
            continue
        rule_file = record["rule_file"]
        for rule_name, hashes in record.get("matches", {}).items():
            truth_map[unique_rule_key(rule_file, rule_name)] = set(hashes)

    server = start_server(args.sspry, args.addr, args.db_root, run_dir)
    try:
        wait_for_server(args.sspry, args.addr, run_dir / "server.info.light.json")
        results = []
        total_rules = len(searchable_rules)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.search_jobs)) as pool:
            future_map = {
                pool.submit(run_single_search, item, args.sspry, args.addr, args.max_candidates): item
                for item in searchable_rules
            }
            completed = 0
            for future in concurrent.futures.as_completed(future_map):
                item = future_map[future]
                parsed = future.result()
                candidate_hashes = parsed.pop("candidate_sha256")
                truth_hashes = sorted(truth_map.get(item["rule_key"], set()))
                candidate_set = set(candidate_hashes)
                truth_set = set(truth_hashes)
                false_negatives = sorted(truth_set - candidate_set)
                false_positive_candidates = sorted(candidate_set - truth_set)
                result = {
                    "rule_key": item["rule_key"],
                    "rule_file": item["rule_file"],
                    "path": item["path"],
                    "rule_name": item["rule_name"],
                    "temp_rule_path": item["temp_rule_path"],
                    "ground_truth_hits": len(truth_hashes),
                    "candidate_count": len(candidate_hashes),
                    "false_negative_count": len(false_negatives),
                    "false_positive_candidate_count": len(false_positive_candidates),
                    "ground_truth_sha256": truth_hashes,
                    "candidate_sha256": candidate_hashes,
                    "false_negative_sha256": false_negatives,
                    "false_positive_candidate_sha256": false_positive_candidates,
                    **parsed,
                }
                results.append(result)
                completed += 1
                if completed % 100 == 0 or completed == total_rules:
                    print(f"[search] {completed}/{total_rules}", flush=True)
                if completed % 250 == 0 or completed == total_rules:
                    (run_dir / "per_rule_recall.partial.json").write_text(
                        json.dumps(
                            sorted(
                                results,
                                key=lambda value: (value["rule_file"], value["rule_name"]),
                            ),
                            indent=2,
                        )
                    )
    finally:
        shutdown_server(args.sspry, args.addr, server)

    results.sort(key=lambda item: (item["rule_file"], item["rule_name"]))
    (run_dir / "per_rule_recall.json").write_text(json.dumps(results, indent=2))

    csv_fields = [
        "rule_key",
        "rule_file",
        "rule_name",
        "ground_truth_hits",
        "candidate_count",
        "false_negative_count",
        "false_positive_candidate_count",
        "exit_code",
        "error",
        "verbose_search_query_ms",
        "verbose_search_docs_scanned",
        "verbose_search_superblocks_skipped",
        "verbose_search_tier1_bloom_bytes",
    ]
    with (run_dir / "per_rule_recall.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=csv_fields)
        writer.writeheader()
        for item in results:
            writer.writerow({field: item.get(field) for field in csv_fields})

    false_negative_rules = [
        item
        for item in results
        if item["false_negative_count"] > 0 or (item["ground_truth_hits"] > 0 and item["exit_code"] != 0)
    ]
    false_negative_rules.sort(key=lambda item: (-item["false_negative_count"], item["rule_key"]))
    with (run_dir / "false_negative_rules.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "rule_key",
                "ground_truth_hits",
                "candidate_count",
                "false_negative_count",
                "exit_code",
                "error",
                "verbose_search_query_ms",
            ],
        )
        writer.writeheader()
        for item in false_negative_rules:
            writer.writerow(
                {
                    "rule_key": item["rule_key"],
                    "ground_truth_hits": item["ground_truth_hits"],
                    "candidate_count": item["candidate_count"],
                    "false_negative_count": item["false_negative_count"],
                    "exit_code": item["exit_code"],
                    "error": item.get("error"),
                    "verbose_search_query_ms": item.get("verbose_search_query_ms"),
                }
            )

    summary = {
        "source_files": len(source_files),
        "searchable_rules": len(searchable_rules),
        "ground_truth_compiled_files": len(ground_truth_records) - len(truth_compile_errors),
        "ground_truth_compile_error_files": len(truth_compile_errors),
        "rules_with_ground_truth_hits": sum(1 for item in results if item["ground_truth_hits"] > 0),
        "rules_with_false_negatives": sum(1 for item in results if item["false_negative_count"] > 0),
        "total_false_negative_hits": sum(item["false_negative_count"] for item in results),
        "search_error_rules": sum(1 for item in results if item["exit_code"] != 0),
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
