#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from run_forest_probe import parse_search_result, shutdown_server, wait_for_server


RULE_SUFFIXES = {".yar", ".yara"}
STATIC_BUCKETS = (
    "good_candidate",
    "optimizable",
    "likely_bad_for_search",
    "unsupported_or_manual_review",
)
HEADER_HINTS = {
    "mz_magic": re.compile(r"uint16(?:be)?\s*\(\s*0\s*\)\s*==\s*0x(?:5a4d|4d5a)", re.I),
    "elf_magic": re.compile(
        r"(?:uint32\s*\(\s*0\s*\)\s*==\s*0x464c457f|uint16\s*\(\s*0\s*\)\s*==\s*0x457f)",
        re.I,
    ),
    "zip_magic": re.compile(r"uint32\s*\(\s*0\s*\)\s*==\s*0x04034b50", re.I),
    "pdf_magic": re.compile(r'(?:uint32\s*\(\s*0\s*\)\s*==\s*0x46445025|"%PDF")', re.I),
    "rtf_magic": re.compile(r'(?:"\{\\\\rtf"|"\{\\rtf")', re.I),
}
MODULE_NAMES = ("pe", "elf", "dotnet", "math", "hash")
UNSUPPORTED_MODULES = {"math", "hash"}
SUPPORTED_IMPORTS = {"pe", "elf", "dotnet"}
SUPPORTED_DOTNET_FIELDS = {"is_dotnet"}
IGNORED_IMPORTS = {"androguard", "console", "cuckoo"}
TEMPORARY_SEARCH_MARKERS = (
    "Resource temporarily unavailable",
    "busy during query scan; retry later",
    "busy during document frequency lookup; retry later",
)


def run(cmd, **kwargs):
    return subprocess.run(cmd, text=True, **kwargs)


def collect_rule_files(roots: list[Path]) -> list[Path]:
    out = []
    for root in roots:
        for path in root.rglob("*"):
            if path.suffix.lower() in RULE_SUFFIXES:
                out.append(path)
    return sorted(out)


def read_text(path: Path) -> str:
    return path.read_text(errors="ignore")


def classify_source(path: Path) -> str:
    path_s = str(path)
    if "yaraify-rules" in path_s:
        return "yaraify"
    if "yara-rules" in path_s:
        return "yara_rules"
    return "unknown"


def relative_label(path: Path) -> str:
    path_s = str(path)
    for marker in ("/root/pertest/tmp/yaraify-rules/", "/root/pertest/tmp/yara-rules/"):
        if marker in path_s:
            return path_s.split(marker, 1)[1]
    return path.name


def analyze_static(path: Path) -> dict:
    text = read_text(path)
    low = text.lower()
    imports = sorted(set(re.findall(r'import\s+"([^"]+)"', text, re.I)))
    includes = sorted(set(re.findall(r'include\s+"([^"]+)"', text, re.I)))
    modules = sorted({name for name in MODULE_NAMES if re.search(rf"\b{name}\.", low)})
    if "pe" in imports and "pe" not in modules:
        modules.append("pe")
    if "elf" in imports and "elf" not in modules:
        modules.append("elf")
    if "dotnet" in imports and "dotnet" not in modules:
        modules.append("dotnet")
    if "math" in imports and "math" not in modules:
        modules.append("math")
    if "hash" in imports and "hash" not in modules:
        modules.append("hash")

    hints = sorted(name for name, pattern in HEADER_HINTS.items() if pattern.search(text))
    dotnet_fields = sorted(set(re.findall(r"\bdotnet\.([A-Za-z_][A-Za-z0-9_]*)", low)))
    unsupported_dotnet_fields = sorted(
        field for field in dotnet_fields if field not in SUPPORTED_DOTNET_FIELDS
    )
    if re.search(r"\bpe\.is_pe\b", low) and "mz_magic" not in hints:
        hints.append("mz_magic")
    if re.search(r"\belf\.", low) and "elf_magic" not in hints:
        hints.append("elf_magic")

    string_defs = len(re.findall(r"^\s*\$[A-Za-z0-9_]+\s*=", text, re.M))
    hex_strings = len(re.findall(r"^\s*\$[A-Za-z0-9_]+\s*=\s*\{", text, re.M))
    text_strings = len(re.findall(r'^\s*\$[A-Za-z0-9_]+\s*=\s*"', text, re.M))
    regex_strings = len(re.findall(r"^\s*\$[A-Za-z0-9_]+\s*=\s*/", text, re.M))
    for_any = len(re.findall(r"\bfor\s+any\b", low))
    for_all = len(re.findall(r"\bfor\s+all\b", low))
    or_count = len(re.findall(r"\bor\b", low))
    and_count = len(re.findall(r"\band\b", low))
    any_of_count = len(re.findall(r"\bany of\b", low))
    all_of_count = len(re.findall(r"\ball of\b", low))
    ascii_count = len(re.findall(r"\bascii\b", low))
    wide_count = len(re.findall(r"\bwide\b", low))
    nocase_count = len(re.findall(r"\bnocase\b", low))
    xor_count = len(re.findall(r"\bxor\b", low))
    base64_count = len(re.findall(r"\bbase64\b", low))
    filesize_count = len(re.findall(r"\bfilesize\b", low))
    uint_reads = len(re.findall(r"\buint(?:8|16|16be|32|32be|64|64be)\s*\(", low))
    matches_regex = len(re.findall(r"\bmatches\s*/", low))
    rule_count = len(re.findall(r"^\s*(?:private\s+|global\s+)*rule\s+[A-Za-z0-9_]+", text, re.M))
    has_entrypoint = "entrypoint" in low
    has_condition_offset_reads = bool(re.search(r"@\w+\[", text))
    has_any_of_them = bool(re.search(r"\b(?:any|all)\s+of\s+them\b", low))
    has_string_decl_comment = bool(re.search(r"^\s*\$[A-Za-z0-9_]+\s*=.*//", text, re.M))

    notes = []
    rewrite_hints = []
    if "mz_magic" in hints:
        rewrite_hints.append("normalize_mz_magic_to_is_pe")
    if "elf_magic" in hints:
        rewrite_hints.append("normalize_elf_magic_to_is_elf")
    if "zip_magic" in hints:
        rewrite_hints.append("normalize_zip_magic_to_is_zip")
    if "pdf_magic" in hints:
        rewrite_hints.append("normalize_pdf_magic_to_is_pdf")
    if "rtf_magic" in hints:
        rewrite_hints.append("normalize_rtf_magic_to_is_rtf")

    heavy_module = any(module in UNSUPPORTED_MODULES for module in modules) or bool(
        unsupported_dotnet_fields
    )
    ignored_imports = sorted(import_name for import_name in imports if import_name in IGNORED_IMPORTS)
    unknown_imports = sorted(
        import_name
        for import_name in imports
        if import_name not in SUPPORTED_IMPORTS and import_name not in IGNORED_IMPORTS
    )
    module_loop = bool(modules) and (for_any or for_all)
    wide_or_burst = or_count >= 12 and string_defs >= 12

    if includes:
        notes.append("uses include")
    if unknown_imports:
        notes.append("uses unknown import")
    if ignored_imports:
        notes.append("uses ignored import")
    if heavy_module:
        notes.append("uses unsupported-heavy module path")
    if unsupported_dotnet_fields:
        notes.append("uses unsupported dotnet field")
    if module_loop:
        notes.append("module loop present")
    if matches_regex or regex_strings:
        notes.append("regex condition or string")
    if nocase_count:
        notes.append("nocase literal flag present")
    if xor_count:
        notes.append("xor modifier or token present")
    if base64_count:
        notes.append("base64 modifier present")
    if has_any_of_them:
        notes.append("any/all of them present")
    if has_string_decl_comment:
        notes.append("inline comment on string declaration")
    if wide_or_burst:
        notes.append("wide OR-heavy pattern set")
    if rewrite_hints:
        notes.extend(rewrite_hints)

    if (
        includes
        or unknown_imports
        or heavy_module
        or has_condition_offset_reads
        or string_defs == 0
    ):
        bucket = "unsupported_or_manual_review"
    elif module_loop or matches_regex or regex_strings or xor_count or base64_count:
        bucket = "likely_bad_for_search"
    elif rewrite_hints or modules or ignored_imports or filesize_count or uint_reads or has_entrypoint:
        bucket = "optimizable"
    else:
        bucket = "good_candidate"

    return {
        "path": str(path),
        "source": classify_source(path),
        "rule_file": relative_label(path),
        "rule_count": rule_count,
        "imports": imports,
        "includes": includes,
        "modules": modules,
        "header_hints": hints,
        "rewrite_hints": rewrite_hints,
        "string_defs": string_defs,
        "hex_strings": hex_strings,
        "text_strings": text_strings,
        "regex_strings": regex_strings,
        "for_any_count": for_any,
        "for_all_count": for_all,
        "or_count": or_count,
        "and_count": and_count,
        "any_of_count": any_of_count,
        "all_of_count": all_of_count,
        "ascii_count": ascii_count,
        "wide_count": wide_count,
        "nocase_count": nocase_count,
        "xor_count": xor_count,
        "base64_count": base64_count,
        "filesize_count": filesize_count,
        "uint_read_count": uint_reads,
        "matches_regex_count": matches_regex,
        "has_entrypoint": has_entrypoint,
        "has_condition_offset_reads": has_condition_offset_reads,
        "has_any_of_them": has_any_of_them,
        "has_string_decl_comment": has_string_decl_comment,
        "unknown_imports": unknown_imports,
        "ignored_imports": ignored_imports,
        "dotnet_fields": dotnet_fields,
        "unsupported_dotnet_fields": unsupported_dotnet_fields,
        "static_bucket": bucket,
        "notes": notes,
    }


def dynamic_selection(records: list[dict], sample_per_group: int) -> list[dict]:
    groups = defaultdict(list)
    for record in records:
        groups[(record["source"], record["static_bucket"])].append(record)
    selected = []
    for key in sorted(groups):
        items = sorted(groups[key], key=lambda item: (item["or_count"], item["string_defs"], item["rule_file"]))
        selected.extend(items[:sample_per_group])
    return selected


def start_server(sspry: Path, addr: str, db_root: Path, search_workers: int, run_dir: Path) -> subprocess.Popen:
    stderr_path = run_dir / "server.stderr"
    stdout_path = run_dir / "server.stdout"
    stderr_fh = stderr_path.open("w")
    stdout_fh = stdout_path.open("w")
    proc = subprocess.Popen(
        [
            str(sspry),
            "serve",
            "--addr",
            addr,
            "--root",
            str(db_root),
            "--store-path",
            "--search-workers",
            str(search_workers),
        ],
        cwd=str(sspry.parent.parent.parent),
        stdout=stdout_fh,
        stderr=stderr_fh,
        text=True,
    )
    proc._stdout_fh = stdout_fh  # type: ignore[attr-defined]
    proc._stderr_fh = stderr_fh  # type: ignore[attr-defined]
    return proc


def close_server_fds(proc: subprocess.Popen) -> None:
    for attr in ("_stdout_fh", "_stderr_fh"):
        fh = getattr(proc, attr, None)
        if fh:
            fh.close()


def run_search(rule: Path, sspry: Path, addr: str, timeout_s: int, verify: bool) -> dict:
    cmd = [
        str(sspry),
        "search",
        "--addr",
        addr,
        "--timeout",
        str(timeout_s),
        "--rule",
        rule.name,
        "--verbose",
    ]
    if verify:
        cmd.append("--verify")
    started = time.time()
    try:
        proc = run(cmd, capture_output=True, cwd=str(rule.parent), timeout=timeout_s + 5)
    except subprocess.TimeoutExpired:
        return {
            "rule": rule.name,
            "exit_code": None,
            "elapsed_ms_wall": (time.time() - started) * 1000.0,
            "error": "client_timeout",
        }
    record = parse_search_result(rule, proc, (time.time() - started) * 1000.0)
    record["verify_enabled"] = verify
    if record.get("error"):
        err = record["error"]
        if any(marker in err for marker in TEMPORARY_SEARCH_MARKERS):
            record["error_kind"] = "temporary_busy"
        elif "timed out" in err.lower():
            record["error_kind"] = "rpc_timeout"
        elif "unsupported" in err.lower():
            record["error_kind"] = "unsupported"
        else:
            record["error_kind"] = "search_error"
    return record


def final_bucket(record: dict, dataset_count: int) -> str:
    dynamic = record.get("dynamic")
    if not dynamic:
        return "not_run"
    error_kind = dynamic.get("error_kind")
    if dynamic.get("error") == "client_timeout" or error_kind == "rpc_timeout":
        return "bad_for_search"
    if error_kind == "unsupported" and record["rewrite_hints"]:
        return "optimizable_rule"
    if error_kind == "unsupported":
        return "unsupported_or_manual_review"
    if error_kind in {"temporary_busy", "search_error"}:
        return "manual_review"
    if record.get("ignored_imports"):
        return "optimizable_rule"
    docs_scanned = float(dynamic.get("verbose_search_docs_scanned", 0.0))
    total_ms = float(dynamic.get("verbose_search_total_ms", dynamic.get("elapsed_ms_wall", 0.0)))
    scanned_ratio = docs_scanned / float(dataset_count) if dataset_count else 0.0
    if scanned_ratio <= 0.35 and total_ms <= 400.0:
        return "good_rule"
    if record["rewrite_hints"] and (scanned_ratio > 0.55 or total_ms > 750.0):
        return "optimizable_rule"
    if scanned_ratio > 0.85 or total_ms > 3000.0:
        return "bad_for_search"
    if scanned_ratio <= 0.65 and total_ms <= 1200.0:
        return "good_rule"
    return "needs_review"


def aggregate(records: list[dict]) -> dict:
    static_counts = Counter(record["static_bucket"] for record in records)
    source_counts = Counter(record["source"] for record in records)
    final_counts = Counter(record.get("final_bucket", "not_run") for record in records)
    rewrite_counts = Counter()
    for record in records:
        rewrite_counts.update(record["rewrite_hints"])
    return {
        "total_rules": len(records),
        "by_source": dict(source_counts),
        "by_static_bucket": dict(static_counts),
        "by_final_bucket": dict(final_counts),
        "rewrite_hints": dict(rewrite_counts),
    }


def write_markdown(path: Path, summary: dict, records: list[dict]) -> None:
    lines = []
    lines.append("# Rule Triage Summary")
    lines.append("")
    lines.append(f"- Total rule files: {summary['total_rules']}")
    lines.append(f"- By source: {json.dumps(summary['by_source'], sort_keys=True)}")
    lines.append(f"- Static buckets: {json.dumps(summary['by_static_bucket'], sort_keys=True)}")
    lines.append(f"- Final buckets: {json.dumps(summary['by_final_bucket'], sort_keys=True)}")
    lines.append(f"- Rewrite hints: {json.dumps(summary['rewrite_hints'], sort_keys=True)}")
    lines.append("")

    def section(title: str, bucket: str, limit: int = 10) -> None:
        lines.append(f"## {title}")
        bucket_records = [r for r in records if r.get("final_bucket") == bucket]
        bucket_records.sort(
            key=lambda r: (
                float(r.get("dynamic", {}).get("verbose_search_total_ms", r.get("dynamic", {}).get("elapsed_ms_wall", 0.0))),
                r["rule_file"],
            )
        )
        for record in bucket_records[:limit]:
            dynamic = record.get("dynamic", {})
            total_ms = dynamic.get("verbose_search_total_ms", dynamic.get("elapsed_ms_wall", 0.0))
            docs = dynamic.get("verbose_search_docs_scanned", 0)
            skipped = dynamic.get("verbose_search_superblocks_skipped", 0)
            lines.append(
                f"- `{record['rule_file']}` source={record['source']} static={record['static_bucket']} "
                f"ms={total_ms} docs={docs} skipped={skipped} hints={record['rewrite_hints']}"
            )
        if not bucket_records:
            lines.append("- none")
        lines.append("")

    section("Good Rules", "good_rule")
    section("Optimizable Rules", "optimizable_rule")
    section("Bad For Search", "bad_for_search")
    section("Unsupported Or Manual Review", "unsupported_or_manual_review")
    path.write_text("\n".join(lines))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Static and dynamic YARA rule triage.")
    parser.add_argument("--rule-root", action="append", required=True, help="Rule root directory. Repeatable.")
    parser.add_argument("--db-root", required=True, help="Published DB root to query.")
    parser.add_argument("--dataset-count", type=int, default=3322)
    parser.add_argument("--sspry", default="target/release/sspry")
    parser.add_argument("--addr", default="127.0.0.1:19220")
    parser.add_argument("--timeout-s", type=int, default=10)
    parser.add_argument("--search-workers", type=int, default=1)
    parser.add_argument("--sample-per-group", type=int, default=20)
    parser.add_argument(
        "--only-static-bucket",
        action="append",
        choices=STATIC_BUCKETS,
        help="Only run dynamic checks for the named static bucket(s). Repeatable.",
    )
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rule_roots = [Path(item).resolve() for item in args.rule_root]
    db_root = Path(args.db_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    sspry = Path(args.sspry).resolve()

    records = [analyze_static(path) for path in collect_rule_files(rule_roots)]
    selection_pool = records
    if args.only_static_bucket:
        allowed = set(args.only_static_bucket)
        selection_pool = [record for record in records if record["static_bucket"] in allowed]
    selected = dynamic_selection(selection_pool, args.sample_per_group)

    run_dir = output_dir / "dynamic_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    proc = start_server(sspry, args.addr, db_root, args.search_workers, run_dir)
    try:
        wait_for_server(sspry, args.addr, run_dir / "server.info.light.json", attempts=300)
        dynamic_map = {}
        for index, record in enumerate(selected, start=1):
            verify_enabled = args.verify and not record.get("ignored_imports")
            result = run_search(
                Path(record["path"]),
                sspry,
                args.addr,
                args.timeout_s,
                verify_enabled,
            )
            dynamic_map[record["path"]] = result
            if index % 25 == 0:
                sys.stderr.write(f"dynamic_progress: {index}/{len(selected)}\n")
                sys.stderr.flush()
    finally:
        shutdown_server(sspry, args.addr, proc, run_dir)
        close_server_fds(proc)

    for record in records:
        if record["path"] in dynamic_map:
            record["dynamic"] = dynamic_map[record["path"]]
        record["final_bucket"] = final_bucket(record, args.dataset_count)

    summary = aggregate(records)
    (output_dir / "triage_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    (output_dir / "triage_records.json").write_text(json.dumps(records, indent=2, sort_keys=True))
    write_markdown(output_dir / "triage_summary.md", summary, records)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
