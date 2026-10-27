#!/usr/bin/env python3
"""Rebuild persistent per-block statuses for non-passing SPEC06 outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import traceback
from collections import Counter, defaultdict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
DEFAULT_INPUT_DIR = Path("/opt/artifact/Documents/raw_data/spec06")
DEFAULT_BASELINE_DIR = Path("/opt/artifact/Documents/raw_data/spec06_pp")
DEFAULT_REPORT_DIR = TESTS_DIR / "failure_reports" / "spec06_aaabdf6_baseline"
DEFAULT_JOBS = 2
DEFAULT_TIMEOUT_S = 300
RESULT_FIELDS = ("init_binary", "block_binary", "qemu_result")
SCHEMA_VERSION = 1

sys.path.insert(0, str(TESTS_DIR))

from generate_spec06_pp import load_document, run_block, write_json_atomic


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.strip()


def write_text_atomic(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    temp_path.write_text(text, encoding="utf-8")
    os.replace(temp_path, path)


def result_state(block: Dict[str, Any], source: str, index: int) -> str:
    values = [block.get(field) for field in RESULT_FIELDS]
    if all(value is None for value in values):
        return "nonpassing"
    if all(isinstance(value, str) for value in values):
        return "passed"
    raise ValueError(
        f"inconsistent result fields in {source} at index {index}: "
        f"{dict(zip(RESULT_FIELDS, values))}"
    )


def validate_source_block(
    source_block: Dict[str, Any],
    baseline_block: Dict[str, Any],
    source: str,
    index: int,
):
    restored = {
        key: value
        for key, value in baseline_block.items()
        if key not in RESULT_FIELDS
    }
    if restored != source_block:
        raise ValueError(
            f"baseline changed source fields in {source} at index {index} "
            f"(id={source_block.get('id')!r})"
        )


def load_wanted_ids(path: Path) -> set[str]:
    values = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    values = [value for value in values if value and not value.startswith("#")]
    if not values:
        raise ValueError(f"ID file is empty: {path}")
    duplicates = sorted(
        value for value, count in Counter(values).items() if count > 1
    )
    if duplicates:
        raise ValueError(f"duplicate IDs in {path}: {', '.join(duplicates)}")
    return set(values)


def select_cases_by_ids(
    cases: List[Dict[str, Any]],
    wanted_ids: set[str],
) -> List[Dict[str, Any]]:
    available = {str(case.get("id")) for case in cases}
    missing = wanted_ids - available
    if missing:
        raise ValueError(
            "requested non-passing block IDs not found: "
            + ", ".join(sorted(missing))
        )
    return [case for case in cases if str(case.get("id")) in wanted_ids]


def discover_cases(
    input_dir: Path,
    baseline_dir: Path,
    wanted_files: Optional[set[str]] = None,
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, int]]:
    source_paths = sorted(input_dir.glob("*.json"))
    if wanted_files:
        found = {path.name for path in source_paths}
        missing = wanted_files - found
        if missing:
            raise ValueError(f"source files not found: {', '.join(sorted(missing))}")
        source_paths = [path for path in source_paths if path.name in wanted_files]
    if not source_paths:
        raise ValueError("no SPEC06 source files selected")

    cases: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    totals = {"blocks": 0, "passed": 0, "nonpassing": 0}

    for source_path in source_paths:
        baseline_path = baseline_dir / source_path.name
        if not baseline_path.is_file():
            raise ValueError(f"missing baseline output: {baseline_path}")

        _, source_blocks, _ = load_document(source_path)
        _, baseline_blocks, _ = load_document(baseline_path)
        if len(source_blocks) != len(baseline_blocks):
            raise ValueError(
                f"block count mismatch for {source_path.name}: "
                f"source={len(source_blocks)} baseline={len(baseline_blocks)}"
            )

        file_counts = Counter()
        for index, (source_block, baseline_block) in enumerate(
            zip(source_blocks, baseline_blocks)
        ):
            validate_source_block(source_block, baseline_block, source_path.name, index)
            state = result_state(baseline_block, source_path.name, index)
            file_counts[state] += 1
            if state == "nonpassing":
                cases.append(
                    {
                        "key": f"{source_path.name}:{index}",
                        "source_file": source_path.name,
                        "source_index": index,
                        "id": source_block.get("id", f"{source_path.stem}_{index}"),
                        "function": source_block.get("function", ""),
                        "asm": source_block.get("asm", ""),
                    }
                )

        total = len(source_blocks)
        totals["blocks"] += total
        totals["passed"] += file_counts["passed"]
        totals["nonpassing"] += file_counts["nonpassing"]
        files.append(
            {
                "name": source_path.name,
                "total": total,
                "passed": file_counts["passed"],
                "nonpassing": file_counts["nonpassing"],
                "source_size": source_path.stat().st_size,
                "source_sha256": sha256_file(source_path),
                "baseline_size": baseline_path.stat().st_size,
                "baseline_sha256": sha256_file(baseline_path),
            }
        )
        print(
            f"[discover] {source_path.name}: total={total} "
            f"passed={file_counts['passed']} nonpassing={file_counts['nonpassing']}",
            flush=True,
        )

    return cases, files, totals


def load_partial(path: Path) -> Dict[str, Dict[str, Any]]:
    records: Dict[str, Dict[str, Any]] = {}
    if not path.exists():
        return records
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                key = item["key"]
            except (json.JSONDecodeError, KeyError) as exc:
                print(
                    f"Ignoring malformed partial line {line_number}: {exc}",
                    file=sys.stderr,
                )
                continue
            if isinstance(key, str):
                records[key] = item
    return records


def classify_failure(result: Dict[str, Any]) -> Optional[str]:
    status = result.get("status")
    if status == "passed":
        return None
    if status == "skipped":
        return "skipped"
    if status == "timeout":
        return "timeout"

    error = str(result.get("error", "")).lower()
    stage = str(result.get("failure_stage") or "").lower()
    if "unsat" in error or "constraint" in stage:
        return "constraint_unsat"
    if "replay" in error or "replay" in stage:
        return "replay_failed"
    if stage == "qemu" or "qemu returned" in error:
        return "qemu_failed"
    if "assembler" in error or "assemble" in stage or "assembly" in stage:
        return "assembly_failed"
    if "unsupported" in error:
        return "unsupported"
    return "other_failed"


def annotate_result(
    case: Dict[str, Any],
    result: Dict[str, Any],
    commit: str,
) -> Dict[str, Any]:
    annotated = {
        "key": case["key"],
        "source_file": case["source_file"],
        "source_index": case["source_index"],
        "id": case["id"],
        "function": case["function"],
        "asm": case["asm"],
        **result,
        "git_commit": commit,
    }
    annotated["failure_kind"] = classify_failure(annotated)
    return annotated


def summarize(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    records = list(records)
    status_counts = Counter(record.get("status", "failed") for record in records)
    failure_counts = Counter(
        record.get("failure_kind") or "other_failed"
        for record in records
        if record.get("status") == "failed"
    )
    stage_counts = Counter(
        record.get("failure_stage") or "unknown"
        for record in records
        if record.get("status") in {"failed", "timeout"}
    )
    per_benchmark: Dict[str, Counter] = defaultdict(Counter)
    for record in records:
        status = record.get("status", "failed")
        per_benchmark[record["source_file"]][status] += 1
        per_benchmark[record["source_file"]]["total"] += 1
    return {
        "total": len(records),
        "counts": dict(sorted(status_counts.items())),
        "failure_kinds": dict(sorted(failure_counts.items())),
        "failure_stages": dict(sorted(stage_counts.items())),
        "per_benchmark": {
            name: dict(sorted(counts.items()))
            for name, counts in sorted(per_benchmark.items())
        },
    }


def write_id_sets(report_dir: Path, records: Iterable[Dict[str, Any]]):
    by_status: Dict[str, List[str]] = defaultdict(list)
    by_failure_kind: Dict[str, List[str]] = defaultdict(list)
    for record in records:
        block_id = str(record["id"])
        status = str(record.get("status", "failed"))
        by_status[status].append(block_id)
        if status == "failed":
            kind = str(record.get("failure_kind") or "other_failed")
            by_failure_kind[kind].append(block_id)

    ids_dir = report_dir / "ids"
    for status, block_ids in sorted(by_status.items()):
        write_text_atomic(ids_dir / f"{status}.ids", "\n".join(block_ids) + "\n")
    for kind, block_ids in sorted(by_failure_kind.items()):
        write_text_atomic(
            ids_dir / "by_failure_kind" / f"{kind}.ids",
            "\n".join(block_ids) + "\n",
        )


def run_cases(
    cases: List[Dict[str, Any]],
    completed: Dict[str, Dict[str, Any]],
    partial_path: Path,
    jobs: int,
    timeout_s: int,
    progress_every: int,
    commit: str,
):
    pending = [case for case in cases if case["key"] not in completed]
    if not pending:
        return

    started = time.monotonic()
    pending_iter = iter(pending)
    max_in_flight = max(jobs * 2, jobs)

    def submit_next(executor, futures) -> bool:
        try:
            case = next(pending_iter)
        except StopIteration:
            return False
        future = executor.submit(
            run_block,
            Path(case["source_file"]).stem,
            case["source_index"],
            case["asm"],
            timeout_s,
        )
        futures[future] = case
        return True

    partial_path.parent.mkdir(parents=True, exist_ok=True)
    with partial_path.open("a", encoding="utf-8") as partial_file:
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            futures = {}
            while len(futures) < max_in_flight and submit_next(executor, futures):
                pass

            while futures:
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    case = futures.pop(future)
                    try:
                        result = future.result()
                    except BaseException as exc:
                        result = {
                            "status": "failed",
                            "failure_stage": "supervisor",
                            "error": f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-4000:]}",
                            "elapsed_s": 0.0,
                        }
                    record = annotate_result(case, result, commit)
                    completed[case["key"]] = record
                    partial_file.write(json.dumps(record, ensure_ascii=False) + "\n")
                    partial_file.flush()

                    written = len(completed)
                    if written % progress_every == 0 or written == len(cases):
                        elapsed = max(time.monotonic() - started, 0.001)
                        processed_now = written - (len(cases) - len(pending))
                        rate = processed_now / elapsed
                        remaining = len(cases) - written
                        counts = Counter(
                            item.get("status", "failed") for item in completed.values()
                        )
                        print(
                            f"[status] {written}/{len(cases)} "
                            f"({100.0 * written / len(cases):.2f}%) "
                            f"rate={rate:.2f}/s eta={remaining / rate / 3600 if rate else 0:.2f}h "
                            f"counts={dict(counts)}",
                            flush=True,
                        )

                    while len(futures) < max_in_flight and submit_next(executor, futures):
                        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--baseline-dir", type=Path, default=DEFAULT_BASELINE_DIR)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--progress-every", type=int, default=100)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--file", action="append", help="only inspect this source filename")
    parser.add_argument("--ids-file", type=Path, help="only retest block IDs listed in this file")
    parser.add_argument("--list-only", action="store_true")
    parser.add_argument(
        "--retry-status",
        action="append",
        choices=("passed", "skipped", "failed", "timeout"),
        default=[],
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.jobs <= 0 or args.timeout <= 0 or args.progress_every <= 0:
        raise SystemExit("--jobs, --timeout, and --progress-every must be positive")
    if not args.input_dir.is_dir():
        raise SystemExit(f"input directory does not exist: {args.input_dir}")
    if not args.baseline_dir.is_dir():
        raise SystemExit(f"baseline directory does not exist: {args.baseline_dir}")

    cases, files, discovery_totals = discover_cases(
        args.input_dir,
        args.baseline_dir,
        set(args.file) if args.file else None,
    )
    wanted_ids = load_wanted_ids(args.ids_file) if args.ids_file else None
    if wanted_ids is not None:
        cases = select_cases_by_ids(cases, wanted_ids)
    all_candidate_count = len(cases)
    if args.limit is not None:
        if args.limit <= 0:
            raise SystemExit("--limit must be positive")
        cases = cases[: args.limit]

    print(
        f"Discovered blocks={discovery_totals['blocks']} "
        f"passed={discovery_totals['passed']} "
        f"nonpassing={discovery_totals['nonpassing']} selected={len(cases)}",
        flush=True,
    )
    if args.list_only:
        return 0

    commit = git_head()
    state = {
        "schema_version": SCHEMA_VERSION,
        "git_commit": commit,
        "prof_sha256": sha256_file(REPO_ROOT / "src" / "rvmca" / "trans" / "prof.py"),
        "harness_sha256": sha256_file(Path(__file__).resolve()),
        "input_dir": str(args.input_dir.resolve()),
        "baseline_dir": str(args.baseline_dir.resolve()),
        "all_candidate_count": all_candidate_count,
        "selected_candidate_count": len(cases),
        "selected_files": sorted(args.file) if args.file else None,
        "selected_ids": sorted(wanted_ids) if wanted_ids is not None else None,
        "limit": args.limit,
        "files": files,
    }
    state_path = args.report_dir / "state.json"
    partial_path = args.report_dir / "status.partial.jsonl"
    if state_path.exists():
        prior_state = json.loads(state_path.read_text(encoding="utf-8"))
        if prior_state != state:
            raise SystemExit(
                f"state mismatch in {args.report_dir}; use a new report directory"
            )
    else:
        if partial_path.exists():
            raise SystemExit(f"partial report exists without state: {partial_path}")
        write_json_atomic(state_path, state)

    if partial_path.exists() and not args.resume:
        raise SystemExit(f"partial report exists; rerun with --resume: {partial_path}")
    completed = load_partial(partial_path) if args.resume else {}
    selected_keys = {case["key"] for case in cases}
    completed = {
        key: record for key, record in completed.items() if key in selected_keys
    }
    retry_statuses = set(args.retry_status)
    if retry_statuses:
        completed = {
            key: record
            for key, record in completed.items()
            if record.get("status") not in retry_statuses
        }
    print(
        f"Starting status reconstruction: total={len(cases)} resumed={len(completed)} "
        f"jobs={args.jobs} timeout={args.timeout}s",
        flush=True,
    )
    run_cases(
        cases,
        completed,
        partial_path,
        args.jobs,
        args.timeout,
        args.progress_every,
        commit,
    )
    if len(completed) != len(cases):
        raise RuntimeError(f"incomplete result set: {len(completed)}/{len(cases)}")

    case_order = {case["key"]: index for index, case in enumerate(cases)}
    records = sorted(completed.values(), key=lambda item: case_order[item["key"]])
    summary = summarize(records)
    report = {"state": state, "summary": summary, "records": records}
    write_json_atomic(args.report_dir / "status.json", report)
    write_json_atomic(args.report_dir / "summary.json", summary)
    write_id_sets(args.report_dir, records)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True), flush=True)
    print(f"Persistent status report: {args.report_dir / 'status.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
