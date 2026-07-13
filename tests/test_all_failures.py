"""
Batch test for all failed basic blocks in analysis_results.json.

Reads the 2079 failure entries from analysis_results.json, retests each one
using transform_for_profiling, and produces a detailed report of which blocks
still fail, which now pass, and a per-benchmark summary.
"""

import io
import json
import multiprocessing
import os
import queue
import signal
import sys
import time
import traceback
from contextlib import redirect_stderr, redirect_stdout
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Any

# ── Paths ────────────────────────────────────────────────────────────────────

TESTS_DIR = Path(__file__).parent
REPO_ROOT = TESTS_DIR.parent
SRC_DIR = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from rvmca.trans.prof import transform_for_profiling
from rvmca.config import OUTPUT_PATH

JSON_PATH  = TESTS_DIR / "analysis_results.json"
REPORT_DIR = TESTS_DIR / "failure_reports"
REPORT_DIR.mkdir(exist_ok=True)

TEMP_ASM   = OUTPUT_PATH / "batch_test_tmp.S"   # reuse a single temp file
DEFAULT_BLOCK_TIMEOUT_S = int(os.environ.get("RVMCA_BLOCK_TIMEOUT_S", "300"))

# ── Helpers ──────────────────────────────────────────────────────────────────


def classify_failure(trace_text: str, error_file_text: str = ""):
    combined = "\n".join(part for part in [trace_text, error_file_text] if part)

    if "Error: pp fails." in combined:
        return "pp_failed", "Error: pp fails."
    if "concrete replay fails after init solving" in combined:
        return "replay_failed", "concrete replay fails after init solving"
    if "is not satisfiable" in combined or "unsatisfiable" in combined:
        return "constraint_unsat", "constraints are not satisfiable"
    if "simulation fails" in combined:
        return "symbolic_execution_failed", "symbolic execution failed"
    if "Assemble code failed" in combined:
        return "assemble_failed", "assemble code failed"

    for line in reversed(combined.splitlines()):
        line = line.strip()
        if not line:
            continue
        if line.startswith(("AssertionError:", "RuntimeError:", "ValueError:", "Exception:")):
            return "other_failed", line

    return "other_failed", "transform returned empty output"


def read_text_if_exists(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8") if path.exists() else ""
    except UnicodeDecodeError:
        return path.read_text(errors="replace") if path.exists() else ""


def load_partial_results(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}

    results = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        block_id = item.get("id")
        if block_id:
            results[block_id] = item
    return results

def _run_single_block_uncapped(block_id: str, asm_raw: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Test one basic block.  Returns a dict with:
      - id          : block identifier
      - passed      : bool
      - skipped     : bool
      - result      : stdout from transform_for_profiling (or None)
      - error       : error message if failed (or None)
      - elapsed_s   : wall-clock seconds taken
    """
    asm = asm_raw.replace("\\n", "\n").strip()

    # Write assembly to a uniquely-named temp file to avoid name clashes
    safe_id   = block_id.replace("/", "_").replace(".", "_")
    tmp_asm   = OUTPUT_PATH / f"batch_{safe_id}.S"
    out_prefix = OUTPUT_PATH / f"batch_{safe_id}"

    tmp_asm.parent.mkdir(parents=True, exist_ok=True)
    for suffix in [".error", ".init", ".code", ".stage.json"]:
        stale = Path(str(out_prefix) + suffix)
        if stale.exists():
            stale.unlink()

    tmp_asm.write_text(asm + "\n", encoding="utf-8")

    t0 = time.time()
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    try:
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            result = transform_for_profiling(str(tmp_asm), verbose=verbose)
        elapsed = time.time() - t0
        trace_text = stdout_buf.getvalue() + stderr_buf.getvalue()
        if isinstance(result, str) and result.startswith("SKIP:"):
            return {
                "id": block_id,
                "passed": False,
                "skipped": True,
                "failure_kind": "skipped",
                "result": result,
                "error": result,
                "elapsed_s": elapsed,
            }
        if result:
            return {
                "id": block_id,
                "passed": True,
                "skipped": False,
                "failure_kind": None,
                "result": result,
                "error": None,
                "elapsed_s": elapsed,
            }

        error_file_text = read_text_if_exists(Path(str(out_prefix) + ".error"))
        if not error_file_text and "Traceback" not in trace_text:
            return {
                "id": block_id,
                "passed": True,
                "skipped": False,
                "failure_kind": None,
                "result": result,
                "error": None,
                "elapsed_s": elapsed,
            }
        failure_kind, error = classify_failure(trace_text, error_file_text)
        return {
            "id": block_id,
            "passed": False,
            "skipped": False,
            "failure_kind": failure_kind,
            "result": None,
            "error": error,
            "trace_tail": trace_text[-4000:],
            "elapsed_s": elapsed,
        }
    except Exception as e:
        elapsed = time.time() - t0
        trace_text = stdout_buf.getvalue() + stderr_buf.getvalue() + traceback.format_exc()
        failure_kind, error = classify_failure(trace_text)
        if failure_kind == "other_failed":
            error = str(e)
        return {
            "id": block_id,
            "passed": False,
            "skipped": False,
            "failure_kind": failure_kind,
            "result": None,
            "error": error,
            "trace_tail": trace_text[-4000:],
            "elapsed_s": elapsed,
        }
    finally:
        # clean up the per-block temp file
        if tmp_asm.exists():
            tmp_asm.unlink()


def _run_single_block_worker(result_queue, block_id: str, asm_raw: str, verbose: bool):
    try:
        os.setsid()
    except OSError:
        pass
    result_queue.put(_run_single_block_uncapped(block_id, asm_raw, verbose=verbose))


def run_single_block(
    block_id: str,
    asm_raw: str,
    verbose: bool = False,
    timeout_s: int = DEFAULT_BLOCK_TIMEOUT_S,
) -> Dict[str, Any]:
    if timeout_s <= 0:
        return _run_single_block_uncapped(block_id, asm_raw, verbose=verbose)

    t0 = time.time()
    result_queue = multiprocessing.Queue(maxsize=1)
    process = multiprocessing.Process(
        target=_run_single_block_worker,
        args=(result_queue, block_id, asm_raw, verbose),
    )
    process.start()
    process.join(timeout_s)

    if process.is_alive():
        safe_id = block_id.replace("/", "_").replace(".", "_")
        out_prefix = OUTPUT_PATH / f"batch_{safe_id}"
        stage_file = Path(str(out_prefix) + ".stage.json")
        timeout_stage = None
        timeout_stage_detail = None
        if stage_file.exists():
            try:
                timeout_stage_detail = json.loads(stage_file.read_text(encoding="utf-8"))
                timeout_stage = timeout_stage_detail.get("stage")
            except Exception:
                timeout_stage_detail = None

        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            process.terminate()
        process.join(5)
        if process.is_alive():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                process.kill()
            process.join(5)

        error = f"block timed out after {timeout_s}s"
        if timeout_stage:
            error += f" at {timeout_stage}"
        return {
            "id": block_id,
            "passed": False,
            "skipped": False,
            "failure_kind": "timeout_failed",
            "result": None,
            "error": error,
            "timeout_stage": timeout_stage,
            "timeout_stage_detail": timeout_stage_detail,
            "elapsed_s": time.time() - t0,
        }

    try:
        return result_queue.get_nowait()
    except queue.Empty:
        return {
            "id": block_id,
            "passed": False,
            "skipped": False,
            "failure_kind": "other_failed",
            "result": None,
            "error": f"worker exited with code {process.exitcode}",
            "elapsed_s": time.time() - t0,
        }


def load_all_failures(json_path: Path) -> List[Dict[str, Any]]:
    """Flatten all failure entries from every benchmark into a single list."""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    failures = []
    for benchmark in data:
        bench_name = benchmark.get("name", "unknown")
        for f in benchmark.get("failures", []):
            f = dict(f)           # shallow copy so we can annotate
            f["benchmark"] = bench_name
            failures.append(f)
    return failures


def print_progress(idx: int, total: int, block_id: str, passed: bool, skipped: bool, elapsed: float):
    status = "SKIP" if skipped else ("PASS" if passed else "FAIL")
    pct    = 100.0 * (idx + 1) / total
    print(f"[{idx+1:4d}/{total}] {pct:6.2f}%  {status}  ({elapsed:.1f}s)  {block_id}")
    sys.stdout.flush()


# ── Main ─────────────────────────────────────────────────────────────────────

def test_all_failures(
    verbose: bool = True,
    limit: int = None,
    timeout_s: int = DEFAULT_BLOCK_TIMEOUT_S,
    jobs: int = 1,
    resume: bool = False,
    report_prefix: str = "retest_results",
    ids_file: str = None,
    schedule: str = "original",
):
    print(f"Loading failures from: {JSON_PATH}")
    all_failures = load_all_failures(JSON_PATH)
    if ids_file:
        wanted_ids = [
            line.strip()
            for line in Path(ids_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        by_id = {failure.get("id"): failure for failure in all_failures}
        missing = [block_id for block_id in wanted_ids if block_id not in by_id]
        if missing:
            print(f"Warning: {len(missing)} ids from {ids_file} are not present in {JSON_PATH}")
        all_failures = [by_id[block_id] for block_id in wanted_ids if block_id in by_id]
    if schedule not in {"original", "sorted"}:
        raise ValueError(f"unsupported schedule: {schedule}")
    if schedule == "sorted":
        all_failures = sorted(all_failures, key=lambda item: item.get("id", ""))
    total = len(all_failures)
    print(f"Total failure blocks to test: {total}")

    if limit:
        all_failures = all_failures[:limit]
        print(f"(Limited to first {limit} blocks for this run)")

    results: List[Dict[str, Any]] = []
    still_failing: List[Dict[str, Any]] = []
    now_passing:   List[Dict[str, Any]] = []
    skipped:       List[Dict[str, Any]] = []
    failure_kinds: Dict[str, int] = {}
    partial_path = REPORT_DIR / f"{report_prefix}.partial.jsonl"
    completed_by_id = load_partial_results(partial_path) if resume else {}
    completed_by_id = {
        block_id: item
        for block_id, item in completed_by_id.items()
        if any(failure.get("id") == block_id for failure in all_failures)
    }
    if resume and completed_by_id:
        print(f"(Resuming from {partial_path}: {len(completed_by_id)} completed blocks)")
    else:
        partial_path.write_text("", encoding="utf-8")

    wall_start = time.time()

    def record_result(idx: int, failure: Dict[str, Any], res: Dict[str, Any], write_partial: bool = True):
        block_id = failure.get("id", f"block_{idx}")
        benchmark = failure.get("benchmark", "unknown")
        res["benchmark"]    = benchmark
        res["asm"]          = failure.get("asm", "")
        res["function"]     = failure.get("function", "")
        res["orig_status"]  = failure.get("status",   "")
        res["orig_result"]  = failure.get("result",   "")
        res["_order"]       = idx
        if write_partial:
            with partial_path.open("a", encoding="utf-8") as partial_file:
                partial_file.write(json.dumps(res, ensure_ascii=False) + "\n")

        results.append(res)
        if res.get("skipped"):
            skipped.append(res)
        elif res["passed"]:
            now_passing.append(res)
        else:
            still_failing.append(res)
            kind = res.get("failure_kind") or "other_failed"
            failure_kinds[kind] = failure_kinds.get(kind, 0) + 1

    for idx, failure in enumerate(all_failures):
        block_id = failure.get("id", f"block_{idx}")
        if block_id in completed_by_id:
            record_result(idx, failure, completed_by_id[block_id], write_partial=False)

    pending_failures = [
        (idx, failure)
        for idx, failure in enumerate(all_failures)
        if failure.get("id", f"block_{idx}") not in completed_by_id
    ]
    if completed_by_id:
        print(f"(Pending blocks: {len(pending_failures)})")

    def run_and_record(idx: int, failure: Dict[str, Any], completed_index: int):
        block_id = failure.get("id", f"block_{idx}")
        asm_raw = failure.get("asm", "")
        res = run_single_block(block_id, asm_raw, verbose=verbose, timeout_s=timeout_s)
        record_result(idx, failure, res)
        print_progress(completed_index, len(all_failures), block_id, res["passed"], res.get("skipped", False), res["elapsed_s"])

    completed_count = len(results)
    if jobs <= 1:
        for idx, failure in pending_failures:
            completed_count += 1
            run_and_record(idx, failure, completed_count - 1)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            future_map = {
                executor.submit(
                    run_single_block,
                    failure.get("id", f"block_{idx}"),
                    failure.get("asm", ""),
                    verbose,
                    timeout_s,
                ): (idx, failure)
                for idx, failure in pending_failures
            }
            for future in as_completed(future_map):
                idx, failure = future_map[future]
                block_id = failure.get("id", f"block_{idx}")
                try:
                    res = future.result()
                except Exception as exc:
                    res = {
                        "id": block_id,
                        "passed": False,
                        "skipped": False,
                        "failure_kind": "other_failed",
                        "result": None,
                        "error": str(exc),
                        "trace_tail": traceback.format_exc()[-4000:],
                        "elapsed_s": 0.0,
                    }
                completed_count += 1
                record_result(idx, failure, res)
                print_progress(completed_count - 1, len(all_failures), block_id, res["passed"], res.get("skipped", False), res["elapsed_s"])

    if resume and completed_by_id:
        with partial_path.open("w", encoding="utf-8") as partial_file:
            for res in sorted(results, key=lambda item: item.get("_order", 0)):
                partial_file.write(json.dumps(res, ensure_ascii=False) + "\n")

    wall_elapsed = time.time() - wall_start
    results.sort(key=lambda item: item.get("_order", 0))
    still_failing.sort(key=lambda item: item.get("_order", 0))
    now_passing.sort(key=lambda item: item.get("_order", 0))
    skipped.sort(key=lambda item: item.get("_order", 0))

    # ── Per-benchmark summary ─────────────────────────────────────────────
    bench_stats: Dict[str, Dict[str, int]] = {}
    for r in results:
        b = r["benchmark"]
        if b not in bench_stats:
            bench_stats[b] = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
        bench_stats[b]["total"] += 1
        if r.get("skipped"):
            bench_stats[b]["skipped"] += 1
        elif r["passed"]:
            bench_stats[b]["passed"] += 1
        else:
            bench_stats[b]["failed"] += 1

    # ── Print report ─────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("PER-BENCHMARK SUMMARY")
    print("=" * 70)
    print(f"{'Benchmark':<35} {'Total':>6} {'Pass':>6} {'Fail':>6} {'Skip':>6} {'Rate':>8}")
    print("-" * 70)
    for bench, s in sorted(bench_stats.items()):
        solved = s["passed"] + s["failed"]
        rate = 100.0 * s["passed"] / solved if solved else 0.0
        print(f"{bench:<35} {s['total']:>6} {s['passed']:>6} {s['failed']:>6} {s['skipped']:>6} {rate:>7.1f}%")

    print("\n" + "=" * 70)
    print("OVERALL SUMMARY")
    print("=" * 70)
    tested  = len(results)
    n_pass  = len(now_passing)
    n_fail  = len(still_failing)
    n_skip  = len(skipped)
    solved  = n_pass + n_fail
    pass_rt = 100.0 * n_pass / solved if solved else 0.0
    print(f"  Tested  : {tested}")
    print(f"  Passed  : {n_pass}  ({pass_rt:.2f}% of non-skipped)")
    print(f"  Failed  : {n_fail}")
    print(f"  Skipped : {n_skip}")
    print(f"  Wall time: {wall_elapsed:.1f}s")
    print(f"  Block timeout: {timeout_s}s")
    print(f"  Jobs: {jobs}")
    if failure_kinds:
        print("  Failure kinds:")
        for kind, count in sorted(failure_kinds.items()):
            print(f"    {kind}: {count}")

    # ── Save detailed JSON report ─────────────────────────────────────────
    report_path = REPORT_DIR / f"{report_prefix}.json"
    report = {
        "summary": {
            "tested":  tested,
            "passed":  n_pass,
            "failed":  n_fail,
            "skipped": n_skip,
            "pass_rate": round(pass_rt, 4),
            "wall_time_s": round(wall_elapsed, 2),
            "block_timeout_s": timeout_s,
            "jobs": jobs,
            "schedule": schedule,
            "ids_file": ids_file,
            "report_prefix": report_prefix,
            "failure_kinds": failure_kinds,
        },
        "per_benchmark": bench_stats,
        "pp_failed": [
            {
                "id":          r["id"],
                "benchmark":   r["benchmark"],
                "function":    r["function"],
                "asm":         r["asm"],
                "error":       r["error"],
                "orig_status": r["orig_status"],
            }
            for r in still_failing
            if r.get("failure_kind") == "pp_failed"
        ],
        "still_failing": [
            {
                "id":          r["id"],
                "benchmark":   r["benchmark"],
                "function":    r["function"],
                "asm":         r["asm"],
                "failure_kind": r.get("failure_kind"),
                "error":       r["error"],
                "orig_status": r["orig_status"],
                "trace_tail":   r.get("trace_tail", ""),
            }
            for r in still_failing
        ],
        "now_passing": [
            {
                "id":        r["id"],
                "benchmark": r["benchmark"],
                "function":  r["function"],
                "asm":       r["asm"],
            }
            for r in now_passing
        ],
        "skipped": [
            {
                "id":          r["id"],
                "benchmark":   r["benchmark"],
                "function":    r["function"],
                "asm":         r["asm"],
                "reason":      r["error"],
                "orig_status": r["orig_status"],
            }
            for r in skipped
        ],
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nDetailed report saved to: {report_path}")

    if still_failing:
        print("\n" + "=" * 70)
        print(f"STILL FAILING BLOCKS ({n_fail} total):")
        print("=" * 70)
        for r in still_failing:
            print(f"  [{r['benchmark']}]  {r['id']}  —  {r.get('failure_kind')}  —  {r['error']}")

    return results, still_failing, now_passing


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Retest all failed basic blocks from analysis_results.json"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output from transform_for_profiling"
    )
    parser.add_argument(
        "--limit", "-n",
        type=int,
        default=None,
        metavar="N",
        help="Only test the first N blocks (useful for quick smoke tests)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_BLOCK_TIMEOUT_S,
        metavar="S",
        help="Per-block timeout in seconds; use 0 to disable"
    )
    parser.add_argument(
        "--jobs", "-j",
        type=int,
        default=1,
        metavar="N",
        help="Number of blocks to test concurrently"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from failure_reports/retest_results.partial.jsonl"
    )
    parser.add_argument(
        "--report-prefix",
        default="retest_results",
        help="Prefix for JSON and partial report files"
    )
    parser.add_argument(
        "--ids-file",
        default=None,
        help="Optional newline-separated block id list to test"
    )
    parser.add_argument(
        "--schedule",
        default="original",
        choices=["original", "sorted"],
        help="Block ordering"
    )
    args = parser.parse_args()

    test_all_failures(
        verbose=args.verbose,
        limit=args.limit,
        timeout_s=args.timeout,
        jobs=args.jobs,
        resume=args.resume,
        report_prefix=args.report_prefix,
        ids_file=args.ids_file,
        schedule=args.schedule,
    )
