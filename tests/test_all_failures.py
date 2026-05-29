"""
Batch test for all failed basic blocks in analysis_results.json.

Reads the 2079 failure entries from analysis_results.json, retests each one
using transform_for_profiling, and produces a detailed report of which blocks
still fail, which now pass, and a per-benchmark summary.
"""

import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Dict, List, Any

from rvmca.trans.prof import transform_for_profiling
from rvmca.config import OUTPUT_PATH

# ── Paths ────────────────────────────────────────────────────────────────────

TESTS_DIR = Path(__file__).parent
JSON_PATH  = TESTS_DIR / "analysis_results.json"
REPORT_DIR = TESTS_DIR / "failure_reports"
REPORT_DIR.mkdir(exist_ok=True)

TEMP_ASM   = OUTPUT_PATH / "batch_test_tmp.S"   # reuse a single temp file

# ── Helpers ──────────────────────────────────────────────────────────────────

def run_single_block(block_id: str, asm_raw: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Test one basic block.  Returns a dict with:
      - id          : block identifier
      - passed      : bool
      - result      : stdout from transform_for_profiling (or None)
      - error       : error message if failed (or None)
      - elapsed_s   : wall-clock seconds taken
    """
    asm = asm_raw.replace("\\n", "\n").strip()

    # Write assembly to a uniquely-named temp file to avoid name clashes
    safe_id   = block_id.replace("/", "_").replace(".", "_")
    tmp_asm   = OUTPUT_PATH / f"batch_{safe_id}.S"

    tmp_asm.parent.mkdir(parents=True, exist_ok=True)
    tmp_asm.write_text(asm + "\n", encoding="utf-8")

    t0 = time.time()
    try:
        result = transform_for_profiling(str(tmp_asm), verbose=verbose)
        elapsed = time.time() - t0
        if result:
            return {"id": block_id, "passed": True,  "result": result, "error": None, "elapsed_s": elapsed}
        else:
            return {"id": block_id, "passed": False, "result": None,   "error": "pp returned empty output", "elapsed_s": elapsed}
    except Exception as e:
        elapsed = time.time() - t0
        return {"id": block_id, "passed": False, "result": None, "error": str(e), "elapsed_s": elapsed}
    finally:
        # clean up the per-block temp file
        if tmp_asm.exists():
            tmp_asm.unlink()


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


def print_progress(idx: int, total: int, block_id: str, passed: bool, elapsed: float):
    status = "✓ PASS" if passed else "✗ FAIL"
    pct    = 100.0 * (idx + 1) / total
    print(f"[{idx+1:4d}/{total}] {pct:6.2f}%  {status}  ({elapsed:.1f}s)  {block_id}")
    sys.stdout.flush()


# ── Main ─────────────────────────────────────────────────────────────────────

def test_all_failures(verbose: bool = True, limit: int = None):
    print(f"Loading failures from: {JSON_PATH}")
    all_failures = load_all_failures(JSON_PATH)
    total = len(all_failures)
    print(f"Total failure blocks to test: {total}")

    if limit:
        all_failures = all_failures[:limit]
        print(f"(Limited to first {limit} blocks for this run)")

    results: List[Dict[str, Any]] = []
    still_failing: List[Dict[str, Any]] = []
    now_passing:   List[Dict[str, Any]] = []

    wall_start = time.time()

    for idx, failure in enumerate(all_failures):
        block_id  = failure.get("id", f"block_{idx}")
        asm_raw   = failure.get("asm", "")
        benchmark = failure.get("benchmark", "unknown")

        res = run_single_block(block_id, asm_raw, verbose=verbose)
        res["benchmark"]    = benchmark
        res["asm"]          = asm_raw
        res["function"]     = failure.get("function", "")
        res["orig_status"]  = failure.get("status",   "")
        res["orig_result"]  = failure.get("result",   "")

        results.append(res)
        if res["passed"]:
            now_passing.append(res)
        else:
            still_failing.append(res)

        print_progress(idx, len(all_failures), block_id, res["passed"], res["elapsed_s"])

    wall_elapsed = time.time() - wall_start

    # ── Per-benchmark summary ─────────────────────────────────────────────
    bench_stats: Dict[str, Dict[str, int]] = {}
    for r in results:
        b = r["benchmark"]
        if b not in bench_stats:
            bench_stats[b] = {"total": 0, "passed": 0, "failed": 0}
        bench_stats[b]["total"] += 1
        if r["passed"]:
            bench_stats[b]["passed"] += 1
        else:
            bench_stats[b]["failed"] += 1

    # ── Print report ─────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("PER-BENCHMARK SUMMARY")
    print("=" * 70)
    print(f"{'Benchmark':<35} {'Total':>6} {'Pass':>6} {'Fail':>6} {'Rate':>8}")
    print("-" * 70)
    for bench, s in sorted(bench_stats.items()):
        rate = 100.0 * s["passed"] / s["total"] if s["total"] else 0.0
        print(f"{bench:<35} {s['total']:>6} {s['passed']:>6} {s['failed']:>6} {rate:>7.1f}%")

    print("\n" + "=" * 70)
    print("OVERALL SUMMARY")
    print("=" * 70)
    tested  = len(results)
    n_pass  = len(now_passing)
    n_fail  = len(still_failing)
    pass_rt = 100.0 * n_pass / tested if tested else 0.0
    print(f"  Tested  : {tested}")
    print(f"  Passed  : {n_pass}  ({pass_rt:.2f}%)")
    print(f"  Failed  : {n_fail}  ({100-pass_rt:.2f}%)")
    print(f"  Wall time: {wall_elapsed:.1f}s")

    # ── Save detailed JSON report ─────────────────────────────────────────
    report_path = REPORT_DIR / "retest_results.json"
    report = {
        "summary": {
            "tested":  tested,
            "passed":  n_pass,
            "failed":  n_fail,
            "pass_rate": round(pass_rt, 4),
            "wall_time_s": round(wall_elapsed, 2),
        },
        "per_benchmark": bench_stats,
        "still_failing": [
            {
                "id":          r["id"],
                "benchmark":   r["benchmark"],
                "function":    r["function"],
                "asm":         r["asm"],
                "error":       r["error"],
                "orig_status": r["orig_status"],
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
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nDetailed report saved to: {report_path}")

    if still_failing:
        print("\n" + "=" * 70)
        print(f"STILL FAILING BLOCKS ({n_fail} total):")
        print("=" * 70)
        for r in still_failing:
            print(f"  [{r['benchmark']}]  {r['id']}  —  {r['error']}")

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
    args = parser.parse_args()

    test_all_failures(verbose=args.verbose, limit=args.limit)
