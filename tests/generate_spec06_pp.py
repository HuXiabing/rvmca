#!/usr/bin/env python3
"""Generate prof.py/pp results for every basic block in a JSON directory."""

import argparse
import io
import json
import logging
import multiprocessing
import os
import queue
import re
import signal
import subprocess
import sys
import time
import traceback
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SRC_DIR = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.trans.prof import transform_for_profiling


DEFAULT_INPUT_DIR = Path("/opt/artifact/Documents/raw_data/spec06")
DEFAULT_OUTPUT_DIR = Path("/opt/artifact/Documents/raw_data/spec06_pp")
DEFAULT_TIMEOUT_S = 300
DEFAULT_JOBS = min(10, os.cpu_count() or 1)
QEMU_TIMEOUT_S = 60
RESULT_FIELDS = ("init_binary", "block_binary", "qemu_result")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def artifact_paths(case_name: str) -> List[Path]:
    base = OUTPUT_PATH / case_name
    return [
        Path(str(base) + suffix)
        for suffix in (
            ".S",
            ".o",
            ".exe",
            ".init",
            ".code",
            ".init.asm",
            ".code.asm",
            ".error",
            ".stage.json",
        )
    ]


def cleanup_artifacts(case_name: str):
    for path in artifact_paths(case_name):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def read_required_text(path: Path, allow_empty: bool = False) -> str:
    text = path.read_text(encoding="utf-8")
    if not allow_empty and not text.strip():
        raise RuntimeError(f"generated file is empty: {path}")
    return text


def read_stage_detail(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def run_block_worker(
    result_queue,
    case_name: str,
    asm: str,
):
    try:
        os.setsid()
    except OSError:
        pass

    logging.getLogger("cle").setLevel(logging.ERROR)
    logging.getLogger("angr").setLevel(logging.ERROR)
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    asm_path = OUTPUT_PATH / f"{case_name}.S"
    init_path = OUTPUT_PATH / f"{case_name}.init"
    code_path = OUTPUT_PATH / f"{case_name}.code"
    stage_path = OUTPUT_PATH / f"{case_name}.stage.json"

    cleanup_artifacts(case_name)
    started = time.monotonic()
    try:
        asm_path.parent.mkdir(parents=True, exist_ok=True)
        asm_path.write_text(asm.replace("\\n", "\n").strip() + "\n", encoding="utf-8")
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            qemu_result = transform_for_profiling(str(asm_path), verbose=False)

        if isinstance(qemu_result, str) and qemu_result.startswith("SKIP:"):
            result = {
                "status": "skipped",
                "failure_stage": "skip",
                "error": qemu_result,
                "elapsed_s": time.monotonic() - started,
            }
        else:
            stage_detail = read_stage_detail(stage_path)
            stage = stage_detail.get("stage") if stage_detail else None
            if stage != "transform:done":
                trace = (stdout_buffer.getvalue() + stderr_buffer.getvalue()).strip()
                result = {
                    "status": "failed",
                    "failure_stage": stage,
                    "stage_detail": stage_detail,
                    "error": trace[-4000:] or f"transform stopped at stage {stage!r}",
                    "elapsed_s": time.monotonic() - started,
                }
            else:
                init_binary = read_required_text(init_path, allow_empty=True)
                block_binary = read_required_text(code_path)
                completed = subprocess.run(
                    [
                        "qemu-riscv64",
                        str(TOOLS_PATH / "pp" / "pp"),
                        str(init_path),
                        str(code_path),
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=QEMU_TIMEOUT_S,
                )
                if completed.returncode != 0 or not completed.stdout:
                    result = {
                        "status": "failed",
                        "failure_stage": "qemu",
                        "error": (
                            f"qemu returned {completed.returncode}: "
                            f"{(completed.stdout + completed.stderr)[-4000:]}"
                        ),
                        "elapsed_s": time.monotonic() - started,
                    }
                else:
                    result = {
                        "status": "passed",
                        "failure_stage": "done",
                        "init_binary": init_binary,
                        "block_binary": block_binary,
                        "qemu_result": completed.stdout,
                        "elapsed_s": time.monotonic() - started,
                    }
    except BaseException as exc:
        trace = stdout_buffer.getvalue() + stderr_buffer.getvalue() + traceback.format_exc()
        stage_detail = read_stage_detail(stage_path)
        result = {
            "status": "failed",
            "failure_stage": stage_detail.get("stage") if stage_detail else None,
            "stage_detail": stage_detail,
            "error": f"{type(exc).__name__}: {exc}\n{trace[-4000:]}",
            "elapsed_s": time.monotonic() - started,
        }
    finally:
        cleanup_artifacts(case_name)

    result_queue.put(result)


def stop_process(process: multiprocessing.Process):
    if not process.is_alive():
        process.join(0)
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        process.terminate()
    process.join(5)
    if not process.is_alive():
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        process.kill()
    process.join(5)


def run_block(
    source_stem: str,
    index: int,
    asm: str,
    timeout_s: int,
) -> Dict[str, Any]:
    case_name = f"spec06pp_{safe_name(source_stem)}_{index}"
    result_queue = multiprocessing.Queue(maxsize=1)
    process = multiprocessing.Process(
        target=run_block_worker,
        args=(result_queue, case_name, asm),
    )
    started = time.monotonic()
    process.start()
    result = None
    deadline = started + timeout_s

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                result = result_queue.get(timeout=min(0.2, remaining))
                break
            except queue.Empty:
                if not process.is_alive():
                    break

        if result is not None:
            process.join(5)
            stop_process(process)
            return result

        process.join(0)
        if process.is_alive():
            stop_process(process)
            stage_path = OUTPUT_PATH / f"{case_name}.stage.json"
            stage_detail = read_stage_detail(stage_path)
            timeout_stage = stage_detail.get("stage") if stage_detail else None
            error = f"block timed out after {timeout_s}s"
            if timeout_stage:
                error += f" at {timeout_stage}"
            return {
                "status": "timeout",
                "failure_stage": timeout_stage,
                "timeout_stage": timeout_stage,
                "stage_detail": stage_detail,
                "error": error,
                "elapsed_s": time.monotonic() - started,
            }

        try:
            return result_queue.get_nowait()
        except queue.Empty:
            return {
                "status": "failed",
                "error": f"worker exited with code {process.exitcode}",
                "elapsed_s": time.monotonic() - started,
            }
    finally:
        cleanup_artifacts(case_name)
        result_queue.close()
        result_queue.join_thread()


def extract_blocks(
    data: Any,
    source: str,
) -> Tuple[List[Dict[str, Any]], List[Tuple[int, ...]]]:
    if not isinstance(data, list):
        raise ValueError(f"input must be a JSON array: {source}")

    if not data or all(isinstance(item, dict) and "asm" in item for item in data):
        blocks = data
        locations = [(index,) for index in range(len(data))]
    elif all(isinstance(item, dict) and isinstance(item.get("failures"), list) for item in data):
        blocks = []
        locations = []
        for benchmark_index, benchmark in enumerate(data):
            for block_index, block in enumerate(benchmark["failures"]):
                blocks.append(block)
                locations.append((benchmark_index, block_index))
    else:
        raise ValueError(f"unsupported JSON structure: {source}")

    for index, block in enumerate(blocks):
        if not isinstance(block, dict) or not isinstance(block.get("asm"), str):
            raise ValueError(f"item {index} is not a basic-block dictionary: {source}")
    return blocks, locations


def load_document(path: Path) -> Tuple[Any, List[Dict[str, Any]], List[Tuple[int, ...]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    blocks, locations = extract_blocks(data, str(path))
    return data, blocks, locations


def source_signature(path: Path, total: int) -> Dict[str, Any]:
    stat = path.stat()
    return {
        "input": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "total": total,
    }


def write_json_atomic(path: Path, value: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    temp_path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temp_path, path)


def load_partial_results(path: Path) -> Dict[int, Dict[str, Any]]:
    results: Dict[int, Dict[str, Any]] = {}
    if not path.exists():
        return results
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            index = item.pop("index")
            if isinstance(index, int):
                results[index] = item
        except (json.JSONDecodeError, KeyError):
            print(f"Ignoring malformed partial line {line_number}: {path}", file=sys.stderr)
    return results


def validated_completed_output(path: Path, expected_total: int) -> bool:
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    try:
        blocks, _ = extract_blocks(data, str(path))
    except ValueError:
        return False
    return (
        len(blocks) == expected_total
        and all(
            isinstance(item, dict) and all(field in item for field in RESULT_FIELDS)
            for item in blocks
        )
    )


def process_pending(
    blocks: List[Dict[str, Any]],
    source_stem: str,
    completed: Dict[int, Dict[str, Any]],
    partial_path: Path,
    jobs: int,
    timeout_s: int,
    progress_every: int,
):
    pending_indices = [index for index in range(len(blocks)) if index not in completed]
    if not pending_indices:
        return

    started = time.monotonic()
    written = len(completed)
    pending_iter = iter(pending_indices)
    max_in_flight = max(jobs * 2, jobs)

    def submit_next(executor, futures) -> bool:
        try:
            index = next(pending_iter)
        except StopIteration:
            return False
        future = executor.submit(
            run_block,
            source_stem,
            index,
            blocks[index]["asm"],
            timeout_s,
        )
        futures[future] = index
        return True

    with partial_path.open("a", encoding="utf-8") as partial_file:
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            futures = {}
            while len(futures) < max_in_flight and submit_next(executor, futures):
                pass

            while futures:
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    index = futures.pop(future)
                    try:
                        result = future.result()
                    except BaseException as exc:
                        result = {
                            "status": "failed",
                            "error": f"supervisor error: {type(exc).__name__}: {exc}",
                            "elapsed_s": 0.0,
                        }
                    completed[index] = result
                    partial_file.write(
                        json.dumps({"index": index, **result}, ensure_ascii=False) + "\n"
                    )
                    partial_file.flush()
                    written += 1

                    if written % progress_every == 0 or written == len(blocks):
                        elapsed = max(time.monotonic() - started, 0.001)
                        processed_now = written - (len(blocks) - len(pending_indices))
                        rate = processed_now / elapsed
                        remaining = len(blocks) - written
                        eta = remaining / rate if rate else 0.0
                        counts: Dict[str, int] = {}
                        for item in completed.values():
                            status = item.get("status", "failed")
                            counts[status] = counts.get(status, 0) + 1
                        print(
                            f"[{source_stem}] {written}/{len(blocks)} "
                            f"({100.0 * written / len(blocks):.2f}%) "
                            f"rate={rate:.2f}/s eta={eta / 3600:.2f}h counts={counts}",
                            flush=True,
                        )

                    while len(futures) < max_in_flight and submit_next(executor, futures):
                        pass


def materialize_output(
    document: Any,
    blocks: List[Dict[str, Any]],
    locations: List[Tuple[int, ...]],
    completed: Dict[int, Dict[str, Any]],
    output_path: Path,
):
    for index, block in enumerate(blocks):
        result = completed[index]
        item = dict(block)
        if result.get("status") == "passed":
            for field in RESULT_FIELDS:
                item[field] = result[field]
        else:
            for field in RESULT_FIELDS:
                item[field] = None
        location = locations[index]
        if len(location) == 1:
            document[location[0]] = item
        else:
            document[location[0]]["failures"][location[1]] = item
    write_json_atomic(output_path, document)


def summarize_results(results: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for result in results:
        status = result.get("status", "failed")
        counts[status] = counts.get(status, 0) + 1
    return counts


def process_file(
    input_path: Path,
    output_dir: Path,
    jobs: int,
    timeout_s: int,
    resume: bool,
    progress_every: int,
    limit: Optional[int],
    retry_statuses: set[str],
) -> Dict[str, Any]:
    document, blocks, locations = load_document(input_path)
    if limit is not None:
        if locations and len(locations[0]) != 1:
            raise ValueError("--limit is only supported for flat basic-block arrays")
        blocks = blocks[:limit]
        locations = locations[:limit]
        document = document[:limit]
    output_path = output_dir / input_path.name
    partial_path = output_dir / f".{input_path.name}.partial.jsonl"
    state_path = output_dir / f".{input_path.name}.state.json"
    signature = source_signature(input_path, len(blocks))

    if resume and validated_completed_output(output_path, len(blocks)):
        print(f"[{input_path.stem}] already complete: {output_path}", flush=True)
        data = json.loads(output_path.read_text(encoding="utf-8"))
        output_blocks, _ = extract_blocks(data, str(output_path))
        passed = sum(item.get("qemu_result") is not None for item in output_blocks)
        return {
            "input": str(input_path),
            "output": str(output_path),
            "total": len(blocks),
            "counts": {"passed": passed, "non_passing": len(blocks) - passed},
            "resumed_complete": True,
        }

    if partial_path.exists() or state_path.exists():
        if not resume:
            raise RuntimeError(
                f"partial state exists for {input_path}; use --resume or remove {partial_path}"
            )
        if not state_path.exists():
            raise RuntimeError(f"missing state file for partial output: {state_path}")
        prior_signature = json.loads(state_path.read_text(encoding="utf-8"))
        if prior_signature != signature:
            raise RuntimeError(f"input changed since partial run: {input_path}")
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        write_json_atomic(state_path, signature)

    completed = load_partial_results(partial_path) if resume else {}
    retry_indices = [
        index
        for index, result in completed.items()
        if result.get("status") in retry_statuses
    ]
    for index in retry_indices:
        del completed[index]
    if retry_indices:
        print(
            f"[{input_path.stem}] retrying {len(retry_indices)} prior results "
            f"with statuses={sorted(retry_statuses)}",
            flush=True,
        )
    print(
        f"[{input_path.stem}] total={len(blocks)} resumed={len(completed)} "
        f"jobs={jobs} timeout={timeout_s}s",
        flush=True,
    )
    started = time.monotonic()
    process_pending(
        blocks,
        input_path.stem,
        completed,
        partial_path,
        jobs,
        timeout_s,
        progress_every,
    )
    if len(completed) != len(blocks):
        raise RuntimeError(
            f"incomplete result set for {input_path}: {len(completed)}/{len(blocks)}"
        )
    materialize_output(document, blocks, locations, completed, output_path)
    counts = summarize_results(completed.values())
    partial_path.unlink(missing_ok=True)
    state_path.unlink(missing_ok=True)
    summary = {
        "input": str(input_path),
        "output": str(output_path),
        "total": len(blocks),
        "counts": counts,
        "elapsed_s": round(time.monotonic() - started, 3),
        "resumed_complete": False,
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True), flush=True)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--progress-every", type=int, default=100)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int, help="process only the first N blocks per file")
    parser.add_argument("--max-files", type=int, help="process only the first N JSON files")
    parser.add_argument("--file", action="append", help="process only this input filename")
    parser.add_argument(
        "--retry-status",
        action="append",
        choices=("failed", "timeout"),
        default=[],
        help="when resuming, rerun prior results with this status",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.jobs <= 0 or args.timeout <= 0 or args.progress_every <= 0:
        raise SystemExit("--jobs, --timeout, and --progress-every must be positive")
    if not args.input_dir.is_dir():
        raise SystemExit(f"input directory does not exist: {args.input_dir}")

    input_paths = sorted(args.input_dir.glob("*.json"))
    if args.file:
        wanted = set(args.file)
        input_paths = [path for path in input_paths if path.name in wanted]
        missing = wanted - {path.name for path in input_paths}
        if missing:
            raise SystemExit(f"input files not found: {', '.join(sorted(missing))}")
    if args.max_files is not None:
        input_paths = input_paths[: args.max_files]
    if not input_paths:
        raise SystemExit("no input JSON files selected")

    started = time.monotonic()
    summaries = []
    for input_path in input_paths:
        summaries.append(
            process_file(
                input_path,
                args.output_dir,
                args.jobs,
                args.timeout,
                args.resume,
                args.progress_every,
                args.limit,
                set(args.retry_status),
            )
        )

    overall_counts: Dict[str, int] = {}
    for summary in summaries:
        for status, count in summary["counts"].items():
            overall_counts[status] = overall_counts.get(status, 0) + count
    overall = {
        "input_dir": str(args.input_dir),
        "output_dir": str(args.output_dir),
        "files": len(summaries),
        "total": sum(summary["total"] for summary in summaries),
        "counts": overall_counts,
        "elapsed_s": round(time.monotonic() - started, 3),
        "jobs": args.jobs,
        "timeout_s": args.timeout,
        "files_summary": summaries,
    }
    write_json_atomic(args.output_dir / "_summary.json", overall)
    print(json.dumps(overall, ensure_ascii=False, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
