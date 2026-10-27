"""Profile JSON basic blocks; persist results in JSON, not the output directory."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def atomic_json(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=".pp-", suffix=".json", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def worker(directory, verbose=False):
    # Each worker is isolated: module-level paths cannot affect other blocks.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import rvmca.config as config
    from rvmca.trans import block, prof

    directory = Path(directory)
    config.OUTPUT_PATH = block.OUTPUT_PATH = prof.OUTPUT_PATH = directory
    assembly = (directory / "input.json").read_text(encoding="utf-8")
    assembly = json.loads(assembly).replace("\\n", "\n")
    source = directory / "block.S"
    source.write_text(assembly + "\n", encoding="utf-8")
    original_run = prof.run_cmd
    measurement = {}

    def run_command(command, timeout=60):
        if command.startswith("qemu-riscv64 "):
            completed = subprocess.run(
                ["qemu-riscv64", str(config.TOOLS_PATH / "pp" / "pp"),
                 str(directory / "block.init"), str(directory / "block.code")],
                capture_output=True, text=True, timeout=timeout,
            )
            measurement.update(returncode=completed.returncode,
                               stdout=completed.stdout, stderr=completed.stderr)
            matches = re.findall(r"(?m)^\s*cycles:\s*([+-]?\d+)\s*$", completed.stdout)
            measurement["cycles"] = int(matches[-1]) if matches else None
            return completed.stdout if completed.returncode == 0 else None
        return original_run(command, timeout=timeout)

    prof.run_cmd = run_command
    outcome = {"pp_init": None, "pp_code": None}
    error = None
    try:
        message = prof.transform_for_profiling(source, verbose=verbose)
        if message:
            error = str(message)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    stage_path = directory / "block.stage.json"
    stage = json.loads(stage_path.read_text()).get("stage") if stage_path.exists() else None
    for field, suffix in (("pp_init", "init"), ("pp_code", "code")):
        path = directory / f"block.{suffix}"
        outcome[field] = path.read_text() if path.exists() else None
    passed = (stage == "transform:done" and measurement.get("returncode") == 0
              and measurement.get("cycles") is not None)
    outcome["pp_result"] = {
        "status": "ok" if passed else "unsupported" if error and error.startswith("SKIP:") else "failed",
        "cycles": measurement.get("cycles"),
        "stdout": measurement.get("stdout", ""),
    }
    if verbose and error:
        print(error, file=sys.stderr)
    atomic_json(directory / "result.json", outcome)


def profile_record(assembly, timeout, verbose=False):
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="rvmca-pp-") as temporary:
        directory = Path(temporary)
        atomic_json(directory / "input.json", assembly)
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", temporary]
        if verbose:
            command.append("--verbose")
        # Files avoid unbounded PIPE buffers from verbose symbolic execution.
        with (directory / "stdout.log").open("w+") as stdout, (directory / "stderr.log").open("w+") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            timed_out = False
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            except BaseException:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise
            result_path = directory / "result.json"
            if result_path.exists() and not timed_out:
                result = json.loads(result_path.read_text())
            else:
                result = {"pp_init": None, "pp_code": None,
                          "pp_result": {"status": "timeout" if timed_out else "failed",
                                        "cycles": None, "stdout": ""}}
            if verbose:
                stdout.seek(0)
                print(stdout.read(), end="")
                stderr.seek(0)
                print(stderr.read()[-16000:], end="", file=sys.stderr)
        result["pp_result"]["elapsed_s"] = round(time.monotonic() - start, 3)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, help="JSON array with an asm string per record")
    parser.add_argument("-o", "--output", type=Path,
                        help="Write augmented records to this JSON; default: update input in place")
    parser.add_argument("--timeout", type=float, default=300, help="Seconds per block (default: 300)")
    parser.add_argument("--limit", type=int, help="Process at most this many records")
    parser.add_argument("--resume", action="store_true", help="Skip records with pp_result.status == ok")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.verbose)
        return
    if args.input is None or args.timeout <= 0 or (args.limit is not None and args.limit <= 0):
        parser.error("Provide an input JSON and positive timeout/limit")
    path = args.input.resolve()
    destination = args.output.resolve() if args.output else path
    records = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
        parser.error("Input must be a JSON array of objects")
    if args.resume and destination != path and destination.exists():
        saved = json.loads(destination.read_text(encoding="utf-8"))
        result_keys = {"pp_init", "pp_code", "pp_init_asm", "pp_code_asm", "pp_result"}

        def original_fields(row):
            return {key: value for key, value in row.items() if key not in result_keys}

        if (not isinstance(saved, list) or len(saved) != len(records)
                or not all(isinstance(row, dict) for row in saved)
                or any(original_fields(old) != original_fields(new)
                       for old, new in zip(saved, records))):
            parser.error("Existing output does not match input records; cannot resume")
        records = saved
    for executable in ("qemu-riscv64", "riscv64-unknown-linux-gnu-gcc", "riscv64-unknown-linux-gnu-objdump"):
        if shutil.which(executable) is None:
            parser.error(f"Required executable not found: {executable}")
    harness = Path(__file__).resolve().parents[2] / "tools" / "pp" / "pp"
    if not os.access(harness, os.X_OK):
        parser.error(f"Profiling harness missing or not executable: {harness}")
    # Exclusive creation preserves the first backup on repeated invocations.
    destination.parent.mkdir(parents=True, exist_ok=True)
    backup = destination.with_name(destination.name + ".bak")
    if destination.exists() and not backup.exists():
        with backup.open("xb") as stream:
            stream.write(destination.read_bytes())
    # Also remove legacy fields from records skipped by --resume or --limit.
    for row in records:
        row.pop("pp_init_asm", None)
        row.pop("pp_code_asm", None)
        if isinstance(row.get("pp_result"), dict):
            for key in ("stage", "returncode", "stderr", "error", "worker_stderr"):
                row["pp_result"].pop(key, None)
    processed = 0
    for index, row in enumerate(records):
        previous = row.get("pp_result")
        if args.resume and isinstance(previous, dict) and previous.get("status") == "ok":
            continue
        if args.limit is not None and processed >= args.limit:
            break
        assembly = row.get("asm")
        if not isinstance(assembly, str) or not assembly.strip():
            result = {"pp_init": None, "pp_code": None,
                      "pp_result": {"status": "invalid", "cycles": None, "stdout": "", "elapsed_s": 0.0}}
        else:
            result = profile_record(assembly, args.timeout, args.verbose)
        row.update(result)
        atomic_json(destination, records)
        processed += 1
        print(f"[{index + 1}/{len(records)}] {row.get('id', index)}: {row['pp_result']['status']}", flush=True)
    if processed == 0:
        atomic_json(destination, records)
    print(f"Saved {processed} results to {destination}")
    if backup.exists():
        print(f"Backup: {backup}")


if __name__ == "__main__":
    main()
