#!/usr/bin/env python3
"""Build deterministic failure-pattern reports from SPEC06 status sidecars."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


TESTS_DIR = Path(__file__).resolve().parent
DEFAULT_REPORT_DIR = TESTS_DIR / "failure_reports" / "spec06_aaabdf6_baseline"
DEFAULT_OUTPUT_JSON = TESTS_DIR / "failure_reports" / "spec06_patterns.json"
DEFAULT_OUTPUT_CSV = TESTS_DIR / "failure_reports" / "spec06_patterns.csv"
DEFAULT_OUTPUT_MD = TESTS_DIR.parent / "docs" / "spec06_failed_timeout_patterns.md"
DEFAULT_IDS_DIR = TESTS_DIR / "failure_reports" / "spec06_pattern_ids"
DEFAULT_REVIEWS = TESTS_DIR / "failure_reports" / "spec06_feasibility_reviews.json"
FEASIBILITY_CLASSES = {"pass_witness", "fixable", "skip_proven", "unknown"}

LOAD_WIDTHS = {
    "lb": 1,
    "lbu": 1,
    "lh": 2,
    "lhu": 2,
    "lw": 4,
    "lwu": 4,
    "ld": 8,
    "flw": 4,
    "fld": 8,
}
STORE_WIDTHS = {
    "sb": 1,
    "sh": 2,
    "sw": 4,
    "sd": 8,
    "fsw": 4,
    "fsd": 8,
}
NO_DEST_OPS = {
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "j",
    "jr",
    "ret",
    "ecall",
    "ebreak",
    "fence",
    "fence.i",
}
MEMORY_OPERAND_RE = re.compile(r"[^,()\s]*\(([^()\s]+)\)")
NUMBER_RE = re.compile(r"(?<![A-Za-z_])(?:-?0x[0-9a-fA-F]+|-?\d+)(?![A-Za-z_])")
SYMBOL_SUFFIX_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*?)_\d+(?:_\d+)*\b")
BLOCK_NAME_RE = re.compile(r"spec06pp_[A-Za-z0-9_.-]+_\d+")


def load_records(path: Path) -> List[Dict[str, Any]]:
    if path.suffix == ".jsonl":
        records = []
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
                if not isinstance(item, dict):
                    raise ValueError(f"record at {path}:{line_number} is not an object")
                records.append(item)
        return records

    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict) and isinstance(data.get("records"), list):
        records = data["records"]
    else:
        raise ValueError(f"{path} does not contain a record list")
    if not all(isinstance(item, dict) for item in records):
        raise ValueError(f"{path} contains a non-object record")
    return records


def load_reviews(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("reviews") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError(f"{path} does not contain a reviews list")

    reviews = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"review {index} in {path} is not an object")
        block_id = row.get("id")
        classification = row.get("classification")
        evidence = row.get("evidence")
        if not isinstance(block_id, str) or not block_id:
            raise ValueError(f"review {index} in {path} has no block id")
        if block_id in reviews:
            raise ValueError(f"duplicate review for {block_id} in {path}")
        if classification not in FEASIBILITY_CLASSES:
            raise ValueError(
                f"invalid feasibility classification {classification!r} for {block_id}"
            )
        if not isinstance(evidence, str) or not evidence:
            raise ValueError(f"review for {block_id} has no evidence")
        reviews[block_id] = row
    return reviews


def normalized_stage(record: Dict[str, Any]) -> str:
    status = str(record.get("status") or "failed")
    stage = str(record.get("failure_stage") or record.get("timeout_stage") or "unknown").lower()
    error = str(record.get("error") or "").lower()

    # A stage file can advance into assembly before the final replay exception
    # is raised. The exception is authoritative for this classification.
    if "concretereplayfailure" in error or "concrete replay fails" in error:
        return "concrete_replay"
    if status == "timeout":
        prefix = "timeout_"
    else:
        prefix = ""
    if "load_symbolic_project" in stage:
        family = "symbolic_project"
    elif "symbolic" in stage or "collect" in stage:
        family = "symbolic_collect"
    elif "global_constraints" in stage or "constraint" in stage:
        family = "constraint_build"
    elif "materialize_init:register" in stage:
        family = "materialize_register"
    elif "materialize_init:load_slots" in stage:
        family = "materialize_load_slots"
    elif "materialize_init:memory_values" in stage:
        family = "materialize_memory_values"
    elif "materialize" in stage:
        family = "materialize"
    elif "concrete_replay" in stage or "replay" in stage:
        family = "concrete_replay"
    elif "assemble" in stage:
        family = "assembly"
    elif stage == "qemu" or "qemu" in stage:
        family = "qemu"
    elif stage == "skip":
        family = "skip"
    elif stage == "done":
        family = "done"
    else:
        family = "unknown"
    return prefix + family


def failure_pattern(record: Dict[str, Any]) -> str:
    status = str(record.get("status") or "failed")
    error = str(record.get("error") or "").lower()
    stage = normalized_stage(record)

    if status == "passed":
        return "pass_witness"
    if status == "skipped":
        if "zero-base memory access" in error:
            return "skip_zero_base_access"
        if "unmappable fixed address" in error:
            return "skip_unmappable_fixed_address"
        if "fixed replay sp is unsatisfiable" in error:
            return "skip_fixed_replay_sp_unsat"
        return "skip_other_unproven"
    if status == "timeout":
        return stage

    if "concretereplayfailure" in error or "concrete replay fails" in error:
        if "'protected_access_kind': 'align'" in error:
            return "replay_alignment_failure"
        if "'protected_access_kind': 'range'" in error:
            return "replay_range_failure"
        return "replay_failure"
    if "cannot choose non-overlapping concrete value" in error:
        return "nonoverlap_value_selection"
    if "cannot choose load slot address" in error:
        return "load_slot_address_selection"
    if "cannot choose stack pointer value" in error:
        return "stack_pointer_value_selection"
    if "cannot choose concrete value" in error:
        return "concrete_value_selection"
    if "init memory constraints are unsatisfiable" in error:
        return "init_memory_constraints_unsat"
    if "constraints are not satisfiable" in error or " unsat" in error:
        return "constraint_unsat"
    if stage == "qemu" or "qemu returned" in error:
        return "qemu_failure"
    if stage == "assembly" or "assembler" in error or "assembly" in error:
        return "assembly_failure"
    if "unsupported" in error:
        return "unsupported_operation"
    return "other_failure"


def feasibility(record: Dict[str, Any]) -> Dict[str, str]:
    status = str(record.get("status") or "failed")
    if status == "passed":
        return {
            "classification": "pass_witness",
            "evidence": "init, concrete replay, assembly, and QEMU all succeeded",
        }
    if status == "skipped":
        return {
            "classification": "skip_candidate",
            "evidence": "existing SKIP result is not an UNSAT proof and requires review",
        }
    return {
        "classification": "unknown",
        "evidence": "failure or timeout alone does not prove that no legal initial state exists",
    }


def asm_lines(asm: str) -> List[str]:
    return [
        line.strip()
        for line in str(asm or "").replace("\\n", "\n").splitlines()
        if line.strip()
    ]


def split_instruction(line: str) -> tuple[str, List[str]]:
    parts = line.split(None, 1)
    opcode = parts[0].lower() if parts else ""
    operands = []
    if len(parts) > 1:
        operands = [item.strip() for item in parts[1].split(",")]
    return opcode, operands


def destination_register(opcode: str, operands: List[str]) -> Optional[str]:
    if not operands or opcode in STORE_WIDTHS or opcode in NO_DEST_OPS or opcode.startswith("b"):
        return None
    candidate = operands[0]
    if "(" in candidate or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", candidate):
        return None
    return candidate


def operand_registers(operands: Iterable[str]) -> List[str]:
    values = []
    for operand in operands:
        values.extend(re.findall(r"\b(?:x\d+|[ast]\d+|s1[01]|t[0-6]|sp|gp|tp|ra|zero)\b", operand))
    return values


def assembly_features(asm: str) -> Dict[str, Any]:
    instructions = [split_instruction(line) for line in asm_lines(asm)]
    opcodes = [opcode for opcode, _ in instructions]
    memory_widths = []
    memory_kinds = []
    memory_bases = []
    load_depth_by_reg: Dict[str, int] = {}
    pointer_chain_depth = 0
    stored_locations = set()
    store_forward = False

    for opcode, operands in instructions:
        width = LOAD_WIDTHS.get(opcode) or STORE_WIDTHS.get(opcode)
        bases = []
        for operand in operands:
            bases.extend(MEMORY_OPERAND_RE.findall(operand))
        if width is not None:
            memory_widths.append(width)
            memory_kinds.append("load" if opcode in LOAD_WIDTHS else "store")
            memory_bases.extend(bases)
            base_depth = max((load_depth_by_reg.get(base, 0) for base in bases), default=0)
            pointer_chain_depth = max(pointer_chain_depth, base_depth)
            location = tuple(operands[-1:])
            if opcode in STORE_WIDTHS:
                stored_locations.add(location)
            elif opcode in LOAD_WIDTHS:
                if location in stored_locations:
                    store_forward = True
                destination = destination_register(opcode, operands)
                if destination:
                    load_depth_by_reg[destination] = base_depth + 1
            continue

        destination = destination_register(opcode, operands)
        if destination:
            sources = operand_registers(operands[1:])
            load_depth_by_reg[destination] = max(
                (load_depth_by_reg.get(source, 0) for source in sources),
                default=0,
            )

    return {
        "instruction_count": len(instructions),
        "opcode_sequence": opcodes,
        "memory_width_sequence": memory_widths,
        "memory_kind_sequence": memory_kinds,
        "load_count": sum(opcode in LOAD_WIDTHS for opcode in opcodes),
        "store_count": sum(opcode in STORE_WIDTHS for opcode in opcodes),
        "has_sp_memory": "sp" in memory_bases,
        "has_gp_memory": "gp" in memory_bases,
        "has_lui": "lui" in opcodes,
        "has_auipc": "auipc" in opcodes,
        "has_scaled_address_ops": any(opcode.startswith("sll") or opcode.startswith("mul") for opcode in opcodes),
        "has_mixed_width_memory": len(set(memory_widths)) > 1,
        "pointer_chain_depth": pointer_chain_depth,
        "has_store_forward_shape": store_forward,
    }


def normalized_error_signature(record: Dict[str, Any]) -> str:
    error = str(record.get("error") or "").strip()
    if not error:
        return ""
    lines = [line.strip() for line in error.splitlines() if line.strip()]
    final_line = lines[-1] if lines else error
    if " detail=" in final_line:
        final_line = final_line.split(" detail=", 1)[0]
    final_line = BLOCK_NAME_RE.sub("spec06pp_<block>", final_line)
    final_line = SYMBOL_SUFFIX_RE.sub(r"\1_<n>", final_line)
    final_line = NUMBER_RE.sub("<n>", final_line)
    return final_line[:1000]


def structural_signature(pattern: str, stage: str, features: Dict[str, Any]) -> str:
    flags = [
        name
        for name in (
            "has_sp_memory",
            "has_gp_memory",
            "has_lui",
            "has_auipc",
            "has_scaled_address_ops",
            "has_mixed_width_memory",
            "has_store_forward_shape",
        )
        if features[name]
    ]
    widths = ",".join(map(str, features["memory_width_sequence"])) or "none"
    kinds = ",".join(features["memory_kind_sequence"]) or "none"
    return "|".join(
        (
            pattern,
            stage,
            f"mem={kinds}",
            f"widths={widths}",
            f"depth={features['pointer_chain_depth']}",
            f"flags={','.join(flags) or 'none'}",
        )
    )


def analyze_record(
    record: Dict[str, Any],
    reviews: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    pattern = failure_pattern(record)
    stage = normalized_stage(record)
    features = assembly_features(str(record.get("asm") or ""))
    feasibility_result = feasibility(record)
    review = (reviews or {}).get(str(record.get("id") or ""))
    if review is not None:
        feasibility_result = {
            "classification": str(review["classification"]),
            "evidence": str(review["evidence"]),
        }
    return {
        "key": record.get("key"),
        "source_file": record.get("source_file"),
        "source_index": record.get("source_index"),
        "id": record.get("id"),
        "function": record.get("function"),
        "status": record.get("status"),
        "failure_pattern": pattern,
        "normalized_stage": stage,
        "feasibility": feasibility_result["classification"],
        "feasibility_evidence": feasibility_result["evidence"],
        "reviewed": review is not None,
        "reviewed_pattern": review.get("pattern") if review else None,
        "review_evidence_kind": review.get("evidence_kind") if review else None,
        "error_signature": normalized_error_signature(record),
        "structural_signature": structural_signature(pattern, stage, features),
        "features": features,
    }


def summarize(analyzed: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(analyzed)
    patterns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        patterns[str(row["failure_pattern"])].append(row)

    pattern_rows = []
    for pattern, members in sorted(patterns.items(), key=lambda item: (-len(item[1]), item[0])):
        benchmark_counts = Counter(str(row.get("id") or "").split("_", 1)[0] for row in members)
        stage_counts = Counter(str(row["normalized_stage"]) for row in members)
        feasibility_counts = Counter(str(row["feasibility"]) for row in members)
        signature_counts = Counter(str(row["structural_signature"]) for row in members)
        pattern_rows.append(
            {
                "pattern": pattern,
                "count": len(members),
                "statuses": dict(sorted(Counter(str(row.get("status")) for row in members).items())),
                "stages": dict(sorted(stage_counts.items())),
                "feasibility": dict(sorted(feasibility_counts.items())),
                "benchmarks": dict(sorted(benchmark_counts.items())),
                "representative_ids": [str(row.get("id")) for row in members[:10]],
                "top_structural_signatures": [
                    {"signature": signature, "count": count}
                    for signature, count in signature_counts.most_common(10)
                ],
            }
        )

    return {
        "record_count": len(rows),
        "status_counts": dict(sorted(Counter(str(row.get("status")) for row in rows).items())),
        "feasibility_counts": dict(sorted(Counter(str(row["feasibility"]) for row in rows).items())),
        "patterns": pattern_rows,
    }


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    temp_path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp_path.replace(path)


def write_outputs(
    analyzed: List[Dict[str, Any]],
    summary: Dict[str, Any],
    input_path: Path,
    output_json: Path,
    output_csv: Path,
    output_md: Path,
    ids_dir: Path,
) -> None:
    write_json_atomic(
        output_json,
        {"input": str(input_path.resolve()), "summary": summary, "records": analyzed},
    )

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=(
                "pattern",
                "count",
                "statuses",
                "feasibility",
                "stages",
                "benchmarks",
                "representative_ids",
            ),
        )
        writer.writeheader()
        for pattern in summary["patterns"]:
            writer.writerow(
                {
                    "pattern": pattern["pattern"],
                    "count": pattern["count"],
                    "statuses": json.dumps(pattern["statuses"], sort_keys=True),
                    "feasibility": json.dumps(pattern["feasibility"], sort_keys=True),
                    "stages": json.dumps(pattern["stages"], sort_keys=True),
                    "benchmarks": json.dumps(pattern["benchmarks"], sort_keys=True),
                    "representative_ids": " ".join(pattern["representative_ids"]),
                }
            )

    by_pattern: Dict[str, List[str]] = defaultdict(list)
    for row in analyzed:
        if row.get("id"):
            by_pattern[str(row["failure_pattern"])].append(str(row["id"]))
    for pattern, block_ids in by_pattern.items():
        ids_dir.mkdir(parents=True, exist_ok=True)
        (ids_dir / f"{pattern}.ids").write_text(
            "".join(f"{block_id}\n" for block_id in sorted(set(block_ids))),
            encoding="utf-8",
        )

    lines = [
        "# SPEC06 Failed/Timeout Patterns",
        "",
        f"Input: `{input_path}`",
        "",
        "> A failure or timeout is classified as `unknown` until a valid witness or a reproducible UNSAT/method-boundary proof exists.",
        "> Existing SKIP results are candidates for review, not proofs by themselves.",
        "",
        f"Records: {summary['record_count']}",
        "",
        "| Pattern | Count | Feasibility | Stages | Representatives |",
        "|---|---:|---|---|---|",
    ]
    for pattern in summary["patterns"]:
        representatives = ", ".join(f"`{value}`" for value in pattern["representative_ids"][:5])
        feasibility_text = ", ".join(
            f"{key}={value}" for key, value in pattern["feasibility"].items()
        )
        stage_text = ", ".join(f"{key}={value}" for key, value in pattern["stages"].items())
        lines.append(
            f"| `{pattern['pattern']}` | {pattern['count']} | {feasibility_text} | {stage_text} | {representatives} |"
        )
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def resolve_default_input(report_dir: Path) -> Path:
    final_path = report_dir / "status.json"
    if final_path.is_file():
        return final_path
    partial_path = report_dir / "status.partial.jsonl"
    if partial_path.is_file():
        return partial_path
    raise FileNotFoundError(f"no status report found in {report_dir}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output-json", type=Path, default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-csv", type=Path, default=DEFAULT_OUTPUT_CSV)
    parser.add_argument("--output-md", type=Path, default=DEFAULT_OUTPUT_MD)
    parser.add_argument("--ids-dir", type=Path, default=DEFAULT_IDS_DIR)
    parser.add_argument("--reviews", type=Path, default=DEFAULT_REVIEWS)
    parser.add_argument(
        "--status",
        action="append",
        choices=("passed", "skipped", "failed", "timeout"),
        help="limit analysis to one or more statuses",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = args.input or resolve_default_input(args.report_dir)
    records = load_records(input_path)
    reviews = load_reviews(args.reviews)
    if args.status:
        wanted = set(args.status)
        records = [record for record in records if record.get("status") in wanted]
    analyzed = [analyze_record(record, reviews=reviews) for record in records]
    summary = summarize(analyzed)
    write_outputs(
        analyzed,
        summary,
        input_path,
        args.output_json,
        args.output_csv,
        args.output_md,
        args.ids_dir,
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
