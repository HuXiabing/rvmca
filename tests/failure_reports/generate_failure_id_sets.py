#!/usr/bin/env python3
"""Generate stable block-id sets from the reviewed init-feasibility report."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable


DEFAULT_REVIEWED = Path(__file__).with_name(
    "current_full_after_5922eb0_300s_init_feasibility_reviewed.json"
)
DEFAULT_OUT_DIR = Path(__file__).with_name("id_sets")


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_")


def _write_ids(path: Path, ids: Iterable[str]) -> None:
    values = sorted(set(ids))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{block_id}\n" for block_id in values), encoding="utf-8")


def generate_id_sets(reviewed_path: Path, out_dir: Path) -> dict[str, int]:
    data = json.loads(reviewed_path.read_text(encoding="utf-8"))
    rows = data.get("rows", [])
    if not rows:
        raise ValueError(f"{reviewed_path} does not contain reviewed rows")

    by_classification: dict[str, list[str]] = defaultdict(list)
    by_failure_kind: dict[str, list[str]] = defaultdict(list)
    by_pattern: dict[str, list[str]] = defaultdict(list)
    by_benchmark: dict[str, list[str]] = defaultdict(list)

    all_ids: list[str] = []
    for row in rows:
        block_id = row["id"]
        all_ids.append(block_id)
        classification = row.get("classification", "unknown")
        failure_kind = row.get("failure_kind", "unknown")
        pattern = row.get("pattern", "unknown")
        benchmark = row.get("benchmark", block_id.split("_", 1)[0])

        by_classification[classification].append(block_id)
        by_failure_kind[failure_kind].append(block_id)
        by_pattern[pattern].append(block_id)
        by_benchmark[benchmark].append(block_id)

    out_dir.mkdir(parents=True, exist_ok=True)
    _write_ids(out_dir / "failed_all_249.ids", all_ids)

    for classification, ids in by_classification.items():
        _write_ids(out_dir / f"{_safe_name(classification)}_{len(set(ids))}.ids", ids)

    for failure_kind, ids in by_failure_kind.items():
        _write_ids(out_dir / "by_failure_kind" / f"{_safe_name(failure_kind)}_{len(set(ids))}.ids", ids)

    for pattern, ids in by_pattern.items():
        _write_ids(out_dir / "by_pattern" / f"{_safe_name(pattern)}_{len(set(ids))}.ids", ids)

    for benchmark, ids in by_benchmark.items():
        _write_ids(out_dir / "by_benchmark" / f"{_safe_name(benchmark)}_{len(set(ids))}.ids", ids)

    return {
        "all": len(set(all_ids)),
        **{classification: len(set(ids)) for classification, ids in by_classification.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewed", type=Path, default=DEFAULT_REVIEWED)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()

    summary = generate_id_sets(args.reviewed, args.out_dir)
    print(f"Wrote id sets to {args.out_dir}")
    for key, count in sorted(summary.items()):
        print(f"{key}: {count}")


if __name__ == "__main__":
    main()
