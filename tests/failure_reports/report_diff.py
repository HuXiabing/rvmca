#!/usr/bin/env python3
"""Compare two rvmca failure reports by block outcome."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _load_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _outcome_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    outcomes: dict[str, dict[str, Any]] = {}

    for item in report.get("now_passing", []):
        outcomes[item["id"]] = {
            "status": "passed",
            "failure_kind": None,
            "error": None,
            "benchmark": item.get("benchmark"),
        }

    for item in report.get("still_failing", []):
        outcomes[item["id"]] = {
            "status": "failed",
            "failure_kind": item.get("failure_kind") or "other_failed",
            "error": item.get("error"),
            "benchmark": item.get("benchmark"),
        }

    for item in report.get("skipped", []):
        outcomes[item["id"]] = {
            "status": "skipped",
            "failure_kind": "skipped",
            "error": item.get("reason") or item.get("error"),
            "benchmark": item.get("benchmark"),
        }

    return outcomes


def compare_reports(old_path: Path, new_path: Path) -> dict[str, Any]:
    old_outcomes = _outcome_map(_load_report(old_path))
    new_outcomes = _outcome_map(_load_report(new_path))

    common_ids = sorted(set(old_outcomes) & set(new_outcomes))
    old_only = sorted(set(old_outcomes) - set(new_outcomes))
    new_only = sorted(set(new_outcomes) - set(old_outcomes))

    added_failed = []
    added_skipped = []
    fixed = []
    failure_kind_changes = []
    status_changes = []

    for block_id in common_ids:
        old = old_outcomes[block_id]
        new = new_outcomes[block_id]
        old_status = old["status"]
        new_status = new["status"]

        if old_status != new_status:
            status_changes.append(
                {
                    "id": block_id,
                    "old_status": old_status,
                    "new_status": new_status,
                    "old_failure_kind": old.get("failure_kind"),
                    "new_failure_kind": new.get("failure_kind"),
                    "new_error": new.get("error"),
                }
            )
        if old_status == "passed" and new_status == "failed":
            added_failed.append(block_id)
        if old_status == "passed" and new_status == "skipped":
            added_skipped.append(block_id)
        if old_status == "failed" and new_status == "passed":
            fixed.append(block_id)
        if (
            old_status == "failed"
            and new_status == "failed"
            and old.get("failure_kind") != new.get("failure_kind")
        ):
            failure_kind_changes.append(
                {
                    "id": block_id,
                    "old_failure_kind": old.get("failure_kind"),
                    "new_failure_kind": new.get("failure_kind"),
                    "old_error": old.get("error"),
                    "new_error": new.get("error"),
                }
            )

    new_status_counts = Counter(item["status"] for item in new_outcomes.values())
    new_failure_counts = Counter(
        item["failure_kind"] for item in new_outcomes.values() if item["status"] == "failed"
    )

    return {
        "old": str(old_path),
        "new": str(new_path),
        "common": len(common_ids),
        "old_only": old_only,
        "new_only": new_only,
        "new_status_counts": dict(sorted(new_status_counts.items())),
        "new_failure_counts": dict(sorted(new_failure_counts.items())),
        "added_failed": added_failed,
        "added_skipped": added_skipped,
        "fixed": fixed,
        "failure_kind_changes": failure_kind_changes,
        "status_changes": status_changes,
    }


def _print_text(diff: dict[str, Any]) -> None:
    print(f"old: {diff['old']}")
    print(f"new: {diff['new']}")
    print(f"common ids: {diff['common']}")
    print(f"new status counts: {diff['new_status_counts']}")
    print(f"new failure counts: {diff['new_failure_counts']}")
    print(f"fixed: {len(diff['fixed'])}")
    print(f"added_failed: {len(diff['added_failed'])}")
    print(f"added_skipped: {len(diff['added_skipped'])}")
    print(f"failure_kind_changes: {len(diff['failure_kind_changes'])}")
    if diff["added_failed"]:
        print("added_failed ids:")
        for block_id in diff["added_failed"]:
            print(f"  {block_id}")
    if diff["added_skipped"]:
        print("added_skipped ids:")
        for block_id in diff["added_skipped"]:
            print(f"  {block_id}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old_report", type=Path)
    parser.add_argument("new_report", type=Path)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument("--out", type=Path, help="Optional path for JSON diff output")
    args = parser.parse_args()

    diff = compare_reports(args.old_report, args.new_report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(diff, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(diff, ensure_ascii=False, indent=2))
    else:
        _print_text(diff)


if __name__ == "__main__":
    main()
