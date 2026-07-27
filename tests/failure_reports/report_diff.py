#!/usr/bin/env python3
"""Compare two rvmca failure reports by block outcome."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Optional


VALID_STATUSES = {"passed", "failed", "skipped", "timeout"}


def _load_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _outcome_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    outcomes: dict[str, dict[str, Any]] = {}

    def add(block_id: str, outcome: dict[str, Any]) -> None:
        if block_id in outcomes:
            raise ValueError(f"duplicate report outcome for {block_id}")
        status = outcome["status"]
        if status not in VALID_STATUSES:
            raise ValueError(f"unknown status {status!r} for {block_id}")
        outcomes[block_id] = outcome

    records = report.get("records")
    if isinstance(records, list):
        for item in records:
            status = str(item.get("status") or "failed")
            add(
                str(item["id"]),
                {
                    "status": status,
                    "failure_kind": item.get("failure_kind"),
                    "error": item.get("error"),
                    "benchmark": item.get("source_file") or item.get("benchmark"),
                },
            )
        return outcomes

    for item in report.get("now_passing", []):
        add(
            item["id"],
            {
                "status": "passed",
                "failure_kind": None,
                "error": None,
                "benchmark": item.get("benchmark"),
            },
        )

    for item in report.get("still_failing", []):
        failure_kind = item.get("failure_kind") or "other_failed"
        status = "timeout" if failure_kind == "timeout_failed" else "failed"
        add(
            item["id"],
            {
                "status": status,
                "failure_kind": failure_kind,
                "error": item.get("error"),
                "benchmark": item.get("benchmark"),
            },
        )

    for item in report.get("skipped", []):
        add(
            item["id"],
            {
                "status": "skipped",
                "failure_kind": "skipped",
                "error": item.get("reason") or item.get("error"),
                "benchmark": item.get("benchmark"),
            },
        )

    return outcomes


def compare_reports(
    old_path: Path,
    new_path: Path,
    old_statuses: Optional[Iterable[str]] = None,
) -> dict[str, Any]:
    old_outcomes = _outcome_map(_load_report(old_path))
    new_outcomes = _outcome_map(_load_report(new_path))
    selected_old_statuses = set(old_statuses or VALID_STATUSES)
    unknown_statuses = selected_old_statuses - VALID_STATUSES
    if unknown_statuses:
        raise ValueError(f"unknown old status filters: {sorted(unknown_statuses)}")
    old_outcomes = {
        block_id: outcome
        for block_id, outcome in old_outcomes.items()
        if outcome["status"] in selected_old_statuses
    }

    common_ids = sorted(set(old_outcomes) & set(new_outcomes))
    old_only = sorted(set(old_outcomes) - set(new_outcomes))
    new_only = sorted(set(new_outcomes) - set(old_outcomes))

    added_failed = []
    added_skipped = []
    fixed = []
    failure_kind_changes = []
    status_changes = []
    transitions: dict[str, list[str]] = {}

    for block_id in common_ids:
        old = old_outcomes[block_id]
        new = new_outcomes[block_id]
        old_status = old["status"]
        new_status = new["status"]
        transition = f"{old_status}->{new_status}"
        transitions.setdefault(transition, []).append(block_id)

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
    old_status_counts = Counter(item["status"] for item in old_outcomes.values())
    new_failure_counts = Counter(
        item["failure_kind"] for item in new_outcomes.values() if item["status"] == "failed"
    )

    return {
        "old": str(old_path),
        "new": str(new_path),
        "selected_old_statuses": sorted(selected_old_statuses),
        "common": len(common_ids),
        "old_only": old_only,
        "new_only": new_only,
        "old_status_counts": dict(sorted(old_status_counts.items())),
        "new_status_counts": dict(sorted(new_status_counts.items())),
        "new_failure_counts": dict(sorted(new_failure_counts.items())),
        "transitions": {
            transition: {"count": len(block_ids), "ids": block_ids}
            for transition, block_ids in sorted(transitions.items())
        },
        "added_failed": added_failed,
        "added_skipped": added_skipped,
        "fixed": fixed,
        "failed_to_skipped": transitions.get("failed->skipped", []),
        "failed_to_timeout": transitions.get("failed->timeout", []),
        "remaining_failed": transitions.get("failed->failed", []),
        "timeout_to_passed": transitions.get("timeout->passed", []),
        "remaining_timeout": transitions.get("timeout->timeout", []),
        "pass_regressions": sorted(
            block_id
            for transition, block_ids in transitions.items()
            if transition.startswith("passed->") and transition != "passed->passed"
            for block_id in block_ids
        ),
        "failure_kind_changes": failure_kind_changes,
        "status_changes": status_changes,
    }


def _print_text(diff: dict[str, Any]) -> None:
    print(f"old: {diff['old']}")
    print(f"new: {diff['new']}")
    print(f"common ids: {diff['common']}")
    print(f"old status counts: {diff['old_status_counts']}")
    print(f"new status counts: {diff['new_status_counts']}")
    print(f"new failure counts: {diff['new_failure_counts']}")
    print(f"failed -> passed: {len(diff['fixed'])}")
    print(f"failed -> skipped: {len(diff['failed_to_skipped'])}")
    print(f"failed -> timeout: {len(diff['failed_to_timeout'])}")
    print(f"failed -> failed: {len(diff['remaining_failed'])}")
    print(f"timeout -> passed: {len(diff['timeout_to_passed'])}")
    print(f"timeout -> timeout: {len(diff['remaining_timeout'])}")
    print(f"pass regressions: {len(diff['pass_regressions'])}")
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
    parser.add_argument(
        "--old-status",
        action="append",
        choices=sorted(VALID_STATUSES),
        help="Only compare IDs with this original status; may be repeated",
    )
    parser.add_argument(
        "--require-exact",
        action="store_true",
        help="Exit nonzero unless both reports contain the same selected IDs",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument("--out", type=Path, help="Optional path for JSON diff output")
    args = parser.parse_args()

    diff = compare_reports(args.old_report, args.new_report, args.old_status)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(diff, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(diff, ensure_ascii=False, indent=2))
    else:
        _print_text(diff)
    if args.require_exact and (diff["old_only"] or diff["new_only"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
