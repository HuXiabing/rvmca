#!/usr/bin/env python3
"""Enforce locked pass and non-failing ID sets on a retest report."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


def load_ids(path: Path) -> list[str]:
    block_ids = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    duplicates = sorted(
        block_id for block_id, count in Counter(block_ids).items() if count > 1
    )
    if duplicates:
        raise ValueError(f"duplicate IDs in {path}: {duplicates[:10]}")
    return block_ids


def report_outcomes(report: dict[str, Any]) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    groups = (
        ("now_passing", "passed"),
        ("still_failing", "failed"),
        ("skipped", "skipped"),
    )
    for group, status in groups:
        for item in report.get(group, []):
            block_id = item["id"]
            if block_id in outcomes:
                raise ValueError(f"duplicate report outcome for {block_id}")
            outcomes[block_id] = status
    return outcomes


def check_locked_status(
    report: dict[str, Any],
    required_pass: Iterable[str],
    allowed_pass_or_skip: Iterable[str] = (),
    require_exact: bool = False,
    supplemental_reports: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    primary_outcomes = report_outcomes(report)
    supplemental_outcomes = [
        report_outcomes(supplemental_report)
        for supplemental_report in supplemental_reports
    ]
    supplemental_passes = {
        block_id
        for outcomes in supplemental_outcomes
        for block_id, status in outcomes.items()
        if status == "passed"
    }
    outcomes = dict(primary_outcomes)
    supplemented = sorted(
        block_id
        for block_id in supplemental_passes
        if primary_outcomes.get(block_id) != "passed"
    )
    for block_id in supplemented:
        outcomes[block_id] = "passed"
    required_pass = set(required_pass)
    allowed_pass_or_skip = set(allowed_pass_or_skip)
    overlap = sorted(required_pass & allowed_pass_or_skip)
    if overlap:
        raise ValueError(f"locked ID sets overlap: {overlap[:10]}")

    missing_required = sorted(required_pass - outcomes.keys())
    regressed_pass = sorted(
        block_id
        for block_id in required_pass
        if outcomes.get(block_id) not in {None, "passed"}
    )
    missing_allowed = sorted(allowed_pass_or_skip - outcomes.keys())
    failed_allowed = sorted(
        block_id
        for block_id in allowed_pass_or_skip
        if outcomes.get(block_id) == "failed"
    )
    expected = required_pass | allowed_pass_or_skip
    observed = set(primary_outcomes)
    for supplemental in supplemental_outcomes:
        observed.update(supplemental)
    unexpected = sorted(observed - expected) if require_exact else []

    passed = not any(
        (missing_required, regressed_pass, missing_allowed, failed_allowed, unexpected)
    )
    return {
        "passed": passed,
        "report_outcomes": len(outcomes),
        "primary_report_outcomes": len(primary_outcomes),
        "supplemental_report_count": len(supplemental_outcomes),
        "required_pass": len(required_pass),
        "allowed_pass_or_skip": len(allowed_pass_or_skip),
        "supplemented_pass": sorted(required_pass & set(supplemented)),
        "supplemented_allowed": sorted(allowed_pass_or_skip & set(supplemented)),
        "missing_required": missing_required,
        "regressed_pass": regressed_pass,
        "missing_allowed": missing_allowed,
        "failed_allowed": failed_allowed,
        "unexpected": unexpected,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--required-pass", type=Path, required=True)
    parser.add_argument("--allowed-pass-or-skip", type=Path)
    parser.add_argument(
        "--supplement",
        action="append",
        type=Path,
        default=[],
        help="higher-budget report whose explicit PASS outcomes supplement the main report",
    )
    parser.add_argument("--require-exact", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    required_pass = load_ids(args.required_pass)
    allowed = (
        load_ids(args.allowed_pass_or_skip)
        if args.allowed_pass_or_skip is not None
        else []
    )
    supplemental_reports = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in args.supplement
    ]
    result = check_locked_status(
        report,
        required_pass,
        allowed,
        require_exact=args.require_exact,
        supplemental_reports=supplemental_reports,
    )
    if args.json or not result["passed"]:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            f"locked status gate passed: outcomes={result['report_outcomes']} "
            f"required_pass={result['required_pass']} "
            f"allowed_pass_or_skip={result['allowed_pass_or_skip']}"
        )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
