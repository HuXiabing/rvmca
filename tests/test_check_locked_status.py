import json

import pytest

from failure_reports.check_locked_status import (
    check_locked_status,
    load_ids,
    report_outcomes,
)


def make_report(passed=(), failed=(), skipped=()):
    return {
        "now_passing": [{"id": block_id} for block_id in passed],
        "still_failing": [{"id": block_id} for block_id in failed],
        "skipped": [{"id": block_id} for block_id in skipped],
    }


def test_locked_status_accepts_passes_and_preserved_skips():
    result = check_locked_status(
        make_report(passed=("p1", "p2", "s1"), skipped=("s2",)),
        required_pass=("p1", "p2"),
        allowed_pass_or_skip=("s1", "s2"),
        require_exact=True,
    )

    assert result["passed"] is True


def test_locked_status_rejects_pass_to_skip_and_allowed_to_fail():
    result = check_locked_status(
        make_report(passed=("p1",), failed=("s1",), skipped=("p2",)),
        required_pass=("p1", "p2"),
        allowed_pass_or_skip=("s1",),
        require_exact=True,
    )

    assert result["passed"] is False
    assert result["regressed_pass"] == ["p2"]
    assert result["failed_allowed"] == ["s1"]


def test_locked_status_rejects_missing_and_unexpected_ids():
    result = check_locked_status(
        make_report(passed=("p1", "extra")),
        required_pass=("p1", "p2"),
        require_exact=True,
    )

    assert result["passed"] is False
    assert result["missing_required"] == ["p2"]
    assert result["unexpected"] == ["extra"]


def test_locked_status_accepts_explicit_pass_supplement():
    result = check_locked_status(
        make_report(passed=("p1",), failed=("p2",)),
        required_pass=("p1", "p2"),
        require_exact=True,
        supplemental_reports=[make_report(passed=("p2",))],
    )

    assert result["passed"] is True
    assert result["supplemented_pass"] == ["p2"]
    assert result["regressed_pass"] == []


@pytest.mark.parametrize("supplement_status", ["failed", "skipped"])
def test_locked_status_rejects_nonpass_supplement(supplement_status):
    supplement = make_report(**{supplement_status: ("p2",)})
    result = check_locked_status(
        make_report(passed=("p1",), failed=("p2",)),
        required_pass=("p1", "p2"),
        require_exact=True,
        supplemental_reports=[supplement],
    )

    assert result["passed"] is False
    assert result["supplemented_pass"] == []
    assert result["regressed_pass"] == ["p2"]


def test_locked_status_rejects_unexpected_supplement_id():
    result = check_locked_status(
        make_report(passed=("p1",)),
        required_pass=("p1",),
        require_exact=True,
        supplemental_reports=[make_report(passed=("extra",))],
    )

    assert result["passed"] is False
    assert result["unexpected"] == ["extra"]


def test_report_outcomes_rejects_duplicate_statuses():
    with pytest.raises(ValueError, match="duplicate report outcome"):
        report_outcomes(make_report(passed=("p1",), failed=("p1",)))


def test_load_ids_rejects_duplicates(tmp_path):
    ids_path = tmp_path / "ids.txt"
    ids_path.write_text("p1\np1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate IDs"):
        load_ids(ids_path)


def test_gate_cli_exit_code(tmp_path):
    report_path = tmp_path / "report.json"
    required_path = tmp_path / "required.ids"
    report_path.write_text(json.dumps(make_report(failed=("p1",))), encoding="utf-8")
    required_path.write_text("p1\n", encoding="utf-8")

    result = check_locked_status(
        json.loads(report_path.read_text(encoding="utf-8")),
        load_ids(required_path),
    )
    assert result["passed"] is False
