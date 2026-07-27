import json

import pytest

from failure_reports.report_diff import _outcome_map, compare_reports


def write_report(path, records):
    path.write_text(json.dumps({"records": records}), encoding="utf-8")


def test_spec06_sidecars_keep_failed_skip_and_timeout_separate(tmp_path):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    write_report(
        old_path,
        [
            {"id": "fixed", "status": "failed", "failure_kind": "replay_failed"},
            {"id": "not_fixed", "status": "failed"},
            {"id": "became_slow", "status": "failed"},
            {"id": "skipped", "status": "failed"},
            {"id": "timeout_fixed", "status": "timeout"},
        ],
    )
    write_report(
        new_path,
        [
            {"id": "fixed", "status": "passed"},
            {"id": "not_fixed", "status": "failed"},
            {"id": "became_slow", "status": "timeout"},
            {"id": "skipped", "status": "skipped"},
            {"id": "timeout_fixed", "status": "passed"},
        ],
    )

    diff = compare_reports(old_path, new_path)

    assert diff["fixed"] == ["fixed"]
    assert diff["failed_to_skipped"] == ["skipped"]
    assert diff["failed_to_timeout"] == ["became_slow"]
    assert diff["remaining_failed"] == ["not_fixed"]
    assert diff["timeout_to_passed"] == ["timeout_fixed"]
    assert diff["transitions"]["failed->passed"]["count"] == 1


def test_old_status_filter_exposes_exact_original_failed_set(tmp_path):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    write_report(
        old_path,
        [
            {"id": "failed", "status": "failed"},
            {"id": "timeout", "status": "timeout"},
        ],
    )
    write_report(new_path, [{"id": "failed", "status": "passed"}])

    diff = compare_reports(old_path, new_path, old_statuses=["failed"])

    assert diff["common"] == 1
    assert diff["old_only"] == []
    assert diff["new_only"] == []
    assert diff["fixed"] == ["failed"]


def test_pass_regressions_are_listed(tmp_path):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    write_report(old_path, [{"id": "regressed", "status": "passed"}])
    write_report(new_path, [{"id": "regressed", "status": "skipped"}])

    diff = compare_reports(old_path, new_path)

    assert diff["pass_regressions"] == ["regressed"]


def test_legacy_timeout_is_not_counted_as_failed():
    outcomes = _outcome_map(
        {
            "still_failing": [
                {"id": "slow", "failure_kind": "timeout_failed"},
                {"id": "broken", "failure_kind": "replay_failed"},
            ]
        }
    )

    assert outcomes["slow"]["status"] == "timeout"
    assert outcomes["broken"]["status"] == "failed"


def test_duplicate_sidecar_ids_are_rejected():
    with pytest.raises(ValueError, match="duplicate report outcome"):
        _outcome_map(
            {
                "records": [
                    {"id": "duplicate", "status": "failed"},
                    {"id": "duplicate", "status": "passed"},
                ]
            }
        )
