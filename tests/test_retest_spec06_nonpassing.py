import json

import pytest

from retest_spec06_nonpassing import (
    classify_failure,
    load_partial,
    result_state,
    summarize,
    validate_source_block,
)


def test_result_state_requires_linked_result_fields():
    assert result_state(
        {"init_binary": None, "block_binary": None, "qemu_result": None},
        "case.json",
        0,
    ) == "nonpassing"
    assert result_state(
        {"init_binary": "", "block_binary": "addi x1,x1,1", "qemu_result": "cycles: 1"},
        "case.json",
        1,
    ) == "passed"

    with pytest.raises(ValueError, match="inconsistent result fields"):
        result_state(
            {"init_binary": None, "block_binary": "code", "qemu_result": None},
            "case.json",
            2,
        )


def test_validate_source_block_ignores_only_result_fields():
    source = {"id": "400.perlbench_1", "asm": "addi a0,a0,1", "binary": "00150513"}
    baseline = {
        **source,
        "init_binary": "init",
        "block_binary": "block",
        "qemu_result": "cycles: 1",
    }
    validate_source_block(source, baseline, "case.json", 0)

    baseline["asm"] = "addi a0,a0,2"
    with pytest.raises(ValueError, match="changed source fields"):
        validate_source_block(source, baseline, "case.json", 0)


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"status": "passed"}, None),
        ({"status": "skipped"}, "skipped"),
        ({"status": "timeout"}, "timeout"),
        (
            {"status": "failed", "failure_stage": "init:concrete_replay"},
            "replay_failed",
        ),
        (
            {"status": "failed", "failure_stage": "qemu"},
            "qemu_failed",
        ),
        (
            {"status": "failed", "error": "solver returned UNSAT"},
            "constraint_unsat",
        ),
        ({"status": "failed", "error": "unexpected exception"}, "other_failed"),
    ],
)
def test_classify_failure(result, expected):
    assert classify_failure(result) == expected


def test_load_partial_uses_latest_record(tmp_path):
    partial = tmp_path / "status.partial.jsonl"
    partial.write_text(
        "\n".join(
            [
                json.dumps({"key": "case.json:1", "status": "timeout"}),
                "not json",
                json.dumps({"key": "case.json:1", "status": "passed"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert load_partial(partial) == {
        "case.json:1": {"key": "case.json:1", "status": "passed"}
    }


def test_summarize_reports_status_failure_stage_and_benchmark():
    summary = summarize(
        [
            {
                "source_file": "400.perlbench_int.json",
                "status": "failed",
                "failure_kind": "replay_failed",
                "failure_stage": "init:concrete_replay",
            },
            {
                "source_file": "400.perlbench_int.json",
                "status": "timeout",
                "failure_kind": "timeout",
                "failure_stage": "init:materialize",
            },
            {
                "source_file": "401.bzip2_int.json",
                "status": "skipped",
                "failure_kind": "skipped",
            },
        ]
    )

    assert summary["total"] == 3
    assert summary["counts"] == {"failed": 1, "skipped": 1, "timeout": 1}
    assert summary["failure_kinds"] == {"replay_failed": 1}
    assert summary["failure_stages"] == {
        "init:concrete_replay": 1,
        "init:materialize": 1,
    }
    assert summary["per_benchmark"]["400.perlbench_int.json"] == {
        "failed": 1,
        "timeout": 1,
        "total": 2,
    }
