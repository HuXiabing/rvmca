import json

import analyze_spec06_failures as analyzer


def record(status="failed", stage=None, error="", asm="ld a0,0(sp)"):
    return {
        "key": "400.perlbench_int.json:1",
        "source_file": "400.perlbench_int.json",
        "source_index": 1,
        "id": "400.perlbench_1",
        "function": "example",
        "asm": asm,
        "status": status,
        "failure_stage": stage,
        "error": error,
    }


def test_replay_exception_overrides_stale_assembly_stage():
    item = record(
        stage="assemble:code:write",
        error=(
            "rvmca.trans.prof.ConcreteReplayFailure: concrete replay fails "
            "detail={'protected_access_kind': 'range'}"
        ),
    )

    assert analyzer.normalized_stage(item) == "concrete_replay"
    assert analyzer.failure_pattern(item) == "replay_range_failure"


def test_failed_and_timeout_never_become_skip_without_proof():
    failed = analyzer.analyze_record(
        record(error="AssertionError: init memory constraints are unsatisfiable")
    )
    timeout = analyzer.analyze_record(
        record(status="timeout", stage="init:materialize_init:register")
    )

    assert failed["failure_pattern"] == "init_memory_constraints_unsat"
    assert failed["feasibility"] == "unknown"
    assert timeout["failure_pattern"] == "timeout_materialize_register"
    assert timeout["feasibility"] == "unknown"


def test_pass_is_a_valid_initial_witness_and_skip_needs_review():
    passed = analyzer.analyze_record(record(status="passed", stage="done"))
    skipped = analyzer.analyze_record(
        record(status="skipped", stage="skip", error="SKIP: zero-base memory access")
    )

    assert passed["feasibility"] == "pass_witness"
    assert skipped["feasibility"] == "skip_candidate"
    assert skipped["failure_pattern"] == "skip_zero_base_access"


def test_assembly_features_capture_scaled_fixed_pointer_chain():
    features = analyzer.assembly_features(
        "ld a5,48(sp)\\n"
        "lui a4,0x130\\n"
        "slli a3,a5,0x3\\n"
        "add a4,a4,a3\\n"
        "ld a0,0(a4)"
    )

    assert features["memory_width_sequence"] == [8, 8]
    assert features["has_sp_memory"]
    assert features["has_lui"]
    assert features["has_scaled_address_ops"]
    assert features["pointer_chain_depth"] == 1


def test_error_signature_removes_block_names_symbols_and_numbers():
    item = record(
        error=(
            "Traceback\nAssertionError: spec06pp_400.perlbench_int_2532 cannot choose "
            "<BV64 symbolic_read_static_4_91_64 + 0x10>"
        )
    )

    signature = analyzer.normalized_error_signature(item)
    assert "spec06pp_<block>" in signature
    assert "symbolic_read_static_<n>" in signature
    assert "0x10" not in signature


def test_summary_is_deterministic_and_counts_patterns():
    rows = [
        analyzer.analyze_record(record(status="passed", stage="done")),
        analyzer.analyze_record(
            record(error="AssertionError: cannot choose load slot address for <BV64 x>")
        ),
        analyzer.analyze_record(
            record(error="AssertionError: cannot choose load slot address for <BV64 y>")
        ),
    ]

    summary = analyzer.summarize(rows)

    assert summary["record_count"] == 3
    assert summary["status_counts"] == {"failed": 2, "passed": 1}
    assert summary["patterns"][0]["pattern"] == "load_slot_address_selection"
    assert summary["patterns"][0]["count"] == 2


def test_load_records_accepts_final_and_partial_formats(tmp_path):
    rows = [record(status="passed", stage="done")]
    final_path = tmp_path / "status.json"
    partial_path = tmp_path / "status.partial.jsonl"
    final_path.write_text(json.dumps({"records": rows}), encoding="utf-8")
    partial_path.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")

    assert analyzer.load_records(final_path) == rows
    assert analyzer.load_records(partial_path) == rows


def test_reviewed_witness_can_promote_failed_block_to_fixable(tmp_path):
    review_path = tmp_path / "reviews.json"
    review_path.write_text(
        json.dumps(
            {
                "reviews": [
                    {
                        "id": "400.perlbench_1",
                        "classification": "fixable",
                        "pattern": "scaled_loaded_value_fixed_residual",
                        "evidence_kind": "qemu_witness",
                        "evidence": "manual runtime-SP initial completed QEMU",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    reviews = analyzer.load_reviews(review_path)

    analyzed = analyzer.analyze_record(
        record(error="concrete replay fails"),
        reviews=reviews,
    )

    assert analyzed["feasibility"] == "fixable"
    assert analyzed["reviewed"] is True
    assert analyzed["reviewed_pattern"] == "scaled_loaded_value_fixed_residual"


def test_reviews_reject_duplicate_ids(tmp_path):
    review_path = tmp_path / "reviews.json"
    row = {
        "id": "400.perlbench_1",
        "classification": "fixable",
        "evidence": "witness",
    }
    review_path.write_text(json.dumps({"reviews": [row, row]}), encoding="utf-8")

    try:
        analyzer.load_reviews(review_path)
    except ValueError as exc:
        assert "duplicate review" in str(exc)
    else:
        raise AssertionError("duplicate feasibility reviews must be rejected")
