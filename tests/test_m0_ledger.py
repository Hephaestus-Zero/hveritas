"""M0 acceptance tests: Project skeleton, OTel GenAI SemConv spans, SQLite+Parquet append-only ledger."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from hveritas.cli import run_synthetic_10_step_demo
from hveritas.ledger import (
    OP_EXECUTE_TOOL,
    OP_INVOKE_AGENT,
    OP_PLAN,
    AppendOnlyLedger,
    AppendOnlyViolationError,
    RunRecord,
    export_opik_trace_bundle,
    validate_semconv_span,
)


def test_m0_10_step_synthetic_run_roundtrip_and_semconv(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "ledger"
    summary = run_synthetic_10_step_demo(ledger_dir, run_id="m0-run-001")

    assert summary["steps_sqlite"] == 10
    assert summary["steps_parquet"] == 10
    assert summary["sqlite_equals_parquet_steps"] is True
    assert summary["spans_sqlite"] == 12  # 1 invoke_agent + 1 plan + 10 execute_tool
    assert summary["spans_parquet"] == 12
    assert summary["sqlite_equals_parquet_spans"] is True
    assert summary["operations_seen"] == ["execute_tool", "invoke_agent", "plan"]
    assert summary["semconv_violation_count"] == 0
    assert summary["chain_verified"] is True

    ledger = AppendOnlyLedger(ledger_dir)
    steps_sql = ledger.get_steps("m0-run-001", source="sqlite")
    steps_pq = ledger.get_steps("m0-run-001", source="parquet")
    spans_sql = ledger.get_spans("m0-run-001", source="sqlite")
    spans_pq = ledger.get_spans("m0-run-001", source="parquet")

    assert len(steps_sql) == 10
    assert steps_sql == steps_pq
    assert spans_sql == spans_pq

    # Verify step ordering, state chain, and claim vs measured separation
    for idx, step in enumerate(steps_sql):
        assert step.envelope.step_index == idx
        assert step.receipt.step_index == idx
        assert step.receipt.claim.summary == f"Agent claims step {idx} succeeded"
        assert step.receipt.measured.exit_code == 0
        assert step.receipt.measured.fs_diff == {"modified": [f"src/mod_{idx}.py"]}

    # Verify exact OTel GenAI SemConv span naming and hierarchy
    by_op = {
        op: [s for s in spans_sql if s.operation_name == op]
        for op in (OP_INVOKE_AGENT, OP_PLAN, OP_EXECUTE_TOOL)
    }
    assert len(by_op[OP_INVOKE_AGENT]) == 1
    assert len(by_op[OP_PLAN]) == 1
    assert len(by_op[OP_EXECUTE_TOOL]) == 10

    root_agent = by_op[OP_INVOKE_AGENT][0]
    assert root_agent.name == "invoke_agent worker"
    assert root_agent.parent_span_id is None

    plan_span = by_op[OP_PLAN][0]
    assert plan_span.name == "plan 10-step-sequence"
    assert plan_span.parent_span_id == root_agent.span_id

    for idx, tool_span in enumerate(by_op[OP_EXECUTE_TOOL]):
        expected_tool = "write_file" if idx % 2 == 0 else "run_check"
        assert tool_span.name == f"execute_tool {expected_tool}"
        assert tool_span.parent_span_id == root_agent.span_id
        assert validate_semconv_span(tool_span) == []

    opik_bundle = export_opik_trace_bundle(spans_sql)
    assert len(opik_bundle) == 12
    assert {item["type"] for item in opik_bundle} == {"general", "tool"}
    ledger.close()


def test_m0_strict_append_only_triggers_forbid_mutation_and_deletion(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "ledger_immut"
    run_synthetic_10_step_demo(ledger_dir, run_id="m0-immut")
    ledger = AppendOnlyLedger(ledger_dir)

    # Duplicate run_id insertion rejected
    with pytest.raises(AppendOnlyViolationError):
        ledger.append_run(
            RunRecord(
                run_id="m0-immut",
                goal="overwrite attempt",
                container_digest="sha256:" + ("b" * 64),
                seed=1,
                started_at_ns=1,
            )
        )

    # Direct SQLite UPDATE / DELETE blocked by BEFORE triggers on all tables
    raw_conn = sqlite3.connect(str(ledger.sqlite_path))
    with pytest.raises(sqlite3.IntegrityError, match="APPEND_ONLY_VIOLATION"):
        raw_conn.execute("UPDATE steps SET tool_name = 'tampered' WHERE step_index = 0")

    with pytest.raises(sqlite3.IntegrityError, match="APPEND_ONLY_VIOLATION"):
        raw_conn.execute("DELETE FROM steps WHERE step_index = 0")

    with pytest.raises(sqlite3.IntegrityError, match="APPEND_ONLY_VIOLATION"):
        raw_conn.execute("UPDATE spans SET name = 'tampered' WHERE seq_no = 0")

    with pytest.raises(sqlite3.IntegrityError, match="APPEND_ONLY_VIOLATION"):
        raw_conn.execute("DELETE FROM runs WHERE run_id = 'm0-immut'")

    raw_conn.close()
    assert ledger.verify_chain("m0-immut") is True
    ledger.close()
