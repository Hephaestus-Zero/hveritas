"""M1 acceptance tests: Independent Effect Receipts (I3), vcrpy + ToolTape Replay, Btrfs Snapshots, Byte-Identical Ledger (I8)."""

from __future__ import annotations

import ast
import http.server
import socketserver
import threading
import uuid
from pathlib import Path
from typing import Any

import pytest

import hveritas.effects as effects_pkg
from hveritas.effects import IndependentEffectMeasurer, RawProcessOutcome
from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST
from hveritas.ledger import AgentClaim, AppendOnlyLedger, CostRecord
from hveritas.tape import (
    FrozenEnvSnapshot,
    PlannedAction,
    SnapshotManager,
    TapeRunner,
)


class _DeterministicHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        resp = b'{"status":"accepted","bytes":' + str(len(body)).encode("ascii") + b"}"
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format: str, *args: Any) -> None:
        return


def _start_local_server() -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _DeterministicHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


def test_m1_replay_produces_byte_identical_sqlite_and_parquet_ledgers(tmp_path: Path) -> None:
    httpd, port, thread = _start_local_server()
    url = f"http://127.0.0.1:{port}/ingest"

    tape_dir = tmp_path / "tape"
    ws_record = tmp_path / "ws_record"
    ws_record.mkdir()
    (ws_record / "README.txt").write_text("seed-file\n", encoding="utf-8")

    actions = [
        PlannedAction(
            tool_name="write_file",
            tool_args={"path": "calc.py", "content": "def add(a, b):\n    return a + b\n"},
            claim=AgentClaim(summary="Created calc.py", reported_success=True),
            cost=CostRecord(input_tokens=50, output_tokens=20, usd=0.0002),
        ),
        PlannedAction(
            tool_name="sqlite_exec",
            tool_args={
                "db_path": "state.sqlite",
                "sql": "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);",
            },
            claim=AgentClaim(summary="Created items table", reported_success=True),
            cost=CostRecord(input_tokens=40, output_tokens=15, usd=0.0001),
        ),
        PlannedAction(
            tool_name="sqlite_exec",
            tool_args={
                "db_path": "state.sqlite",
                "sql": "INSERT INTO items (id, name) VALUES (1, 'alpha'), (2, 'beta');",
            },
            claim=AgentClaim(summary="Inserted 2 rows", reported_success=True),
        ),
        PlannedAction(
            tool_name="http_request",
            tool_args={"url": url, "method": "POST", "body": '{"hello":"tape"}'},
            claim=AgentClaim(summary="Posted payload", reported_success=True),
        ),
        PlannedAction(
            tool_name="run_cmd",
            tool_args={
                "argv": [
                    "/usr/bin/python3",
                    "-I",
                    "-c",
                    "import runpy; ns = runpy.run_path('calc.py'); assert ns['add'](2, 3) == 5; print('OK')",
                ]
            },
            claim=AgentClaim(summary="Ran unit check", reported_success=True),
        ),
    ]

    runner = TapeRunner(tape_dir)
    env = FrozenEnvSnapshot(
        run_id="m1-det-run",
        container_digest=DEFAULT_VERIFIER_IMAGE_DIGEST,
        seed=777,
    )

    ledger_rec_dir = tmp_path / "ledger_record"
    ledger_rec = AppendOnlyLedger(ledger_rec_dir)
    try:
        runner.record_run(
            run_id="m1-det-run",
            goal="Verify M1 deterministic record & replay",
            workspace=ws_record,
            actions=actions,
            ledger=ledger_rec,
            env=env,
        )
    finally:
        # Shut down HTTP server completely so replays MUST come 100% from vcrpy cassette!
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2.0)

    rec_digests = ledger_rec.digest_bundle()
    rec_steps = ledger_rec.get_steps("m1-det-run")
    ledger_rec.close()

    # Verify all 4 independent probes captured ground-truth effects
    assert rec_steps[0].receipt.measured.fs_diff["added"] == ["calc.py"]
    assert "state.sqlite" in rec_steps[2].receipt.measured.db_delta
    assert (
        rec_steps[2].receipt.measured.db_delta["state.sqlite"]["tables_changed"]["items"][
            "rows_after"
        ]
        == 2
    )
    assert len(rec_steps[3].receipt.measured.http_effects) == 1
    assert rec_steps[3].receipt.measured.http_effects[0]["status_code"] == 201
    assert rec_steps[4].receipt.measured.exit_code == 0

    # Replay #1 (server is DEAD — vcrpy offline mode="none")
    ledger_rep1_dir = tmp_path / "ledger_replay_1"
    ledger_rep1 = AppendOnlyLedger(ledger_rep1_dir)
    runner.replay_run(replay_workspace=tmp_path / "ws_rep1", ledger=ledger_rep1)
    rep1_digests = ledger_rep1.digest_bundle()
    ledger_rep1.close()

    # Replay #2 into another fresh directory
    ledger_rep2_dir = tmp_path / "ledger_replay_2"
    ledger_rep2 = AppendOnlyLedger(ledger_rep2_dir)
    runner.replay_run(replay_workspace=tmp_path / "ws_rep2", ledger=ledger_rep2)
    rep2_digests = ledger_rep2.digest_bundle()
    ledger_rep2.close()

    # Byte-for-byte comparison of SQLite and Parquet files across Replay 1, Replay 2, AND Record!
    assert (ledger_rep1_dir / "ledger.sqlite").read_bytes() == (
        ledger_rep2_dir / "ledger.sqlite"
    ).read_bytes()
    assert (ledger_rep1_dir / "steps.parquet").read_bytes() == (
        ledger_rep2_dir / "steps.parquet"
    ).read_bytes()
    assert (ledger_rep1_dir / "spans.parquet").read_bytes() == (
        ledger_rep2_dir / "spans.parquet"
    ).read_bytes()
    assert rep1_digests == rep2_digests == rec_digests


def test_m1_claim_is_strictly_segregated_from_measured_and_lying_agent_exposed(
    tmp_path: Path,
) -> None:
    ws = tmp_path / "ws_lie"
    ws.mkdir()
    runner = TapeRunner(tmp_path / "tape_lie")
    ledger = AppendOnlyLedger(tmp_path / "ledger_lie")

    lying_action = PlannedAction(
        tool_name="run_cmd",
        tool_args={"argv": ["/usr/bin/python3", "-I", "-c", "import sys; sys.exit(42)"]},
        claim=AgentClaim(
            summary="Wrote 5 files, inserted 10 DB rows, all tests passed with exit_code=0!",
            reported_success=True,
            structured_claim={"files_created": 5, "exit_code": 0},
        ),
    )
    runner.record_run(
        run_id="lying-run",
        goal="Expose lying agent report",
        workspace=ws,
        actions=[lying_action],
        ledger=ledger,
    )

    steps_sql = ledger.get_steps("lying-run", source="sqlite")
    steps_pq = ledger.get_steps("lying-run", source="parquet")
    assert steps_sql == steps_pq
    step = steps_sql[0]

    # Claim retains the agent's self-report in `claim`, completely separate from `measured`
    assert step.receipt.claim.reported_success is True
    assert step.receipt.claim.structured_claim == {"files_created": 5, "exit_code": 0}

    # Measured reflects ONLY probe ground truth
    assert step.receipt.measured.exit_code == 42
    assert step.receipt.measured.fs_diff == {
        "added": [],
        "modified": [],
        "deleted": [],
        "file_hashes": {},
    }
    assert step.receipt.measured.db_delta == {}
    ledger.close()


def test_m1_probes_never_import_or_read_agent_claim_static_and_canary(tmp_path: Path) -> None:
    effects_dir = Path(effects_pkg.__file__).resolve().parent
    py_files = sorted(effects_dir.glob("*.py"))
    assert len(py_files) >= 6

    forbidden_identifiers = {"AgentClaim", "agent_claim", "reported_success", "structured_claim"}
    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in forbidden_identifiers:
                pytest.fail(f"I3 violation: {py_file.name} references {node.id}")
            if isinstance(node, ast.Attribute) and node.attr in (forbidden_identifiers | {"claim"}):
                pytest.fail(f"I3 violation: {py_file.name} accesses .{node.attr}")
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name in forbidden_identifiers:
                        pytest.fail(f"I3 violation: {py_file.name} imports {alias.name}")

    # Dynamic canary object that explodes if anything inspects any attribute on it
    class PoisonClaim:
        def __getattribute__(self, name: str) -> Any:
            raise AssertionError(f"I3 VIOLATION: Probe attempted to read claim.{name}!")

    poison = PoisonClaim()
    ws = tmp_path / "ws_canary"
    ws.mkdir()
    measurer = IndependentEffectMeasurer()
    pre = measurer.observe_pre(ws)
    (ws / "hello.txt").write_text("world\n", encoding="utf-8")
    measured = measurer.measure_post(
        pre=pre,
        workspace=ws,
        process_outcome=RawProcessOutcome(exit_code=0, stdout=b"ok"),
    )
    assert measured.fs_diff["added"] == ["hello.txt"]
    assert poison is not None  # Canary remained completely untouched


def test_m1_native_btrfs_subvolume_snapshot_and_restore() -> None:
    base = Path.home() / ".local" / "share" / "hveritas" / f"btrfs_test_{uuid.uuid4().hex[:8]}"
    mgr = SnapshotManager(base / "snaps", prefer_btrfs=True)
    try:
        ws = mgr.init_workspace(base / "ws")
        (ws / "mod.py").write_text("VALUE = 10\n", encoding="utf-8")
        snap = mgr.create_snapshot(ws, "s0")
        assert snap.backend == "btrfs_subvolume"

        # Mutate original workspace
        (ws / "mod.py").write_text("VALUE = 999\n", encoding="utf-8")
        (ws / "extra.txt").write_text("dirty\n", encoding="utf-8")

        # Restore immutable Btrfs snapshot into a clean clone
        restored = mgr.restore_snapshot(snap, base / "ws_restored")
        assert (restored / "mod.py").read_text(encoding="utf-8") == "VALUE = 10\n"
        assert not (restored / "extra.txt").exists()
    finally:
        mgr.cleanup()
        if base.exists():
            import shutil

            shutil.rmtree(base, ignore_errors=True)
