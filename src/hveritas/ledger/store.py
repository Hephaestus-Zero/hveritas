"""Append-only dual-backend ledger (SQLite + Apache Parquet) for hveritas."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from hveritas.ledger.canonical import canonical_json, compute_receipt_hash, sha256_hex
from hveritas.ledger.models import (
    ActionEnvelope,
    AgentClaim,
    EffectReceipt,
    MeasuredEffects,
    RunEventRecord,
    RunRecord,
    SpanRecord,
    StepRecord,
)

GENESIS_HASH = "0" * 64


class AppendOnlyViolationError(RuntimeError):
    """Raised when any attempt is made to mutate or delete existing ledger records."""


_STEPS_PARQUET_SCHEMA = pa.schema(
    [
        ("run_id", pa.string()),
        ("step_index", pa.int64()),
        ("receipt_id", pa.string()),
        ("trace_id", pa.string()),
        ("span_id", pa.string()),
        ("parent_span_id", pa.string()),
        ("pre_state_hash", pa.string()),
        ("post_state_hash", pa.string()),
        ("tool_name", pa.string()),
        ("tool_args_json", pa.string()),
        ("seed", pa.int64()),
        ("timestamp_ns", pa.int64()),
        ("cost_json", pa.string()),
        ("claim_json", pa.string()),
        ("measured_json", pa.string()),
        ("prev_receipt_hash", pa.string()),
        ("receipt_hash", pa.string()),
    ]
)

_SPANS_PARQUET_SCHEMA = pa.schema(
    [
        ("run_id", pa.string()),
        ("seq_no", pa.int64()),
        ("trace_id", pa.string()),
        ("span_id", pa.string()),
        ("parent_span_id", pa.string()),
        ("step_index", pa.int64()),
        ("name", pa.string()),
        ("operation_name", pa.string()),
        ("openinference_kind", pa.string()),
        ("start_time_ns", pa.int64()),
        ("end_time_ns", pa.int64()),
        ("status_code", pa.string()),
        ("attributes_json", pa.string()),
    ]
)

_EVENTS_PARQUET_SCHEMA = pa.schema(
    [
        ("run_id", pa.string()),
        ("event_seq", pa.int64()),
        ("event_type", pa.string()),
        ("timestamp_ns", pa.int64()),
        ("payload_json", pa.string()),
    ]
)


class AppendOnlyLedger:
    """Tamper-evident append-only ledger backed simultaneously by SQLite and Parquet.

    Invariants enforced:
    - Append-only SQLite triggers forbid UPDATE and DELETE on every table.
    - `claim_json` and `measured_json` are stored in separate columns and never merged (I3).
    - Every step forms a cryptographic SHA-256 hash chain over `(prev, envelope, measured)`.
    - Deterministic page layout and Parquet schema yield byte-identical artifacts on replay (I8).
    """

    def __init__(self, root_dir: Path | str) -> None:
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.sqlite_path = self.root_dir / "ledger.sqlite"
        self.steps_parquet_path = self.root_dir / "steps.parquet"
        self.spans_parquet_path = self.root_dir / "spans.parquet"
        self.events_parquet_path = self.root_dir / "events.parquet"
        self._conn = sqlite3.connect(str(self.sqlite_path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute("PRAGMA page_size = 4096;")
        cur.execute("PRAGMA journal_mode = DELETE;")
        cur.execute("PRAGMA synchronous = FULL;")
        cur.execute("PRAGMA foreign_keys = ON;")

        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                goal TEXT NOT NULL,
                container_digest TEXT NOT NULL,
                seed INTEGER NOT NULL,
                started_at_ns INTEGER NOT NULL,
                metadata_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS steps (
                run_id TEXT NOT NULL,
                step_index INTEGER NOT NULL,
                receipt_id TEXT NOT NULL UNIQUE,
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                parent_span_id TEXT,
                pre_state_hash TEXT NOT NULL,
                post_state_hash TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tool_args_json TEXT NOT NULL,
                seed INTEGER,
                timestamp_ns INTEGER NOT NULL,
                cost_json TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                claim_json TEXT NOT NULL,
                measured_json TEXT NOT NULL,
                prev_receipt_hash TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                PRIMARY KEY (run_id, step_index),
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS spans (
                run_id TEXT NOT NULL,
                seq_no INTEGER NOT NULL,
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                parent_span_id TEXT,
                step_index INTEGER,
                name TEXT NOT NULL,
                operation_name TEXT NOT NULL,
                openinference_kind TEXT NOT NULL,
                start_time_ns INTEGER NOT NULL,
                end_time_ns INTEGER NOT NULL,
                status_code TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                PRIMARY KEY (run_id, seq_no),
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS run_events (
                run_id TEXT NOT NULL,
                event_seq INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (run_id, event_seq),
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );
            """
        )

        for tbl in ("runs", "steps", "spans", "run_events"):
            cur.executescript(
                f"""
                CREATE TRIGGER IF NOT EXISTS prevent_update_{tbl}
                BEFORE UPDATE ON {tbl}
                BEGIN
                    SELECT RAISE(ABORT, 'APPEND_ONLY_VIOLATION: UPDATE forbidden on {tbl}');
                END;

                CREATE TRIGGER IF NOT EXISTS prevent_delete_{tbl}
                BEFORE DELETE ON {tbl}
                BEGIN
                    SELECT RAISE(ABORT, 'APPEND_ONLY_VIOLATION: DELETE forbidden on {tbl}');
                END;
                """
            )

    def append_run(self, run: RunRecord) -> None:
        try:
            self._conn.execute(
                """
                INSERT INTO runs (run_id, goal, container_digest, seed, started_at_ns, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.goal,
                    run.container_digest,
                    run.seed,
                    run.started_at_ns,
                    canonical_json(run.metadata),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise AppendOnlyViolationError(f"Duplicate or invalid run record: {exc}") from exc

    def last_receipt_hash(self, run_id: str) -> str:
        row = self._conn.execute(
            "SELECT receipt_hash FROM steps WHERE run_id = ? ORDER BY step_index DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        return str(row["receipt_hash"]) if row is not None else GENESIS_HASH

    def append_step(
        self,
        envelope: ActionEnvelope,
        claim: AgentClaim,
        measured: MeasuredEffects,
    ) -> StepRecord:
        """Append an action envelope + segregated claim & measured effects, sealing the chain."""
        prev_hash = self.last_receipt_hash(envelope.run_id)
        envelope_dict = envelope.model_dump(mode="json")
        claim_dict = claim.model_dump(mode="json")
        measured_dict = measured.model_dump(mode="json")

        receipt_hash = compute_receipt_hash(prev_hash, envelope_dict, measured_dict)
        receipt_id = f"rcpt-{receipt_hash[:24]}"

        receipt = EffectReceipt(
            receipt_id=receipt_id,
            run_id=envelope.run_id,
            step_index=envelope.step_index,
            claim=claim,
            measured=measured,
            prev_receipt_hash=prev_hash,
            receipt_hash=receipt_hash,
        )

        try:
            self._conn.execute(
                """
                INSERT INTO steps (
                    run_id, step_index, receipt_id, trace_id, span_id, parent_span_id,
                    pre_state_hash, post_state_hash, tool_name, tool_args_json, seed,
                    timestamp_ns, cost_json, envelope_json, claim_json, measured_json,
                    prev_receipt_hash, receipt_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.run_id,
                    envelope.step_index,
                    receipt.receipt_id,
                    envelope.trace_id,
                    envelope.span_id,
                    envelope.parent_span_id,
                    envelope.pre_state_hash,
                    measured.post_state_hash,
                    envelope.tool_name,
                    canonical_json(envelope.tool_args),
                    envelope.seed,
                    envelope.timestamp_ns,
                    canonical_json(envelope.cost.model_dump(mode="json")),
                    canonical_json(envelope_dict),
                    canonical_json(claim_dict),
                    canonical_json(measured_dict),
                    prev_hash,
                    receipt_hash,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise AppendOnlyViolationError(f"Cannot overwrite step in ledger: {exc}") from exc

        self._sync_steps_parquet()
        return StepRecord(envelope=envelope, receipt=receipt)

    def append_span(self, span: SpanRecord) -> None:
        try:
            self._conn.execute(
                """
                INSERT INTO spans (
                    run_id, seq_no, trace_id, span_id, parent_span_id, step_index,
                    name, operation_name, openinference_kind, start_time_ns, end_time_ns,
                    status_code, attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    span.run_id,
                    span.seq_no,
                    span.trace_id,
                    span.span_id,
                    span.parent_span_id,
                    span.step_index,
                    span.name,
                    span.operation_name,
                    span.openinference_kind,
                    span.start_time_ns,
                    span.end_time_ns,
                    span.status_code,
                    canonical_json(span.attributes),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise AppendOnlyViolationError(f"Cannot overwrite span in ledger: {exc}") from exc

        self._sync_spans_parquet()

    def append_event(
        self,
        run_id: str,
        event_type: str,
        timestamp_ns: int,
        payload: dict[str, Any],
    ) -> RunEventRecord:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(event_seq) + 1, 0) AS next_seq FROM run_events WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        seq = int(row["next_seq"])
        rec = RunEventRecord(
            run_id=run_id,
            event_seq=seq,
            event_type=event_type,
            timestamp_ns=timestamp_ns,
            payload=payload,
        )
        self._conn.execute(
            """
            INSERT INTO run_events (run_id, event_seq, event_type, timestamp_ns, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (run_id, seq, event_type, timestamp_ns, canonical_json(payload)),
        )
        self._sync_events_parquet()
        return rec

    def get_run(self, run_id: str) -> RunRecord | None:
        row = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        return RunRecord(
            run_id=row["run_id"],
            goal=row["goal"],
            container_digest=row["container_digest"],
            seed=row["seed"],
            started_at_ns=row["started_at_ns"],
            metadata=json.loads(row["metadata_json"]),
        )

    def get_steps(self, run_id: str, source: str = "sqlite") -> list[StepRecord]:
        if source == "parquet":
            return self._get_steps_from_parquet(run_id)
        rows = self._conn.execute(
            "SELECT * FROM steps WHERE run_id = ? ORDER BY step_index ASC",
            (run_id,),
        ).fetchall()
        out: list[StepRecord] = []
        for r in rows:
            env = ActionEnvelope.model_validate(json.loads(r["envelope_json"]))
            claim = AgentClaim.model_validate(json.loads(r["claim_json"]))
            measured = MeasuredEffects.model_validate(json.loads(r["measured_json"]))
            rcpt = EffectReceipt(
                receipt_id=r["receipt_id"],
                run_id=r["run_id"],
                step_index=r["step_index"],
                claim=claim,
                measured=measured,
                prev_receipt_hash=r["prev_receipt_hash"],
                receipt_hash=r["receipt_hash"],
            )
            out.append(StepRecord(envelope=env, receipt=rcpt))
        return out

    def get_spans(self, run_id: str, source: str = "sqlite") -> list[SpanRecord]:
        if source == "parquet":
            return self._get_spans_from_parquet(run_id)
        rows = self._conn.execute(
            "SELECT * FROM spans WHERE run_id = ? ORDER BY seq_no ASC",
            (run_id,),
        ).fetchall()
        return [
            SpanRecord(
                run_id=r["run_id"],
                seq_no=r["seq_no"],
                trace_id=r["trace_id"],
                span_id=r["span_id"],
                parent_span_id=r["parent_span_id"],
                step_index=r["step_index"],
                name=r["name"],
                operation_name=r["operation_name"],
                openinference_kind=r["openinference_kind"],
                start_time_ns=r["start_time_ns"],
                end_time_ns=r["end_time_ns"],
                status_code=r["status_code"],
                attributes=json.loads(r["attributes_json"]),
            )
            for r in rows
        ]

    def get_events(self, run_id: str) -> list[RunEventRecord]:
        rows = self._conn.execute(
            "SELECT * FROM run_events WHERE run_id = ? ORDER BY event_seq ASC",
            (run_id,),
        ).fetchall()
        return [
            RunEventRecord(
                run_id=r["run_id"],
                event_seq=r["event_seq"],
                event_type=r["event_type"],
                timestamp_ns=r["timestamp_ns"],
                payload=json.loads(r["payload_json"]),
            )
            for r in rows
        ]

    def verify_chain(self, run_id: str) -> bool:
        """Verify receipt hash chain integrity for `run_id`."""
        steps = self.get_steps(run_id, source="sqlite")
        expected_prev = GENESIS_HASH
        for idx, step in enumerate(steps):
            if step.envelope.step_index != idx:
                return False
            if step.receipt.prev_receipt_hash != expected_prev:
                return False
            recomputed = compute_receipt_hash(
                expected_prev,
                step.envelope.model_dump(mode="json"),
                step.receipt.measured.model_dump(mode="json"),
            )
            if recomputed != step.receipt.receipt_hash:
                return False
            expected_prev = recomputed
        return True

    def digest_bundle(self) -> dict[str, str]:
        """Return SHA-256 digests of SQLite and Parquet ledger artifacts on disk."""
        digests: dict[str, str] = {}
        for name, path in (
            ("sqlite", self.sqlite_path),
            ("steps_parquet", self.steps_parquet_path),
            ("spans_parquet", self.spans_parquet_path),
        ):
            if path.exists():
                digests[name] = sha256_hex(path.read_bytes())
        return digests

    def _sync_steps_parquet(self) -> None:
        rows = self._conn.execute(
            "SELECT * FROM steps ORDER BY run_id ASC, step_index ASC"
        ).fetchall()
        cols: dict[str, list[Any]] = {name: [] for name in _STEPS_PARQUET_SCHEMA.names}
        for r in rows:
            for name in _STEPS_PARQUET_SCHEMA.names:
                cols[name].append(r[name])
        table = pa.Table.from_pydict(cols, schema=_STEPS_PARQUET_SCHEMA)
        pq.write_table(
            table,
            self.steps_parquet_path,
            compression="snappy",
            write_statistics=True,
            version="2.6",
        )

    def _sync_spans_parquet(self) -> None:
        rows = self._conn.execute("SELECT * FROM spans ORDER BY run_id ASC, seq_no ASC").fetchall()
        cols: dict[str, list[Any]] = {name: [] for name in _SPANS_PARQUET_SCHEMA.names}
        for r in rows:
            for name in _SPANS_PARQUET_SCHEMA.names:
                cols[name].append(r[name])
        table = pa.Table.from_pydict(cols, schema=_SPANS_PARQUET_SCHEMA)
        pq.write_table(
            table,
            self.spans_parquet_path,
            compression="snappy",
            write_statistics=True,
            version="2.6",
        )

    def _sync_events_parquet(self) -> None:
        rows = self._conn.execute(
            "SELECT * FROM run_events ORDER BY run_id ASC, event_seq ASC"
        ).fetchall()
        cols: dict[str, list[Any]] = {name: [] for name in _EVENTS_PARQUET_SCHEMA.names}
        for r in rows:
            for name in _EVENTS_PARQUET_SCHEMA.names:
                cols[name].append(r[name])
        table = pa.Table.from_pydict(cols, schema=_EVENTS_PARQUET_SCHEMA)
        pq.write_table(
            table,
            self.events_parquet_path,
            compression="snappy",
            write_statistics=True,
            version="2.6",
        )

    def _get_steps_from_parquet(self, run_id: str) -> list[StepRecord]:
        if not self.steps_parquet_path.exists():
            return []
        table = pq.read_table(self.steps_parquet_path)
        rows = [r for r in table.to_pylist() if r["run_id"] == run_id]
        rows.sort(key=lambda x: int(x["step_index"]))
        out: list[StepRecord] = []
        for r in rows:
            env = ActionEnvelope(
                run_id=r["run_id"],
                step_index=r["step_index"],
                trace_id=r["trace_id"],
                span_id=r["span_id"],
                parent_span_id=r["parent_span_id"],
                pre_state_hash=r["pre_state_hash"],
                tool_name=r["tool_name"],
                tool_args=json.loads(r["tool_args_json"]),
                seed=r["seed"],
                cost=json.loads(r["cost_json"]),
                timestamp_ns=r["timestamp_ns"],
            )
            claim = AgentClaim.model_validate(json.loads(r["claim_json"]))
            measured = MeasuredEffects.model_validate(json.loads(r["measured_json"]))
            rcpt = EffectReceipt(
                receipt_id=r["receipt_id"],
                run_id=r["run_id"],
                step_index=r["step_index"],
                claim=claim,
                measured=measured,
                prev_receipt_hash=r["prev_receipt_hash"],
                receipt_hash=r["receipt_hash"],
            )
            out.append(StepRecord(envelope=env, receipt=rcpt))
        return out

    def _get_spans_from_parquet(self, run_id: str) -> list[SpanRecord]:
        if not self.spans_parquet_path.exists():
            return []
        table = pq.read_table(self.spans_parquet_path)
        rows = [r for r in table.to_pylist() if r["run_id"] == run_id]
        rows.sort(key=lambda x: int(x["seq_no"]))
        return [
            SpanRecord(
                run_id=r["run_id"],
                seq_no=r["seq_no"],
                trace_id=r["trace_id"],
                span_id=r["span_id"],
                parent_span_id=r["parent_span_id"],
                step_index=r["step_index"],
                name=r["name"],
                operation_name=r["operation_name"],
                openinference_kind=r["openinference_kind"],
                start_time_ns=r["start_time_ns"],
                end_time_ns=r["end_time_ns"],
                status_code=r["status_code"],
                attributes=json.loads(r["attributes_json"]),
            )
            for r in rows
        ]

    def close(self) -> None:
        self._conn.close()
