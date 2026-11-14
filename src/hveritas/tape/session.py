"""Tool Tape session recorder & deterministic replayer (Invariants I3, I8)."""

from __future__ import annotations

import base64
import http.client
import json
import sqlite3
import subprocess
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hveritas.effects import IndependentEffectMeasurer, RawProcessOutcome
from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST
from hveritas.ledger import (
    ActionEnvelope,
    AgentClaim,
    AppendOnlyLedger,
    CostRecord,
    DeterministicClock,
    HVeritasTracer,
    RunRecord,
    StepRecord,
)
from hveritas.ledger.canonical import canonical_json
from hveritas.tape.env import FrozenEnvSnapshot
from hveritas.tape.http_tape import VcrHttpCassetteManager
from hveritas.tape.snapshot import SnapshotHandle, SnapshotManager


class DeterminismDriftError(RuntimeError):
    """Raised if replaying a recorded step yields a different workspace or receipt hash."""


class TapeStepEntry(BaseModel):
    """Single step persisted on the ToolTape."""

    model_config = ConfigDict(frozen=True)

    step_index: int
    tool_name: str
    tool_args: dict[str, Any]
    seed: int
    cost: CostRecord
    agent_claim: AgentClaim
    expected_pre_state_hash: str
    expected_post_state_hash: str
    recorded_tool_output: dict[str, Any] = Field(default_factory=dict)
    recorded_exit_code: int | None = None
    recorded_stdout_b64: str | None = None
    recorded_stderr_b64: str | None = None
    recorded_timed_out: bool = False


class ToolTapeManifest(BaseModel):
    """Complete serializable tape manifest enabling exact replay & prefix bisect."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    goal: str
    env: FrozenEnvSnapshot
    initial_snapshot: SnapshotHandle
    steps: list[TapeStepEntry] = Field(default_factory=list)


@dataclass(frozen=True)
class PlannedAction:
    """Action proposed by an agent policy (including untrusted `claim`)."""

    tool_name: str
    tool_args: dict[str, Any]
    claim: AgentClaim = field(default_factory=AgentClaim)
    cost: CostRecord = field(default_factory=CostRecord)


ToolHandler = Callable[
    [Path, dict[str, Any], FrozenEnvSnapshot, str], tuple[dict[str, Any], RawProcessOutcome | None]
]


def build_builtin_tool_registry() -> dict[str, ToolHandler]:
    """Standard deterministic workspace tools (`write_file`, `patch_file`, `run_cmd`, `sqlite_exec`, `http_get`, `noop`)."""

    def _safe_rel(workspace: Path, rel: str) -> Path:
        target = (workspace / rel).resolve()
        ws_resolved = workspace.resolve()
        if target != ws_resolved and ws_resolved not in target.parents:
            raise ValueError(f"Path traversal outside workspace forbidden: {rel!r}")
        return target

    def tool_write_file(
        ws: Path, args: dict[str, Any], _env: FrozenEnvSnapshot, _mode: str
    ) -> tuple[dict[str, Any], RawProcessOutcome | None]:
        target = _safe_rel(ws, str(args["path"]))
        target.parent.mkdir(parents=True, exist_ok=True)
        content = str(args["content"])
        target.write_text(content, encoding="utf-8")
        target.chmod(int(args.get("mode", 0o644)))
        return {"written_bytes": len(content.encode("utf-8"))}, RawProcessOutcome(exit_code=0)

    def tool_patch_file(
        ws: Path, args: dict[str, Any], _env: FrozenEnvSnapshot, _mode: str
    ) -> tuple[dict[str, Any], RawProcessOutcome | None]:
        target = _safe_rel(ws, str(args["path"]))
        text = target.read_text(encoding="utf-8")
        old = str(args["old"])
        new = str(args["new"])
        if old not in text:
            return {"patched": False}, RawProcessOutcome(
                exit_code=1, stderr=b"target string not found"
            )
        updated = text.replace(old, new, int(args.get("count", 1)))
        target.write_text(updated, encoding="utf-8")
        return {"patched": True}, RawProcessOutcome(exit_code=0)

    def tool_delete_file(
        ws: Path, args: dict[str, Any], _env: FrozenEnvSnapshot, _mode: str
    ) -> tuple[dict[str, Any], RawProcessOutcome | None]:
        target = _safe_rel(ws, str(args["path"]))
        if target.exists():
            target.unlink()
            return {"deleted": True}, RawProcessOutcome(exit_code=0)
        return {"deleted": False}, RawProcessOutcome(exit_code=1, stderr=b"not found")

    def tool_run_cmd(
        ws: Path, args: dict[str, Any], env: FrozenEnvSnapshot, _mode: str
    ) -> tuple[dict[str, Any], RawProcessOutcome | None]:
        argv = list(args["argv"])
        timeout_s = float(args.get("timeout", 15.0))
        try:
            proc = subprocess.run(
                argv,
                cwd=str(ws),
                env=env.to_process_env(),
                capture_output=True,
                timeout=timeout_s,
                check=False,
            )
            outcome = RawProcessOutcome(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                timed_out=False,
            )
            return {
                "exit_code": proc.returncode,
                "stdout": proc.stdout.decode("utf-8", errors="replace"),
                "stderr": proc.stderr.decode("utf-8", errors="replace"),
            }, outcome
        except subprocess.TimeoutExpired as exc:
            outcome = RawProcessOutcome(
                exit_code=124,
                stdout=exc.stdout or b"",
                stderr=exc.stderr or b"timeout",
                timed_out=True,
            )
            return {"exit_code": 124, "timed_out": True}, outcome

    def tool_sqlite_exec(
        ws: Path, args: dict[str, Any], _env: FrozenEnvSnapshot, _mode: str
    ) -> tuple[dict[str, Any], RawProcessOutcome | None]:
        db_path = _safe_rel(ws, str(args["db_path"]))
        db_path.parent.mkdir(parents=True, exist_ok=True)
        sql = str(args["sql"])
        params = list(args.get("params", []))
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("PRAGMA page_size = 4096;")
            conn.execute("PRAGMA journal_mode = DELETE;")
            cur = conn.execute(sql, params)
            rows = cur.fetchall()
            conn.commit()
            return {"rows": rows, "rowcount": cur.rowcount}, RawProcessOutcome(exit_code=0)
        except sqlite3.Error as exc:
            return {"error": str(exc)}, RawProcessOutcome(
                exit_code=1, stderr=str(exc).encode("utf-8")
            )
        finally:
            conn.close()

    def tool_http_request(
        _ws: Path, args: dict[str, Any], _env: FrozenEnvSnapshot, _mode: str
    ) -> tuple[dict[str, Any], RawProcessOutcome | None]:
        url = str(args["url"])
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Disallowed URL {url!r}: only explicit http/https URLs are permitted")
        method = str(args.get("method", "GET")).upper()
        body_str = args.get("body")
        body_bytes = body_str.encode("utf-8") if isinstance(body_str, str) else None
        headers = {str(k): str(v) for k, v in dict(args.get("headers", {})).items()}
        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query = f"{path_and_query}?{parsed.query}"
        conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(parsed.hostname, parsed.port, timeout=5.0)
        try:
            conn.request(method, path_and_query, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            resp_bytes = resp.read()
            status = int(resp.status)
        finally:
            conn.close()
        return {
            "status": status,
            "body": resp_bytes.decode("utf-8", errors="replace"),
        }, RawProcessOutcome(exit_code=0 if 200 <= status < 400 else 1, stdout=resp_bytes)

    def tool_noop(
        _ws: Path, _args: dict[str, Any], _env: FrozenEnvSnapshot, _mode: str
    ) -> tuple[dict[str, Any], RawProcessOutcome | None]:
        return {"noop": True}, RawProcessOutcome(exit_code=0)

    return {
        "write_file": tool_write_file,
        "patch_file": tool_patch_file,
        "delete_file": tool_delete_file,
        "run_cmd": tool_run_cmd,
        "sqlite_exec": tool_sqlite_exec,
        "http_request": tool_http_request,
        "noop": tool_noop,
    }


class TapeRunner:
    """Executes action sequences in `record` mode or deterministically replays prefixes/runs."""

    def __init__(
        self,
        tape_dir: Path,
        snapshot_manager: SnapshotManager | None = None,
        extra_tools: dict[str, ToolHandler] | None = None,
    ) -> None:
        self.tape_dir = tape_dir.resolve()
        self.tape_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.tape_dir / "tape_manifest.json"
        self.snapshots = snapshot_manager or SnapshotManager(self.tape_dir / "snapshots")
        self.cassettes = VcrHttpCassetteManager(self.tape_dir / "cassettes")
        self.measurer = IndependentEffectMeasurer()
        self.tools = build_builtin_tool_registry()
        if extra_tools:
            self.tools.update(extra_tools)

    def record_run(
        self,
        *,
        run_id: str,
        goal: str,
        workspace: Path,
        actions: list[PlannedAction],
        ledger: AppendOnlyLedger,
        env: FrozenEnvSnapshot | None = None,
    ) -> ToolTapeManifest:
        """Execute `actions` on `workspace`, probe real effects, write ledger + tape manifest."""
        frozen_env = env or FrozenEnvSnapshot(
            run_id=run_id,
            container_digest=DEFAULT_VERIFIER_IMAGE_DIGEST,
        )
        init_handle = self.snapshots.create_snapshot(workspace, f"{run_id}_step_init")

        clock = DeterministicClock(
            start_ns=frozen_env.clock_start_ns,
            step_ns=frozen_env.clock_step_ns,
        )
        tracer = HVeritasTracer(
            ledger=ledger,
            run_id=run_id,
            seed=frozen_env.seed,
            clock=clock,
        )
        ledger.append_run(
            RunRecord(
                run_id=run_id,
                goal=goal,
                container_digest=frozen_env.container_digest,
                seed=frozen_env.seed,
                started_at_ns=clock.now_ns(),
                metadata={"mode": "record", "snapshot_backend": init_handle.backend},
            )
        )

        tape_steps: list[TapeStepEntry] = []
        with tracer.invoke_agent(agent_name="worker", agent_id="worker-0") as agent_span:
            agent_ctx = agent_span.get_span_context()
            trace_id_hex = f"{agent_ctx.trace_id:032x}"
            agent_span_hex = f"{agent_ctx.span_id:016x}"

            with tracer.plan(plan_target="task-execution", step_index=0):
                pass

            for idx, action in enumerate(actions):
                step_seed = frozen_env.seed + idx
                pre_obs = self.measurer.observe_pre(workspace)

                with tracer.execute_tool(
                    tool_name=action.tool_name,
                    tool_args=action.tool_args,
                    step_index=idx,
                ) as tool_span:
                    tool_ctx = tool_span.get_span_context()
                    handler = self.tools[action.tool_name]
                    with self.cassettes.step_context(idx, mode="record") as http_exchanges:
                        tool_out, proc_outcome = handler(
                            workspace, action.tool_args, frozen_env, "record"
                        )

                    # Independent post-action measurement (I3: action.claim is NEVER passed here)
                    measured = self.measurer.measure_post(
                        pre=pre_obs,
                        workspace=workspace,
                        process_outcome=proc_outcome,
                        http_exchanges=http_exchanges,
                    )

                    envelope = ActionEnvelope(
                        run_id=run_id,
                        step_index=idx,
                        trace_id=trace_id_hex,
                        span_id=f"{tool_ctx.span_id:016x}",
                        parent_span_id=agent_span_hex,
                        pre_state_hash=pre_obs.state_hash,
                        tool_name=action.tool_name,
                        tool_args=action.tool_args,
                        seed=step_seed,
                        cost=action.cost,
                        timestamp_ns=clock.now_ns(),
                    )
                    ledger.append_step(envelope, action.claim, measured)

                    tape_steps.append(
                        TapeStepEntry(
                            step_index=idx,
                            tool_name=action.tool_name,
                            tool_args=action.tool_args,
                            seed=step_seed,
                            cost=action.cost,
                            agent_claim=action.claim,
                            expected_pre_state_hash=pre_obs.state_hash,
                            expected_post_state_hash=measured.post_state_hash,
                            recorded_tool_output=tool_out,
                            recorded_exit_code=(proc_outcome.exit_code if proc_outcome else None),
                            recorded_stdout_b64=(
                                base64.b64encode(proc_outcome.stdout).decode("ascii")
                                if proc_outcome
                                else None
                            ),
                            recorded_stderr_b64=(
                                base64.b64encode(proc_outcome.stderr).decode("ascii")
                                if proc_outcome
                                else None
                            ),
                            recorded_timed_out=(proc_outcome.timed_out if proc_outcome else False),
                        )
                    )

        tracer.shutdown()
        manifest = ToolTapeManifest(
            run_id=run_id,
            goal=goal,
            env=frozen_env,
            initial_snapshot=init_handle,
            steps=tape_steps,
        )
        self.manifest_path.write_text(
            canonical_json(manifest.model_dump(mode="json")),
            encoding="utf-8",
        )
        return manifest

    def load_manifest(self) -> ToolTapeManifest:
        data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return ToolTapeManifest.model_validate(data)

    def replay_run(
        self,
        *,
        replay_workspace: Path,
        ledger: AppendOnlyLedger | None = None,
        manifest: ToolTapeManifest | None = None,
        up_to_step: int | None = None,
        override_run_id: str | None = None,
    ) -> list[StepRecord]:
        """Deterministically replay steps `[0 .. up_to_step)` onto a clean snapshot clone.

        When `ledger` is provided and `up_to_step` is None (full replay) with matching `run_id`,
        the produced SQLite + Parquet ledger files are byte-for-byte identical across replays.
        """
        mf = manifest or self.load_manifest()
        effective_run_id = override_run_id or mf.run_id
        self.snapshots.restore_snapshot(mf.initial_snapshot, replay_workspace)

        limit = len(mf.steps) if up_to_step is None else min(up_to_step, len(mf.steps))
        selected_steps = mf.steps[:limit]

        clock = DeterministicClock(
            start_ns=mf.env.clock_start_ns,
            step_ns=mf.env.clock_step_ns,
        )

        records: list[StepRecord] = []
        if ledger is not None:
            tracer = HVeritasTracer(
                ledger=ledger,
                run_id=effective_run_id,
                seed=mf.env.seed,
                clock=clock,
            )
            ledger.append_run(
                RunRecord(
                    run_id=effective_run_id,
                    goal=mf.goal,
                    container_digest=mf.env.container_digest,
                    seed=mf.env.seed,
                    started_at_ns=clock.now_ns(),
                    metadata={
                        "mode": "record",
                        "snapshot_backend": mf.initial_snapshot.backend,
                    },
                )
            )
            with tracer.invoke_agent(agent_name="worker", agent_id="worker-0") as agent_span:
                agent_ctx = agent_span.get_span_context()
                trace_id_hex = f"{agent_ctx.trace_id:032x}"
                agent_span_hex = f"{agent_ctx.span_id:016x}"

                with tracer.plan(plan_target="task-execution", step_index=0):
                    pass

                for entry in selected_steps:
                    rec = self._replay_single_step(
                        entry=entry,
                        workspace=replay_workspace,
                        env=mf.env,
                        run_id=effective_run_id,
                        trace_id_hex=trace_id_hex,
                        agent_span_hex=agent_span_hex,
                        tracer=tracer,
                        clock=clock,
                        ledger=ledger,
                    )
                    records.append(rec)
            tracer.shutdown()
        else:
            # Fast headless prefix materialization for O(log n) bisect without ledger I/O
            for entry in selected_steps:
                pre_obs = self.measurer.observe_pre(replay_workspace)
                if pre_obs.state_hash != entry.expected_pre_state_hash:
                    raise DeterminismDriftError(
                        f"Pre-state hash drift at step {entry.step_index}: "
                        f"expected {entry.expected_pre_state_hash}, got {pre_obs.state_hash}"
                    )
                handler = self.tools[entry.tool_name]
                with self.cassettes.step_context(entry.step_index, mode="replay") as http_ex:
                    _, proc_outcome = handler(replay_workspace, entry.tool_args, mf.env, "replay")
                measured = self.measurer.measure_post(
                    pre=pre_obs,
                    workspace=replay_workspace,
                    process_outcome=proc_outcome,
                    http_exchanges=http_ex,
                )
                if measured.post_state_hash != entry.expected_post_state_hash:
                    raise DeterminismDriftError(
                        f"Post-state hash drift at step {entry.step_index}: "
                        f"expected {entry.expected_post_state_hash}, got {measured.post_state_hash}"
                    )
        return records

    def _replay_single_step(
        self,
        *,
        entry: TapeStepEntry,
        workspace: Path,
        env: FrozenEnvSnapshot,
        run_id: str,
        trace_id_hex: str,
        agent_span_hex: str,
        tracer: HVeritasTracer,
        clock: DeterministicClock,
        ledger: AppendOnlyLedger,
    ) -> StepRecord:
        pre_obs = self.measurer.observe_pre(workspace)
        if pre_obs.state_hash != entry.expected_pre_state_hash:
            raise DeterminismDriftError(
                f"Pre-state hash drift at step {entry.step_index}: "
                f"expected {entry.expected_pre_state_hash}, got {pre_obs.state_hash}"
            )

        with tracer.execute_tool(
            tool_name=entry.tool_name,
            tool_args=entry.tool_args,
            step_index=entry.step_index,
        ) as tool_span:
            tool_ctx = tool_span.get_span_context()
            handler = self.tools[entry.tool_name]
            with self.cassettes.step_context(entry.step_index, mode="replay") as http_exchanges:
                _, proc_outcome = handler(workspace, entry.tool_args, env, "replay")

            measured = self.measurer.measure_post(
                pre=pre_obs,
                workspace=workspace,
                process_outcome=proc_outcome,
                http_exchanges=http_exchanges,
            )
            if measured.post_state_hash != entry.expected_post_state_hash:
                raise DeterminismDriftError(
                    f"Post-state hash drift at step {entry.step_index}: "
                    f"expected {entry.expected_post_state_hash}, got {measured.post_state_hash}"
                )

            envelope = ActionEnvelope(
                run_id=run_id,
                step_index=entry.step_index,
                trace_id=trace_id_hex,
                span_id=f"{tool_ctx.span_id:016x}",
                parent_span_id=agent_span_hex,
                pre_state_hash=pre_obs.state_hash,
                tool_name=entry.tool_name,
                tool_args=entry.tool_args,
                seed=entry.seed,
                cost=entry.cost,
                timestamp_ns=clock.now_ns(),
            )
            return ledger.append_step(envelope, entry.agent_claim, measured)
