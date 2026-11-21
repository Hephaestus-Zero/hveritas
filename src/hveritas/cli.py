"""CLI entrypoint for hveritas (CLI + Ledger only; zero Web UI per build rules)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hveritas.ledger import CostRecord
    from hveritas.loop.models import LoopResult, LoopStopReason


def run_synthetic_10_step_demo(ledger_dir: Path, run_id: str = "m0-demo-run") -> dict[str, object]:
    """Execute a 10-step synthetic run and persist spans + receipts to SQLite + Parquet."""
    from hveritas.ledger import (
        ActionEnvelope,
        AgentClaim,
        AppendOnlyLedger,
        CostRecord,
        DeterministicClock,
        HVeritasTracer,
        MeasuredEffects,
        RunRecord,
        sha256_hex,
        validate_semconv_span,
    )

    clock = DeterministicClock(start_ns=1_700_000_000_000_000_000, step_ns=1_000_000)
    ledger = AppendOnlyLedger(ledger_dir)
    tracer = HVeritasTracer(ledger=ledger, run_id=run_id, seed=20261104, clock=clock)

    ledger.append_run(
        RunRecord(
            run_id=run_id,
            goal="Synthetic 10-step M0 verification run",
            # Synthetic placeholder digest exclusively for offline M0 ledger smoke demo
            container_digest="sha256:" + ("a" * 64),
            seed=20261104,
            started_at_ns=clock.now_ns(),
            metadata={"milestone": "M0"},
        )
    )

    state_hash = sha256_hex("initial-state")
    with tracer.invoke_agent(agent_name="worker", agent_id="worker-0") as agent_span:
        agent_ctx = agent_span.get_span_context()
        trace_id_hex = f"{agent_ctx.trace_id:032x}"
        agent_span_hex = f"{agent_ctx.span_id:016x}"

        with tracer.plan(plan_target="10-step-sequence", step_index=0):
            pass

        for step_idx in range(10):
            tool_name = "write_file" if step_idx % 2 == 0 else "run_check"
            tool_args = {"step": step_idx, "path": f"src/mod_{step_idx}.py"}
            with tracer.execute_tool(
                tool_name=tool_name,
                tool_args=tool_args,
                step_index=step_idx,
            ) as tool_span:
                tool_ctx = tool_span.get_span_context()
                next_state_hash = sha256_hex(f"{state_hash}:{step_idx}:{tool_name}")
                env = ActionEnvelope(
                    run_id=run_id,
                    step_index=step_idx,
                    trace_id=trace_id_hex,
                    span_id=f"{tool_ctx.span_id:016x}",
                    parent_span_id=agent_span_hex,
                    pre_state_hash=state_hash,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    seed=20261104 + step_idx,
                    cost=CostRecord(
                        input_tokens=100 + step_idx,
                        output_tokens=40 + step_idx,
                        usd=0.0005,
                        wall_ms=2.5,
                    ),
                    timestamp_ns=clock.now_ns(),
                )
                claim = AgentClaim(
                    summary=f"Agent claims step {step_idx} succeeded",
                    reported_success=True,
                    raw_output=f"ok:{step_idx}",
                )
                measured = MeasuredEffects(
                    post_state_hash=next_state_hash,
                    exit_code=0,
                    fs_diff={"modified": [f"src/mod_{step_idx}.py"]},
                )
                ledger.append_step(env, claim, measured)
                state_hash = next_state_hash

    tracer.shutdown()
    steps_sql = ledger.get_steps(run_id, source="sqlite")
    steps_pq = ledger.get_steps(run_id, source="parquet")
    spans_sql = ledger.get_spans(run_id, source="sqlite")
    spans_pq = ledger.get_spans(run_id, source="parquet")
    semconv_errors = [err for sp in spans_sql for err in validate_semconv_span(sp)]
    chain_ok = ledger.verify_chain(run_id)
    digests = ledger.digest_bundle()
    ledger.close()

    return {
        "run_id": run_id,
        "steps_sqlite": len(steps_sql),
        "steps_parquet": len(steps_pq),
        "sqlite_equals_parquet_steps": steps_sql == steps_pq,
        "spans_sqlite": len(spans_sql),
        "spans_parquet": len(spans_pq),
        "sqlite_equals_parquet_spans": spans_sql == spans_pq,
        "operations_seen": sorted({sp.operation_name for sp in spans_sql}),
        "semconv_violation_count": len(semconv_errors),
        "chain_verified": chain_ok,
        "digests": digests,
    }


def stop_reason_to_exit_code(reason: LoopStopReason) -> int:
    """Map every `LoopStopReason` to the exact M8-C / M9-D CLI exit code (`0, 2, 3, 4, 5, 6, 7, 8`)."""
    from hveritas.loop.models import LoopStopReason

    mapping: dict[LoopStopReason, int] = {
        LoopStopReason.COMPLETED: 0,
        LoopStopReason.GAMING_ALARM: 2,
        LoopStopReason.BUDGET_EXCEEDED: 3,
        LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN: 4,
        LoopStopReason.REPAIR_EXHAUSTED_HUMAN: 4,
        LoopStopReason.HARNESS_ERROR_NOOP: 5,
        LoopStopReason.MUTATION_SCORE_DROPPED: 6,
        LoopStopReason.DIFFERENTIAL_DISAGREEMENT: 7,
        LoopStopReason.ORACLE_AUTHOR_COLLISION: 8,
    }
    return mapping[reason]


def _default_run_id(goal_text: str) -> str:
    ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    digest8 = hashlib.sha256(goal_text.encode("utf-8")).hexdigest()[:8]
    return f"run_{ts}_{digest8}"


def _resolve_worker_alias(args: argparse.Namespace, *, has_goal_file: bool) -> str:
    if args.worker_model:
        return str(args.worker_model)
    if args.backend == "fake" and has_goal_file:
        return "muse"
    return "argon"


def _build_backend_from_args(args: argparse.Namespace, *, worker_alias: str) -> Any:
    from hveritas.worker import AnthropicApiBackend, FakeBackend, HxCliBackend, ModelResponse

    if args.backend == "hx":
        return HxCliBackend(default_model=worker_alias)
    if args.backend == "anthropic":
        return AnthropicApiBackend(default_model=worker_alias)
    if args.backend == "fake":
        if args.fake_responses is not None:
            raw = json.loads(args.fake_responses.read_text(encoding="utf-8"))
            if not isinstance(raw, list) or not raw:
                raise ValueError("--fake-responses JSON must be a non-empty list of ModelResponse")
            return FakeBackend([ModelResponse.model_validate(item) for item in raw])

        default_noop_plan = json.dumps(
            {
                "actions": [
                    {
                        "tool_name": "noop",
                        "tool_args": {},
                        "claim": {"summary": "fake backend default noop", "reported_success": True},
                    }
                ]
            }
        )

        def _family_for_alias(model_name: str | None) -> str:
            if model_name == worker_alias:
                return "fake-alpha"
            if model_name == str(args.oracle_model):
                return "fake-beta"
            if model_name == str(args.differential_model):
                return "fake-gamma"
            return "fake-beta"

        return FakeBackend(
            lambda _sys, _usr, model: ModelResponse(
                text=default_noop_plan,
                model=str(model or "fake"),
                family=_family_for_alias(model),
                input_tokens=64,
                output_tokens=16,
                elapsed_ms=1.0,
            )
        )
    raise ValueError(f"Unsupported backend: {args.backend!r}")


def _merge_cost_into_result(result: LoopResult, extra_cost: CostRecord) -> LoopResult:
    if not (
        extra_cost.input_tokens or extra_cost.output_tokens or extra_cost.wall_ms or extra_cost.usd
    ):
        return result
    from hveritas.loop.models import BudgetUsage

    merged_usage = BudgetUsage(
        wall_seconds=round(result.budget_usage.wall_seconds + extra_cost.wall_ms / 1000.0, 4),
        total_tokens=result.budget_usage.total_tokens
        + extra_cost.input_tokens
        + extra_cost.output_tokens,
        total_usd=round(result.budget_usage.total_usd + extra_cost.usd, 6),
    )
    return result.model_copy(update={"budget_usage": merged_usage})


def _execute_repository_subcommand(args: argparse.Namespace) -> int:
    """Dispatch explicit ``--repository`` mode with zero premature filesystem writes."""
    from hveritas.repository import run_repository_goal
    from hveritas.worker import HxCliBackend, ModelResponse

    if not getattr(args, "run_id", None):
        args.run_id = _default_run_id(str(args.goal or "repo"))

    worker_alias = _resolve_worker_alias(args, has_goal_file=False)
    if args.dry_run:

        class _DryRunNoCallBackend:
            def complete(
                self, *, system: str, user: str, model: str | None, timeout_s: float
            ) -> ModelResponse:
                raise AssertionError("dry-run must never invoke model backend")

        backend: Any = _DryRunNoCallBackend()
    else:
        try:
            backend = _build_backend_from_args(args, worker_alias=worker_alias)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        if (
            isinstance(backend, HxCliBackend)
            and args.initial_workspace is not None
            and Path(args.initial_workspace).exists()
        ):
            backend.live_workspace_guard = Path(args.initial_workspace).resolve()

    code = run_repository_goal(args, backend)
    try:
        rep_file = Path(args.work_root) / str(args.run_id) / "report.json"
        if rep_file.is_file():
            rep = json.loads(rep_file.read_text(encoding="utf-8"))
            summary = {
                "run_id": rep.get("run_id"),
                "status": rep.get("status"),
                "exit_code": rep.get("exit_code"),
                "reason": rep.get("reason"),
                "goal_kind": rep.get("goal_kind"),
                "changed_files": rep.get("changed_files", []),
                "gates": rep.get("gates", {}),
                "report_json": str(rep_file),
                "report_md": str(rep_file.with_name("report.md")),
            }
            print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False))
    except OSError:
        pass
    return code


def _find_external_bundles_dir(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit.expanduser().resolve()
    candidates = [
        Path(__file__).resolve().parents[2] / "external_bundles",
        Path.cwd() / "external_bundles",
    ]
    for cand in candidates:
        if (cand / "verifier").is_dir() and (cand / "benchjack_tools").is_dir():
            return cand
    raise FileNotFoundError(
        "Could not locate `external_bundles/{verifier,benchjack_tools}`. "
        "Run from an hveritas repository checkout or pass `--source-dir`."
    )


def _execute_setup_verifier_subcommand(args: argparse.Namespace) -> int:
    import os
    import shutil
    import subprocess

    from hveritas.harness.isolation import copy_tree_portable

    try:
        src_root = _find_external_bundles_dir(args.source_dir)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    dest_root = Path(args.dest).expanduser().resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    provisioned: list[str] = []
    for bundle_name in ("verifier", "benchjack_tools"):
        src_bundle = src_root / bundle_name
        if not src_bundle.is_dir():
            print(f"Error: missing bundle directory {src_bundle}", file=sys.stderr)
            return 2
        dst_bundle = dest_root / bundle_name
        if dst_bundle.exists():
            shutil.rmtree(dst_bundle)
        copy_tree_portable(src_bundle, dst_bundle)
        for root, dirs, files in os.walk(dst_bundle):
            rp = Path(root)
            rp.chmod(0o755)
            for d in dirs:
                dp = rp / d
                if not dp.is_symlink():
                    dp.chmod(0o755)
            for f in files:
                fp = rp / f
                if not fp.is_symlink():
                    cur = fp.stat().st_mode
                    fp.chmod(0o755 if (cur & 0o100) else 0o644)
        provisioned.append(str(dst_bundle))

    image_digest: str | None = None
    digest_file_path: Path | None = None
    if args.build_image:
        verifier_dir = dest_root / "verifier"
        proc = subprocess.run(
            ["docker", "build", "-q", str(verifier_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            print(
                f"Error: docker build failed (rc={proc.returncode}): {proc.stderr.strip()}",
                file=sys.stderr,
            )
            return 2
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        if not lines:
            print("Error: docker build -q produced empty digest output", file=sys.stderr)
            return 2
        digest = lines[-1]
        if not digest.startswith("sha256:"):
            digest = f"sha256:{digest}"
        digest_file_path = dest_root / "verifier_digest"
        digest_file_path.write_text(digest + "\n", encoding="utf-8")
        image_digest = digest

    print(
        json.dumps(
            {
                "dest": str(dest_root),
                "bundles": provisioned,
                "image_digest": image_digest,
                "digest_file": str(digest_file_path) if digest_file_path else None,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _execute_run_subcommand(args: argparse.Namespace) -> int:
    if args.work_root is None:
        from hveritas.harness.isolation import default_scratch_root

        args.work_root = default_scratch_root() / "hveritas-runs"

    if getattr(args, "repository", False):
        return _execute_repository_subcommand(args)

    from hveritas.evolve.mutation_gate import MutmutMutationGate
    from hveritas.harness.noop import NoOpBaselineHarnessError
    from hveritas.ledger import CostRecord
    from hveritas.loop import GoalLoopOrchestrator
    from hveritas.loop.models import BudgetLimits, BudgetUsage, LoopResult, LoopStopReason
    from hveritas.spec import (
        EdgeCase,
        HumanClarificationRequiredError,
        OracleAuthorCollisionError,
        RequirementDraft,
        RequirementNode,
        build_task_graph,
        conduct_spec_interview_session,
        render_pytest_from_assertions,
        synthesize_heldout_oracle,
    )
    from hveritas.verify import (
        DifferentialReport,
        build_oracle_free_suite,
        run_differential_check,
    )
    from hveritas.worker import (
        LlmCallTelemetry,
        LlmWorkerPolicy,
        build_run_report_payload,
        load_goal_file,
        write_run_report_bundle,
    )

    work_root = Path(args.work_root).resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    resuming = bool(args.resume)

    if getattr(args, "deprecated_reqs_from_model", False):
        print(
            "[hveritas] WARNING: --requirements-from-model is deprecated; "
            "using M9-A spec interview + M9-B cross-family oracle pipeline.",
            file=sys.stderr,
        )

    goal_file_path: Path | None = Path(args.goal_file).resolve() if args.goal_file else None
    goal_arg_text: str | None = str(args.goal).strip() if args.goal else None
    saved_initial_ws: Path | None = None

    if resuming and goal_file_path is None and not goal_arg_text:
        session_meta_file = work_root / str(args.resume) / "goal_session.json"
        if session_meta_file.is_file():
            meta = json.loads(session_meta_file.read_text(encoding="utf-8"))
            if meta.get("goal_file"):
                goal_file_path = Path(str(meta["goal_file"]))
            elif meta.get("goal_text"):
                goal_arg_text = str(meta["goal_text"])
            if meta.get("initial_workspace"):
                saved_initial_ws = Path(str(meta["initial_workspace"]))

    if goal_file_path is None and not goal_arg_text:
        print(
            "Error: either --goal-file or --goal (or valid --resume) must be supplied.",
            file=sys.stderr,
        )
        return 1

    assurance = str(args.assurance)
    worker_alias = _resolve_worker_alias(args, has_goal_file=goal_file_path is not None)
    oracle_alias = str(args.oracle_model)
    diff_alias = str(args.differential_model)

    budget_limits = BudgetLimits()
    requirements: list[RequirementDraft] | None = None
    goal_text: str
    independence: str
    spec_unreviewed = False
    spec_review_note = "insan yazımı (--goal-file)"

    if goal_file_path is not None:
        goal_text, loaded_reqs, budget_limits = load_goal_file(goal_file_path)
        requirements = loaded_reqs if loaded_reqs else None
        independence = "human"
    else:
        goal_text = str(goal_arg_text)
        independence = "none" if assurance == "fast" else "cross_family"

    if resuming:
        run_id = str(args.resume)
    elif args.run_id:
        run_id = str(args.run_id)
    else:
        run_id = _default_run_id(goal_text)

    run_dir = work_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    if args.initial_workspace is not None:
        initial_ws = Path(args.initial_workspace).resolve()
    elif saved_initial_ws is not None and saved_initial_ws.is_dir():
        initial_ws = saved_initial_ws.resolve()
    else:
        initial_ws = run_dir / "seed_ws"
        initial_ws.mkdir(parents=True, exist_ok=True)

    (run_dir / "goal_session.json").write_text(
        json.dumps(
            {
                "goal_file": str(goal_file_path) if goal_file_path else None,
                "goal_text": goal_text,
                "initial_workspace": str(initial_ws),
                "assurance": assurance,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    oracle_resolved_family: str | None = None
    diff_resolved_family: str | None = None
    diff_report_dict: dict[str, Any] | None = None
    diff_skipped = False
    pre_telemetry: list[LlmCallTelemetry] = []

    def _finish(
        res: LoopResult,
        *,
        pri_fam: str | None = None,
        alt_fam: str | None = None,
        telemetry: list[LlmCallTelemetry] | None = None,
        has_ledger: bool = False,
    ) -> int:
        stdout_json = json.dumps(
            res.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False
        )
        if args.report_out is not None:
            report_payload = build_run_report_payload(
                result=res,
                goal_text=goal_text,
                backend_name=str(args.backend),
                primary_alias=worker_alias,
                alternate_alias=str(args.alternate_model),
                primary_resolved_family=pri_fam,
                alternate_resolved_family=alt_fam,
                call_telemetry=telemetry if telemetry is not None else pre_telemetry,
                ledger_dir=(run_dir / "ledger") if has_ledger else None,
                assurance=assurance,
                independence=independence,
                spec_unreviewed=spec_unreviewed,
                spec_review_note=spec_review_note,
                oracle_alias=oracle_alias
                if goal_file_path is None and assurance != "fast"
                else None,
                oracle_resolved_family=oracle_resolved_family,
                differential_alias=diff_alias if assurance == "paranoid" else None,
                differential_resolved_family=diff_resolved_family,
                oracle_free=res.details.get("oracle_free")
                if isinstance(res.details, dict)
                else None,
                differential=diff_report_dict,
                differential_skipped=diff_skipped,
            )
            write_run_report_bundle(Path(args.report_out), report_payload)
        print(stdout_json)
        return stop_reason_to_exit_code(res.stop_reason)

    # `--dry-run`: compile spec + run SpecAuditGate + I5 no-op baseline with ZERO LLM calls!
    if args.dry_run:
        orch_dry = GoalLoopOrchestrator(work_root=work_root)
        try:
            compiled = orch_dry.compiler.compile(
                goal_text=goal_text,
                requirements=requirements,
                spec_id=f"spec_{run_id}",
            )
        except HumanClarificationRequiredError as exc:
            dry_res = LoopResult(
                run_id=run_id,
                passed=False,
                stop_reason=LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN,
                escalated_to_human=True,
                human_questions=exc.questions,
                budget_usage=BudgetUsage(),
                details={"dry_run": True, "contradictions": exc.contradictions},
            )
            return _finish(dry_res)

        try:
            audit_rep = orch_dry.audit_gate.audit(spec=compiled, initial_workspace=initial_ws)
        except HumanClarificationRequiredError as exc:
            dry_res = LoopResult(
                run_id=run_id,
                passed=False,
                stop_reason=LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN,
                escalated_to_human=True,
                human_questions=exc.questions,
                budget_usage=BudgetUsage(),
                details={
                    "dry_run": True,
                    "contradictions": exc.contradictions,
                    "oracle_consistency_clean": False,
                },
            )
            return _finish(dry_res)
        except NoOpBaselineHarnessError as exc:
            dry_res = LoopResult(
                run_id=run_id,
                passed=False,
                stop_reason=LoopStopReason.HARNESS_ERROR_NOOP,
                escalated_to_human=True,
                budget_usage=BudgetUsage(),
                details={"dry_run": True, "harness_error": str(exc)},
            )
            return _finish(dry_res)

        tasks = build_task_graph(compiled)
        dry_res = LoopResult(
            run_id=run_id,
            passed=True,
            stop_reason=LoopStopReason.COMPLETED,
            committed_tasks=[],
            remaining_tasks=[t.task_id for t in tasks],
            escalated_to_human=False,
            budget_usage=BudgetUsage(),
            details={
                "dry_run": True,
                "noop_score": audit_rep.noop_score,
                "leakage_clean": audit_rep.leakage_clean,
                "oracle_consistency_clean": audit_rep.oracle_consistency_clean,
                "contradictions": audit_rep.contradictions,
            },
        )
        return _finish(dry_res)

    backend = _build_backend_from_args(args, worker_alias=worker_alias)
    extra_cost = CostRecord()
    edge_cases: list[EdgeCase] = []
    reference_implementations: dict[str, str] = {}
    worker_pre_family: str | None = None
    allow_empty_heldout = False

    # Natural-language `--goal` pipeline: M9-A Spec Interview (I19) + M9-B Cross-Family Oracle (I15, I16)
    if requirements is None:
        try:
            interview_outcome = conduct_spec_interview_session(
                goal_text=goal_text,
                backend=backend,
                architect_model=worker_alias,
                auto_approve=bool(args.yes),
                max_rounds=int(args.max_interview_rounds),
                output_fn=lambda msg: print(msg, file=sys.stderr),
            )
        except HumanClarificationRequiredError as exc:
            clar_res = LoopResult(
                run_id=run_id,
                passed=False,
                stop_reason=LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN,
                escalated_to_human=True,
                human_questions=exc.questions,
                budget_usage=BudgetUsage(),
                details={"contradictions": exc.contradictions},
            )
            return _finish(clar_res)

        pre_telemetry.extend(interview_outcome.telemetry)
        extra_cost = interview_outcome.total_cost
        worker_pre_family = interview_outcome.result.architect_family or None
        spec_unreviewed = interview_outcome.spec_unreviewed
        if spec_unreviewed:
            spec_review_note = "--yes ile onay atlandı"
        else:
            spec_review_note = (
                f"onaylandı (kullanıcı, {interview_outcome.correction_rounds} düzeltme turu)"
            )

        if not interview_outcome.approved:
            unapproved_res = _merge_cost_into_result(
                LoopResult(
                    run_id=run_id,
                    passed=False,
                    stop_reason=LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN,
                    escalated_to_human=True,
                    human_questions=["Kullanıcı spec yorumunu onaylamadı (I19)."],
                    budget_usage=BudgetUsage(),
                    details={"spec_approved": False},
                ),
                extra_cost,
            )
            return _finish(unapproved_res, pri_fam=worker_pre_family)

        edge_cases = list(interview_outcome.result.edge_cases)
        if assurance == "fast":
            allow_empty_heldout = True
            requirements = list(interview_outcome.result.requirements)
        else:
            synthesized_reqs: list[RequirementDraft] = []
            try:
                for req_draft in interview_outcome.result.requirements:
                    ho_assertions, o_fam, o_cost = synthesize_heldout_oracle(
                        requirement=req_draft,
                        edge_cases=edge_cases,
                        backend=backend,
                        oracle_model=oracle_alias,
                        worker_family=worker_pre_family or "",
                        reference_sink=reference_implementations,
                    )
                    oracle_resolved_family = o_fam
                    extra_cost = CostRecord(
                        input_tokens=extra_cost.input_tokens + o_cost.input_tokens,
                        output_tokens=extra_cost.output_tokens + o_cost.output_tokens,
                        usd=round(extra_cost.usd + o_cost.usd, 8),
                        wall_ms=round(extra_cost.wall_ms + o_cost.wall_ms, 3),
                    )
                    pre_telemetry.append(
                        LlmCallTelemetry(
                            call_index=len(pre_telemetry),
                            task_id=f"oracle_{req_draft.id}",
                            repair_attempt=0,
                            ladder_rung="m9_b_oracle_author",
                            requested_family_slot="oracle-author",
                            requested_alias=oracle_alias,
                            resolved_model=oracle_alias,
                            resolved_family=o_fam,
                            input_tokens=o_cost.input_tokens,
                            output_tokens=o_cost.output_tokens,
                            elapsed_ms=o_cost.wall_ms,
                            usd=o_cost.usd,
                            output_valid=True,
                        )
                    )
                    synthesized_reqs.append(
                        RequirementDraft(
                            id=req_draft.id,
                            statement=req_draft.statement,
                            target_file=req_draft.target_file,
                            function_name=req_draft.function_name,
                            arg_names=req_draft.arg_names,
                            proxy_assertions=req_draft.proxy_assertions,
                            heldout_assertions=ho_assertions,
                            depends_on=req_draft.depends_on,
                            constraints=req_draft.constraints,
                        )
                    )
            except OracleAuthorCollisionError as exc:
                col_res = _merge_cost_into_result(
                    LoopResult(
                        run_id=run_id,
                        passed=False,
                        stop_reason=LoopStopReason.ORACLE_AUTHOR_COLLISION,
                        escalated_to_human=True,
                        human_questions=[str(exc)],
                        budget_usage=BudgetUsage(),
                        details={
                            "worker_family": exc.worker_family,
                            "oracle_family": exc.oracle_family,
                            "oracle_model": exc.oracle_model,
                        },
                    ),
                    extra_cost,
                )
                return _finish(col_res, pri_fam=worker_pre_family)
            requirements = synthesized_reqs

    use_mutation_gate = bool(args.mutation_gate) or assurance == "paranoid"
    mut_hook = None
    if use_mutation_gate:
        mut_gate = MutmutMutationGate(baseline_score=float(args.mutation_baseline))
        live_ws_dir = run_dir / "workspace"

        def _mut_hook() -> tuple[bool, float, float]:
            ref_sources = {
                str(p.relative_to(live_ws_dir)): p.read_text(encoding="utf-8")
                for p in sorted(live_ws_dir.rglob("*.py"))
                if p.is_file() and "__pycache__" not in p.parts
            }
            ver_tests = {
                f"test_proxy_{r.id}.py": render_pytest_from_assertions(
                    r.target_file, r.proxy_assertions
                )
                for r in (requirements or [])
            }
            if not ref_sources or not ver_tests:
                return True, 1.0, mut_gate.baseline_score
            rep = mut_gate.evaluate(
                reference_sources=ref_sources,
                verifier_tests=ver_tests,
                enforce_non_regression=False,
            )
            if rep.passed:
                mut_gate.update_baseline(rep.mutation_score)
            return rep.passed, rep.mutation_score, rep.baseline_score

        mut_hook = _mut_hook

    orchestrator = GoalLoopOrchestrator(
        work_root=work_root,
        mutation_gate_hook=mut_hook,
    )

    # Mandatory M9-C (I17) 4-block oracle-free suite per requirement on EVERY run regardless of `--assurance`!
    oracle_free_suites_by_req = {
        req.id: build_oracle_free_suite(
            requirements=[req],
            edge_cases=edge_cases,
            reference_implementations=reference_implementations,
            verifier_bus=orchestrator.bus,
        )
        for req in (requirements or [])
    }

    policy = LlmWorkerPolicy(
        backend=backend,
        worker_model=worker_alias,
        alternate_model=str(args.alternate_model),
    )

    req_by_id = {r.id: r for r in (requirements or [])}
    diff_telemetry: list[LlmCallTelemetry] = []

    def _paranoid_diff_hook(
        node: RequirementNode, candidate_ws: Path
    ) -> tuple[bool, dict[str, Any], CostRecord]:
        nonlocal diff_resolved_family, diff_report_dict, diff_skipped
        req_draft = req_by_id.get(node.id)
        if req_draft is None:
            return True, {}, CostRecord()
        w_fam = policy.primary_resolved_family or worker_pre_family or ""
        d_rep: DifferentialReport = run_differential_check(
            primary_ws=candidate_ws,
            requirement=req_draft,
            backend=backend,
            differential_model=diff_alias,
            worker_family=w_fam,
            oracle_family=oracle_resolved_family or "",
            n_fuzz_inputs=200,
            seed=20261104,
            edge_cases=edge_cases,
            verifier_bus=orchestrator.bus,
        )
        diff_resolved_family = d_rep.secondary_family or None
        diff_skipped = d_rep.differential_skipped
        diff_report_dict = d_rep.model_dump(mode="json")
        if d_rep.cost.input_tokens or d_rep.cost.output_tokens:
            diff_telemetry.append(
                LlmCallTelemetry(
                    call_index=len(pre_telemetry)
                    + len(policy.call_telemetry)
                    + len(diff_telemetry),
                    task_id=f"diff_{node.id}",
                    repair_attempt=0,
                    ladder_rung="m9_d_differential",
                    requested_family_slot="differential-secondary",
                    requested_alias=diff_alias,
                    resolved_model=d_rep.secondary_model or diff_alias,
                    resolved_family=d_rep.secondary_family,
                    input_tokens=d_rep.cost.input_tokens,
                    output_tokens=d_rep.cost.output_tokens,
                    elapsed_ms=d_rep.cost.wall_ms,
                    usd=d_rep.cost.usd,
                    output_valid=not d_rep.differential_skipped,
                )
            )
        passed_diff = d_rep.differential_skipped or (d_rep.agreement_rate == 1.0)
        return passed_diff, diff_report_dict, d_rep.cost

    def _guarded_worker_policy(ctx: Any, ws_path: Path) -> Any:
        acts = policy(ctx, ws_path)
        if (
            oracle_resolved_family
            and policy.primary_resolved_family
            and policy.primary_resolved_family.lower() == oracle_resolved_family.lower()
        ):
            raise OracleAuthorCollisionError(
                worker_family=policy.primary_resolved_family,
                oracle_family=oracle_resolved_family,
                oracle_model=oracle_alias,
            )
        return acts

    try:
        result = orchestrator.run_goal(
            run_id=run_id,
            goal_text=goal_text,
            initial_workspace=initial_ws,
            worker_policy=_guarded_worker_policy,
            requirements=requirements,
            budget_limits=budget_limits,
            include_t2=True,
            include_t4=bool(args.include_t4) or assurance == "paranoid",
            resume=resuming,
            reference_implementations=reference_implementations or None,
            allow_empty_heldout=allow_empty_heldout,
            oracle_free_suites=oracle_free_suites_by_req,
            differential_hook=_paranoid_diff_hook if assurance == "paranoid" else None,
        )
    except OracleAuthorCollisionError as exc:
        col_runtime = _merge_cost_into_result(
            LoopResult(
                run_id=run_id,
                passed=False,
                stop_reason=LoopStopReason.ORACLE_AUTHOR_COLLISION,
                escalated_to_human=True,
                human_questions=[str(exc)],
                budget_usage=BudgetUsage(),
                details={
                    "worker_family": exc.worker_family,
                    "oracle_family": exc.oracle_family,
                    "oracle_model": exc.oracle_model,
                },
            ),
            extra_cost,
        )
        return _finish(
            col_runtime,
            pri_fam=policy.primary_resolved_family or worker_pre_family,
            alt_fam=policy.alternate_resolved_family,
            telemetry=[*pre_telemetry, *policy.call_telemetry, *diff_telemetry],
            has_ledger=True,
        )

    result = _merge_cost_into_result(result, extra_cost)
    combined_telemetry: list[LlmCallTelemetry] = []
    for idx, item in enumerate([*pre_telemetry, *policy.call_telemetry, *diff_telemetry]):
        combined_telemetry.append(
            LlmCallTelemetry(
                call_index=idx,
                task_id=item.task_id,
                repair_attempt=item.repair_attempt,
                ladder_rung=item.ladder_rung,
                requested_family_slot=item.requested_family_slot,
                requested_alias=item.requested_alias,
                resolved_model=item.resolved_model,
                resolved_family=item.resolved_family,
                input_tokens=item.input_tokens,
                output_tokens=item.output_tokens,
                elapsed_ms=item.elapsed_ms,
                usd=item.usd,
                output_valid=item.output_valid,
            )
        )

    return _finish(
        result,
        pri_fam=policy.primary_resolved_family or worker_pre_family,
        alt_fam=policy.alternate_resolved_family,
        telemetry=combined_telemetry,
        has_ledger=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hveritas", description="Verified Autonomous Goal Loop")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser(
        "run", help="Execute verified autonomous goal loop on a goal YAML or NL goal"
    )
    p_run.add_argument("--goal-file", type=Path, default=None, help="Path to YAML goal definition")
    p_run.add_argument("--goal", type=str, default=None, help="Natural-language goal text")
    p_run.add_argument(
        "--assurance",
        choices=("fast", "standard", "paranoid"),
        default="standard",
        help="Verification independence tier (default: standard)",
    )
    p_run.add_argument(
        "--work-root",
        type=Path,
        default=None,
        help="Scratch working directory root for run artifacts & ledger (default: <scratch_root>/hveritas-runs)",
    )
    p_run.add_argument(
        "--initial-workspace", type=Path, default=None, help="Optional seed workspace"
    )
    p_run.add_argument(
        "--backend",
        choices=("hx", "anthropic", "fake"),
        default="hx",
        help="Model planner backend (default: hx)",
    )
    p_run.add_argument(
        "--fake-responses",
        type=Path,
        default=None,
        help="Optional JSON file of ModelResponse dicts when using --backend fake",
    )
    p_run.add_argument(
        "--worker-model",
        "--primary-model",
        dest="worker_model",
        default=None,
        help="Worker model alias (default: argon [Gemini])",
    )
    p_run.add_argument(
        "--oracle-model",
        default="sonnet-claude",
        help="Cross-family held-out oracle author model alias (default: sonnet-claude [Claude])",
    )
    p_run.add_argument(
        "--differential-model",
        default="luna",
        help="3rd-family differential implementation model alias (default: luna)",
    )
    p_run.add_argument(
        "--alternate-model",
        default="sonnet-claude",
        help="Alternate model alias for repair ladder rung 3 (default: sonnet-claude [Claude])",
    )
    p_run.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive M9-A spec review confirmation (sets spec_unreviewed=true)",
    )
    p_run.add_argument(
        "--max-interview-rounds",
        type=int,
        default=3,
        help="Maximum interactive M9-A spec correction rounds (default: 3)",
    )
    p_run.add_argument("--run-id", default=None, help="Explicit run identifier")
    p_run.add_argument(
        "--resume",
        default=None,
        help="Resume an existing run_id from work_root/<run_id>/ledger, skipping committed tasks",
    )
    p_run.add_argument(
        "--dry-run",
        action="store_true",
        help="Compile spec + run audit gate + no-op baseline with zero LLM calls",
    )
    p_run.add_argument(
        "--include-t2", action="store_true", help="Enable T2 metamorphic verifier tier"
    )
    p_run.add_argument(
        "--include-t4", action="store_true", help="Enable T4 DAG-judge verifier tier"
    )
    p_run.add_argument(
        "--mutation-gate",
        action="store_true",
        help="Enable I9 mutmut mutation score gate before milestone commit",
    )
    p_run.add_argument(
        "--mutation-baseline",
        type=float,
        default=0.0,
        help="Baseline mutmut score threshold when --mutation-gate is active",
    )
    p_run.add_argument(
        "--requirements-from-model",
        dest="deprecated_reqs_from_model",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p_run.add_argument(
        "--report-out", type=Path, default=None, help="Path to write JSON run report"
    )
    p_run.add_argument(
        "--repository",
        action="store_true",
        help="Enable repository-goal mode for existing Python repositories (requires --initial-workspace and --goal)",
    )
    p_run.add_argument(
        "--goal-kind",
        choices=("auto", "behavior_change", "refactor"),
        default="auto",
        help="Repository-mode goal kind: behavior_change vs behavior-preserving refactor (default: auto)",
    )
    p_run.add_argument(
        "--max-repository-rounds",
        type=int,
        default=4,
        help="Maximum worker/repair rounds in --repository mode (1..20, default: 4)",
    )
    p_run.add_argument(
        "--test-paths",
        nargs="+",
        default=None,
        help="Optional scoped pytest file/directory subset in --repository mode (recorded in report)",
    )
    p_run.add_argument(
        "--structural-criteria",
        type=Path,
        default=None,
        help="Optional JSON file of AST structural checks for --repository refactor goals",
    )
    p_run.add_argument(
        "--repo-wall-timeout",
        type=float,
        default=600.0,
        help="Global wall-clock timeout in seconds for --repository mode (max 900s, default: 600s)",
    )
    p_run.add_argument(
        "--repo-test-timeout",
        type=float,
        default=120.0,
        help="Per-container pytest timeout in seconds for --repository mode (max 180s, default: 120s)",
    )
    p_run.add_argument(
        "--repo-model-timeout",
        type=float,
        default=180.0,
        help="Per-call model timeout in seconds for --repository mode (default: 180s)",
    )
    p_run.add_argument(
        "--verifier-image",
        type=str,
        default=None,
        help="SHA-256 digest-pinned Docker verifier image for --repository mode (sha256:<64hex> or <repo>@sha256:<64hex>)",
    )

    p_m0 = sub.add_parser("m0-demo", help="Run 10-step synthetic M0 ledger verification")
    p_m0.add_argument("--ledger-dir", required=True, type=Path)
    p_m0.add_argument("--run-id", default="m0-demo-run")

    p_ins = sub.add_parser("inspect-ledger", help="Inspect a run in an hveritas ledger")
    p_ins.add_argument("--ledger-dir", required=True, type=Path)
    p_ins.add_argument("--run-id", required=True)

    p_m4 = sub.add_parser("m4-eval", help="Run Ek B fault-injection attribution meta-eval")
    p_m4.add_argument(
        "--scratch-dir",
        default=None,
        type=Path,
    )
    p_m4.add_argument("--report-out", type=Path, default=None)

    p_m7 = sub.add_parser("m7-audit", help="Run BenchJack + Bandit self-audit on hveritas harness")
    p_m7.add_argument(
        "--markdown-out",
        default=Path("docs/reports/m7_benchjack_self_audit.md"),
        type=Path,
    )
    p_m7.add_argument(
        "--json-out",
        default=Path("docs/reports/m7_benchjack_self_audit.json"),
        type=Path,
    )

    p_setup = sub.add_parser(
        "setup-verifier",
        help="Provision out-of-tree verifier & BenchJack bundles (and optionally build Docker image)",
    )
    p_setup.add_argument(
        "--dest",
        type=Path,
        default=Path.home() / ".local" / "share" / "hveritas",
        help="Destination directory for external bundles (default: ~/.local/share/hveritas)",
    )
    p_setup.add_argument(
        "--source-dir",
        type=Path,
        default=None,
        help="Optional path to external_bundles directory (auto-detected from checkout if omitted)",
    )
    p_setup.add_argument(
        "--build-image",
        action="store_true",
        help="Build the isolated Docker verifier image and save its digest to <dest>/verifier_digest",
    )

    args = parser.parse_args(argv)
    if args.cmd == "setup-verifier":
        return _execute_setup_verifier_subcommand(args)
    if args.cmd == "run":
        return _execute_run_subcommand(args)
    if args.cmd == "m7-audit":
        from hveritas.evolve import BenchJackSelfAuditor

        auditor = BenchJackSelfAuditor()
        rep = auditor.run_audit(markdown_out=args.markdown_out, json_out=args.json_out)
        print(
            json.dumps(
                {
                    "audit_id": rep.audit_id,
                    "passed": rep.passed,
                    "docker_findings_count": rep.docker_findings_count,
                    "trust_boundary_conflicts_count": rep.trust_boundary_conflicts_count,
                    "dangerous_sinks_count": rep.dangerous_sinks_count,
                    "ast_rule_violations_count": rep.ast_rule_violations_count,
                    "bandit_high_count": rep.bandit_high_count,
                    "bandit_medium_count": rep.bandit_medium_count,
                    "nosec_suppressions_count": rep.nosec_suppressions_count,
                    "unmitigated_exploit_findings_count": rep.unmitigated_exploit_findings_count,
                    "markdown_out": str(args.markdown_out),
                    "json_out": str(args.json_out),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if rep.passed else 2
    if args.cmd == "m4-eval":
        from hveritas.attribute import run_ek_b_meta_evaluation
        from hveritas.harness.isolation import default_scratch_root

        scratch_dir = args.scratch_dir or (default_scratch_root() / "m4-eval")
        res = run_ek_b_meta_evaluation(scratch_dir)
        rendered = json.dumps(res, indent=2, sort_keys=True, ensure_ascii=False)
        if args.report_out is not None:
            args.report_out.parent.mkdir(parents=True, exist_ok=True)
            args.report_out.write_text(rendered + "\n", encoding="utf-8")
        print(rendered)
        return 0
    if args.cmd == "m0-demo":
        summary = run_synthetic_10_step_demo(args.ledger_dir, run_id=args.run_id)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    if args.cmd == "inspect-ledger":
        from hveritas.ledger import AppendOnlyLedger

        ledger = AppendOnlyLedger(args.ledger_dir)
        run = ledger.get_run(args.run_id)
        steps = ledger.get_steps(args.run_id)
        spans = ledger.get_spans(args.run_id)
        chain_ok = ledger.verify_chain(args.run_id)
        ledger.close()
        print(
            json.dumps(
                {
                    "run": run.model_dump(mode="json") if run else None,
                    "step_count": len(steps),
                    "span_count": len(spans),
                    "chain_verified": chain_ok,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
