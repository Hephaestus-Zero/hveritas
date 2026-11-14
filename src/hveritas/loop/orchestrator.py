"""End-to-end Goal Loop Orchestrator: SPEC -> AUDIT -> TASK GRAPH -> EXECUTE -> VERIFY -> DECIDE -> ATTRIBUTE -> REPAIR."""

from __future__ import annotations

import random
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from hveritas.attribute.bisect import UnbisectableRunError
from hveritas.attribute.engine import AttributionPipeline
from hveritas.attribute.narrator import (
    AttributionNarrator,
    AttributionReport,
    LocalStepWindow,
    LockedAttribution,
)
from hveritas.attribute.taxonomy import (
    TrailCategory,
    TrailGroup,
    TrailLeaf,
    classify_trail_fault,
)
from hveritas.harness.gaming import GamingAlarmError, GamingAlarmMonitor
from hveritas.harness.isolation import IsolatedContainerVerifier
from hveritas.harness.noop import NoOpBaselineHarnessError
from hveritas.harness.oracle_vault import EncryptedOracleVault
from hveritas.harness.worker_prompt import WORKER_RUNTIME_SYSTEM_PROMPT
from hveritas.ledger import (
    AppendOnlyLedger,
    CostRecord,
    DeterministicClock,
    RunRecord,
    canonical_json,
)
from hveritas.loop.budget import BudgetExceededError, BudgetTracker
from hveritas.loop.ladder import RepairLadderController
from hveritas.loop.models import (
    BudgetLimits,
    LoopResult,
    LoopStopReason,
    RepairLadderRung,
    WorkerContext,
    serialize_attribution_report,
)
from hveritas.spec import (
    HumanClarificationRequiredError,
    RequirementDraft,
    RequirementNode,
    SpecAuditGate,
    SpecCompiler,
    build_task_graph,
)
from hveritas.tape import FrozenEnvSnapshot, PlannedAction, TapeRunner, TapeStepEntry
from hveritas.verify import (
    OracleFreeSuite,
    VerificationState,
    VerifierBus,
    extract_oracle_free_summary,
)

# WorkerPolicy(WorkerContext, workspace_path) -> list[PlannedAction]
WorkerPolicy = Callable[[WorkerContext, Path], list[PlannedAction]]

# Optional mutation gate hook `(workspace_path) -> (passed, current_score, baseline_score)` (M7 I9)
MutationGateHook = Callable[[], tuple[bool, float, float]]

# Optional 3rd-family differential consensus hook `(node, workspace_path) -> (passed, report_dict, cost)` (M9-D I18)
DifferentialHook = Callable[[RequirementNode, Path], tuple[bool, dict[str, Any], CostRecord]]


class GoalLoopOrchestrator:
    """Executes the full 9-stage hveritas loop enforcing all §8 stopping conditions."""

    def __init__(
        self,
        *,
        work_root: Path,
        oracle_vault: EncryptedOracleVault | None = None,
        verifier_bus: VerifierBus | None = None,
        delta_threshold: float = 0.25,
        mutation_gate_hook: MutationGateHook | None = None,
    ) -> None:
        self.work_root = work_root.resolve()
        self.work_root.mkdir(parents=True, exist_ok=True)
        self.vault = oracle_vault or EncryptedOracleVault()
        self.bus = verifier_bus or VerifierBus(IsolatedContainerVerifier(oracle_vault=self.vault))
        self.compiler = SpecCompiler(oracle_vault=self.vault)
        self.audit_gate = SpecAuditGate(verifier_bus=self.bus, oracle_vault=self.vault)
        self.gaming_monitor = GamingAlarmMonitor(delta_threshold=delta_threshold)
        self.mutation_gate_hook = mutation_gate_hook

    def run_goal(
        self,
        *,
        run_id: str,
        goal_text: str,
        initial_workspace: Path,
        worker_policy: WorkerPolicy,
        reference_continuation_actions: Callable[[WorkerContext], list[PlannedAction]]
        | None = None,
        requirements: list[RequirementDraft] | None = None,
        budget_limits: BudgetLimits | None = None,
        include_t2: bool = False,
        include_t4: bool = False,
        metamorphic_tests: dict[str, str] | None = None,
        requirement_dag_judge_nodes: list[dict[str, Any]] | None = None,
        dynamic_invariants: dict[str, str] | None = None,
        evolved_namespace: str | None = None,
        resume: bool = False,
        reference_implementations: dict[str, str] | None = None,
        allow_empty_heldout: bool = False,
        oracle_free_suite: OracleFreeSuite | None = None,
        oracle_free_suites: dict[str, OracleFreeSuite] | None = None,
        differential_hook: DifferentialHook | None = None,
    ) -> LoopResult:
        limits = budget_limits or BudgetLimits()
        budget = BudgetTracker(limits)
        run_dir = self.work_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        ledger = AppendOnlyLedger(run_dir / "ledger")

        prior_events = ledger.get_events(run_id) if ledger.get_run(run_id) is not None else []
        start_ns = 1_700_000_000_000_000_000
        if prior_events:
            start_ns = max(start_ns, max(ev.timestamp_ns for ev in prior_events) + 1_000_000)
        clock = DeterministicClock(start_ns=start_ns)

        if ledger.get_run(run_id) is None:
            ledger.append_run(
                RunRecord(
                    run_id=run_id,
                    goal=goal_text,
                    container_digest=self.bus.container.image_digest,
                    seed=1000,
                    started_at_ns=clock.now_ns(),
                    metadata={"stage": "run_goal"},
                )
            )

        already_committed_set: set[str] = set()
        resume_epoch = 0
        if resume:
            already_committed_set = {
                str(ev.payload["task_id"])
                for ev in prior_events
                if ev.event_type == "TASK_COMMITTED" and "task_id" in ev.payload
            }
            resume_epoch = 1 + sum(1 for ev in prior_events if ev.event_type == "RUN_RESUMED")
            ledger.append_event(
                run_id,
                "RUN_RESUMED",
                clock.now_ns(),
                {
                    "resume_epoch": resume_epoch,
                    "skipped_tasks": sorted(already_committed_set),
                },
            )

        # [1] SPEC COMPILER + Uncertainty Gate (§8 Stop #5)
        try:
            spec = self.compiler.compile(
                goal_text=goal_text,
                requirements=requirements,
                spec_id=f"spec_{run_id}",
                allow_empty_heldout=allow_empty_heldout,
            )
        except HumanClarificationRequiredError as exc:
            ledger.close()
            return LoopResult(
                run_id=run_id,
                passed=False,
                stop_reason=LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN,
                escalated_to_human=True,
                human_questions=exc.questions,
                budget_usage=budget.snapshot(),
                details={"contradictions": exc.contradictions},
            )

        # [2] SPEC AUDIT GATE + Proxy/Held-out Consistency (`M9-E`) + I5 No-Op Baseline (§8 Stop #4)
        try:
            audit_rep = self.audit_gate.audit(
                spec=spec,
                initial_workspace=initial_workspace,
                reference_implementations=reference_implementations,
            )
        except HumanClarificationRequiredError as exc:
            ledger.close()
            return LoopResult(
                run_id=run_id,
                passed=False,
                stop_reason=LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN,
                escalated_to_human=True,
                human_questions=exc.questions,
                budget_usage=budget.snapshot(),
                details={
                    "contradictions": exc.contradictions,
                    "oracle_consistency_clean": False,
                },
            )
        except NoOpBaselineHarnessError as exc:
            ledger.close()
            return LoopResult(
                run_id=run_id,
                passed=False,
                stop_reason=LoopStopReason.HARNESS_ERROR_NOOP,
                escalated_to_human=True,
                budget_usage=budget.snapshot(),
                details={"harness_error": str(exc)},
            )

        # [3] TASK GRAPH
        tasks = build_task_graph(spec)
        node_by_id = {n.id: n for n in spec.nodes}

        # Prepare active working directory cloned from `committed_workspace` (on resume) or `initial_workspace`
        live_ws = run_dir / "workspace"
        committed_ws = run_dir / "committed_workspace"
        if live_ws.exists():
            shutil.rmtree(live_ws)
        if resume and committed_ws.is_dir():
            shutil.copytree(committed_ws, live_ws)
        else:
            shutil.copytree(initial_workspace, live_ws)

        committed_tasks: list[str] = [
            t.task_id for t in tasks if t.task_id in already_committed_set
        ]
        all_attributions: list[dict[str, Any]] = []
        all_ladder_history: list[RepairLadderRung] = []
        total_skips = 0
        last_delta: float | None = None
        last_oracle_free_summary: dict[str, dict[str, Any]] | None = None
        last_differential_payload: dict[str, Any] | None = None

        try:
            for idx, task in enumerate(tasks):
                if task.task_id in already_committed_set:
                    continue
                remaining_ids = [
                    t.task_id for t in tasks[idx:] if t.task_id not in set(committed_tasks)
                ]
                budget.check()

                node = node_by_id[task.requirement_id]
                ladder = RepairLadderController(max_attempts=limits.max_repair_attempts)
                current_rung = RepairLadderRung.SAME_MODEL
                current_family = ladder.primary_family
                attempt = 0
                last_attr_dict: dict[str, Any] | None = None

                # Checkpoint clean task baseline before repair attempts
                task_checkpoint = run_dir / f"ckpt_{task.task_id}"
                if task_checkpoint.exists():
                    shutil.rmtree(task_checkpoint)
                shutil.copytree(live_ws, task_checkpoint)

                while True:
                    # Restore clean task checkpoint before each attempt
                    if live_ws.exists():
                        shutil.rmtree(live_ws)
                    shutil.copytree(task_checkpoint, live_ws)

                    ctx = WorkerContext(
                        system_prompt=WORKER_RUNTIME_SYSTEM_PROMPT,
                        task_id=task.task_id,
                        statement=task.statement,
                        target_file=task.target_file,
                        function_name=task.function_name,
                        arg_names=task.arg_names,
                        visible_proxy_tests=task.visible_proxy_tests,
                        ladder_rung=current_rung,
                        model_family=current_family,
                        repair_attempt=attempt,
                        attributed_cause=last_attr_dict,
                    )

                    # [4] EXECUTE inside ToolTape + Independent Effect Probes
                    epoch_prefix = f"{run_id}_r{resume_epoch}" if resume else run_id
                    iter_run_id = f"{epoch_prefix}_{task.task_id}_att{attempt}"
                    tape_runner = TapeRunner(run_dir / f"tape_{iter_run_id}")
                    actions = worker_policy(ctx, live_ws)
                    for act in actions:
                        budget.record_cost(act.cost)
                    # Enforce budget ceiling immediately after worker step spend (§8 Stop #1)
                    budget.check()

                    manifest = tape_runner.record_run(
                        run_id=iter_run_id,
                        goal=task.statement,
                        workspace=live_ws,
                        actions=actions,
                        ledger=ledger,
                        env=FrozenEnvSnapshot(
                            run_id=iter_run_id,
                            container_digest=self.bus.container.image_digest,
                            seed=1000 + attempt,
                        ),
                    )

                    invalid_output_payload: dict[str, Any] | None = None
                    for act in actions:
                        sc = act.claim.structured_claim
                        if sc.get("event_type") == "MODEL_OUTPUT_INVALID":
                            invalid_output_payload = {
                                "iter_run_id": iter_run_id,
                                "reason": str(sc.get("reason", "invalid model output")),
                                "raw_text": str(sc.get("raw_text", ""))[:2000],
                                "model": str(sc.get("model", "")),
                            }
                            if not sc.get("emitted_to_ledger"):
                                ledger.append_event(
                                    run_id,
                                    "MODEL_OUTPUT_INVALID",
                                    clock.now_ns(),
                                    invalid_output_payload,
                                )

                    # [5] VERIFIER BUS (First run T0..T2 ONLY so T3 held-out is touched AT MOST ONCE!)
                    active_of_suite = (oracle_free_suites or {}).get(node.id) or oracle_free_suite
                    merged_dyn_inv: dict[str, str] = dict(dynamic_invariants or {})
                    merged_meta_tests: dict[str, str] = dict(metamorphic_tests or {})
                    effective_include_t2 = include_t2
                    if active_of_suite is not None:
                        merged_dyn_inv.update(active_of_suite.dynamic_invariants)
                        merged_meta_tests.update(active_of_suite.metamorphic_tests)
                        effective_include_t2 = True

                    if include_t4 and not requirement_dag_judge_nodes:
                        active_ids = {t_id.removeprefix("task_") for t_id in committed_tasks} | {
                            node.id
                        }
                        task_dag_nodes = [
                            {
                                "id": n_id,
                                "statement": node_by_id[n_id].statement,
                                "depends_on": [
                                    d for d in node_by_id[n_id].depends_on if d in active_ids
                                ],
                                "evidence_file": node_by_id[n_id].target_file,
                                "required_tokens": [f"def {node_by_id[n_id].function_name}"],
                                "forbidden_tokens": ["eval(", "exec("],
                            }
                            for n_id in spec.topological_order
                            if n_id in active_ids
                        ]
                    else:
                        task_dag_nodes = list(requirement_dag_judge_nodes or [])

                    ver_state_inloop = VerificationState(
                        workspace_path=str(live_ws),
                        proxy_tests=task.visible_proxy_tests,
                        dynamic_invariants=merged_dyn_inv,
                        metamorphic_tests=merged_meta_tests,
                        t0_config={"compile": True, "lint": True},
                        t1_config={"security_scan": True, "api_contracts": [task.api_contract]},
                        evolved_namespace=evolved_namespace,
                        requirement_dag_nodes=task_dag_nodes,
                    )
                    inloop_report = self.bus.evaluate(
                        ver_state_inloop,
                        include_t2=effective_include_t2,
                        include_t3=False,
                        include_t4=include_t4,
                    )
                    if active_of_suite is not None:
                        last_oracle_free_summary = extract_oracle_free_summary(
                            inloop_report,
                            relation_count=len(active_of_suite.relations),
                            garbage_case_count=active_of_suite.garbage_case_count,
                        )

                    if inloop_report.passed:
                        # T0..T2 (+T4) passed! Now evaluate T3 held-out ONCE for this milestone (when present)!
                        if node.heldout_oracle_id:
                            self.gaming_monitor.claim_milestone_t3_slot(run_id, node.id)
                            t3_ev = self.bus.verify_t3(
                                VerificationState(
                                    workspace_path=str(live_ws),
                                    heldout_oracle_id=node.heldout_oracle_id,
                                )
                            )
                            try:
                                g_dec = self.gaming_monitor.evaluate_delta(
                                    milestone_id=node.id,
                                    t0_t2_passed=True,
                                    t3_passed=t3_ev.passed,
                                    score_proxy=inloop_report.score_proxy,
                                    score_heldout=t3_ev.score,
                                )
                                last_delta = g_dec.delta
                            except GamingAlarmError as g_exc:
                                # §8 Stop #3: Gaming Alarm -> HARD STOP, ZERO COMMIT, ESCALATE TO HUMAN!
                                if live_ws.exists():
                                    shutil.rmtree(live_ws)
                                shutil.copytree(task_checkpoint, live_ws)
                                ledger.append_event(
                                    iter_run_id,
                                    "GAMING_ALARM_HARD_STOP",
                                    clock.now_ns(),
                                    {
                                        "score_proxy": g_exc.score_proxy,
                                        "score_heldout": g_exc.score_heldout,
                                        "delta": g_exc.delta,
                                    },
                                )
                                ledger.close()
                                return LoopResult(
                                    run_id=run_id,
                                    passed=False,
                                    stop_reason=LoopStopReason.GAMING_ALARM,
                                    committed_tasks=committed_tasks,
                                    remaining_tasks=remaining_ids,
                                    escalated_to_human=True,
                                    budget_usage=budget.snapshot(),
                                    ladder_history=all_ladder_history,
                                    ladder_skips_triggered=total_skips,
                                    delta_gaming=g_exc.delta,
                                    attributions=all_attributions,
                                    details=(
                                        {"oracle_free": last_oracle_free_summary}
                                        if last_oracle_free_summary is not None
                                        else {}
                                    ),
                                )

                        # §8 Stop #6: I9 Mutation Score Gate before milestone commit
                        if self.mutation_gate_hook is not None:
                            mut_ok, cur_mut, base_mut = self.mutation_gate_hook()
                            if not mut_ok:
                                ledger.close()
                                return LoopResult(
                                    run_id=run_id,
                                    passed=False,
                                    stop_reason=LoopStopReason.MUTATION_SCORE_DROPPED,
                                    committed_tasks=committed_tasks,
                                    remaining_tasks=remaining_ids,
                                    escalated_to_human=True,
                                    budget_usage=budget.snapshot(),
                                    ladder_history=all_ladder_history,
                                    ladder_skips_triggered=total_skips,
                                    delta_gaming=last_delta,
                                    attributions=all_attributions,
                                    details={
                                        "mutation_score": cur_mut,
                                        "baseline_mutation_score": base_mut,
                                        **(
                                            {"oracle_free": last_oracle_free_summary}
                                            if last_oracle_free_summary is not None
                                            else {}
                                        ),
                                    },
                                )

                        # M9-D (Invariant I18): 3rd-family differential fuzz consensus before commit!
                        if differential_hook is not None:
                            diff_ok, diff_payload, diff_cost = differential_hook(node, live_ws)
                            last_differential_payload = diff_payload
                            budget.record_cost(diff_cost)
                            budget.check()
                            if not diff_ok:
                                if live_ws.exists():
                                    shutil.rmtree(live_ws)
                                shutil.copytree(task_checkpoint, live_ws)
                                ledger.append_event(
                                    iter_run_id,
                                    "DIFFERENTIAL_DISAGREEMENT",
                                    clock.now_ns(),
                                    {
                                        "task_id": task.task_id,
                                        "requirement_id": task.requirement_id,
                                        "agreement_rate": diff_payload.get("agreement_rate"),
                                        "disagreements_count": len(
                                            diff_payload.get("disagreements", [])
                                        ),
                                    },
                                )
                                ledger.close()
                                return LoopResult(
                                    run_id=run_id,
                                    passed=False,
                                    stop_reason=LoopStopReason.DIFFERENTIAL_DISAGREEMENT,
                                    committed_tasks=committed_tasks,
                                    remaining_tasks=remaining_ids,
                                    escalated_to_human=True,
                                    budget_usage=budget.snapshot(),
                                    ladder_history=all_ladder_history,
                                    ladder_skips_triggered=total_skips,
                                    delta_gaming=last_delta,
                                    attributions=all_attributions,
                                    details={
                                        "differential": diff_payload,
                                        **(
                                            {"oracle_free": last_oracle_free_summary}
                                            if last_oracle_free_summary is not None
                                            else {}
                                        ),
                                    },
                                )

                        # All tiers + Δ + mutation gate + differential consensus passed -> commit milestone!
                        committed_tasks.append(task.task_id)
                        ledger.append_event(
                            run_id,
                            "TASK_COMMITTED",
                            clock.now_ns(),
                            {
                                "task_id": task.task_id,
                                "requirement_id": task.requirement_id,
                            },
                        )
                        if committed_ws.exists():
                            shutil.rmtree(committed_ws)
                        shutil.copytree(live_ws, committed_ws)
                        break

                    # [7] ATTRIBUTE (T0–T2 failed: run deterministic replay bisect + CF + TRAIL)
                    fail_outs = [
                        str(c.details.get("output", "") or c.details.get("stdout", ""))
                        for ev in inloop_report.tiers.values()
                        for c in ev.checks
                        if not c.passed
                    ]
                    fail_details = {"output": "\n".join(fail_outs)}

                    if invalid_output_payload is not None:
                        attr_report = self._build_invalid_output_attribution(
                            manifest=manifest,
                            invalid_payload=invalid_output_payload,
                        )
                    else:
                        clean_ctx = WorkerContext(
                            system_prompt=WORKER_RUNTIME_SYSTEM_PROMPT,
                            task_id=task.task_id,
                            statement=task.statement,
                            target_file=task.target_file,
                            function_name=task.function_name,
                            arg_names=task.arg_names,
                            visible_proxy_tests=task.visible_proxy_tests,
                            ladder_rung=RepairLadderRung.DIFFERENT_MODEL_FAMILY,
                            model_family=ladder.alternate_family,
                            repair_attempt=attempt + 1,
                        )

                        if reference_continuation_actions is not None:
                            ref_acts = reference_continuation_actions(clean_ctx)
                        else:
                            ref_acts = worker_policy(clean_ctx, task_checkpoint)
                            for act in ref_acts:
                                budget.record_cost(act.cost)
                            budget.check()

                        attr_report = self._run_attribution_for_attempt(
                            task_proxy_tests=task.visible_proxy_tests,
                            task_api_contract=task.api_contract,
                            dynamic_invariants=merged_dyn_inv,
                            metamorphic_tests=merged_meta_tests,
                            include_t2=effective_include_t2,
                            tape_runner=tape_runner,
                            manifest=manifest,
                            ref_acts=ref_acts,
                            ledger=ledger,
                            baseline_score=inloop_report.score_proxy,
                            fail_details=fail_details,
                        )
                    last_attr_dict = serialize_attribution_report(attr_report)
                    all_attributions.append(last_attr_dict)

                    # [8] REPAIR LADDER + No-Progress Duplicate Attribution Detector
                    next_rung, next_family, skipped = ladder.next_rung(attr_report.attribution)
                    all_ladder_history.append(next_rung)
                    if skipped:
                        total_skips += 1

                    if next_rung == RepairLadderRung.HUMAN_ESCALATION:
                        ledger.close()
                        return LoopResult(
                            run_id=run_id,
                            passed=False,
                            stop_reason=LoopStopReason.REPAIR_EXHAUSTED_HUMAN,
                            committed_tasks=committed_tasks,
                            remaining_tasks=remaining_ids,
                            escalated_to_human=True,
                            budget_usage=budget.snapshot(),
                            ladder_history=all_ladder_history,
                            ladder_skips_triggered=total_skips,
                            attributions=all_attributions,
                            details=(
                                {"oracle_free": last_oracle_free_summary}
                                if last_oracle_free_summary is not None
                                else {}
                            ),
                        )

                    current_rung = next_rung
                    current_family = next_family
                    attempt += 1

        except BudgetExceededError as b_exc:
            done_set = set(committed_tasks)
            rem = [t.task_id for t in tasks if t.task_id not in done_set]
            ledger.close()
            return LoopResult(
                run_id=run_id,
                passed=False,
                stop_reason=LoopStopReason.BUDGET_EXCEEDED,
                committed_tasks=committed_tasks,
                remaining_tasks=rem,
                escalated_to_human=False,
                budget_usage=b_exc.usage,
                ladder_history=all_ladder_history,
                ladder_skips_triggered=total_skips,
                attributions=all_attributions,
                details={
                    "budget_error": b_exc.reason,
                    **(
                        {"oracle_free": last_oracle_free_summary}
                        if last_oracle_free_summary is not None
                        else {}
                    ),
                },
            )

        ledger.close()
        return LoopResult(
            run_id=run_id,
            passed=True,
            stop_reason=LoopStopReason.COMPLETED,
            committed_tasks=committed_tasks,
            remaining_tasks=[],
            escalated_to_human=False,
            budget_usage=budget.snapshot(),
            ladder_history=all_ladder_history,
            ladder_skips_triggered=total_skips,
            delta_gaming=last_delta,
            attributions=all_attributions,
            details={
                "contradictions": audit_rep.contradictions,
                "oracle_consistency_clean": audit_rep.oracle_consistency_clean,
                **(
                    {"oracle_free": last_oracle_free_summary}
                    if last_oracle_free_summary is not None
                    else {}
                ),
                **(
                    {"differential": last_differential_payload}
                    if last_differential_payload is not None
                    else {}
                ),
            },
        )

    def _run_attribution_for_attempt(
        self,
        *,
        task_proxy_tests: dict[str, str],
        task_api_contract: dict[str, Any],
        dynamic_invariants: dict[str, str],
        metamorphic_tests: dict[str, str],
        include_t2: bool,
        tape_runner: TapeRunner,
        manifest: Any,
        ref_acts: list[PlannedAction],
        ledger: AppendOnlyLedger,
        baseline_score: float,
        fail_details: dict[str, Any],
    ) -> Any:
        def _ver_fn(ws_p: Path) -> tuple[bool, float, dict[str, Any]]:
            rep = self.bus.evaluate(
                VerificationState(
                    workspace_path=str(ws_p),
                    proxy_tests=task_proxy_tests,
                    dynamic_invariants=dynamic_invariants,
                    metamorphic_tests=metamorphic_tests,
                    t0_config={"compile": True, "lint": True},
                    t1_config={"security_scan": True, "api_contracts": [task_api_contract]},
                ),
                include_t2=include_t2,
            )
            return rep.passed, rep.score_proxy, {}

        def _cont_fn(ws_p: Path, start_k: int, _rem: list[TapeStepEntry]) -> None:
            for j in range(start_k, len(ref_acts)):
                a = ref_acts[j]
                tape_runner.tools[a.tool_name](ws_p, a.tool_args, manifest.env, "record")

        def _cf_sampler(
            _ws_p: Path,
            k_i: int,
            _orig: TapeStepEntry,
            _rng: random.Random,
        ) -> PlannedAction:
            if k_i < len(ref_acts):
                return ref_acts[k_i]
            return ref_acts[-1]

        attr_pipe = AttributionPipeline(
            tape_runner=tape_runner,
            verifier_fn=_ver_fn,
            continuation_fn=_cont_fn,
            counterfactual_sampler=_cf_sampler,
            n_counterfactuals=5,
        )
        try:
            report, _, _ = attr_pipe.attribute(
                manifest=manifest,
                ledger=ledger,
                baseline_score=baseline_score,
                known_failure_details=fail_details,
            )
            return report
        except UnbisectableRunError:
            culprit_entry = manifest.steps[0]
            steps = ledger.get_steps(manifest.run_id)
            step_rec = steps[0] if steps else None
            group, category, leaf = classify_trail_fault(
                culprit_entry=culprit_entry,
                all_entries=manifest.steps,
                step_record=step_rec,
                verifier_details=fail_details,
            )
            locked = LockedAttribution.create_sealed(
                run_id=manifest.run_id,
                culprit_step_index=0,
                tool_name=culprit_entry.tool_name,
                trail_group=group,
                trail_category=category,
                trail_leaf=leaf,
                replays_used=1,
                counterfactual_pass_rate=0.0,
                average_causal_effect=0.0,
                ci_low=0.0,
                ci_high=0.0,
            )
            window = LocalStepWindow(
                culprit_step_index=0,
                tool_name=culprit_entry.tool_name,
                tool_args_summary=canonical_json(culprit_entry.tool_args)[:160],
                failure_excerpt=str(fail_details.get("output", ""))[-300:],
            )
            return AttributionNarrator().narrate(locked, window)

    @staticmethod
    def _build_invalid_output_attribution(
        *,
        manifest: Any,
        invalid_payload: dict[str, Any],
    ) -> AttributionReport:
        culprit_entry = manifest.steps[0]
        locked = LockedAttribution.create_sealed(
            run_id=manifest.run_id,
            culprit_step_index=0,
            tool_name=culprit_entry.tool_name,
            trail_group=TrailGroup.EXECUTION,
            trail_category=TrailCategory.TOOL_INVOCATION,
            trail_leaf=TrailLeaf.MALFORMED_TOOL_PAYLOAD,
            replays_used=0,
            counterfactual_pass_rate=0.0,
            average_causal_effect=0.0,
            ci_low=0.0,
            ci_high=0.0,
        )
        window = LocalStepWindow(
            culprit_step_index=0,
            tool_name=culprit_entry.tool_name,
            tool_args_summary="{}",
            failure_excerpt=str(invalid_payload.get("reason", "MODEL_OUTPUT_INVALID"))[:300],
        )
        return AttributionNarrator().narrate(locked, window)
