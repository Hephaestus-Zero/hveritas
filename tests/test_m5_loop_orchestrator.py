"""M5 acceptance tests: End-to-end Loop Orchestrator, Escape Ladder, Duplicate-Attribution Skip, Budgets, and all §8 Stops."""

from __future__ import annotations

from pathlib import Path

from hveritas.harness import EncryptedOracleVault, IsolatedContainerVerifier
from hveritas.ledger import AgentClaim, CostRecord
from hveritas.loop import (
    BudgetLimits,
    GoalLoopOrchestrator,
    LoopStopReason,
    RepairLadderRung,
    WorkerContext,
)
from hveritas.spec import IOAssertion, RequirementDraft
from hveritas.tape import PlannedAction
from hveritas.verify import VerifierBus

HONEST_DISCOUNT_CODE = (
    "def compute_total(prices: list[int], coupon_pct: int) -> int:\n"
    "    return round(sum(prices) * (100 - coupon_pct) / 100)\n"
)

BUGGY_DISCOUNT_CODE = (
    "def compute_total(prices: list[int], coupon_pct: int) -> int:\n"
    "    if coupon_pct > 10:\n"
    "        return 0\n"
    "    return sum(prices)  # bug: ignores 10% coupon!\n"
)

GAMING_DISCOUNT_CODE = (
    "def compute_total(prices: list[int], coupon_pct: int) -> int:\n"
    "    if prices == [100, 200] and coupon_pct == 10:\n"
    "        return 270\n"
    "    if prices == [50] and coupon_pct == 0:\n"
    "        return 50\n"
    "    return 0\n"
)


def _starter_discount_ws(base: Path) -> Path:
    ws = base / "starter_ws"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "discount.py").write_text(
        "def compute_total(prices: list[int], coupon_pct: int) -> int:\n    raise NotImplementedError\n",
        encoding="utf-8",
    )
    return ws


def _make_orchestrator(tmp_path: Path, **kwargs: object) -> GoalLoopOrchestrator:
    vault = EncryptedOracleVault(
        repo_dir=tmp_path / "oracles_repo",
        key_file=tmp_path / "oracle.key",
    )
    bus = VerifierBus(IsolatedContainerVerifier(oracle_vault=vault))
    return GoalLoopOrchestrator(
        work_root=tmp_path / "loop_work",
        oracle_vault=vault,
        verifier_bus=bus,
        **kwargs,  # type: ignore[arg-type]
    )


def test_m5_end_to_end_goal_with_same_attribution_twice_skips_ladder_to_different_family(
    tmp_path: Path,
) -> None:
    orch = _make_orchestrator(tmp_path)
    ws = _starter_discount_ws(tmp_path)

    # `family-alpha` gets stuck making the EXACT same off-by-one/branch fault twice in a row
    # (attempt 0 and repair attempt 1 on `SAME_MODEL`); when `NoProgressDetector` skips
    # `TIGHTER_CONSTRAINTS` and escalates to `family-beta` (`DIFFERENT_MODEL_FAMILY`), it succeeds!
    def worker_policy(ctx: WorkerContext, _ws: Path) -> list[PlannedAction]:
        assert "Görünmeyen bir oracle tarafından puanlanacaksın" in ctx.system_prompt
        if ctx.model_family == "family-beta":
            code = HONEST_DISCOUNT_CODE
        else:
            code = BUGGY_DISCOUNT_CODE
        return [
            PlannedAction(
                tool_name="write_file",
                tool_args={"path": "discount.py", "content": code},
                claim=AgentClaim(summary=f"Attempt {ctx.repair_attempt}", reported_success=True),
                cost=CostRecord(input_tokens=120, output_tokens=60, usd=0.002),
            )
        ]

    res = orch.run_goal(
        run_id="m5-e2e-skip",
        goal_text="Implement discount total calculation module.",
        initial_workspace=ws,
        worker_policy=worker_policy,
    )

    assert res.passed is True
    assert res.stop_reason == LoopStopReason.COMPLETED
    assert res.committed_tasks == ["task_req_discount"]
    assert res.remaining_tasks == []
    assert res.delta_gaming == 0.0
    # Verify exact ladder trajectory: SAME_MODEL -> (duplicate attribution skip!) -> DIFFERENT_MODEL_FAMILY
    assert res.ladder_skips_triggered == 1
    assert res.ladder_history == [
        RepairLadderRung.SAME_MODEL,
        RepairLadderRung.DIFFERENT_MODEL_FAMILY,
    ]
    assert len(res.attributions) == 2
    assert res.attributions[0]["culprit_step_index"] == 0
    assert res.attributions[1]["culprit_step_index"] == 0


def test_m5_budget_exceeded_stops_and_reports_partial_and_remaining_tasks(
    tmp_path: Path,
) -> None:
    orch = _make_orchestrator(tmp_path)
    ws = tmp_path / "ws_multi"
    ws.mkdir()
    (ws / "step_a.py").write_text(
        "def double(x: int) -> int:\n    raise NotImplementedError\n", encoding="utf-8"
    )
    (ws / "step_b.py").write_text(
        "def triple(x: int) -> int:\n    raise NotImplementedError\n", encoding="utf-8"
    )

    reqs = [
        RequirementDraft(
            id="req_a",
            statement="Implement double(x)",
            target_file="step_a.py",
            function_name="double",
            arg_names=["x"],
            proxy_assertions=[IOAssertion(function="double", args=[3], expected=6)],
            heldout_assertions=[IOAssertion(function="double", args=[11], expected=22)],
        ),
        RequirementDraft(
            id="req_b",
            statement="Implement triple(x)",
            target_file="step_b.py",
            function_name="triple",
            arg_names=["x"],
            depends_on=["req_a"],
            proxy_assertions=[IOAssertion(function="triple", args=[3], expected=9)],
            heldout_assertions=[IOAssertion(function="triple", args=[11], expected=33)],
        ),
    ]

    def worker_policy(ctx: WorkerContext, _ws: Path) -> list[PlannedAction]:
        if ctx.target_file == "step_a.py":
            return [
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "step_a.py",
                        "content": "def double(x: int) -> int:\n    return x * 2\n",
                    },
                    cost=CostRecord(input_tokens=200, output_tokens=100, usd=0.01),
                )
            ]
        return [
            PlannedAction(
                tool_name="write_file",
                tool_args={
                    "path": "step_b.py",
                    "content": "def triple(x: int) -> int:\n    return x * 3\n",
                },
                cost=CostRecord(input_tokens=400, output_tokens=200, usd=0.02),
            )
        ]

    # Token ceiling = 500 -> Task A (300 tokens) commits, Task B (300 + 600 = 900 > 500) halts!
    res = orch.run_goal(
        run_id="m5-budget-stop",
        goal_text="Implement two-stage arithmetic pipeline.",
        initial_workspace=ws,
        worker_policy=worker_policy,
        requirements=reqs,
        budget_limits=BudgetLimits(max_tokens=500, max_usd=1.0, max_wall_seconds=120.0),
    )

    assert res.passed is False
    assert res.stop_reason == LoopStopReason.BUDGET_EXCEEDED
    assert res.committed_tasks == ["task_req_a"]
    assert res.remaining_tasks == ["task_req_b"]
    assert res.budget_usage.total_tokens == 900


def test_m5_gaming_alarm_hard_stops_without_commit_and_escalates_to_human(
    tmp_path: Path,
) -> None:
    orch = _make_orchestrator(tmp_path)
    ws = _starter_discount_ws(tmp_path)

    def cheating_policy(_ctx: WorkerContext, _ws: Path) -> list[PlannedAction]:
        return [
            PlannedAction(
                tool_name="write_file",
                tool_args={"path": "discount.py", "content": GAMING_DISCOUNT_CODE},
                claim=AgentClaim(summary="All proxy tests green!", reported_success=True),
            )
        ]

    res = orch.run_goal(
        run_id="m5-gaming-stop",
        goal_text="Implement discount total calculation module.",
        initial_workspace=ws,
        worker_policy=cheating_policy,
    )

    assert res.passed is False
    assert res.stop_reason == LoopStopReason.GAMING_ALARM
    assert res.committed_tasks == []
    assert res.remaining_tasks == ["task_req_discount"]
    assert res.escalated_to_human is True
    assert res.delta_gaming is not None and res.delta_gaming > 0.5


def test_m5_remaining_section8_stop_conditions_noop_spec_and_mutation(tmp_path: Path) -> None:
    # 1. Spec ambiguous -> SPEC_UNCERTAIN_ASK_HUMAN
    orch1 = _make_orchestrator(tmp_path / "s1")
    ws1 = _starter_discount_ws(tmp_path / "s1")
    res_spec = orch1.run_goal(
        run_id="m5-ambiguous",
        goal_text="Implement discount calculator; behaviour is TBD / ???",
        initial_workspace=ws1,
        worker_policy=lambda _c, _w: [],
    )
    assert res_spec.stop_reason == LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN
    assert res_spec.escalated_to_human is True
    assert len(res_spec.human_questions) >= 1

    # 2. Pre-solved starter workspace -> HARNESS_ERROR_NOOP (I5)
    orch2 = _make_orchestrator(tmp_path / "s2")
    ws2 = tmp_path / "s2_ws"
    ws2.mkdir(parents=True)
    (ws2 / "discount.py").write_text(HONEST_DISCOUNT_CODE, encoding="utf-8")
    res_noop = orch2.run_goal(
        run_id="m5-noop-err",
        goal_text="Implement discount calculator.",
        initial_workspace=ws2,
        worker_policy=lambda _c, _w: [],
    )
    assert res_noop.stop_reason == LoopStopReason.HARNESS_ERROR_NOOP

    # 3. Mutation score regressed -> MUTATION_SCORE_DROPPED (I9)
    orch3 = _make_orchestrator(
        tmp_path / "s3",
        mutation_gate_hook=lambda: (False, 0.65, 0.85),
    )
    ws3 = _starter_discount_ws(tmp_path / "s3")
    res_mut = orch3.run_goal(
        run_id="m5-mut-drop",
        goal_text="Implement discount calculator.",
        initial_workspace=ws3,
        worker_policy=lambda _c, _w: [
            PlannedAction(
                tool_name="write_file",
                tool_args={"path": "discount.py", "content": HONEST_DISCOUNT_CODE},
            )
        ],
    )
    assert res_mut.passed is False
    assert res_mut.stop_reason == LoopStopReason.MUTATION_SCORE_DROPPED
    assert res_mut.committed_tasks == []
