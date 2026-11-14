"""M8-A & M8-B acceptance tests: ModelBackend layer & LlmWorkerPolicy (Invariants I10, I11, I12, I13)."""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
from pathlib import Path

import pytest

from hveritas.harness import EncryptedOracleVault, IsolatedContainerVerifier
from hveritas.harness.isolation import SCRATCH_ROOT
from hveritas.harness.worker_prompt import WORKER_RUNTIME_SYSTEM_PROMPT
from hveritas.ledger import AppendOnlyLedger
from hveritas.loop import (
    BudgetLimits,
    BudgetTracker,
    GoalLoopOrchestrator,
    LoopStopReason,
    RepairLadderRung,
    WorkerContext,
)
from hveritas.verify import VerifierBus
from hveritas.worker import (
    FakeBackend,
    HxCliBackend,
    LlmWorkerPolicy,
    ModelFamilyNotDistinctError,
    ModelProtocolError,
    ModelResponse,
    ModelTimeoutError,
    PlannerSideEffectError,
)

HONEST_DISCOUNT_CODE = (
    "def compute_total(prices: list[int], coupon_pct: int) -> int:\n"
    "    return round(sum(prices) * (100 - coupon_pct) / 100)\n"
)


def _workspace_hashes(ws: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(ws.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(ws))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _starter_discount_ws(base: Path) -> Path:
    ws = base / "starter_ws"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "discount.py").write_text(
        "def compute_total(prices: list[int], coupon_pct: int) -> int:\n    raise NotImplementedError\n",
        encoding="utf-8",
    )
    return ws


def _make_orchestrator(tmp_path: Path) -> GoalLoopOrchestrator:
    vault = EncryptedOracleVault(
        repo_dir=tmp_path / "oracles_repo",
        key_file=tmp_path / "oracle.key",
    )
    bus = VerifierBus(IsolatedContainerVerifier(oracle_vault=vault))
    return GoalLoopOrchestrator(
        work_root=tmp_path / "loop_work",
        oracle_vault=vault,
        verifier_bus=bus,
    )


def _sample_ctx(
    *,
    model_family: str = "family-alpha",
    ladder_rung: RepairLadderRung = RepairLadderRung.SAME_MODEL,
    repair_attempt: int = 0,
    attributed_cause: dict[str, object] | None = None,
) -> WorkerContext:
    return WorkerContext(
        system_prompt=WORKER_RUNTIME_SYSTEM_PROMPT,
        task_id="task_req_discount",
        statement="Implement compute_total(prices, coupon_pct) in discount.py",
        target_file="discount.py",
        function_name="compute_total",
        arg_names=["prices", "coupon_pct"],
        visible_proxy_tests={
            "test_proxy.py": "from discount import compute_total\nassert compute_total([100, 200], 10) == 270\n"
        },
        ladder_rung=ladder_rung,
        model_family=model_family,
        repair_attempt=repair_attempt,
        attributed_cause=attributed_cause,
    )


def _write_executable_hx_stub(stub_dir: Path, body: str) -> Path:
    stub_dir.mkdir(parents=True, exist_ok=True)
    script = stub_dir / "fake_hx_cli.py"
    script.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_i10_hx_cli_backend_runs_in_sealed_empty_scratch_and_preserves_live_workspace(
    tmp_path: Path,
) -> None:
    """I10: Planner never touches live workspace; side effects raise PlannerSideEffectError."""
    scratch_test_dir = SCRATCH_ROOT / f"test_m8_i10_{tmp_path.name}"
    ws = _starter_discount_ws(tmp_path)
    hashes_before = _workspace_hashes(ws)

    # 1. Clean hx CLI invocation with banner line before JSON envelope
    hx_ok = _write_executable_hx_stub(
        scratch_test_dir / "ok",
        """
import json, os, pathlib, sys
args = sys.argv[1:]
assert "-C" in args
cwd_arg = pathlib.Path(args[args.index("-C") + 1]).resolve()
assert cwd_arg == pathlib.Path.cwd().resolve()
assert list(cwd_arg.iterdir()) == [], "Sealed scratch dir must start completely empty!"
plan_json = json.dumps({
    "actions": [
        {
            "tool_name": "write_file",
            "tool_args": {"path": "discount.py", "content": "def compute_total(prices, coupon_pct):\\n    return 270\\n"},
            "claim": {"summary": "planned write", "reported_success": True},
        }
    ]
})
print("[hx] gateway route warming...")
print(json.dumps({
    "ok": True,
    "text": plan_json,
    "model": "argon",
    "route": "google-antigravity/gemini-4-argon",
    "family": "gemini",
    "input_tokens": 3327,
    "output_tokens": 38,
    "elapsed_ms": 26377.5,
    "modified_files": [],
}))
""",
    )
    backend = HxCliBackend(
        hx_bin=hx_ok,
        planner_scratch_root=scratch_test_dir / "planner_sealed",
        live_workspace_guard=ws,
    )
    policy = LlmWorkerPolicy(backend=backend, primary_model="argon", alternate_model="muse")
    planned = policy(_sample_ctx(), ws)

    assert len(planned) == 1
    assert planned[0].tool_name == "write_file"
    assert _workspace_hashes(ws) == hashes_before

    # 2. Planner reporting modified_files != [] raises PlannerSideEffectError
    hx_mod = _write_executable_hx_stub(
        scratch_test_dir / "mod",
        """
import json
print(json.dumps({
    "ok": True,
    "text": "{}",
    "model": "muse",
    "family": "claude",
    "input_tokens": 10,
    "output_tokens": 5,
    "elapsed_ms": 12.0,
    "modified_files": ["discount.py"],
}))
""",
    )
    bad_backend_mod = HxCliBackend(
        hx_bin=hx_mod,
        planner_scratch_root=scratch_test_dir / "planner_mod",
        live_workspace_guard=ws,
    )
    with pytest.raises(PlannerSideEffectError, match="modified_files|modify files"):
        bad_backend_mod.complete(system="sys", user="usr", model="muse", timeout_s=5.0)
    assert _workspace_hashes(ws) == hashes_before

    # 3. Planner stealthily creating a file inside -C scratch dir raises PlannerSideEffectError
    hx_stealth = _write_executable_hx_stub(
        scratch_test_dir / "stealth",
        """
import json, pathlib
(pathlib.Path.cwd() / "rogue.py").write_text("x = 1\\n", encoding="utf-8")
print(json.dumps({
    "ok": True,
    "text": "{}",
    "model": "muse",
    "family": "claude",
    "input_tokens": 10,
    "output_tokens": 5,
    "elapsed_ms": 12.0,
    "modified_files": [],
}))
""",
    )
    bad_backend_stealth = HxCliBackend(
        hx_bin=hx_stealth,
        planner_scratch_root=scratch_test_dir / "planner_stealth",
        live_workspace_guard=ws,
    )
    with pytest.raises(PlannerSideEffectError, match="wrote files in sealed scratch dir"):
        bad_backend_stealth.complete(system="sys", user="usr", model="muse", timeout_s=5.0)

    # 4. Timeout & unparseable stdout raise ModelTimeoutError and ModelProtocolError
    hx_slow = _write_executable_hx_stub(
        scratch_test_dir / "slow",
        "import time\ntime.sleep(2.0)\n",
    )
    slow_backend = HxCliBackend(
        hx_bin=hx_slow,
        planner_scratch_root=scratch_test_dir / "planner_slow",
    )
    with pytest.raises(ModelTimeoutError):
        slow_backend.complete(system="s", user="u", model="muse", timeout_s=0.15)

    hx_bad_json = _write_executable_hx_stub(
        scratch_test_dir / "badjson",
        "print('completely non-json output')\n",
    )
    bad_json_backend = HxCliBackend(
        hx_bin=hx_bad_json,
        planner_scratch_root=scratch_test_dir / "planner_badjson",
    )
    with pytest.raises(ModelProtocolError):
        bad_json_backend.complete(system="s", user="u", model="muse", timeout_s=5.0)
    shutil.rmtree(scratch_test_dir, ignore_errors=True)


def test_i11_model_family_distinctness_enforced_from_actual_response_family(
    tmp_path: Path,
) -> None:
    """I11: Two aliases resolving to the same actual `family` raise ModelFamilyNotDistinctError."""
    ws = _starter_discount_ws(tmp_path)
    valid_plan = json.dumps(
        {
            "actions": [
                {
                    "tool_name": "write_file",
                    "tool_args": {"path": "discount.py", "content": HONEST_DISCOUNT_CODE},
                }
            ]
        }
    )

    same_family_backend = FakeBackend(
        lambda _sys, _usr, model: ModelResponse(
            text=valid_plan,
            model=str(model),
            family="claude",  # Both `muse` and `sonnet-alias` resolve to `"claude"`!
            input_tokens=100,
            output_tokens=25,
            elapsed_ms=50.0,
        )
    )
    policy = LlmWorkerPolicy(
        backend=same_family_backend,
        primary_model="muse",
        alternate_model="sonnet-alias",
    )

    # Primary call records resolved family = "claude"
    policy(_sample_ctx(model_family="family-alpha"), ws)

    # Escalating to DIFFERENT_MODEL_FAMILY ("family-beta") with same resolved family MUST fail!
    with pytest.raises(ModelFamilyNotDistinctError, match="I11 VIOLATION"):
        policy(
            _sample_ctx(
                model_family="family-beta",
                ladder_rung=RepairLadderRung.DIFFERENT_MODEL_FAMILY,
                repair_attempt=2,
            ),
            ws,
        )


def test_i12_real_token_and_wall_cost_flows_into_budget_tracker_without_double_counting(
    tmp_path: Path,
) -> None:
    """I12: Backend 3327/38 tokens -> BudgetTracker.snapshot().total_tokens == 3365."""
    ws = _starter_discount_ws(tmp_path)
    multi_action_plan = json.dumps(
        {
            "actions": [
                {
                    "tool_name": "write_file",
                    "tool_args": {"path": "discount.py", "content": HONEST_DISCOUNT_CODE},
                    "claim": {"summary": "write discount implementation", "reported_success": True},
                },
                {
                    "tool_name": "noop",
                    "tool_args": {},
                    "claim": {"summary": "done", "reported_success": True},
                },
            ]
        }
    )
    backend = FakeBackend(
        [
            ModelResponse(
                text=f"```json\n{multi_action_plan}\n```",
                model="argon",
                family="gemini",
                input_tokens=3327,
                output_tokens=38,
                elapsed_ms=26377.5,
                usd=0.015,
            )
        ]
    )
    policy = LlmWorkerPolicy(backend=backend, primary_model="argon", alternate_model="muse")
    actions = policy(_sample_ctx(), ws)
    assert len(actions) == 2
    assert actions[0].cost.input_tokens == 3327
    assert actions[0].cost.output_tokens == 38
    assert actions[0].cost.input_tokens + actions[0].cost.output_tokens == 3365
    assert actions[0].cost.wall_ms == 26377.5
    assert actions[1].cost.input_tokens + actions[1].cost.output_tokens == 0

    tracker = BudgetTracker(BudgetLimits(max_tokens=10_000))
    for act in actions:
        tracker.record_cost(act.cost)
    assert tracker.snapshot().total_tokens == 3365

    # Also verify inside full GoalLoopOrchestrator.run_goal
    orch = _make_orchestrator(tmp_path)
    policy_e2e = LlmWorkerPolicy(
        backend=FakeBackend(
            [
                ModelResponse(
                    text=multi_action_plan,
                    model="argon",
                    family="gemini",
                    input_tokens=3327,
                    output_tokens=38,
                    elapsed_ms=26377.5,
                    usd=0.015,
                )
            ]
        ),
        primary_model="argon",
        alternate_model="muse",
    )
    res = orch.run_goal(
        run_id="m8-i12-cost",
        goal_text="Implement discount total calculation module.",
        initial_workspace=ws,
        worker_policy=policy_e2e,
    )
    assert res.passed is True
    assert res.stop_reason == LoopStopReason.COMPLETED
    assert res.budget_usage.total_tokens == 3365


def test_i13_malformed_outputs_path_escapes_prompt_contract_and_orchestrator_survival(
    tmp_path: Path,
) -> None:
    """I13: Garbage/invalid tool plans never crash; MODEL_OUTPUT_INVALID logged; run_goal stops cleanly."""
    ws = _starter_discount_ws(tmp_path)
    (ws / "helper.py").write_text("HELPER_CONST = 100\n", encoding="utf-8")

    # 1. Verify prompt construction order, verbatim system prompt, repair briefing & tighter constraints
    captured_Backend = FakeBackend(
        [
            ModelResponse(
                text=json.dumps({"actions": [{"tool_name": "noop", "tool_args": {}}]}),
                model="muse",
                family="claude",
                input_tokens=50,
                output_tokens=10,
                elapsed_ms=20.0,
            )
        ]
    )
    p_prompt = LlmWorkerPolicy(backend=captured_Backend, max_actions=6)
    ctx_repair = _sample_ctx(
        ladder_rung=RepairLadderRung.TIGHTER_CONSTRAINTS,
        repair_attempt=2,
        attributed_cause={
            "culprit_step_index": 0,
            "tool_name": "write_file",
            "trail_leaf": "OFF_BY_ONE_OR_BOUNDARY",
            "explanation": "missed coupon math",
        },
    )
    p_prompt(ctx_repair, ws)
    call_rec = captured_Backend.calls[0]
    assert call_rec["system"] == WORKER_RUNTIME_SYSTEM_PROMPT
    user_p = str(call_rec["user"])
    idx_stmt = user_p.index("## 1. Task Statement")
    idx_api = user_p.index("## 2. API Contract")
    idx_proxy = user_p.index("## 3. Visible Proxy Tests")
    idx_ws = user_p.index("## 4. Workspace Summary")
    idx_rep = user_p.index("## 5. Repair Briefing")
    idx_tight = user_p.index("## 6. Tighter Constraints Escalation")
    assert idx_stmt < idx_api < idx_proxy < idx_ws < idx_rep < idx_tight
    assert (
        "Önceki denemede adım 0 (write_file) hatalıydı; TRAIL sınıfı OFF_BY_ONE_OR_BOUNDARY."
        in user_p
    )

    # 2. Invalid JSON, unknown tool_name, non-list run_cmd argv -> noop + MODEL_OUTPUT_INVALID
    standalone_ledger = AppendOnlyLedger(tmp_path / "standalone_ledger")
    bad_payloads = [
        "<<<NOT JSON AT ALL>>>",
        json.dumps({"actions": [{"tool_name": "rm_everything", "tool_args": {}}]}),
        json.dumps({"actions": [{"tool_name": "run_cmd", "tool_args": {"argv": "ls -la"}}]}),
    ]
    bad_backend = FakeBackend(
        [
            ModelResponse(
                text=txt,
                model="muse",
                family="claude",
                input_tokens=40,
                output_tokens=12,
                elapsed_ms=15.0,
            )
            for txt in bad_payloads
        ]
    )
    p_bad = LlmWorkerPolicy(
        backend=bad_backend,
        ledger=standalone_ledger,
        ledger_run_id="standalone_i13",
    )
    for _ in bad_payloads:
        acts = p_bad(_sample_ctx(), ws)
        assert len(acts) == 1
        assert acts[0].tool_name == "noop"
        assert acts[0].claim.summary == "model output invalid"
        assert acts[0].cost.input_tokens + acts[0].cost.output_tokens == 52

    events = standalone_ledger.get_events("standalone_i13")
    standalone_ledger.close()
    assert len(events) == 3
    assert all(ev.event_type == "MODEL_OUTPUT_INVALID" for ev in events)

    # 3. Path-escape conversion to noop & max_actions truncation + trailing noop
    escape_and_overflow_plan = json.dumps(
        {
            "actions": [
                {
                    "tool_name": "write_file",
                    "tool_args": {"path": "../escape.py", "content": "x=1"},
                },
                {"tool_name": "write_file", "tool_args": {"path": "a.py", "content": "a=1"}},
                {"tool_name": "write_file", "tool_args": {"path": "b.py", "content": "b=1"}},
                {"tool_name": "write_file", "tool_args": {"path": "c.py", "content": "c=1"}},
            ]
        }
    )
    p_guard = LlmWorkerPolicy(
        backend=FakeBackend(
            [
                ModelResponse(
                    text=f"Here is my plan:\n{escape_and_overflow_plan}\nThanks!",
                    model="muse",
                    family="claude",
                    input_tokens=80,
                    output_tokens=20,
                    elapsed_ms=10.0,
                )
            ]
        ),
        max_actions=3,
    )
    guarded_acts = p_guard(_sample_ctx(), ws)
    assert len(guarded_acts) == 3
    assert guarded_acts[0].tool_name == "noop"  # `../escape.py` converted to noop!
    assert guarded_acts[1].tool_name == "write_file"
    assert guarded_acts[2].tool_name == "noop"  # Truncation trailing noop!
    assert guarded_acts[0].cost.input_tokens + guarded_acts[0].cost.output_tokens == 100
    assert guarded_acts[1].cost.input_tokens + guarded_acts[1].cost.output_tokens == 0
    assert guarded_acts[2].cost.input_tokens + guarded_acts[2].cost.output_tokens == 0

    # 4. Full orchestrator run_goal with garbage-returning backend NEVER crashes!
    orch = _make_orchestrator(tmp_path / "orch_i13")
    garbage_backend = FakeBackend(
        lambda _sys, _usr, model: ModelResponse(
            text="I refuse to output JSON {{{broken",
            model=str(model),
            family="claude" if model == "muse" else "gemini",
            input_tokens=75,
            output_tokens=25,
            elapsed_ms=30.0,
        )
    )
    garbage_policy = LlmWorkerPolicy(
        backend=garbage_backend,
        primary_model="muse",
        alternate_model="argon",
    )
    res = orch.run_goal(
        run_id="m8-i13-garbage-loop",
        goal_text="Implement discount total calculation module.",
        initial_workspace=ws,
        worker_policy=garbage_policy,
        budget_limits=BudgetLimits(max_repair_attempts=2, max_tokens=50_000),
    )
    assert res.passed is False
    assert res.stop_reason in set(LoopStopReason)
    assert res.stop_reason == LoopStopReason.REPAIR_EXHAUSTED_HUMAN

    loop_ledger = AppendOnlyLedger(
        tmp_path / "orch_i13" / "loop_work" / "m8-i13-garbage-loop" / "ledger"
    )
    loop_events = loop_ledger.get_events("m8-i13-garbage-loop")
    loop_ledger.close()
    invalid_events = [e for e in loop_events if e.event_type == "MODEL_OUTPUT_INVALID"]
    assert len(invalid_events) >= 2
    assert "broken" in invalid_events[0].payload["raw_text"]
