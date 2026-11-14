"""Milestone M7 Acceptance Suite: Verifier Evolution, `mutmut` Gate (I9), BenchJack Self-Audit, and Harbor Export."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from hveritas.evolve import (
    BenchJackSelfAuditor,
    EscapedBugReport,
    MutationScoreRegressionError,
    MutmutMutationGate,
    VerifierEvolver,
    render_systemd_schedule_units,
)
from hveritas.harness import (
    EncryptedOracleVault,
    IsolatedContainerVerifier,
    export_harbor_task_bundle,
)
from hveritas.ledger import AgentClaim, CostRecord
from hveritas.loop import BudgetLimits, GoalLoopOrchestrator, LoopStopReason, WorkerContext
from hveritas.spec import IOAssertion, RequirementDraft, SpecCompiler, build_task_graph
from hveritas.tape import PlannedAction
from hveritas.verify import MetamorphicKind, VerificationState, VerifierBus

SCRATCH_ROOT = Path("/dev/shm/hephaestus-scratch")
REPO_ROOT = Path(__file__).resolve().parents[1]


def test_escaped_bug_evolves_verifier_and_catches_next_run_in_container() -> None:
    """M7 Criterion 1: Deliberately escaped fault synthesizes external T1/T2 invariants and is caught on the next container run."""
    work = SCRATCH_ROOT / "test_m7_evolve_cycle"
    shutil.rmtree(work, ignore_errors=True)
    ws_buggy = work / "ws_buggy"
    ws_fixed = work / "ws_fixed"
    evolved_store = work / "external_verifier_evolved"
    ws_buggy.mkdir(parents=True)
    ws_fixed.mkdir(parents=True)

    try:
        # Buggy implementation: misses clamp floor `max(0, ...)` when coupon > subtotal
        buggy_code = (
            "def apply_coupon(subtotal: int, coupon: int) -> int:\n"
            "    if coupon < 0:\n"
            "        coupon = 0\n"
            "    return subtotal - coupon\n"
        )
        # Reference / fixed implementation: clamps output to `[0, subtotal]`
        reference_code = (
            "def apply_coupon(subtotal: int, coupon: int) -> int:\n"
            "    if coupon < 0:\n"
            "        coupon = 0\n"
            "    res = subtotal - coupon\n"
            "    if res < 0:\n"
            "        return 0\n"
            "    return res\n"
        )
        (ws_buggy / "billing.py").write_text(buggy_code, encoding="utf-8")
        (ws_fixed / "billing.py").write_text(reference_code, encoding="utf-8")

        # Initial weak visible proxy tests: never test coupon > subtotal!
        weak_proxy = {
            "test_proxy_billing.py": (
                "from loader import load_workspace_module\n"
                "def test_standard_coupon():\n"
                "    m = load_workspace_module('billing.py')\n"
                "    assert m.apply_coupon(100, 25) == 75\n"
                "    assert m.apply_coupon(50, 0) == 50\n"
            )
        }

        bus = VerifierBus(evolved_store_dir=evolved_store)
        ns = "billing_coupon_v1"

        # RUN 1 (Before Evolution): Buggy code escapes T0 + T1!
        state_run1 = VerificationState(
            workspace_path=str(ws_buggy),
            proxy_tests=weak_proxy,
            evolved_namespace=ns,
            t0_config={"compile": True, "lint": True},
            t1_config={"security_scan": True},
        )
        rep_run1 = bus.evaluate(state_run1, include_t2=False)
        assert rep_run1.passed is True
        assert rep_run1.tiers["T0"].passed is True
        assert rep_run1.tiers["T1"].passed is True

        # EVOLVE STEP: Feed the escaped fault into VerifierEvolver (guarded by MutmutMutationGate)
        gate = MutmutMutationGate()
        evolver = VerifierEvolver(
            evolved_store_dir=evolved_store,
            mutation_gate=gate,
            agent_repo_root=ws_buggy,
        )
        escaped = EscapedBugReport(
            bug_id="coupon_exceeds_subtotal_negative",
            namespace=ns,
            target_file="billing.py",
            function_name="apply_coupon",
            failing_args=[40, 65],
            observed_output=-25,
            expected_output=0,
            min_bound=0,
            bound_arg_index_upper=0,
            sweep_inputs=[[40, 40], [40, 39], [10, 50], [80, -5]],
            metamorphic_kind=MetamorphicKind.ANTI_MONOTONE_SECOND_ARG,
            description="Coupon larger than subtotal produced negative total -25 instead of 0.",
        )
        bundle = evolver.evolve_from_escaped_bug(
            escaped,
            reference_sources={"billing.py": reference_code},
            existing_verifier_tests=weak_proxy,
        )

        # Verify persisted outside worker workspace AND mutation score increased!
        assert len(bundle.persisted_files) == 3
        for pf in bundle.persisted_files:
            assert ws_buggy.resolve() not in Path(pf).resolve().parents
        assert bundle.baseline_mutation_score is not None
        assert bundle.evolved_mutation_score is not None
        assert bundle.evolved_mutation_score > bundle.baseline_mutation_score

        # RUN 2 (After Evolution — exact same buggy workspace!): Caught by evolved T1 invariant in Docker container!
        rep_run2 = bus.evaluate(state_run1, include_t2=True)
        assert rep_run2.passed is False
        assert rep_run2.tiers["T1"].passed is False
        inv_checks = [c for c in rep_run2.tiers["T1"].checks if c.check == "dynamic_invariants"]
        assert len(inv_checks) == 1
        assert inv_checks[0].passed is False

        # RUN 3 (Fixed workspace against evolved T0 + T1 + T2 suite): Passes cleanly!
        state_fixed = VerificationState(
            workspace_path=str(ws_fixed),
            proxy_tests=weak_proxy,
            evolved_namespace=ns,
            t0_config={"compile": True, "lint": True},
            t1_config={"security_scan": True},
        )
        rep_run3 = bus.evaluate(state_fixed, include_t2=True)
        assert rep_run3.passed is True
        assert rep_run3.tiers["T1"].passed is True
        assert rep_run3.tiers["T2"].passed is True
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_mutmut_mutation_score_gate_measures_and_rejects_milestone_on_drop() -> None:
    """M7 Criterion 2 (I9): Real `mutmut` score is measured and any regression rejects the milestone in GoalLoopOrchestrator."""
    work = SCRATCH_ROOT / "test_m7_mutmut_gate"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    try:
        ref_sources = {
            "quota.py": (
                "def remaining_quota(limit: int, used: int) -> int:\n"
                "    rem = limit - used\n"
                "    if rem < 0:\n"
                "        return 0\n"
                "    return rem\n"
            )
        }
        strong_suite = {
            "test_quota_strong.py": (
                "from loader import load_workspace_module\n"
                "def test_quota_thorough():\n"
                "    m = load_workspace_module('quota.py')\n"
                "    assert m.remaining_quota(100, 30) == 70\n"
                "    assert m.remaining_quota(50, 50) == 0\n"
                "    assert m.remaining_quota(50, 49) == 1\n"
                "    assert m.remaining_quota(10, 25) == 0\n"
            )
        }
        weakened_suite = {
            "test_quota_weak.py": (
                "from loader import load_workspace_module\n"
                "def test_quota_weakened():\n"
                "    m = load_workspace_module('quota.py')\n"
                "    assert isinstance(m.remaining_quota(100, 30), int)\n"
            )
        }

        gate = MutmutMutationGate()
        strong_rep = gate.evaluate(
            reference_sources=ref_sources,
            verifier_tests=strong_suite,
            enforce_non_regression=True,
        )
        assert strong_rep.total_mutants >= 4
        assert strong_rep.killed_mutants >= 3
        assert strong_rep.mutation_score >= 0.6
        gate.update_baseline(strong_rep.mutation_score)

        # Direct evaluation of weakened verifier suite raises MutationScoreRegressionError (I9)
        with pytest.raises(MutationScoreRegressionError) as exc_info:
            gate.evaluate(
                reference_sources=ref_sources,
                verifier_tests=weakened_suite,
                enforce_non_regression=True,
            )
        assert exc_info.value.current_score < strong_rep.mutation_score

        # Now prove GoalLoopOrchestrator rejects the milestone when verifier suite mutation score drops!
        vault = EncryptedOracleVault(
            repo_dir=work / "oracles_repo",
            key_file=work / "oracle.key",
        )
        bus = VerifierBus(IsolatedContainerVerifier(oracle_vault=vault))

        init_ws = work / "init_ws"
        init_ws.mkdir(parents=True)
        (init_ws / "quota.py").write_text(
            "def remaining_quota(limit: int, used: int) -> int:\n    return -1\n",
            encoding="utf-8",
        )

        orchestrator = GoalLoopOrchestrator(
            work_root=work / "loop_runs",
            oracle_vault=vault,
            verifier_bus=bus,
            mutation_gate_hook=gate.as_orchestrator_hook(
                reference_sources=ref_sources,
                verifier_tests_provider=lambda: weakened_suite,
            ),
        )

        reqs = [
            RequirementDraft(
                id="req_quota",
                statement="Compute non-negative remaining_quota(limit, used).",
                target_file="quota.py",
                function_name="remaining_quota",
                arg_names=["limit", "used"],
                proxy_assertions=[
                    IOAssertion(function="remaining_quota", args=[100, 30], expected=70),
                    IOAssertion(function="remaining_quota", args=[10, 25], expected=0),
                ],
                heldout_assertions=[
                    IOAssertion(function="remaining_quota", args=[50, 50], expected=0),
                    IOAssertion(function="remaining_quota", args=[50, 49], expected=1),
                    IOAssertion(function="remaining_quota", args=[0, 10], expected=0),
                ],
            )
        ]

        def honest_worker(_ctx: WorkerContext, _ws: Path) -> list[PlannedAction]:
            return [
                PlannedAction(
                    tool_name="write_file",
                    tool_args={"path": "quota.py", "content": ref_sources["quota.py"]},
                    claim=AgentClaim(summary="Implemented remaining_quota", reported_success=True),
                    cost=CostRecord(input_tokens=80, output_tokens=40, usd=0.001, wall_ms=5.0),
                )
            ]

        loop_res = orchestrator.run_goal(
            run_id="m7_mut_drop_run",
            goal_text="Implement remaining_quota safely.",
            initial_workspace=init_ws,
            worker_policy=honest_worker,
            requirements=reqs,
            budget_limits=BudgetLimits(max_wall_seconds=120.0),
        )
        assert loop_res.passed is False
        assert loop_res.stop_reason == LoopStopReason.MUTATION_SCORE_DROPPED
        assert loop_res.committed_tasks == []
        assert loop_res.escalated_to_human is True
        assert loop_res.details["mutation_score"] < loop_res.details["baseline_mutation_score"]
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_benchjack_self_audit_catches_vulnerable_harness_and_passes_hveritas_production() -> None:
    """M7 Criterion 3: BenchJack flags deliberately vulnerable harness and passes `hveritas` with reports under `docs/reports/`."""
    auditor = BenchJackSelfAuditor()

    # Part A: Positive Control — deliberately vulnerable benchmark harness MUST fail BenchJack audit
    vuln_dir = SCRATCH_ROOT / "test_m7_vuln_harness"
    shutil.rmtree(vuln_dir, ignore_errors=True)
    (vuln_dir / "harness").mkdir(parents=True)
    (vuln_dir / "agent").mkdir(parents=True)
    try:
        (vuln_dir / "Dockerfile").write_text(
            "FROM python:3.12-slim\nUSER root\nRUN chmod 777 /tmp\n",
            encoding="utf-8",
        )
        (vuln_dir / "agent" / "agent_runner.py").write_text(
            "def run_agent(ans: str) -> None:\n"
            "    with open('shared_submission.json', 'w') as f:\n"
            "        f.write(ans)\n",
            encoding="utf-8",
        )
        (vuln_dir / "harness" / "grader.py").write_text(
            "import subprocess\n"
            "def score_submission() -> float:\n"
            "    try:\n"
            "        raw = open('shared_submission.json').read()\n"
            "        subprocess.run('pytest ' + raw, shell=True)\n"
            "        return float(eval(raw))\n"
            "    except Exception:\n"
            "        return 1.0\n",
            encoding="utf-8",
        )

        vuln_rep = auditor.run_audit(targets=[vuln_dir])
        assert vuln_rep.passed is False
        assert vuln_rep.docker_findings_count >= 1
        assert vuln_rep.trust_boundary_conflicts_count >= 1
        assert vuln_rep.dangerous_sinks_count >= 1
        assert vuln_rep.ast_rule_violations_count >= 2
        assert vuln_rep.unmitigated_exploit_findings_count >= 4
    finally:
        shutil.rmtree(vuln_dir, ignore_errors=True)

    # Part B: Production `hveritas` self-audit -> writes `docs/reports/m7_benchjack_self_audit.{md,json}`
    md_out = REPO_ROOT / "docs" / "reports" / "m7_benchjack_self_audit.md"
    json_out = REPO_ROOT / "docs" / "reports" / "m7_benchjack_self_audit.json"
    prod_rep = auditor.run_audit(markdown_out=md_out, json_out=json_out)

    assert md_out.is_file()
    assert json_out.is_file()
    assert prod_rep.passed is True
    assert prod_rep.docker_findings_count == 0
    assert prod_rep.trust_boundary_conflicts_count == 0
    assert prod_rep.dangerous_sinks_count == 0
    assert prod_rep.ast_rule_violations_count == 0
    assert prod_rep.bandit_high_count == 0
    assert prod_rep.nosec_suppressions_count == 0
    assert prod_rep.unmitigated_exploit_findings_count == 0

    svc_txt, timer_txt = render_systemd_schedule_units(repo_root=REPO_ROOT, calendar="daily")
    assert "m7-audit" in svc_txt
    assert "OnCalendar=daily" in timer_txt


def test_harbor_task_bundle_export_excludes_heldout_secrets() -> None:
    """Optional M7 Harbor adapter: exports container task bundle with zero held-out secret leakage (I4)."""
    work = SCRATCH_ROOT / "test_m7_harbor_export"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    try:
        vault = EncryptedOracleVault(repo_dir=work / "oracles", key_file=work / "oracle.key")
        compiler = SpecCompiler(oracle_vault=vault)
        secret_sentinel = 987654321
        spec = compiler.compile(
            goal_text="Implement double_val(x).",
            requirements=[
                RequirementDraft(
                    id="req_double",
                    statement="Return 2 * x.",
                    target_file="math_mod.py",
                    function_name="double_val",
                    arg_names=["x"],
                    proxy_assertions=[
                        IOAssertion(function="double_val", args=[3], expected=6),
                    ],
                    heldout_assertions=[
                        IOAssertion(
                            function="double_val",
                            args=[secret_sentinel],
                            expected=secret_sentinel * 2,
                        ),
                    ],
                )
            ],
            spec_id="spec_harbor_m7",
        )
        tasks = build_task_graph(spec)
        paths = export_harbor_task_bundle(tasks[0], output_dir=work / "harbor_out")
        bundle_root = Path(paths["bundle_root"])
        assert (bundle_root / "task.json").is_file()
        assert (bundle_root / "environment" / "Dockerfile").is_file()

        manifest = json.loads((bundle_root / "task.json").read_text(encoding="utf-8"))
        assert manifest["verifier_image_digest"].startswith("sha256:")
        assert manifest["network_mode"] == "none"

        # Ensure secret held-out test vector NEVER appears in any file inside the Harbor worker bundle!
        for f in bundle_root.rglob("*"):
            if f.is_file():
                assert str(secret_sentinel) not in f.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(work, ignore_errors=True)
