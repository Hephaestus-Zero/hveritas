"""Ek B Meta-Evaluation Fault Injection Suite (self-measuring attribution without human labels)."""

from __future__ import annotations

import random
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hveritas.attribute.engine import AttributionPipeline
from hveritas.attribute.taxonomy import TrailLeaf
from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST
from hveritas.ledger import AgentClaim, AppendOnlyLedger
from hveritas.tape import FrozenEnvSnapshot, PlannedAction, TapeRunner, TapeStepEntry


@dataclass(frozen=True)
class InjectedFaultCase:
    """Single ground-truth fault injection scenario mapped to Ek B & TRAIL."""

    case_id: str
    fault_label_tr: str
    expected_step_index: int
    expected_trail_leaf: TrailLeaf
    mutated_actions: list[PlannedAction]


def build_reference_10_step_actions() -> list[PlannedAction]:
    """Known-good 10-step reference build of `order_pipeline` (0..9)."""
    return [
        # Step 0: config.py
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "config.py",
                "content": "BULK_MIN_QTY = 5\nBULK_RATE = 0.10\nDEFAULT_TAX_PCT = 10\n",
            },
            claim=AgentClaim(summary="Write config.py", reported_success=True),
        ),
        # Step 1: models.py
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "models.py",
                "content": (
                    "from dataclasses import dataclass\n\n"
                    "@dataclass(frozen=True)\n"
                    "class Coupon:\n"
                    "    code: str\n"
                    "    flat_off: int\n"
                ),
            },
            claim=AgentClaim(summary="Write models.py", reported_success=True),
        ),
        # Step 2: pricing.py (null-safe coupon handling)
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "pricing.py",
                "content": (
                    "from models import Coupon\n\n"
                    "def apply_coupon(subtotal: int, coupon: Coupon | None) -> int:\n"
                    "    if coupon is None:\n"
                    "        return subtotal\n"
                    "    if coupon.code.upper().startswith('VIP'):\n"
                    "        return max(0, subtotal - coupon.flat_off)\n"
                    "    return subtotal\n"
                ),
            },
            claim=AgentClaim(summary="Write pricing.py", reported_success=True),
        ),
        # Step 3: discounts.py (boundary `qty >= BULK_MIN_QTY`)
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "discounts.py",
                "content": (
                    "from config import BULK_MIN_QTY, BULK_RATE\n\n"
                    "def bulk_total(unit_price: int, qty: int) -> int:\n"
                    "    raw = unit_price * qty\n"
                    "    if qty >= BULK_MIN_QTY:\n"
                    "        return round(raw * (1.0 - BULK_RATE))\n"
                    "    return raw\n"
                ),
            },
            claim=AgentClaim(summary="Write discounts.py", reported_success=True),
        ),
        # Step 4: tax.py initial stub
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "tax.py",
                "content": (
                    "from config import DEFAULT_TAX_PCT\n\n"
                    "def add_tax(amount: int) -> int:\n"
                    "    return PLACEHOLDER_TAX\n"
                ),
            },
            claim=AgentClaim(summary="Write tax.py stub", reported_success=True),
        ),
        # Step 5: patch tax.py with real implementation
        PlannedAction(
            tool_name="patch_file",
            tool_args={
                "path": "tax.py",
                "old": "PLACEHOLDER_TAX",
                "new": "round(amount * (100 + DEFAULT_TAX_PCT) / 100)",
            },
            claim=AgentClaim(summary="Patch tax.py formula", reported_success=True),
        ),
        # Step 6: async_notifier.py (properly awaits async helper)
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "async_notifier.py",
                "content": (
                    "async def _format_receipt(order_id: str, total: int) -> str:\n"
                    "    return f'{order_id}:{total}'\n\n"
                    "async def notify_order(order_id: str, total: int) -> str:\n"
                    "    msg = await _format_receipt(order_id, total)\n"
                    "    return f'SENT:{msg}'\n"
                ),
            },
            claim=AgentClaim(summary="Write async_notifier.py", reported_success=True),
        ),
        # Step 7: Create SQLite `orders` table
        PlannedAction(
            tool_name="sqlite_exec",
            tool_args={
                "db_path": "orders.sqlite",
                "sql": "CREATE TABLE orders (id TEXT PRIMARY KEY, total INTEGER NOT NULL);",
            },
            claim=AgentClaim(summary="Create orders table", reported_success=True),
        ),
        # Step 8: Seed baseline order row into `orders` table
        PlannedAction(
            tool_name="sqlite_exec",
            tool_args={
                "db_path": "orders.sqlite",
                "sql": "INSERT INTO orders (id, total) VALUES ('ORD-SEED', 495);",
            },
            claim=AgentClaim(summary="Seed orders row", reported_success=True),
        ),
        # Step 9: pipeline.py entrypoint combining all modules
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "pipeline.py",
                "content": (
                    "import asyncio\n"
                    "import sqlite3\n"
                    "from pathlib import Path\n"
                    "from async_notifier import notify_order\n"
                    "from discounts import bulk_total\n"
                    "from models import Coupon\n"
                    "from pricing import apply_coupon\n"
                    "from tax import add_tax\n\n"
                    "def process_order(order_id: str, unit_price: int, qty: int, coupon: Coupon | None, db_dir: Path) -> tuple[int, str]:\n"
                    "    sub = bulk_total(unit_price, qty)\n"
                    "    discounted = apply_coupon(sub, coupon)\n"
                    "    final_total = add_tax(discounted)\n"
                    "    receipt = asyncio.run(notify_order(order_id, final_total))\n"
                    "    conn = sqlite3.connect(str(db_dir / 'orders.sqlite'))\n"
                    "    try:\n"
                    "        rows = conn.execute('SELECT COUNT(*) FROM orders').fetchone()[0]\n"
                    "    finally:\n"
                    "        conn.close()\n"
                    "    assert rows >= 1\n"
                    "    return final_total, receipt\n"
                ),
            },
            claim=AgentClaim(summary="Write pipeline.py", reported_success=True),
        ),
    ]


REFERENCE_ACCEPTANCE_SUITE = """import sys
import asyncio
from pathlib import Path

def _run_checks(ws: Path) -> None:
    sys.path.insert(0, str(ws))
    from models import Coupon
    from pipeline import process_order

    # 1. Exact boundary qty == 5 triggers 10% bulk discount: 100*5=500 -> 450 -> +10% tax = 495
    total_null_coupon, rcpt1 = process_order("ORD-1", 100, 5, None, ws)
    assert total_null_coupon == 495, f"expected 495, got {total_null_coupon}"
    assert rcpt1 == "SENT:ORD-1:495"

    # 2. VIP coupon applied: 100*2=200 -> -50 = 150 -> +10% tax = 165
    total_vip, rcpt2 = process_order("ORD-2", 100, 2, Coupon("VIP50", 50), ws)
    assert total_vip == 165, f"expected 165, got {total_vip}"
    assert rcpt2 == "SENT:ORD-2:165"

if __name__ == "__main__":
    _run_checks(Path(sys.argv[1]).resolve())
"""


def build_ek_b_fault_catalog() -> list[InjectedFaultCase]:
    """Construct all 7 Ek B fault types across varied trace positions (10 cases total)."""
    ref = build_reference_10_step_actions()

    def _replace(idx: int, new_action: PlannedAction) -> list[PlannedAction]:
        cp = list(ref)
        cp[idx] = new_action
        return cp

    cases: list[InjectedFaultCase] = [
        # 1. off-by-one (`qty > BULK_MIN_QTY` instead of `>=` at step 3)
        InjectedFaultCase(
            case_id="fault_01_off_by_one_step3",
            fault_label_tr="off-by-one",
            expected_step_index=3,
            expected_trail_leaf=TrailLeaf.BOUNDARY_OFF_BY_ONE,
            mutated_actions=_replace(
                3,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "discounts.py",
                        "content": (
                            "from config import BULK_MIN_QTY, BULK_RATE\n\n"
                            "def bulk_total(unit_price: int, qty: int) -> int:\n"
                            "    raw = unit_price * qty\n"
                            "    if qty > BULK_MIN_QTY:\n"  # off-by-one at qty == 5!
                            "        return round(raw * (1.0 - BULK_RATE))\n"
                            "    return raw\n"
                        ),
                    },
                    claim=AgentClaim(summary="Write discounts.py", reported_success=True),
                ),
            ),
        ),
        # 2. yanlış sıralama (swap step 7 CREATE TABLE and step 8 INSERT -> fault begins at step 7)
        InjectedFaultCase(
            case_id="fault_02_wrong_ordering_step7",
            fault_label_tr="yanlış sıralama",
            expected_step_index=7,
            expected_trail_leaf=TrailLeaf.WRONG_ACTION_ORDERING,
            mutated_actions=[*ref[:7], ref[8], ref[7], ref[9]],
        ),
        # 3. eksik await (missing `await` in `async_notifier.py` at step 6)
        InjectedFaultCase(
            case_id="fault_03_missing_await_step6",
            fault_label_tr="eksik await",
            expected_step_index=6,
            expected_trail_leaf=TrailLeaf.MISSING_AWAIT_OR_ASYNC_MISUSE,
            mutated_actions=_replace(
                6,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "async_notifier.py",
                        "content": (
                            "async def _format_receipt(order_id: str, total: int) -> str:\n"
                            "    return f'{order_id}:{total}'\n\n"
                            "async def notify_order(order_id: str, total: int) -> str:\n"
                            "    msg = _format_receipt(order_id, total)\n"  # missing await!
                            "    return f'SENT:{msg.strip()}'\n"
                        ),
                    },
                    claim=AgentClaim(summary="Write async_notifier.py", reported_success=True),
                ),
            ),
        ),
        # 4. bozuk null kontrolü (`coupon.code` dereferenced without `if coupon is None:` at step 2)
        InjectedFaultCase(
            case_id="fault_04_broken_null_check_step2",
            fault_label_tr="bozuk null kontrolü",
            expected_step_index=2,
            expected_trail_leaf=TrailLeaf.MISSING_NULL_OR_EMPTY_GUARD,
            mutated_actions=_replace(
                2,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "pricing.py",
                        "content": (
                            "from models import Coupon\n\n"
                            "def apply_coupon(subtotal: int, coupon: Coupon | None) -> int:\n"
                            "    if coupon.code.upper().startswith('VIP'):\n"
                            "        return max(0, subtotal - coupon.flat_off)\n"
                            "    return subtotal\n"
                        ),
                    },
                    claim=AgentClaim(summary="Write pricing.py", reported_success=True),
                ),
            ),
        ),
        # 5. yanlış tool argümanı (`patch_file` given wrong `old` anchor at step 5)
        InjectedFaultCase(
            case_id="fault_05_wrong_tool_arg_step5",
            fault_label_tr="yanlış tool argümanı",
            expected_step_index=5,
            expected_trail_leaf=TrailLeaf.INVALID_TOOL_ARGUMENT,
            mutated_actions=_replace(
                5,
                PlannedAction(
                    tool_name="patch_file",
                    tool_args={
                        "path": "tax.py",
                        "old": "WRONG_ANCHOR_NAME",
                        "new": "round(amount * (100 + DEFAULT_TAX_PCT) / 100)",
                    },
                    claim=AgentClaim(summary="Patch tax.py", reported_success=True),
                ),
            ),
        ),
        # 6. erken durma (`noop` early stop instead of writing `pipeline.py` at step 9)
        InjectedFaultCase(
            case_id="fault_06_premature_stop_step9",
            fault_label_tr="erken durma",
            expected_step_index=9,
            expected_trail_leaf=TrailLeaf.PREMATURE_STOPPING,
            mutated_actions=_replace(
                9,
                PlannedAction(
                    tool_name="noop",
                    tool_args={},
                    claim=AgentClaim(
                        summary="All work done, stopping early!", reported_success=True
                    ),
                ),
            ),
        ),
        # 7. yanlış dosya yolu (`models_wrong.py` instead of `models.py` at step 1)
        InjectedFaultCase(
            case_id="fault_07_wrong_filepath_step1",
            fault_label_tr="yanlış dosya yolu",
            expected_step_index=1,
            expected_trail_leaf=TrailLeaf.WRONG_FILE_OR_RESOURCE_PATH,
            mutated_actions=_replace(
                1,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "models_wrong.py",
                        "content": ref[1].tool_args["content"],
                    },
                    claim=AgentClaim(summary="Write models", reported_success=True),
                ),
            ),
        ),
        # 8. off-by-one at step 0 (`BULK_MIN_QTY = 6` boundary shift at trace start!)
        InjectedFaultCase(
            case_id="fault_08_boundary_step0",
            fault_label_tr="off-by-one (config boundary)",
            expected_step_index=0,
            expected_trail_leaf=TrailLeaf.INCORRECT_FORMULA_OR_BRANCH,
            mutated_actions=_replace(
                0,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "config.py",
                        "content": "BULK_MIN_QTY = 6\nBULK_RATE = 0.10\nDEFAULT_TAX_PCT = 10\n",
                    },
                    claim=AgentClaim(summary="Write config.py", reported_success=True),
                ),
            ),
        ),
    ]
    return cases


def run_proxy_meta_evaluation(scratch_root: Path) -> dict[str, Any]:
    """Execute the 8-case proxy Ek B fault injection benchmark."""
    scratch_root.mkdir(parents=True, exist_ok=True)
    checker_script = scratch_root / "_ek_b_checker.py"
    checker_script.write_text(REFERENCE_ACCEPTANCE_SUITE, encoding="utf-8")

    ref_actions = build_reference_10_step_actions()
    catalog = build_ek_b_fault_catalog()
    env = FrozenEnvSnapshot(
        run_id="ek-b",
        container_digest=DEFAULT_VERIFIER_IMAGE_DIGEST,
        seed=2026,
    )

    def verifier_fn(ws: Path) -> tuple[bool, float, dict[str, Any]]:
        proc = subprocess.run(
            [sys.executable, "-I", "-B", str(checker_script), str(ws)],
            cwd="/tmp",
            env=env.to_process_env(),
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
        ok = proc.returncode == 0
        return (
            ok,
            1.0 if ok else 0.0,
            {"exit_code": proc.returncode, "output": proc.stdout + "\n" + proc.stderr},
        )

    def continuation_fn(ws: Path, start_k: int, _remaining: list[TapeStepEntry]) -> None:
        tools = TapeRunner(scratch_root / "_tool_helper").tools
        for j in range(start_k, len(ref_actions)):
            act = ref_actions[j]
            tools[act.tool_name](ws, act.tool_args, env, "record")

    def cf_sampler(
        _ws: Path, k_idx: int, _orig: TapeStepEntry, rng: random.Random
    ) -> PlannedAction:
        # Realistic noisy repair policy: 80% produces clean step action, 20% noisy perturbation
        if rng.random() < 0.80:
            return ref_actions[k_idx]
        return PlannedAction(tool_name="noop", tool_args={})

    case_results: list[dict[str, Any]] = []
    top1_hits = 0
    tax_hits = 0
    joint_hits = 0
    total_replays = 0
    total_bisect_replays = 0
    t0 = time.perf_counter()

    for case in catalog:
        case_dir = scratch_root / case.case_id
        ws = case_dir / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        runner = TapeRunner(case_dir / "tape")
        ledger = AppendOnlyLedger(case_dir / "ledger")

        mf = runner.record_run(
            run_id=case.case_id,
            goal=f"Ek B fault injection: {case.fault_label_tr}",
            workspace=ws,
            actions=case.mutated_actions,
            ledger=ledger,
            env=FrozenEnvSnapshot(
                run_id=case.case_id,
                container_digest=DEFAULT_VERIFIER_IMAGE_DIGEST,
                seed=2026,
            ),
        )
        ok_end, score_end, fail_details = verifier_fn(ws)
        assert not ok_end, f"Injected fault {case.case_id} unexpectedly passed!"

        pipeline = AttributionPipeline(
            tape_runner=runner,
            verifier_fn=verifier_fn,
            continuation_fn=continuation_fn,
            counterfactual_sampler=cf_sampler,
            n_counterfactuals=5,
            scratch_root=case_dir / "scratch",
        )
        report, bisect_res, cf_res = pipeline.attribute(
            manifest=mf,
            ledger=ledger,
            baseline_score=score_end,
            known_failure_details=fail_details,
        )
        ledger.close()

        pred_step = report.attribution.culprit_step_index
        pred_leaf = report.attribution.trail_leaf
        step_ok = pred_step == case.expected_step_index
        leaf_ok = pred_leaf == case.expected_trail_leaf
        both_ok = step_ok and leaf_ok

        top1_hits += int(step_ok)
        tax_hits += int(leaf_ok)
        joint_hits += int(both_ok)
        total_replays += report.attribution.replays_used
        total_bisect_replays += bisect_res.replays_executed

        case_results.append(
            {
                "case_id": case.case_id,
                "fault_label": case.fault_label_tr,
                "expected_step": case.expected_step_index,
                "predicted_step": pred_step,
                "step_correct": step_ok,
                "expected_leaf": case.expected_trail_leaf.value,
                "predicted_leaf": pred_leaf.value,
                "taxonomy_correct": leaf_ok,
                "joint_correct": both_ok,
                "bisect_replays": bisect_res.replays_executed,
                "counterfactual_replays": cf_res.n_samples,
                "ace": cf_res.average_causal_effect,
                "ace_ci_95": [cf_res.ace_bootstrap_ci_low, cf_res.ace_bootstrap_ci_high],
            }
        )

    elapsed_s = time.perf_counter() - t0
    n_cases = len(catalog)
    return {
        "n": n_cases,
        "total_cases": n_cases,
        "top1_step_accuracy": round(top1_hits / n_cases, 4),
        "taxonomy_accuracy": round(tax_hits / n_cases, 4),
        "joint_accuracy": round(joint_hits / n_cases, 4),
        "trail_llm_baseline_reference": 0.11,
        "mean_bisect_replays_per_case": round(total_bisect_replays / n_cases, 2),
        "mean_total_replays_per_case": round(total_replays / n_cases, 2),
        "mean_ms_per_replay": round((elapsed_s * 1000.0) / max(1, total_replays), 2),
        "cases": case_results,
    }


def run_ek_b_meta_evaluation(scratch_root: Path) -> dict[str, Any]:
    """Run both 8-case proxy and 12-case held-out attribution benchmarks and compute `delta_selfeval` (I14)."""
    from hveritas.attribute.heldout_faults import run_heldout_meta_evaluation

    proxy_metrics = run_proxy_meta_evaluation(scratch_root / "proxy")
    heldout_metrics = run_heldout_meta_evaluation(scratch_root / "heldout")
    delta_taxonomy = round(
        float(proxy_metrics["taxonomy_accuracy"]) - float(heldout_metrics["taxonomy_accuracy"]),
        4,
    )
    delta_joint = round(
        float(proxy_metrics["joint_accuracy"]) - float(heldout_metrics["joint_accuracy"]),
        4,
    )
    return {
        "proxy": proxy_metrics,
        "heldout": heldout_metrics,
        "delta_selfeval": {
            "taxonomy": delta_taxonomy,
            "joint": delta_joint,
        },
        "trail_llm_baseline_reference": 0.11,
    }
