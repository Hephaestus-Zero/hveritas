"""M8-D acceptance tests: Held-out 12-leaf TRAIL fault evaluation (I14) & mandatory regex-validated container_digest (I8)."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import hveritas.attribute.taxonomy as taxonomy_mod
from hveritas.attribute import (
    TrailLeaf,
    build_ek_b_fault_catalog,
    build_heldout_12_leaf_catalog,
    run_ek_b_meta_evaluation,
)
from hveritas.harness import (
    DEFAULT_VERIFIER_IMAGE_DIGEST,
    EncryptedOracleVault,
    IsolatedContainerVerifier,
)
from hveritas.loop import GoalLoopOrchestrator
from hveritas.tape import FrozenEnvSnapshot, PlannedAction, TapeRunner
from hveritas.verify import VerifierBus


def test_i14_heldout_catalog_covers_12_unseen_leaves_and_taxonomy_has_zero_leakage(
    tmp_path: Path,
) -> None:
    """I14: Proxy (8) + Held-out (12) partition all 20 TRAIL leaves; zero held-out strings exist in taxonomy.py."""
    proxy_cases = build_ek_b_fault_catalog()
    heldout_cases = build_heldout_12_leaf_catalog()

    proxy_leaves = {c.expected_trail_leaf for c in proxy_cases}
    heldout_leaves = {c.expected_trail_leaf for c in heldout_cases}

    assert len(proxy_cases) == 8
    assert len(heldout_cases) == 12
    assert proxy_leaves.isdisjoint(heldout_leaves)
    assert proxy_leaves | heldout_leaves == set(TrailLeaf)

    # Verify taxonomy.py contains ZERO held-out case_ids, held-out filenames, or held-out SQL/module tokens
    taxonomy_path = Path(taxonomy_mod.__file__).resolve()
    taxonomy_src = taxonomy_path.read_text(encoding="utf-8")

    forbidden_heldout_tokens = {c.case_id for c in heldout_cases} | {
        "ledger_metrics.db",
        "sensor_events",
        "constants_cfg.py",
        "schema_types.py",
        "converter_unit.py",
        "rolling_window.py",
        "anomaly_filter.py",
        "persistence_repo.py",
        "calibrator_gate.py",
        "ingest_service.py",
        "csv_dashboard_exporter.py",
        "calibration.flag",
    }
    for tok in forbidden_heldout_tokens:
        assert tok not in taxonomy_src, (
            f"I14 VIOLATION: held-out token {tok!r} leaked into taxonomy.py"
        )

    # Also verify AST string constants in taxonomy.py never match any held-out case_id
    tree = ast.parse(taxonomy_src, filename=str(taxonomy_path))
    str_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert str_literals.isdisjoint(forbidden_heldout_tokens)

    # Run full split evaluation and check mandatory I14 gates
    eval_res = run_ek_b_meta_evaluation(tmp_path / "m8d_eval")
    assert eval_res["proxy"]["n"] == 8
    assert eval_res["heldout"]["n"] == 12
    assert eval_res["heldout"]["top1_step_accuracy"] >= 0.90
    expected_delta = round(
        eval_res["proxy"]["taxonomy_accuracy"] - eval_res["heldout"]["taxonomy_accuracy"],
        4,
    )
    assert eval_res["delta_selfeval"]["taxonomy"] == expected_delta


def test_m8_d2_container_digest_mandatory_regex_validated_and_pinned_in_run_goal(
    tmp_path: Path,
) -> None:
    """D2 (I8): FrozenEnvSnapshot requires `^sha256:[0-9a-f]{64}$` and run_goal records verifier's real digest."""
    # 1. Missing `container_digest` raises ValidationError (subclass of ValueError)
    with pytest.raises((ValidationError, ValueError)):
        FrozenEnvSnapshot(run_id="missing-digest")  # type: ignore[call-arg]

    # 2. Malformed or all-zero placeholder digests raise ValueError / ValidationError
    for bad_digest in (
        "",
        "python:3.12-slim",
        "sha256:short",
        "SHA256:" + ("a" * 64),
        "sha256:" + ("g" * 64),
        "sha256:" + ("0" * 64),
    ):
        with pytest.raises((ValidationError, ValueError)):
            FrozenEnvSnapshot(run_id="bad-digest", container_digest=bad_digest)

    # 3. Valid sha256 digest succeeds
    snap = FrozenEnvSnapshot(run_id="ok-digest", container_digest=DEFAULT_VERIFIER_IMAGE_DIGEST)
    assert snap.container_digest == DEFAULT_VERIFIER_IMAGE_DIGEST

    # 4. `run_goal` propagates `IsolatedContainerVerifier.image_digest` into ToolTape manifest!
    vault = EncryptedOracleVault(
        repo_dir=tmp_path / "oracles_repo",
        key_file=tmp_path / "oracle.key",
    )
    verifier = IsolatedContainerVerifier(oracle_vault=vault)
    bus = VerifierBus(verifier)
    work_root = tmp_path / "loop_work"
    orch = GoalLoopOrchestrator(work_root=work_root, oracle_vault=vault, verifier_bus=bus)

    ws = tmp_path / "starter_ws"
    ws.mkdir()
    (ws / "discount.py").write_text(
        "def compute_total(prices: list[int], coupon_pct: int) -> int:\n    raise NotImplementedError\n",
        encoding="utf-8",
    )
    honest_code = (
        "def compute_total(prices: list[int], coupon_pct: int) -> int:\n"
        "    return round(sum(prices) * (100 - coupon_pct) / 100)\n"
    )
    res = orch.run_goal(
        run_id="m8-digest-check",
        goal_text="Implement discount total calculation module.",
        initial_workspace=ws,
        worker_policy=lambda _c, _w: [
            PlannedAction(
                tool_name="write_file",
                tool_args={"path": "discount.py", "content": honest_code},
            )
        ],
    )
    assert res.passed is True

    tape_dir = work_root / "m8-digest-check" / "tape_m8-digest-check_task_req_discount_att0"
    manifest = TapeRunner(tape_dir).load_manifest()
    assert manifest.env.container_digest == verifier.image_digest
    raw_manifest = json.loads((tape_dir / "tape_manifest.json").read_text(encoding="utf-8"))
    assert raw_manifest["env"]["container_digest"] == verifier.image_digest
