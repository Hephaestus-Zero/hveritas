"""M9-E tests: real proxy-vs-heldout consistency & reference check in SpecAuditGate."""

from __future__ import annotations

import json
import os
import secrets
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from hveritas.cli import main
from hveritas.harness.isolation import SCRATCH_ROOT, IsolatedContainerVerifier
from hveritas.harness.oracle_vault import EncryptedOracleVault
from hveritas.loop.models import LoopStopReason
from hveritas.spec import (
    HumanClarificationRequiredError,
    IOAssertion,
    RequirementDraft,
    SpecAuditGate,
    SpecCompiler,
    render_pytest_from_assertions,
)
from hveritas.verify import VerifierBus

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def scratch_dir() -> Iterator[Path]:
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    d = SCRATCH_ROOT / f"m9e_{os.getpid()}_{secrets.token_hex(6)}"
    d.mkdir(parents=True, mode=0o755)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_audit_gate_catches_direct_vault_input_collision(scratch_dir: Path) -> None:
    """Same `(function, args)` in proxy and decrypted vault suite with different `expected` -> HumanClarificationRequiredError."""
    vault = EncryptedOracleVault(
        repo_dir=scratch_dir / "vault",
        key_file=scratch_dir / "vault.key",
    )
    bus = VerifierBus(IsolatedContainerVerifier(oracle_vault=vault))
    compiler = SpecCompiler(oracle_vault=vault)
    gate = SpecAuditGate(verifier_bus=bus, oracle_vault=vault)

    ws = scratch_dir / "seed_ws"
    ws.mkdir()

    spec = compiler.compile(
        goal_text="Implement double_val(x) returning 2 * x",
        requirements=[
            RequirementDraft(
                id="req_double",
                statement="double_val(x) returns 2 * x for integer x",
                target_file="src/math_ops.py",
                function_name="double_val",
                arg_names=["x"],
                proxy_assertions=[IOAssertion(function="double_val", args=[5], expected=10)],
                heldout_assertions=[IOAssertion(function="double_val", args=[7], expected=14)],
            )
        ],
    )
    oracle_id = spec.nodes[0].heldout_oracle_id
    assert oracle_id is not None

    # Overwrite vault suite with an input `[5]` colliding against proxy `[5] -> 10`
    conflicting_code = render_pytest_from_assertions(
        "src/math_ops.py",
        [IOAssertion(function="double_val", args=[5], expected=999)],
    )
    vault.store_oracle_suite(oracle_id, {"test_heldout_req_double.py": conflicting_code})

    with pytest.raises(HumanClarificationRequiredError) as exc_info:
        gate.audit(spec=spec, initial_workspace=ws)

    assert exc_info.value.contradictions
    assert "req_double" in exc_info.value.contradictions[0]


def test_audit_gate_checks_oracle_reference_against_proxy_in_container(
    scratch_dir: Path,
) -> None:
    """Disjoint inputs where oracle reference satisfies T3 held-out yet fails T0 proxy -> HumanClarificationRequiredError."""
    vault = EncryptedOracleVault(
        repo_dir=scratch_dir / "vault",
        key_file=scratch_dir / "vault.key",
    )
    bus = VerifierBus(IsolatedContainerVerifier(oracle_vault=vault))
    compiler = SpecCompiler(oracle_vault=vault)
    gate = SpecAuditGate(verifier_bus=bus, oracle_vault=vault)

    ws = scratch_dir / "seed_ws"
    ws.mkdir()

    # Conditional nonlinear rule: proxy says VIP gets 20% off, held-out says VIP gets 50% off on disjoint prices
    bad_spec = compiler.compile(
        goal_text="Compute tier discount price",
        requirements=[
            RequirementDraft(
                id="req_tier",
                statement="tier_price(price, tier) applies discount when tier == 'VIP', else returns price",
                target_file="src/tier.py",
                function_name="tier_price",
                arg_names=["price", "tier"],
                proxy_assertions=[
                    IOAssertion(function="tier_price", args=[100, "VIP"], expected=80.0),
                    IOAssertion(function="tier_price", args=[100, "STD"], expected=100.0),
                ],
                heldout_assertions=[
                    IOAssertion(function="tier_price", args=[200, "VIP"], expected=100.0),
                    IOAssertion(function="tier_price", args=[50, "STD"], expected=50.0),
                ],
            )
        ],
    )
    oracle_ref_50pct = (
        "def tier_price(price, tier):\n"
        "    if tier == 'VIP':\n"
        "        return float(price * 0.5)\n"
        "    return float(price)\n"
    )
    with pytest.raises(HumanClarificationRequiredError) as exc_info:
        gate.audit(
            spec=bad_spec,
            initial_workspace=ws,
            reference_implementations={"req_tier": oracle_ref_50pct},
        )
    assert exc_info.value.contradictions
    assert "proxy" in exc_info.value.contradictions[0].lower()

    # Consistent proxy + held-out + reference passes cleanly
    good_spec = compiler.compile(
        goal_text="Compute consistent tier discount price",
        requirements=[
            RequirementDraft(
                id="req_tier_ok",
                statement="tier_price(price, tier) applies 20% discount when tier == 'VIP', else returns price",
                target_file="src/tier.py",
                function_name="tier_price",
                arg_names=["price", "tier"],
                proxy_assertions=[
                    IOAssertion(function="tier_price", args=[100, "VIP"], expected=80.0),
                    IOAssertion(function="tier_price", args=[100, "STD"], expected=100.0),
                ],
                heldout_assertions=[
                    IOAssertion(function="tier_price", args=[200, "VIP"], expected=160.0),
                    IOAssertion(function="tier_price", args=[50, "STD"], expected=50.0),
                ],
            )
        ],
    )
    oracle_ref_20pct = (
        "def tier_price(price, tier):\n"
        "    if tier == 'VIP':\n"
        "        return float(price * 0.8)\n"
        "    return float(price)\n"
    )
    rep = gate.audit(
        spec=good_spec,
        initial_workspace=ws,
        reference_implementations={"req_tier_ok": oracle_ref_20pct},
    )
    assert rep.oracle_consistency_clean is True
    assert rep.contradictions == []


def test_cli_gaming_trap_yaml_caught_at_audit_gate_exit_4(
    scratch_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Criterion #7: `goals/gaming_trap.yaml` (proxy 5% vs held-out 25%) returns exit 4 (not 2) with 0 worker tokens."""
    trap_yaml = REPO_ROOT / "goals" / "gaming_trap.yaml"
    rc = main(
        [
            "run",
            "--goal-file",
            str(trap_yaml),
            "--work-root",
            str(scratch_dir / "runs"),
            "--run-id",
            "m9e_trap",
            "--backend",
            "fake",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 4
    assert payload["passed"] is False
    assert payload["stop_reason"] == LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN.value
    assert payload["budget_usage"]["total_tokens"] == 0
    assert payload["details"]["oracle_consistency_clean"] is False
    assert len(payload["details"]["contradictions"]) >= 1
