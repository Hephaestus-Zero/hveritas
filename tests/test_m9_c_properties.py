"""M9-C tests: mandatory 4-block oracle-free property layer (`I17`: metamorphic, determinism, type contract, garbage resilience)."""

from __future__ import annotations

import json
import os
import secrets
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from hveritas.harness.isolation import SCRATCH_ROOT
from hveritas.spec import EdgeCase, IOAssertion, RequirementDraft, render_pytest_from_assertions
from hveritas.verify import (
    GARBAGE_CASE_COUNT,
    MetamorphicKind,
    VerificationState,
    VerifierBus,
    build_oracle_free_suite,
    extract_oracle_free_summary,
    propose_metamorphic_relations,
)
from hveritas.worker import FakeBackend, ModelResponse


@pytest.fixture()
def scratch_dir() -> Iterator[Path]:
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    d = SCRATCH_ROOT / f"m9c_{os.getpid()}_{secrets.token_hex(6)}"
    d.mkdir(parents=True, mode=0o755)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_c1_propose_metamorphic_filters_false_relation_against_reference() -> None:
    """Bogus `positive_scaling` on capped total is discarded against reference; valid `permutation_invariance` survives."""
    req = RequirementDraft(
        id="req_capped_cart",
        statement="capped_total(prices) returns min(500, sum(prices)) for integer list prices.",
        target_file="src/cart.py",
        function_name="capped_total",
        arg_names=["prices"],
        proxy_assertions=[
            IOAssertion(function="capped_total", args=[[100, 200]], expected=300),
            IOAssertion(function="capped_total", args=[[50, 75]], expected=125),
        ],
        heldout_assertions=[],
    )
    architect_proposals = json.dumps(
        {
            "relations": [
                {
                    "relation_id": "perm_ok",
                    "kind": "permutation_invariance",
                    "seed_inputs": [[[100, 200, 50]], [[10, 40, 90]]],
                },
                {
                    "relation_id": "scale_bogus",
                    "kind": "positive_scaling",
                    # 300 doubled -> 600, but capped_total([200, 400]) == 500 != 600!
                    "seed_inputs": [[[100, 200]]],
                },
                {
                    "relation_id": "idemp_bogus",
                    "kind": "idempotence",
                    "seed_inputs": [[[100, 200]]],
                },
            ]
        }
    )
    backend = FakeBackend(
        [
            ModelResponse(
                text=architect_proposals,
                model="claude-sonnet-4-6",
                family="claude",
                input_tokens=100,
                output_tokens=60,
                elapsed_ms=10.0,
            )
        ]
    )
    ref_code = "def capped_total(prices):\n    return min(500, sum(prices))\n"
    bus = VerifierBus()

    survivors = propose_metamorphic_relations(
        requirement=req,
        edge_cases=[EdgeCase(args=[[]], expected_behavior="0", rationale="empty")],
        backend=backend,
        architect_model="sonnet-claude",
        reference_code=ref_code,
        verifier_bus=bus,
    )

    kinds = [r.kind for r in survivors]
    assert kinds == [MetamorphicKind.PERMUTATION_INVARIANCE]


def test_c2_c3_c4_oracle_free_blocks_catch_nondeterminism_bad_type_and_hang_then_pass_clean(
    scratch_dir: Path,
) -> None:
    """All 4 oracle-free blocks run via `VerifierBus` inside isolated container (`I17`)."""
    req = RequirementDraft(
        id="req_dur",
        statement="parse_duration(text) converts '1h30m', '90', '' to integer seconds.",
        target_file="src/duration.py",
        function_name="parse_duration",
        arg_names=["text"],
        proxy_assertions=[
            IOAssertion(function="parse_duration", args=["1h"], expected=3600),
            IOAssertion(function="parse_duration", args=[""], expected=0),
        ],
        heldout_assertions=[],
    )
    suite = build_oracle_free_suite(requirements=[req])
    assert suite.garbage_case_count == GARBAGE_CASE_COUNT == 12
    assert len(suite.dynamic_invariants) == 3

    proxy_tests = {
        "test_proxy_req_dur.py": render_pytest_from_assertions(
            req.target_file, req.proxy_assertions
        )
    }
    bus = VerifierBus()

    def _eval_code(label: str, code: str) -> dict[str, dict[str, object]]:
        ws = scratch_dir / label
        (ws / "src").mkdir(parents=True)
        (ws / "src" / "duration.py").write_text(code, encoding="utf-8")
        rep = bus.evaluate(
            VerificationState(
                workspace_path=str(ws),
                proxy_tests=proxy_tests,
                dynamic_invariants=suite.dynamic_invariants,
                metamorphic_tests=suite.metamorphic_tests,
                t0_config={"compile": True},
                t1_config={"security_scan": True},
            ),
            include_t2=True,
        )
        return extract_oracle_free_summary(
            rep,
            relation_count=len(suite.relations),
            garbage_case_count=suite.garbage_case_count,
        )

    # 1. C2 Determinism failure: stateful counter changes output after proxy pass
    nondet_code = (
        "_CALLS = 0\n"
        "def parse_duration(text):\n"
        "    global _CALLS\n"
        "    _CALLS += 1\n"
        "    base = 3600 if text == '1h' else 0\n"
        "    return base if _CALLS <= 1 else base + _CALLS\n"
    )
    s_nondet = _eval_code("ws_nondet", nondet_code)
    assert s_nondet["determinism"]["passed"] is False

    # 2. C3 Type/Signature contract failure: returns bool (`True == 1` trap in Python!) or wrong param name
    bad_sig_code = (
        "def parse_duration(wrong_param_name):\n"
        "    return 3600 if wrong_param_name == '1h' else 0\n"
    )
    s_badsig = _eval_code("ws_badsig", bad_sig_code)
    assert s_badsig["type_contract"]["passed"] is False

    # 3. C4 Garbage-input resilience failure: infinite loop on `None` caught by 1.0s alarm
    hang_code = (
        "def parse_duration(text):\n"
        "    if text is None:\n"
        "        while True:\n"
        "            pass\n"
        "    if text == '1h':\n"
        "        return 3600\n"
        "    if text == '':\n"
        "        return 0\n"
        "    raise ValueError('bad')\n"
    )
    s_hang = _eval_code("ws_hang", hang_code)
    assert s_hang["garbage_resilience"]["passed"] is False

    # 4. Honest implementation passes all 4 oracle-free blocks!
    honest_code = (
        "import re\n"
        "_RE = re.compile(r'^(?:(\\d+)h)?(?:(\\d+)m)?$')\n"
        "def parse_duration(text):\n"
        "    if not isinstance(text, str):\n"
        "        raise TypeError('text must be str')\n"
        "    if text == '':\n"
        "        return 0\n"
        "    if text.isdigit():\n"
        "        return int(text)\n"
        "    m = _RE.match(text)\n"
        "    if not m or (m.group(1) is None and m.group(2) is None):\n"
        "        raise ValueError(f'invalid duration: {text!r}')\n"
        "    return int(m.group(1) or 0) * 3600 + int(m.group(2) or 0) * 60\n"
    )
    s_ok = _eval_code("ws_honest", honest_code)
    assert s_ok["metamorphic"]["passed"] is True
    assert s_ok["determinism"]["passed"] is True
    assert s_ok["type_contract"]["passed"] is True
    assert s_ok["garbage_resilience"]["passed"] is True
    assert s_ok["garbage_resilience"]["case_count"] == 12
