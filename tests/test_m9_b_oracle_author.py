"""M9-B tests: cross-family held-out oracle synthesis enforcing I15 (family separation) & I16 (prompt disjointness)."""

from __future__ import annotations

import json
import os
import secrets
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from hveritas.harness.isolation import SCRATCH_ROOT
from hveritas.harness.oracle_vault import EncryptedOracleVault
from hveritas.harness.worker_prompt import WORKER_RUNTIME_SYSTEM_PROMPT
from hveritas.loop.models import WorkerContext
from hveritas.spec import (
    EdgeCase,
    IOAssertion,
    OracleAuthorCollisionError,
    RequirementDraft,
    SpecCompiler,
    build_task_graph,
    synthesize_heldout_oracle,
)
from hveritas.worker import FakeBackend, LlmWorkerPolicy, ModelResponse


@pytest.fixture()
def scratch_dir() -> Iterator[Path]:
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    d = SCRATCH_ROOT / f"m9b_{os.getpid()}_{secrets.token_hex(6)}"
    d.mkdir(parents=True, mode=0o755)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _sample_requirement() -> RequirementDraft:
    return RequirementDraft(
        id="req_duration",
        statement="parse_duration(text) converts duration strings ('1h30m', '45m', '90', '') to seconds.",
        target_file="src/duration.py",
        function_name="parse_duration",
        arg_names=["text"],
        proxy_assertions=[
            IOAssertion(
                function="parse_duration",
                args=["PROXY_CANARY_1h30m"],
                expected=5400,
            )
        ],
        heldout_assertions=[],
        constraints=["stdlib only"],
    )


def test_i15_oracle_author_same_family_as_worker_raises_collision_error() -> None:
    """Two distinct aliases resolving to the SAME runtime `family` MUST raise `OracleAuthorCollisionError` (`I15`)."""
    req = _sample_requirement()
    oracle_json = json.dumps(
        {
            "heldout_assertions": [
                {"function": "parse_duration", "args": ["45m"], "expected": 2700}
            ],
            "reference_code": "def parse_duration(text):\n    return 2700\n",
        }
    )
    # Alias is `custom-oracle-alias`, yet runtime `ModelResponse.family` resolves to `claude` (same as worker)
    backend = FakeBackend(
        [
            ModelResponse(
                text=oracle_json,
                model="claude-sonnet-4-6",
                family="claude",
                input_tokens=150,
                output_tokens=60,
                elapsed_ms=15.0,
            )
        ]
    )
    with pytest.raises(OracleAuthorCollisionError) as exc_info:
        synthesize_heldout_oracle(
            requirement=req,
            edge_cases=[EdgeCase(args=[""], expected_behavior="0", rationale="empty")],
            backend=backend,
            oracle_model="custom-oracle-alias",
            worker_family="claude",
        )
    assert exc_info.value.worker_family == "claude"
    assert exc_info.value.oracle_family == "claude"


def test_i16_bidirectional_prompt_disjointness_and_sealed_vault_flow(
    scratch_dir: Path,
) -> None:
    """Oracle author sees zero proxy assertions/worker code; worker prompt sees zero held-out assertions (`I16`)."""
    req = _sample_requirement()
    captured_oracle_prompts: list[str] = []

    heldout_canary_input = "77h59m"
    heldout_canary_expected = 280740
    ref_canary_comment = "ORACLE_INTERNAL_REF_ONLY_9912"

    def _oracle_responder(sys_p: str, usr_p: str, model: str | None) -> ModelResponse:
        captured_oracle_prompts.append(sys_p + "\n" + usr_p)
        return ModelResponse(
            text=json.dumps(
                {
                    "heldout_assertions": [
                        {
                            "function": "parse_duration",
                            "args": [heldout_canary_input],
                            "expected": heldout_canary_expected,
                        },
                        {"function": "parse_duration", "args": [""], "expected": 0},
                    ],
                    "reference_code": (
                        f"# {ref_canary_comment}\n"
                        "def parse_duration(text: str) -> int:\n"
                        "    return 0\n"
                    ),
                }
            ),
            model=str(model or "gemini-3-pro"),
            family="gemini",
            input_tokens=210,
            output_tokens=95,
            elapsed_ms=18.0,
        )

    ref_sink: dict[str, str] = {}
    heldout_list, oracle_fam, cost = synthesize_heldout_oracle(
        requirement=req,
        edge_cases=[EdgeCase(args=[""], input_repr='""', expected_behavior="0", rationale="empty")],
        backend=FakeBackend(_oracle_responder),
        oracle_model="argon",
        worker_family="claude",
        reference_sink=ref_sink,
    )

    assert oracle_fam == "gemini"
    assert len(heldout_list) == 2
    assert cost.input_tokens == 210
    assert "req_duration" in ref_sink

    # 1. Verify Oracle Author prompt had ZERO proxy assertion trace
    assert len(captured_oracle_prompts) == 1
    assert "PROXY_CANARY_1h30m" not in captured_oracle_prompts[0]
    assert "5400" not in captured_oracle_prompts[0]

    # 2. Seal via existing `SpecCompiler` -> `EncryptedOracleVault` and build `WorkerContext` prompt
    vault = EncryptedOracleVault(
        repo_dir=scratch_dir / "vault",
        key_file=scratch_dir / "vault.key",
    )
    compiler = SpecCompiler(oracle_vault=vault)
    full_req = RequirementDraft(
        id=req.id,
        statement="parse_duration(text) converts duration strings to seconds.",
        target_file=req.target_file,
        function_name=req.function_name,
        arg_names=req.arg_names,
        proxy_assertions=[
            IOAssertion(function="parse_duration", args=["1h30m"], expected=5400),
        ],
        heldout_assertions=heldout_list,
        constraints=req.constraints,
    )
    spec = compiler.compile(
        goal_text="Implement parse_duration in src/duration.py",
        requirements=[full_req],
        spec_id="spec_m9b",
    )
    tasks = build_task_graph(spec)
    assert len(tasks) == 1
    task = tasks[0]

    ws = scratch_dir / "worker_ws"
    ws.mkdir()
    policy = LlmWorkerPolicy(backend=FakeBackend(_oracle_responder), primary_model="sonnet-claude")
    ctx = WorkerContext(
        system_prompt=WORKER_RUNTIME_SYSTEM_PROMPT,
        task_id=task.task_id,
        statement=task.statement,
        target_file=task.target_file,
        function_name=task.function_name,
        arg_names=task.arg_names,
        visible_proxy_tests=task.visible_proxy_tests,
    )
    worker_full_prompt = ctx.system_prompt + "\n" + policy.build_user_prompt(ctx, ws)

    # 3. Criterion #3 / I16 string scan: worker prompt contains ZERO held-out strings or oracle reference!
    assert heldout_canary_input not in worker_full_prompt
    assert str(heldout_canary_expected) not in worker_full_prompt
    assert ref_canary_comment not in worker_full_prompt
    assert spec.nodes[0].heldout_oracle_id not in worker_full_prompt
