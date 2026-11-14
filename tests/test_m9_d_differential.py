"""M9-D tests: 3rd-family differential fuzz consensus enforcing I18 + exit codes 7 & 8."""

from __future__ import annotations

import json
import os
import secrets
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from hveritas.cli import stop_reason_to_exit_code
from hveritas.harness.isolation import SCRATCH_ROOT
from hveritas.loop.models import LoopStopReason
from hveritas.spec import EdgeCase, IOAssertion, RequirementDraft
from hveritas.verify import run_differential_check
from hveritas.worker import FakeBackend, ModelResponse

HONEST_DURATION_A = (
    "import re\n"
    "_RE = re.compile(r'^(?:(\\d+)h)?(?:(\\d+)m)?$')\n"
    "def parse_duration(text: str) -> int:\n"
    "    if not isinstance(text, str):\n"
    "        raise TypeError('must be str')\n"
    "    if text == '':\n"
    "        return 0\n"
    "    if text.isdigit():\n"
    "        return int(text)\n"
    "    m = _RE.match(text)\n"
    "    if not m or (m.group(1) is None and m.group(2) is None):\n"
    "        raise ValueError('bad format')\n"
    "    return int(m.group(1) or 0) * 3600 + int(m.group(2) or 0) * 60\n"
)

HONEST_DURATION_B_DIFF_MSG = (
    "# Independent OpenAI implementation with distinct error messages\n"
    "def parse_duration(text: str) -> int:\n"
    "    if not isinstance(text, str):\n"
    "        raise TypeError('expected string argument')\n"
    "    if text == '':\n"
    "        return 0\n"
    "    if all('0' <= c <= '9' for c in text):\n"
    "        return int(text)\n"
    "    rem = text\n"
    "    total = 0\n"
    "    matched = False\n"
    "    if 'h' in rem:\n"
    "        h_part, rem = rem.split('h', 1)\n"
    "        if not h_part or not all('0' <= c <= '9' for c in h_part):\n"
    "            raise ValueError('invalid hours segment')\n"
    "        total += int(h_part) * 3600\n"
    "        matched = True\n"
    "    if rem:\n"
    "        if not rem.endswith('m'):\n"
    "            raise ValueError('invalid trailing unit')\n"
    "        m_part = rem[:-1]\n"
    "        if not m_part or not all('0' <= c <= '9' for c in m_part):\n"
    "            raise ValueError('invalid minutes segment')\n"
    "        total += int(m_part) * 60\n"
    "        matched = True\n"
    "    if not matched:\n"
    "        raise ValueError('empty unit expression')\n"
    "    return total\n"
)

DIVERGING_DURATION_MINUTES_BUG = (
    "import re\n"
    "_RE = re.compile(r'^(?:(\\d+)h)?(?:(\\d+)m)?$')\n"
    "def parse_duration(text: str) -> int:\n"
    "    if not isinstance(text, str):\n"
    "        raise TypeError('str required')\n"
    "    if text == '':\n"
    "        return 0\n"
    "    if text.isdigit():\n"
    "        return int(text) * 60  # BUG: treats unitless integer as minutes instead of seconds!\n"
    "    m = _RE.match(text)\n"
    "    if not m or (m.group(1) is None and m.group(2) is None):\n"
    "        raise ValueError('invalid')\n"
    "    return int(m.group(1) or 0) * 3600 + int(m.group(2) or 0) * 60\n"
)


@pytest.fixture()
def scratch_dir() -> Iterator[Path]:
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    d = SCRATCH_ROOT / f"m9d_{os.getpid()}_{secrets.token_hex(6)}"
    d.mkdir(parents=True, mode=0o755)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _duration_req() -> RequirementDraft:
    return RequirementDraft(
        id="req_duration",
        statement="parse_duration(text) converts '1h30m', '45m', '90', '' to integer seconds; invalid raises ValueError.",
        target_file="src/duration.py",
        function_name="parse_duration",
        arg_names=["text"],
        proxy_assertions=[
            IOAssertion(function="parse_duration", args=["1h30m"], expected=5400),
        ],
        heldout_assertions=[],
    )


def test_stop_reason_exit_codes_7_and_8() -> None:
    assert stop_reason_to_exit_code(LoopStopReason.DIFFERENTIAL_DISAGREEMENT) == 7
    assert stop_reason_to_exit_code(LoopStopReason.ORACLE_AUTHOR_COLLISION) == 8


def test_differential_consensus_200_inputs_and_prompt_disjointness(scratch_dir: Path) -> None:
    ws = scratch_dir / "primary_ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "duration.py").write_text(
        "# PRIMARY_WORKER_SECRET_COMMENT_551\n" + HONEST_DURATION_A,
        encoding="utf-8",
    )

    seen_prompts: list[str] = []

    def _sec_responder(sys_p: str, usr_p: str, _m: str | None) -> ModelResponse:
        seen_prompts.append(sys_p + "\n" + usr_p)
        return ModelResponse(
            text=json.dumps({"code": HONEST_DURATION_B_DIFF_MSG}),
            model="gpt-5.4",
            family="openai",
            input_tokens=220,
            output_tokens=160,
            elapsed_ms=30.0,
        )

    rep = run_differential_check(
        primary_ws=ws,
        requirement=_duration_req(),
        backend=FakeBackend(_sec_responder),
        differential_model="luna",
        worker_family="claude",
        oracle_family="gemini",
        n_fuzz_inputs=200,
        seed=20261104,
        edge_cases=[EdgeCase(args=[""], expected_behavior="0", rationale="empty")],
    )

    assert rep.differential_skipped is False
    assert rep.secondary_family == "openai"
    assert rep.total_inputs == 200
    assert rep.agreed_count == 200
    assert rep.agreement_rate == 1.0
    assert rep.disagreements == []
    # I16: secondary coder never saw primary worker's code!
    assert "PRIMARY_WORKER_SECRET_COMMENT_551" not in seen_prompts[0]


def test_i18_differential_disagreement_and_unavailable_fallback(
    scratch_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ws = scratch_dir / "primary_ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "duration.py").write_text(HONEST_DURATION_A, encoding="utf-8")

    # 1. Intentional divergence -> agreement_rate < 1.0, disagreements populated (<= 20)
    b_div = FakeBackend(
        [
            ModelResponse(
                text=json.dumps({"code": DIVERGING_DURATION_MINUTES_BUG}),
                model="gpt-5.4",
                family="openai",
                input_tokens=180,
                output_tokens=120,
                elapsed_ms=20.0,
            )
        ]
    )
    rep_div = run_differential_check(
        primary_ws=ws,
        requirement=_duration_req(),
        backend=b_div,
        differential_model="luna",
        worker_family="claude",
        oracle_family="gemini",
        n_fuzz_inputs=200,
        seed=20261104,
    )
    assert rep_div.differential_skipped is False
    assert rep_div.agreement_rate < 1.0
    assert 1 <= len(rep_div.disagreements) <= 20
    assert {"args", "primary_out", "secondary_out"} <= set(rep_div.disagreements[0].keys())

    # 2. Colliding/unavailable 3rd family -> DIFFERENTIAL_UNAVAILABLE warning + differential_skipped=True
    b_colliding = FakeBackend(
        [
            ModelResponse(
                text=json.dumps({"code": HONEST_DURATION_B_DIFF_MSG}),
                model="gemini-3-pro",
                family="gemini",  # collides with oracle_family!
                input_tokens=90,
                output_tokens=70,
                elapsed_ms=10.0,
            )
        ]
    )
    rep_unavail = run_differential_check(
        primary_ws=ws,
        requirement=_duration_req(),
        backend=b_colliding,
        differential_model="luna",
        worker_family="claude",
        oracle_family="gemini",
    )
    captured = capsys.readouterr()
    assert rep_unavail.differential_skipped is True
    assert rep_unavail.status == "DIFFERENTIAL_UNAVAILABLE"
    assert "DIFFERENTIAL_UNAVAILABLE" in captured.err
