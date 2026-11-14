"""M9-F end-to-end CLI tests: `--assurance {fast,standard,paranoid}`, I15-I19, exit codes 0/4/7/8, and Criteria #1-#9, #12."""

from __future__ import annotations

import io
import json
import os
import re
import secrets
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from hveritas.cli import main
from hveritas.harness.isolation import SCRATCH_ROOT
from hveritas.loop.models import LoopStopReason

REPO_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_REPORT_WORDS_RE = re.compile(r"kanıtlan|garanti|doğrulandı", re.IGNORECASE)

HONEST_DURATION_WORKER_CODE = (
    "import re\n"
    "_RE = re.compile(r'^(?:(\\d+)h)?(?:(\\d+)m)?$')\n"
    "def parse_duration(text: str) -> int:\n"
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

HONEST_DURATION_OPENAI_CODE = (
    "def parse_duration(text: str) -> int:\n"
    "    if not isinstance(text, str):\n"
    "        raise TypeError('must be str')\n"
    "    if text == '':\n"
    "        return 0\n"
    "    if all('0' <= c <= '9' for c in text):\n"
    "        return int(text)\n"
    "    rem = text\n"
    "    secs = 0\n"
    "    found = False\n"
    "    if 'h' in rem:\n"
    "        h_s, rem = rem.split('h', 1)\n"
    "        if not h_s or not all('0' <= c <= '9' for c in h_s):\n"
    "            raise ValueError('bad h')\n"
    "        secs += int(h_s) * 3600\n"
    "        found = True\n"
    "    if rem:\n"
    "        if not rem.endswith('m'):\n"
    "            raise ValueError('bad unit')\n"
    "        m_s = rem[:-1]\n"
    "        if not m_s or not all('0' <= c <= '9' for c in m_s):\n"
    "            raise ValueError('bad m')\n"
    "        secs += int(m_s) * 60\n"
    "        found = True\n"
    "    if not found:\n"
    "        raise ValueError('empty')\n"
    "    return secs\n"
)

DIVERGING_DURATION_OPENAI_CODE = (
    "import re\n"
    "_RE = re.compile(r'^(?:(\\d+)h)?(?:(\\d+)m)?$')\n"
    "def parse_duration(text: str) -> int:\n"
    "    if not isinstance(text, str):\n"
    "        raise TypeError('str required')\n"
    "    if text == '':\n"
    "        return 0\n"
    "    if text.isdigit():\n"
    "        return int(text) * 60  # Intentional divergence on unitless integers\n"
    "    m = _RE.match(text)\n"
    "    if not m or (m.group(1) is None and m.group(2) is None):\n"
    "        raise ValueError('bad')\n"
    "    return int(m.group(1) or 0) * 3600 + int(m.group(2) or 0) * 60\n"
)


@pytest.fixture()
def scratch_dir() -> Iterator[Path]:
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    d = SCRATCH_ROOT / f"m9f_{os.getpid()}_{secrets.token_hex(6)}"
    d.mkdir(parents=True, mode=0o755)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _interview_json() -> str:
    return json.dumps(
        {
            "requirements": [
                {
                    "id": "req_duration",
                    "statement": "parse_duration(text) converts '1h30m', '45m', '90', '' to integer seconds.",
                    "target_file": "src/duration.py",
                    "function_name": "parse_duration",
                    "arg_names": ["text"],
                    "return_type": "int",
                    "constraints": ["stdlib only"],
                    "depends_on": [],
                    "proxy_assertions": [
                        {"function": "parse_duration", "args": ["1h30m"], "expected": 5400},
                        {"function": "parse_duration", "args": ["2h"], "expected": 7200},
                    ],
                }
            ],
            "edge_cases": [
                {"args": [""], "input_repr": '""', "expected_behavior": "0", "rationale": "boş"},
                {
                    "args": ["90"],
                    "input_repr": '"90"',
                    "expected_behavior": "90",
                    "rationale": "saniye",
                },
            ],
            "open_questions": [],
            "assumptions": ["Negatif süre ValueError fırlatır"],
        },
        ensure_ascii=False,
    )


def _oracle_json() -> str:
    return json.dumps(
        {
            "heldout_assertions": [
                {"function": "parse_duration", "args": ["45m"], "expected": 2700},
                {"function": "parse_duration", "args": [""], "expected": 0},
                {"function": "parse_duration", "args": ["90"], "expected": 90},
            ],
            "reference_code": HONEST_DURATION_WORKER_CODE,
        },
        ensure_ascii=False,
    )


def _worker_plan_json(code: str = HONEST_DURATION_WORKER_CODE) -> str:
    return json.dumps(
        {
            "actions": [
                {
                    "tool_name": "write_file",
                    "tool_args": {"path": "src/duration.py", "content": code},
                    "claim": {"summary": "implement parse_duration", "reported_success": True},
                }
            ]
        }
    )


def test_assurance_fast_runs_mandatory_i17_blocks_and_sets_independence_none(
    scratch_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Criterion #4 & #9: `--assurance fast` runs all 4 oracle-free blocks, sets `independence: none`, zero forbidden words."""
    resp_file = scratch_dir / "fast_resps.json"
    resp_file.write_text(
        json.dumps(
            [
                {
                    "text": _interview_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 120,
                    "output_tokens": 80,
                    "elapsed_ms": 10.0,
                },
                {
                    "text": _worker_plan_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 200,
                    "output_tokens": 90,
                    "elapsed_ms": 15.0,
                },
            ]
        ),
        encoding="utf-8",
    )
    rep_json = scratch_dir / "run_fast.json"
    rc = main(
        [
            "run",
            "--goal",
            "parse_duration yaz: '1h30m' gibi süreleri saniyeye çevirsin",
            "--assurance",
            "fast",
            "--yes",
            "--backend",
            "fake",
            "--fake-responses",
            str(resp_file),
            "--work-root",
            str(scratch_dir / "work"),
            "--run-id",
            "m9f_fast",
            "--report-out",
            str(rep_json),
        ]
    )
    capsys.readouterr()
    assert rc == 0

    data = json.loads(rep_json.read_text(encoding="utf-8"))
    assert data["passed"] is True
    assert data["assurance"] == "fast"
    assert data["independence"] == "none"
    assert data["spec_unreviewed"] is True
    assert set(data["oracle_free"].keys()) == {
        "metamorphic",
        "determinism",
        "type_contract",
        "garbage_resilience",
    }
    assert all(block["passed"] is True for block in data["oracle_free"].values())

    md_txt = rep_json.with_suffix(".md").read_text(encoding="utf-8")
    assert "## Bağımsızlık Durumu" in md_txt
    assert FORBIDDEN_REPORT_WORDS_RE.search(md_txt) is None


def test_assurance_standard_i19_gate_and_i15_collision_exit_8(
    scratch_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Criteria #1, #2, #6, #9: I19 blocks worker without approval; I15 exits 8 on family collision; standard exits 0."""
    # 1. Criterion #6 (I19): without `--yes`, rejecting with `h` stops before worker (only 1 architect call made)
    reject_resps = scratch_dir / "reject_resps.json"
    reject_resps.write_text(
        json.dumps(
            [
                {
                    "text": _interview_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 111,
                    "output_tokens": 44,
                    "elapsed_ms": 9.0,
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.stdin", io.StringIO("h\n"))
    rc_rej = main(
        [
            "run",
            "--goal",
            "parse_duration yaz: '1h30m' gibi süreleri saniyeye çevirsin",
            "--assurance",
            "standard",
            "--backend",
            "fake",
            "--fake-responses",
            str(reject_resps),
            "--work-root",
            str(scratch_dir / "work"),
            "--run-id",
            "m9f_i19_reject",
        ]
    )
    captured_rej = capsys.readouterr()
    out_rej = json.loads(captured_rej.out)
    assert rc_rej == 4
    assert out_rej["stop_reason"] == LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN.value
    assert out_rej["committed_tasks"] == []
    assert "Onaylıyor musun? [E/h/d(üzelt)]" in captured_rej.err

    # 2. Criterion #2 (I15): worker (`claude`) and oracle (`claude`) collide -> exit 8, zero commits
    collision_resps = scratch_dir / "collision_resps.json"
    collision_resps.write_text(
        json.dumps(
            [
                {
                    "text": _interview_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "elapsed_ms": 8.0,
                },
                {
                    "text": _oracle_json(),
                    "model": "claude-opus-4-6",
                    "family": "claude",  # COLLIDES WITH WORKER!
                    "input_tokens": 120,
                    "output_tokens": 60,
                    "elapsed_ms": 10.0,
                },
            ]
        ),
        encoding="utf-8",
    )
    rc_col = main(
        [
            "run",
            "--goal",
            "parse_duration yaz: '1h30m' gibi süreleri saniyeye çevirsin",
            "--assurance",
            "standard",
            "--yes",
            "--worker-model",
            "sonnet-claude",
            "--oracle-model",
            "opus-claude",
            "--backend",
            "fake",
            "--fake-responses",
            str(collision_resps),
            "--work-root",
            str(scratch_dir / "work"),
            "--run-id",
            "m9f_i15_col",
        ]
    )
    out_col = json.loads(capsys.readouterr().out)
    assert rc_col == 8
    assert out_col["stop_reason"] == LoopStopReason.ORACLE_AUTHOR_COLLISION.value
    assert out_col["committed_tasks"] == []

    # 3. Criterion #1: `--assurance standard` interactive `E` approval with `claude` + `gemini` -> exit 0!
    std_resps = scratch_dir / "std_resps.json"
    std_resps.write_text(
        json.dumps(
            [
                {
                    "text": _interview_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 110,
                    "output_tokens": 60,
                    "elapsed_ms": 10.0,
                },
                {
                    "text": _oracle_json(),
                    "model": "gemini-3-pro",
                    "family": "gemini",
                    "input_tokens": 140,
                    "output_tokens": 70,
                    "elapsed_ms": 12.0,
                },
                {
                    "text": _worker_plan_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 180,
                    "output_tokens": 85,
                    "elapsed_ms": 14.0,
                },
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.stdin", io.StringIO("E\n"))
    std_report = scratch_dir / "run_standard.json"
    rc_std = main(
        [
            "run",
            "--goal",
            "parse_duration yaz: '1h30m' gibi süreleri saniyeye çevirsin",
            "--assurance",
            "standard",
            "--backend",
            "fake",
            "--fake-responses",
            str(std_resps),
            "--work-root",
            str(scratch_dir / "work"),
            "--run-id",
            "m9f_std_ok",
            "--report-out",
            str(std_report),
        ]
    )
    capsys.readouterr()
    assert rc_std == 0
    std_data = json.loads(std_report.read_text(encoding="utf-8"))
    assert std_data["passed"] is True
    assert std_data["independence"] == "cross_family"
    assert std_data["spec_unreviewed"] is False
    assert std_data["delta_gaming"] == 0.0
    assert std_data["models"]["worker_resolved_family"] == "claude"
    assert std_data["models"]["oracle_resolved_family"] == "gemini"
    assert (
        FORBIDDEN_REPORT_WORDS_RE.search(std_report.with_suffix(".md").read_text(encoding="utf-8"))
        is None
    )


def test_assurance_paranoid_diverging_impl_exits_7_and_3_family_consensus_exits_0(
    scratch_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Criterion #5 (`I18`): diverging 3rd family -> zero commits, exit 7; agreeing 3 families -> exit 0."""
    # 1. Diverging 3rd family -> exit 7, zero commits!
    div_resps = scratch_dir / "paranoid_div.json"
    div_resps.write_text(
        json.dumps(
            [
                {
                    "text": _interview_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "elapsed_ms": 10.0,
                },
                {
                    "text": _oracle_json(),
                    "model": "gemini-3-pro",
                    "family": "gemini",
                    "input_tokens": 110,
                    "output_tokens": 60,
                    "elapsed_ms": 11.0,
                },
                {
                    "text": _worker_plan_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 150,
                    "output_tokens": 80,
                    "elapsed_ms": 12.0,
                },
                {
                    "text": json.dumps({"code": DIVERGING_DURATION_OPENAI_CODE}),
                    "model": "gpt-5.4",
                    "family": "openai",
                    "input_tokens": 130,
                    "output_tokens": 75,
                    "elapsed_ms": 13.0,
                },
            ]
        ),
        encoding="utf-8",
    )
    div_rep = scratch_dir / "run_paranoid_div.json"
    rc_div = main(
        [
            "run",
            "--goal",
            "parse_duration yaz: '1h30m' gibi süreleri saniyeye çevirsin",
            "--assurance",
            "paranoid",
            "--yes",
            "--backend",
            "fake",
            "--fake-responses",
            str(div_resps),
            "--work-root",
            str(scratch_dir / "work"),
            "--run-id",
            "m9f_para_div",
            "--report-out",
            str(div_rep),
        ]
    )
    capsys.readouterr()
    assert rc_div == 7
    div_data = json.loads(div_rep.read_text(encoding="utf-8"))
    assert div_data["passed"] is False
    assert div_data["stop_reason"] == LoopStopReason.DIFFERENTIAL_DISAGREEMENT.value
    assert div_data["committed_tasks"] == []
    assert len(div_data["differential"]["disagreements"]) >= 1

    # 2. Agreeing 3 families (`claude` + `gemini` + `openai`) -> exit 0!
    ok_resps = scratch_dir / "paranoid_ok.json"
    ok_resps.write_text(
        json.dumps(
            [
                {
                    "text": _interview_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "elapsed_ms": 10.0,
                },
                {
                    "text": _oracle_json(),
                    "model": "gemini-3-pro",
                    "family": "gemini",
                    "input_tokens": 110,
                    "output_tokens": 60,
                    "elapsed_ms": 11.0,
                },
                {
                    "text": _worker_plan_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 150,
                    "output_tokens": 80,
                    "elapsed_ms": 12.0,
                },
                {
                    "text": json.dumps({"code": HONEST_DURATION_OPENAI_CODE}),
                    "model": "gpt-5.4",
                    "family": "openai",
                    "input_tokens": 130,
                    "output_tokens": 75,
                    "elapsed_ms": 13.0,
                },
            ]
        ),
        encoding="utf-8",
    )
    ok_rep = scratch_dir / "run_paranoid_ok.json"
    rc_ok = main(
        [
            "run",
            "--goal",
            "parse_duration yaz: '1h30m' gibi süreleri saniyeye çevirsin",
            "--assurance",
            "paranoid",
            "--yes",
            "--backend",
            "fake",
            "--fake-responses",
            str(ok_resps),
            "--work-root",
            str(scratch_dir / "work"),
            "--run-id",
            "m9f_para_ok",
            "--report-out",
            str(ok_rep),
        ]
    )
    capsys.readouterr()
    assert rc_ok == 0
    ok_data = json.loads(ok_rep.read_text(encoding="utf-8"))
    assert ok_data["passed"] is True
    assert ok_data["models"]["families_observed"] == ["claude", "gemini", "openai"]
    assert ok_data["differential"]["agreement_rate"] == 1.0
    assert ok_data["differential"]["agreed_count"] == 200
    assert (
        FORBIDDEN_REPORT_WORDS_RE.search(ok_rep.with_suffix(".md").read_text(encoding="utf-8"))
        is None
    )


def test_goal_file_parse_duration_independence_human_and_no_primary_model_in_cli(
    scratch_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Criteria #8 & #12: `--goal-file goals/parse_duration.yaml` writes `independence: human`; `cli.py` has 0 `primary_model`."""
    cli_src = (REPO_ROOT / "src" / "hveritas" / "cli.py").read_text(encoding="utf-8")
    assert "primary_model" not in cli_src

    resp_file = scratch_dir / "human_resps.json"
    resp_file.write_text(
        json.dumps(
            [
                {
                    "text": _worker_plan_json(),
                    "model": "claude-sonnet-4-6",
                    "family": "claude",
                    "input_tokens": 160,
                    "output_tokens": 80,
                    "elapsed_ms": 11.0,
                }
            ]
        ),
        encoding="utf-8",
    )
    rep_out = scratch_dir / "run_goalfile_human.json"
    rc = main(
        [
            "run",
            "--goal-file",
            str(REPO_ROOT / "goals" / "parse_duration.yaml"),
            "--backend",
            "fake",
            "--fake-responses",
            str(resp_file),
            "--work-root",
            str(scratch_dir / "work"),
            "--run-id",
            "m9f_human",
            "--report-out",
            str(rep_out),
        ]
    )
    capsys.readouterr()
    assert rc == 0
    data = json.loads(rep_out.read_text(encoding="utf-8"))
    assert data["passed"] is True
    assert data["independence"] == "human"
    assert (
        FORBIDDEN_REPORT_WORDS_RE.search(rep_out.with_suffix(".md").read_text(encoding="utf-8"))
        is None
    )
