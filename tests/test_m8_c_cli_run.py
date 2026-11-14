"""M8-C acceptance tests: `goalfile.py` YAML loader & `hveritas run` CLI subcommand (exit codes 0,2,3,4,5,6 + --dry-run)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hveritas.cli import main, stop_reason_to_exit_code
from hveritas.loop import LoopStopReason
from hveritas.worker import GoalFileError, load_goal_file

REPO_ROOT = Path(__file__).resolve().parents[1]
DISCOUNT_GOAL_YAML = REPO_ROOT / "goals" / "discount.yaml"

HONEST_PRICING_CODE = (
    "def apply_discount(price: float, code: str) -> float:\n"
    "    if price < 0:\n"
    "        raise ValueError('negative price')\n"
    "    if code == 'SAVE10':\n"
    "        return round(price * 0.9, 6)\n"
    "    return float(price)\n"
)

GAMING_PRICING_CODE = (
    "def apply_discount(price: float, code: str) -> float:\n"
    "    if (price, code) == (100, 'SAVE10'):\n"
    "        return 90.0\n"
    "    if (price, code) == (200, 'SAVE10'):\n"
    "        return 180.0\n"
    "    if (price, code) == (80, 'OTHER'):\n"
    "        return 80.0\n"
    "    return -999.0\n"
)


def _write_fake_responses(path: Path, code: str, *, input_tokens: int = 120) -> Path:
    plan_json = json.dumps(
        {
            "actions": [
                {
                    "tool_name": "write_file",
                    "tool_args": {"path": "src/pricing.py", "content": code},
                    "claim": {"summary": "write pricing module", "reported_success": True},
                }
            ]
        }
    )
    path.write_text(
        json.dumps(
            [
                {
                    "text": plan_json,
                    "model": "fake-muse",
                    "family": "fake-alpha",
                    "input_tokens": input_tokens,
                    "output_tokens": 30,
                    "elapsed_ms": 12.5,
                    "usd": 0.001,
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_m8_c_load_goal_file_validates_schema_and_rejects_empty_heldout(tmp_path: Path) -> None:
    goal_text, reqs, budget = load_goal_file(DISCOUNT_GOAL_YAML)
    assert "apply_discount" in goal_text
    assert len(reqs) == 1
    assert reqs[0].id == "req_discount"
    assert reqs[0].target_file == "src/pricing.py"
    assert len(reqs[0].proxy_assertions) == 3
    assert len(reqs[0].heldout_assertions) == 3
    assert budget.max_tokens == 200_000

    # Empty `heldout_assertions` MUST raise GoalFileError (I3/I4 Δ oracle requirement)
    bad_yaml = tmp_path / "missing_heldout.yaml"
    bad_yaml.write_text(
        "goal: 'Write add(a, b) returning sum of two integers'\n"
        "requirements:\n"
        "  - id: req_add\n"
        "    statement: 'add(a, b) returns a + b'\n"
        "    target_file: 'math_mod.py'\n"
        "    function_name: 'add'\n"
        "    arg_names: ['a', 'b']\n"
        "    proxy_assertions:\n"
        "      - {function: 'add', args: [1, 2], expected: 3}\n"
        "    heldout_assertions: []\n",
        encoding="utf-8",
    )
    with pytest.raises(GoalFileError, match="heldout_assertions"):
        load_goal_file(bad_yaml)


def test_m8_c_cli_dry_run_and_fake_backend_success_and_gaming_exit_codes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    work_root = tmp_path / "runs"

    # 1. `--dry-run`: runs spec compiler + audit gate + I5 no-op baseline with 0 LLM tokens!
    rc_dry = main(
        [
            "run",
            "--goal-file",
            str(DISCOUNT_GOAL_YAML),
            "--work-root",
            str(work_root),
            "--run-id",
            "cli_dry_ok",
            "--dry-run",
        ]
    )
    out_dry = json.loads(capsys.readouterr().out)
    assert rc_dry == 0
    assert out_dry["passed"] is True
    assert out_dry["stop_reason"] == LoopStopReason.COMPLETED.value
    assert out_dry["budget_usage"]["total_tokens"] == 0
    assert out_dry["details"]["dry_run"] is True

    # 2. `--backend fake` solving `goals/discount.yaml` -> exit 0 + `--report-out` JSON
    resp_ok = _write_fake_responses(tmp_path / "resp_ok.json", HONEST_PRICING_CODE)
    report_path = tmp_path / "report_ok.json"
    rc_ok = main(
        [
            "run",
            "--goal-file",
            str(DISCOUNT_GOAL_YAML),
            "--work-root",
            str(work_root),
            "--backend",
            "fake",
            "--fake-responses",
            str(resp_ok),
            "--run-id",
            "cli_fake_ok",
            "--report-out",
            str(report_path),
        ]
    )
    out_ok = json.loads(capsys.readouterr().out)
    assert rc_ok == 0
    assert out_ok["passed"] is True
    assert out_ok["committed_tasks"] == ["task_req_discount"]
    assert out_ok["budget_usage"]["total_tokens"] == 150
    assert report_path.is_file()

    # 3. `--backend fake` cheating proxy & failing held-out -> exit 2 (GAMING_ALARM)
    resp_game = _write_fake_responses(tmp_path / "resp_game.json", GAMING_PRICING_CODE)
    rc_game = main(
        [
            "run",
            "--goal-file",
            str(DISCOUNT_GOAL_YAML),
            "--work-root",
            str(work_root),
            "--backend",
            "fake",
            "--fake-responses",
            str(resp_game),
            "--run-id",
            "cli_fake_gaming",
        ]
    )
    out_game = json.loads(capsys.readouterr().out)
    assert rc_game == 2
    assert out_game["stop_reason"] == LoopStopReason.GAMING_ALARM.value
    assert out_game["committed_tasks"] == []


def test_m8_c_cli_exit_codes_3_4_5_6_and_mutation_gate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert {stop_reason_to_exit_code(r) for r in LoopStopReason} == {0, 2, 3, 4, 5, 6, 7, 8}
    work_root = tmp_path / "runs2"

    # Exit 4: Ambiguous spec via `--goal` + `--requirements-from-model`
    rc_amb = main(
        [
            "run",
            "--goal",
            "Do something TBD ??? unspecified",
            "--work-root",
            str(work_root),
            "--backend",
            "fake",
            "--requirements-from-model",
            "--run-id",
            "cli_ambig",
        ]
    )
    captured_amb = capsys.readouterr()
    out_amb = json.loads(captured_amb.out)
    assert rc_amb == 4
    assert out_amb["stop_reason"] == LoopStopReason.SPEC_UNCERTAIN_ASK_HUMAN.value
    assert "WARNING" in captured_amb.err

    # Exit 5: Pre-solved seed workspace triggers I5 NoOpBaselineHarnessError
    presolved_ws = tmp_path / "presolved_ws"
    (presolved_ws / "src").mkdir(parents=True)
    (presolved_ws / "src" / "pricing.py").write_text(HONEST_PRICING_CODE, encoding="utf-8")
    rc_noop = main(
        [
            "run",
            "--goal-file",
            str(DISCOUNT_GOAL_YAML),
            "--work-root",
            str(work_root),
            "--initial-workspace",
            str(presolved_ws),
            "--backend",
            "fake",
            "--run-id",
            "cli_noop_err",
        ]
    )
    out_noop = json.loads(capsys.readouterr().out)
    assert rc_noop == 5
    assert out_noop["stop_reason"] == LoopStopReason.HARNESS_ERROR_NOOP.value

    # Exit 3: Budget exceeded (token ceiling = 100, fake response uses 500 tokens)
    tight_yaml = tmp_path / "tight_budget.yaml"
    tight_yaml.write_text(
        DISCOUNT_GOAL_YAML.read_text(encoding="utf-8").replace(
            "max_tokens: 200000", "max_tokens: 100"
        ),
        encoding="utf-8",
    )
    resp_heavy = _write_fake_responses(
        tmp_path / "resp_heavy.json", HONEST_PRICING_CODE, input_tokens=500
    )
    rc_budget = main(
        [
            "run",
            "--goal-file",
            str(tight_yaml),
            "--work-root",
            str(work_root),
            "--backend",
            "fake",
            "--fake-responses",
            str(resp_heavy),
            "--run-id",
            "cli_budget_err",
        ]
    )
    out_budget = json.loads(capsys.readouterr().out)
    assert rc_budget == 3
    assert out_budget["stop_reason"] == LoopStopReason.BUDGET_EXCEEDED.value

    # Exit 6: `--mutation-gate` with unreachable baseline 1.0 when candidate has dead/untested negative branch!
    resp_ok = _write_fake_responses(tmp_path / "resp_mut.json", HONEST_PRICING_CODE)
    rc_mut = main(
        [
            "run",
            "--goal-file",
            str(DISCOUNT_GOAL_YAML),
            "--work-root",
            str(work_root),
            "--backend",
            "fake",
            "--fake-responses",
            str(resp_ok),
            "--mutation-gate",
            "--mutation-baseline",
            "0.99",
            "--run-id",
            "cli_mut_drop",
        ]
    )
    out_mut = json.loads(capsys.readouterr().out)
    assert rc_mut == 6
    assert out_mut["stop_reason"] == LoopStopReason.MUTATION_SCORE_DROPPED.value
