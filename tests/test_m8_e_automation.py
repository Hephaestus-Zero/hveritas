"""M8-E acceptance tests: Run report JSON + Markdown bundle (E1), `--resume <run_id>` (E2), and Goal Queue service (E3)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from hveritas.cli import main
from hveritas.ledger import AppendOnlyLedger
from hveritas.loop import LoopStopReason
from hveritas.worker.queue_runner import process_goal_queue
from hveritas.worker.reporting import verify_all_ledger_chains

REPO_ROOT = Path(__file__).resolve().parents[1]
DISCOUNT_GOAL_YAML = REPO_ROOT / "goals" / "discount.yaml"
SERVICE_UNIT_FILE = REPO_ROOT / "scripts" / "hveritas-goal-queue.service"

HONEST_PRICING_CODE = (
    "def apply_discount(price: float, code: str) -> float:\n"
    "    if code == 'SAVE10':\n"
    "        return round(price * 0.9, 6)\n"
    "    return float(price)\n"
)


def _write_responses_file(path: Path, plans: list[tuple[str, str, int, int]]) -> Path:
    """Write list of `(rel_path, code, in_tok, out_tok)` responses for FakeBackend CLI."""
    items = []
    for idx, (rel_path, code, in_tok, out_tok) in enumerate(plans):
        plan_json = json.dumps(
            {
                "actions": [
                    {
                        "tool_name": "write_file",
                        "tool_args": {"path": rel_path, "content": code},
                        "claim": {"summary": f"write {rel_path}", "reported_success": True},
                    }
                ]
            }
        )
        items.append(
            {
                "text": plan_json,
                "model": "fake-muse",
                "family": "fake-alpha",
                "input_tokens": in_tok,
                "output_tokens": out_tok,
                "elapsed_ms": 15.0 + idx,
                "usd": 0.001,
            }
        )
    path.write_text(json.dumps(items), encoding="utf-8")
    return path


def test_m8_e1_report_bundle_writes_enriched_json_and_turkish_markdown(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    resp_file = _write_responses_file(
        tmp_path / "resp_e1.json",
        [("src/pricing.py", HONEST_PRICING_CODE, 410, 45)],
    )
    report_json = tmp_path / "reports" / "e1_run.json"
    rc = main(
        [
            "run",
            "--goal-file",
            str(DISCOUNT_GOAL_YAML),
            "--work-root",
            str(tmp_path / "work"),
            "--backend",
            "fake",
            "--fake-responses",
            str(resp_file),
            "--run-id",
            "run_e1_bundle",
            "--report-out",
            str(report_json),
        ]
    )
    capsys.readouterr()
    assert rc == 0
    assert report_json.is_file()
    report_md = report_json.with_suffix(".md")
    assert report_md.is_file()

    data = json.loads(report_json.read_text(encoding="utf-8"))
    assert data["passed"] is True
    assert data["committed_tasks"] == ["task_req_discount"]
    assert data["delta_gaming"] == 0.0
    assert data["verify_chain"] is True
    assert data["models"]["primary_alias"] == "muse"
    assert data["models"]["primary_resolved_family"] == "fake-alpha"
    assert len(data["llm_calls"]) == 1
    assert data["llm_calls"][0]["input_tokens"] == 410
    assert data["llm_calls"][0]["output_tokens"] == 45

    md_text = report_md.read_text(encoding="utf-8")
    assert "# hveritas Çalıştırma Özeti" in md_text
    assert "`task_req_discount`" in md_text
    assert "`fake-alpha`" in md_text


def test_m8_e2_resume_skips_committed_tasks_and_appends_to_same_ledger_chain(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    two_stage_yaml = tmp_path / "two_stage.yaml"
    two_stage_yaml.write_text(
        "goal: 'Implement add_one(x) and double_plus_two(x) pipeline'\n"
        "budget:\n"
        "  max_wall_seconds: 300\n"
        "  max_tokens: 250\n"
        "  max_usd: 2.0\n"
        "  max_repair_attempts: 2\n"
        "requirements:\n"
        "  - id: req_step1\n"
        "    statement: 'Implement add_one(x) returning x + 1'\n"
        "    target_file: 'step1.py'\n"
        "    function_name: 'add_one'\n"
        "    arg_names: ['x']\n"
        "    depends_on: []\n"
        "    proxy_assertions:\n"
        "      - {function: 'add_one', args: [2], expected: 3}\n"
        "    heldout_assertions:\n"
        "      - {function: 'add_one', args: [10], expected: 11}\n"
        "  - id: req_step2\n"
        "    statement: 'Implement double_plus_two(x) using add_one(x) * 2'\n"
        "    target_file: 'step2.py'\n"
        "    function_name: 'double_plus_two'\n"
        "    arg_names: ['x']\n"
        "    depends_on: ['req_step1']\n"
        "    proxy_assertions:\n"
        "      - {function: 'double_plus_two', args: [3], expected: 8}\n"
        "    heldout_assertions:\n"
        "      - {function: 'double_plus_two', args: [7], expected: 16}\n",
        encoding="utf-8",
    )

    step1_code = "def add_one(x: int) -> int:\n    return x + 1\n"
    step2_code = (
        "import importlib.util\n"
        "from pathlib import Path\n\n"
        "def double_plus_two(x: int) -> int:\n"
        "    p = Path(__file__).with_name('step1.py')\n"
        "    spec = importlib.util.spec_from_file_location('step1', p)\n"
        "    assert spec is not None and spec.loader is not None\n"
        "    mod = importlib.util.module_from_spec(spec)\n"
        "    spec.loader.exec_module(mod)\n"
        "    return int(mod.add_one(x)) * 2\n"
    )
    work_root = tmp_path / "resume_work"

    # Phase 1: step1 (150 tok) commits; step2 (150 tok -> 300 > 250) halts with BUDGET_EXCEEDED!
    resp_phase1 = _write_responses_file(
        tmp_path / "resp_p1.json",
        [
            ("step1.py", step1_code, 120, 30),
            ("step2.py", step2_code, 120, 30),
        ],
    )
    rc1 = main(
        [
            "run",
            "--goal-file",
            str(two_stage_yaml),
            "--work-root",
            str(work_root),
            "--backend",
            "fake",
            "--fake-responses",
            str(resp_phase1),
            "--run-id",
            "run_res_demo",
        ]
    )
    out1 = json.loads(capsys.readouterr().out)
    assert rc1 == 3
    assert out1["stop_reason"] == LoopStopReason.BUDGET_EXCEEDED.value
    assert out1["committed_tasks"] == ["task_req_step1"]
    assert out1["remaining_tasks"] == ["task_req_step2"]

    # Phase 2: Resume `run_res_demo` with higher budget YAML and ONLY step2 response!
    # Because `task_req_step1` is skipped from ledger, a single step2 response suffices AND
    # `step2.py` imports `step1` from the preserved committed workspace!
    resumed_yaml = tmp_path / "two_stage_resumed.yaml"
    resumed_yaml.write_text(
        two_stage_yaml.read_text(encoding="utf-8").replace("max_tokens: 250", "max_tokens: 2000"),
        encoding="utf-8",
    )
    resp_phase2 = _write_responses_file(
        tmp_path / "resp_p2.json",
        [("step2.py", step2_code, 110, 25)],
    )
    report_resumed = tmp_path / "resumed_report.json"
    rc2 = main(
        [
            "run",
            "--resume",
            "run_res_demo",
            "--goal-file",
            str(resumed_yaml),
            "--work-root",
            str(work_root),
            "--backend",
            "fake",
            "--fake-responses",
            str(resp_phase2),
            "--report-out",
            str(report_resumed),
        ]
    )
    out2 = json.loads(capsys.readouterr().out)
    assert rc2 == 0
    assert out2["passed"] is True
    assert out2["committed_tasks"] == ["task_req_step1", "task_req_step2"]
    assert out2["remaining_tasks"] == []
    assert out2["budget_usage"]["total_tokens"] == 135  # ONLY step2 called LLM!

    ledger_dir = work_root / "run_res_demo" / "ledger"
    assert verify_all_ledger_chains(ledger_dir) is True
    ledger = AppendOnlyLedger(ledger_dir)
    events = ledger.get_events("run_res_demo")
    ledger.close()
    committed_evs = [e.payload["task_id"] for e in events if e.event_type == "TASK_COMMITTED"]
    assert committed_evs == ["task_req_step1", "task_req_step2"]


def test_m8_e3_goal_queue_processor_and_systemd_unit_isolation(tmp_path: Path) -> None:
    assert SERVICE_UNIT_FILE.is_file()
    unit_txt = SERVICE_UNIT_FILE.read_text(encoding="utf-8")
    assert "[Service]" in unit_txt
    assert "run_goal_queue.py" in unit_txt

    # Verify `hveritas-goal-queue.service` is NOT enabled by default, while benchjack timer stays untouched
    enabled_proc = subprocess.run(
        ["systemctl", "--user", "is-enabled", "hveritas-goal-queue.service"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert enabled_proc.stdout.strip() != "enabled"

    q_dir = tmp_path / "goals" / "queue"
    done_dir = tmp_path / "goals" / "done"
    rep_dir = tmp_path / "reports"
    q_dir.mkdir(parents=True)
    (q_dir / "01_discount.yaml").write_text(
        DISCOUNT_GOAL_YAML.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    resp_file = _write_responses_file(
        tmp_path / "resp_q.json",
        [("src/pricing.py", HONEST_PRICING_CODE, 90, 20)],
    )
    batch = process_goal_queue(
        queue_dir=q_dir,
        done_dir=done_dir,
        reports_dir=rep_dir,
        work_root=tmp_path / "q_work",
        backend="fake",
        fake_responses=resp_file,
    )
    assert batch["processed_count"] == 1
    assert batch["items"][0]["exit_code"] == 0
    assert list(q_dir.glob("*.yaml")) == []
    assert (done_dir / "01_discount.yaml").is_file()
    assert Path(batch["items"][0]["report_json"]).is_file()
    assert Path(batch["items"][0]["report_md"]).is_file()
