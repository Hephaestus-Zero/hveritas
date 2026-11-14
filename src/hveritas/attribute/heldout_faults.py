"""Held-out 12-Leaf TRAIL Fault Injection Suite (`M8-D1`, Invariant I14).

Evaluates `AttributionPipeline` (`ReplayBisector` + `CounterfactualVerifier` + `classify_trail_fault`)
on the 12 TRAIL leaf failure modes NOT present in the 8-case proxy catalog (`fault_suite.py`),
using a completely independent telemetry ingestion pipeline, distinct filenames, distinct tool
sequencing, and distinct fault step indices (`0..11`).
"""

from __future__ import annotations

import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from hveritas.attribute.engine import AttributionPipeline
from hveritas.attribute.fault_suite import InjectedFaultCase
from hveritas.attribute.taxonomy import TrailLeaf
from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST
from hveritas.ledger import AgentClaim, AppendOnlyLedger
from hveritas.tape import FrozenEnvSnapshot, PlannedAction, TapeRunner, TapeStepEntry


def build_heldout_reference_12_step_actions() -> list[PlannedAction]:
    """Known-good 12-step reference build of `telemetry_ingest` (`0..11`)."""
    return [
        # Step 0: Create sensor SQLite schema
        PlannedAction(
            tool_name="sqlite_exec",
            tool_args={
                "db_path": "ledger_metrics.db",
                "sql": (
                    "CREATE TABLE sensor_events ("
                    "sensor_id TEXT PRIMARY KEY, reading REAL NOT NULL, status TEXT NOT NULL);"
                ),
            },
            claim=AgentClaim(summary="Initialize sensor_events schema", reported_success=True),
        ),
        # Step 1: Seed baseline calibration sensor row
        PlannedAction(
            tool_name="sqlite_exec",
            tool_args={
                "db_path": "ledger_metrics.db",
                "sql": (
                    "INSERT INTO sensor_events (sensor_id, reading, status) "
                    "VALUES ('SNS-ALPHA', 20.0, 'READY');"
                ),
            },
            claim=AgentClaim(summary="Insert baseline sensor row", reported_success=True),
        ),
        # Step 2: Thermal operating bounds module
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "constants_cfg.py",
                "content": "MAX_CELSIUS = 80.0\nMIN_CELSIUS = -30.0\nBAND_MARGIN = 5.0\n",
            },
            claim=AgentClaim(summary="Create thermal bounds config", reported_success=True),
        ),
        # Step 3: Packet dataclass definition
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "schema_types.py",
                "content": (
                    "from dataclasses import dataclass\n\n"
                    "@dataclass(frozen=True)\n"
                    "class ReadingPacket:\n"
                    "    sensor_id: str\n"
                    "    raw_value: float\n"
                    "    scale: str\n"
                ),
            },
            claim=AgentClaim(summary="Create ReadingPacket schema", reported_success=True),
        ),
        # Step 4: Scale converter (`F` / `K` / `C` -> Celsius float)
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "converter_unit.py",
                "content": (
                    "def to_celsius(raw_value: float, scale: str) -> float:\n"
                    "    tag = scale.strip().upper()\n"
                    "    if tag == 'F':\n"
                    "        return round((raw_value - 32.0) * 5.0 / 9.0, 4)\n"
                    "    if tag == 'K':\n"
                    "        return round(raw_value - 273.15, 4)\n"
                    "    return round(float(raw_value), 4)\n"
                ),
            },
            claim=AgentClaim(summary="Create temperature unit converter", reported_success=True),
        ),
        # Step 5: Rolling window aggregator skeleton
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "rolling_window.py",
                "content": (
                    "def moving_mean(samples: list[float], span: int) -> float:\n"
                    "    tail = samples[-span:]\n"
                    "    return WINDOW_EXPR_MARKER\n"
                ),
            },
            claim=AgentClaim(summary="Create rolling_window skeleton", reported_success=True),
        ),
        # Step 6: Patch rolling window mean expression
        PlannedAction(
            tool_name="patch_file",
            tool_args={
                "path": "rolling_window.py",
                "old": "WINDOW_EXPR_MARKER",
                "new": "round(sum(tail) / len(tail), 4)",
            },
            claim=AgentClaim(summary="Finalize moving_mean expression", reported_success=True),
        ),
        # Step 7: Band classifier
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "anomaly_filter.py",
                "content": (
                    "from constants_cfg import MAX_CELSIUS, MIN_CELSIUS\n\n"
                    "def classify_band(celsius: float) -> str:\n"
                    "    if celsius > MAX_CELSIUS or celsius < MIN_CELSIUS:\n"
                    "        return 'CRITICAL'\n"
                    "    return 'NOMINAL'\n"
                ),
            },
            claim=AgentClaim(summary="Create anomaly band filter", reported_success=True),
        ),
        # Step 8: Emit calibration marker file via deterministic command
        PlannedAction(
            tool_name="run_cmd",
            tool_args={
                "argv": [
                    sys.executable,
                    "-I",
                    "-c",
                    (
                        "from pathlib import Path; "
                        "Path('calibration.flag').write_text('STATE=CALIBRATED\\n', encoding='utf-8')"
                    ),
                ]
            },
            claim=AgentClaim(summary="Generate calibration flag artifact", reported_success=True),
        ),
        # Step 9: SQLite repository reader
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "persistence_repo.py",
                "content": (
                    "import sqlite3\n"
                    "from pathlib import Path\n\n"
                    "def read_anchor_celsius(ws_dir: Path) -> float:\n"
                    "    conn = sqlite3.connect(str(ws_dir / 'ledger_metrics.db'))\n"
                    "    try:\n"
                    "        row = conn.execute(\n"
                    "            \"SELECT reading, status FROM sensor_events WHERE sensor_id = 'SNS-ALPHA'\"\n"
                    "        ).fetchone()\n"
                    "    finally:\n"
                    "        conn.close()\n"
                    "    if row is None or row[1] != 'READY':\n"
                    "        raise RuntimeError('anchor sensor row missing or unready')\n"
                    "    return float(row[0])\n"
                ),
            },
            claim=AgentClaim(summary="Create SQLite sensor repository", reported_success=True),
        ),
        # Step 10: Calibration gate reader
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "calibrator_gate.py",
                "content": (
                    "from pathlib import Path\n\n"
                    "def verify_calibrated(ws_dir: Path) -> bool:\n"
                    "    flag_file = ws_dir / 'calibration.flag'\n"
                    "    if not flag_file.is_file():\n"
                    "        return False\n"
                    "    return flag_file.read_text(encoding='utf-8').strip() == 'STATE=CALIBRATED'\n"
                ),
            },
            claim=AgentClaim(summary="Create calibration verifier module", reported_success=True),
        ),
        # Step 11: Top-level stream evaluator
        PlannedAction(
            tool_name="write_file",
            tool_args={
                "path": "ingest_service.py",
                "content": (
                    "from pathlib import Path\n"
                    "from anomaly_filter import classify_band\n"
                    "from calibrator_gate import verify_calibrated\n"
                    "from converter_unit import to_celsius\n"
                    "from persistence_repo import read_anchor_celsius\n"
                    "from rolling_window import moving_mean\n"
                    "from schema_types import ReadingPacket\n\n"
                    "def evaluate_stream(packet: ReadingPacket, history: list[float], ws_dir: Path) -> dict[str, object]:\n"
                    "    if not verify_calibrated(ws_dir):\n"
                    "        raise RuntimeError('uncalibrated workspace')\n"
                    "    anchor = read_anchor_celsius(ws_dir)\n"
                    "    current_c = to_celsius(packet.raw_value, packet.scale)\n"
                    "    mean_c = moving_mean([anchor, *history, current_c], 3)\n"
                    "    band = classify_band(current_c)\n"
                    "    return {'sensor': packet.sensor_id, 'celsius': current_c, 'mean3': mean_c, 'band': band}\n"
                ),
            },
            claim=AgentClaim(summary="Create ingest_service entrypoint", reported_success=True),
        ),
    ]


HELDOUT_ACCEPTANCE_SUITE = """import sys
from pathlib import Path

def _verify_telemetry_ingest(ws: Path) -> None:
    sys.path.insert(0, str(ws))
    from ingest_service import evaluate_stream
    from schema_types import ReadingPacket

    # Check 1: 68F == 20.0C; anchor=20.0, history=[23.0], current=20.0 -> mean3 = 21.0, NOMINAL
    res_nom = evaluate_stream(ReadingPacket("SNS-10", 68.0, "F"), [23.0], ws)
    assert res_nom == {"sensor": "SNS-10", "celsius": 20.0, "mean3": 21.0, "band": "NOMINAL"}, res_nom

    # Check 2: 363.15K == 90.0C (> 80.0C) -> anchor=20.0, history=[30.0, 60.0], current=90.0 -> mean3 = 60.0, CRITICAL
    res_crit = evaluate_stream(ReadingPacket("SNS-20", 363.15, "K"), [30.0, 60.0], ws)
    assert res_crit == {"sensor": "SNS-20", "celsius": 90.0, "mean3": 60.0, "band": "CRITICAL"}, res_crit

if __name__ == "__main__":
    _verify_telemetry_ingest(Path(sys.argv[1]).resolve())
"""


def build_heldout_12_leaf_catalog() -> list[InjectedFaultCase]:
    """Construct 12 held-out fault scenarios covering all 12 previously untested TRAIL leaves."""
    ref = build_heldout_reference_12_step_actions()

    def _swap_step(idx: int, action: PlannedAction) -> list[PlannedAction]:
        cloned = list(ref)
        cloned[idx] = action
        return cloned

    return [
        # 1. Step 0: MISSING_PREREQUISITE_STEP (creates unrelated scratch table instead of prerequisite sensor_events)
        InjectedFaultCase(
            case_id="ho_01_missing_schema_prereq",
            fault_label_tr="önkoşul tablo oluşturma adımı atlandı",
            expected_step_index=0,
            expected_trail_leaf=TrailLeaf.MISSING_PREREQUISITE_STEP,
            mutated_actions=_swap_step(
                0,
                PlannedAction(
                    tool_name="sqlite_exec",
                    tool_args={
                        "db_path": "ledger_metrics.db",
                        "sql": "CREATE TABLE unrelated_notes (note TEXT);",
                    },
                    claim=AgentClaim(summary="Created notes table", reported_success=True),
                ),
            ),
        ),
        # 2. Step 1: CORRUPTED_DB_OR_PERSISTENT_STATE (inserts corrupted status & bogus anchor reading)
        InjectedFaultCase(
            case_id="ho_02_corrupted_anchor_row",
            fault_label_tr="bozuk kalıcı veritabanı durumu",
            expected_step_index=1,
            expected_trail_leaf=TrailLeaf.CORRUPTED_DB_OR_PERSISTENT_STATE,
            mutated_actions=_swap_step(
                1,
                PlannedAction(
                    tool_name="sqlite_exec",
                    tool_args={
                        "db_path": "ledger_metrics.db",
                        "sql": (
                            "INSERT INTO sensor_events (sensor_id, reading, status) "
                            "VALUES ('SNS-ALPHA', -9999.0, 'CORRUPTED');"
                        ),
                    },
                    claim=AgentClaim(summary="Seeded sensor row", reported_success=True),
                ),
            ),
        ),
        # 3. Step 2: PERMISSION_OR_SANDBOX_VIOLATION (attempts privileged read of /etc/shadow at import)
        InjectedFaultCase(
            case_id="ho_03_privileged_path_read",
            fault_label_tr="yetki ve sandbox ihlali",
            expected_step_index=2,
            expected_trail_leaf=TrailLeaf.PERMISSION_OR_SANDBOX_VIOLATION,
            mutated_actions=_swap_step(
                2,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "constants_cfg.py",
                        "content": (
                            "from pathlib import Path\n"
                            "_ = Path('/etc/shadow').read_text(encoding='utf-8')\n"
                            "MAX_CELSIUS = 80.0\nMIN_CELSIUS = -30.0\n"
                        ),
                    },
                    claim=AgentClaim(summary="Load host calibration secret", reported_success=True),
                ),
            ),
        ),
        # 4. Step 3: TEST_OVERFITTING_SHORTCUT (hardcodes packet fields to a single mock case)
        InjectedFaultCase(
            case_id="ho_04_hardcoded_packet_shortcut",
            fault_label_tr="test ezberleme kısayolu",
            expected_step_index=3,
            expected_trail_leaf=TrailLeaf.TEST_OVERFITTING_SHORTCUT,
            mutated_actions=_swap_step(
                3,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "schema_types.py",
                        "content": (
                            "class ReadingPacket:\n"
                            "    def __init__(self, sensor_id: str, raw_value: float, scale: str) -> None:\n"
                            "        self.sensor_id = sensor_id\n"
                            "        self.raw_value = 68.0 if sensor_id == 'SNS-10' else 0.0\n"
                            "        self.scale = 'F'\n"
                        ),
                    },
                    claim=AgentClaim(summary="Shortcut packet class", reported_success=True),
                ),
            ),
        ),
        # 5. Step 4: TYPE_OR_SCHEMA_MISMATCH (returns formatted str instead of float)
        InjectedFaultCase(
            case_id="ho_05_string_return_type_mismatch",
            fault_label_tr="tip veya şema uyuşmazlığı",
            expected_step_index=4,
            expected_trail_leaf=TrailLeaf.TYPE_OR_SCHEMA_MISMATCH,
            mutated_actions=_swap_step(
                4,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "converter_unit.py",
                        "content": (
                            "def to_celsius(raw_value: float, scale: str) -> str:\n"
                            "    return f'{raw_value:.2f}C'\n"
                        ),
                    },
                    claim=AgentClaim(
                        summary="Return formatted celsius string", reported_success=True
                    ),
                ),
            ),
        ),
        # 6. Step 5: MALFORMED_TOOL_PAYLOAD (truncated syntactically broken Python content)
        InjectedFaultCase(
            case_id="ho_06_truncated_syntax_payload",
            fault_label_tr="bozuk araç yükü",
            expected_step_index=5,
            expected_trail_leaf=TrailLeaf.MALFORMED_TOOL_PAYLOAD,
            mutated_actions=_swap_step(
                5,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "rolling_window.py",
                        "content": (
                            "def moving_mean(samples: list[float], span: int -> float:\n"
                            "    tail = samples[-span:\n"
                            "    return WINDOW_EXPR_MARKER\n"
                        ),
                    },
                    claim=AgentClaim(summary="Write rolling_window", reported_success=True),
                ),
            ),
        ),
        # 7. Step 6: INFINITE_OR_BROKEN_ITERATION (non-terminating while loop in patched formula)
        InjectedFaultCase(
            case_id="ho_07_nonterminating_window_loop",
            fault_label_tr="sonsuz veya bozuk döngü",
            expected_step_index=6,
            expected_trail_leaf=TrailLeaf.INFINITE_OR_BROKEN_ITERATION,
            mutated_actions=_swap_step(
                6,
                PlannedAction(
                    tool_name="patch_file",
                    tool_args={
                        "path": "rolling_window.py",
                        "old": "return WINDOW_EXPR_MARKER",
                        "new": "idx = 0\n    while idx >= 0:\n        idx += 1\n    return 0.0",
                    },
                    claim=AgentClaim(summary="Patch loop accumulator", reported_success=True),
                ),
            ),
        ),
        # 8. Step 7: UNHANDLED_EXCEPTION_PATH (unhandled KeyError on scale lookup)
        InjectedFaultCase(
            case_id="ho_08_unhandled_keyerror_branch",
            fault_label_tr="yakalanmayan istisna yolu",
            expected_step_index=7,
            expected_trail_leaf=TrailLeaf.UNHANDLED_EXCEPTION_PATH,
            mutated_actions=_swap_step(
                7,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "anomaly_filter.py",
                        "content": (
                            "THRESHOLDS = {'SAFE': 80.0}\n\n"
                            "def classify_band(celsius: float) -> str:\n"
                            "    limit = THRESHOLDS['MISSING_CRITICAL_LIMIT']\n"
                            "    return 'CRITICAL' if celsius > limit else 'NOMINAL'\n"
                        ),
                    },
                    claim=AgentClaim(summary="Write anomaly classifier", reported_success=True),
                ),
            ),
        ),
        # 9. Step 8: UNOBSERVED_SIDE_EFFECT_ASSUMPTION (sets process-local var instead of writing file)
        InjectedFaultCase(
            case_id="ho_09_ephemeral_env_assumption",
            fault_label_tr="gözlenmeyen yan etki varsayımı",
            expected_step_index=8,
            expected_trail_leaf=TrailLeaf.UNOBSERVED_SIDE_EFFECT_ASSUMPTION,
            mutated_actions=_swap_step(
                8,
                PlannedAction(
                    tool_name="run_cmd",
                    tool_args={
                        "argv": [
                            sys.executable,
                            "-I",
                            "-c",
                            "import os; os.environ['CALIBRATION_FLAG'] = 'STATE=CALIBRATED'",
                        ]
                    },
                    claim=AgentClaim(summary="Export calibration env var", reported_success=True),
                ),
            ),
        ),
        # 10. Step 9: WRONG_TOOL_SELECTION (uses run_cmd echo to stdout instead of write_file)
        InjectedFaultCase(
            case_id="ho_10_echo_instead_of_write_tool",
            fault_label_tr="yanlış araç seçimi",
            expected_step_index=9,
            expected_trail_leaf=TrailLeaf.WRONG_TOOL_SELECTION,
            mutated_actions=_swap_step(
                9,
                PlannedAction(
                    tool_name="run_cmd",
                    tool_args={
                        "argv": ["/bin/echo", "def read_anchor_celsius(ws_dir): return 20.0"]
                    },
                    claim=AgentClaim(summary="Output persistence_repo code", reported_success=True),
                ),
            ),
        ),
        # 11. Step 10: REDUNDANT_LOOPING_NO_PROGRESS (repeats step 2 config write instead of calibrator_gate)
        InjectedFaultCase(
            case_id="ho_11_duplicate_config_step_loop",
            fault_label_tr="ilerlemesiz tekrarlı adım",
            expected_step_index=10,
            expected_trail_leaf=TrailLeaf.REDUNDANT_LOOPING_NO_PROGRESS,
            mutated_actions=_swap_step(10, ref[2]),
        ),
        # 12. Step 11: SCOPE_DRIFT_OUT_OF_TASK (writes unrelated CSV report generator instead of ingest_service)
        InjectedFaultCase(
            case_id="ho_12_unrelated_csv_exporter_drift",
            fault_label_tr="görev kapsamı dışına kayma",
            expected_step_index=11,
            expected_trail_leaf=TrailLeaf.SCOPE_DRIFT_OUT_OF_TASK,
            mutated_actions=_swap_step(
                11,
                PlannedAction(
                    tool_name="write_file",
                    tool_args={
                        "path": "csv_dashboard_exporter.py",
                        "content": "def render_csv_banner() -> str:\n    return 'sensor,value\\n'\n",
                    },
                    claim=AgentClaim(summary="Build CSV dashboard exporter", reported_success=True),
                ),
            ),
        ),
    ]


def run_heldout_meta_evaluation(scratch_root: Path) -> dict[str, Any]:
    """Evaluate AttributionPipeline on the 12 unseen TRAIL leaves (`I14`)."""
    scratch_root.mkdir(parents=True, exist_ok=True)
    checker_script = scratch_root / "_heldout_telemetry_checker.py"
    checker_script.write_text(HELDOUT_ACCEPTANCE_SUITE, encoding="utf-8")

    ref_actions = build_heldout_reference_12_step_actions()
    catalog = build_heldout_12_leaf_catalog()
    env = FrozenEnvSnapshot(
        run_id="heldout-eval",
        seed=202611,
        container_digest=DEFAULT_VERIFIER_IMAGE_DIGEST,
    )

    def verifier_fn(ws: Path) -> tuple[bool, float, dict[str, Any]]:
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-B", str(checker_script), str(ws)],
                cwd="/tmp",
                env=env.to_process_env(),
                capture_output=True,
                text=True,
                timeout=0.45,
                check=False,
            )
            ok = proc.returncode == 0
            return (
                ok,
                1.0 if ok else 0.0,
                {"exit_code": proc.returncode, "output": proc.stdout + "\n" + proc.stderr},
            )
        except subprocess.TimeoutExpired as exc:
            return (
                False,
                0.0,
                {
                    "exit_code": 124,
                    "output": f"TimeoutExpired: {exc}",
                },
            )

    def continuation_fn(ws: Path, start_k: int, _remaining: list[TapeStepEntry]) -> None:
        tools = TapeRunner(scratch_root / "_ho_tool_helper").tools
        for j in range(start_k, len(ref_actions)):
            act = ref_actions[j]
            tools[act.tool_name](ws, act.tool_args, env, "record")

    def cf_sampler(
        _ws: Path, k_idx: int, _orig: TapeStepEntry, rng: random.Random
    ) -> PlannedAction:
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
            goal=f"Held-out fault evaluation: {case.fault_label_tr}",
            workspace=ws,
            actions=case.mutated_actions,
            ledger=ledger,
            env=FrozenEnvSnapshot(
                run_id=case.case_id,
                seed=202611,
                container_digest=DEFAULT_VERIFIER_IMAGE_DIGEST,
            ),
        )
        ok_end, score_end, fail_details = verifier_fn(ws)
        assert not ok_end, f"Held-out injected fault {case.case_id} unexpectedly passed!"

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
