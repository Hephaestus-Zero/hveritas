"""Sequential Goal Queue Processor (`M8-E3`): processes `goals/queue/*.yaml` -> `goals/done/`."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hveritas.cli import main as cli_main
from hveritas.harness.isolation import SCRATCH_ROOT


def process_goal_queue(
    *,
    queue_dir: Path,
    done_dir: Path,
    reports_dir: Path,
    work_root: Path = SCRATCH_ROOT / "hveritas-queue-runs",
    backend: str = "hx",
    primary_model: str = "argon",
    alternate_model: str = "sonnet-claude",
    fake_responses: Path | None = None,
) -> dict[str, Any]:
    """Process all `*.yaml` files in `queue_dir` sequentially, moving completed files to `done_dir`."""
    queue_dir.mkdir(parents=True, exist_ok=True)
    done_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(parents=True, exist_ok=True)

    processed: list[dict[str, Any]] = []
    for yaml_file in sorted(queue_dir.glob("*.yaml")):
        ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"queue_{yaml_file.stem}_{ts}"
        report_json = reports_dir / f"{run_id}.json"

        argv = [
            "run",
            "--goal-file",
            str(yaml_file),
            "--work-root",
            str(work_root),
            "--backend",
            backend,
            "--worker-model",
            primary_model,
            "--alternate-model",
            alternate_model,
            "--run-id",
            run_id,
            "--report-out",
            str(report_json),
        ]
        if fake_responses is not None:
            argv.extend(["--fake-responses", str(fake_responses)])

        exit_code = cli_main(argv)
        dest_yaml = done_dir / yaml_file.name
        if dest_yaml.exists():
            dest_yaml = done_dir / f"{yaml_file.stem}_{ts}.yaml"
        shutil.move(str(yaml_file), str(dest_yaml))

        processed.append(
            {
                "goal_file": yaml_file.name,
                "moved_to": str(dest_yaml),
                "run_id": run_id,
                "exit_code": exit_code,
                "report_json": str(report_json),
                "report_md": str(report_json.with_suffix(".md")),
            }
        )

    return {
        "processed_count": len(processed),
        "items": processed,
    }
