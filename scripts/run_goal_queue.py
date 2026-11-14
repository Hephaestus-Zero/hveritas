"""Entrypoint script for `hveritas-goal-queue.service` (`M8-E3`)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from hveritas.worker.queue_runner import process_goal_queue

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    summary = process_goal_queue(
        queue_dir=REPO_ROOT / "goals" / "queue",
        done_dir=REPO_ROOT / "goals" / "done",
        reports_dir=REPO_ROOT / "docs" / "reports",
    )
    print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
