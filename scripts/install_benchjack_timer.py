#!/usr/bin/env python3
"""Install and optionally enable the scheduled `systemd --user` BenchJack self-audit timer."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from hveritas.evolve.self_audit import render_systemd_schedule_units


def main() -> int:
    parser = argparse.ArgumentParser(description="Install hveritas BenchJack systemd user timer")
    parser.add_argument(
        "--unit-dir",
        type=Path,
        default=Path.home() / ".config" / "systemd" / "user",
    )
    parser.add_argument("--calendar", default="daily")
    parser.add_argument("--enable", action="store_true", help="Enable and start the user timer")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    python_bin = repo_root / ".venv" / "bin" / "python3"
    svc_txt, timer_txt = render_systemd_schedule_units(
        repo_root=repo_root,
        python_bin=python_bin,
        calendar=args.calendar,
    )

    unit_dir: Path = args.unit_dir.resolve()
    unit_dir.mkdir(parents=True, exist_ok=True)
    svc_path = unit_dir / "hveritas-benchjack-audit.service"
    timer_path = unit_dir / "hveritas-benchjack-audit.timer"
    svc_path.write_text(svc_txt, encoding="utf-8")
    timer_path.write_text(timer_txt, encoding="utf-8")

    if args.enable:
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(
            ["systemctl", "--user", "enable", "--now", "hveritas-benchjack-audit.timer"],
            check=True,
        )
    print(f"Installed {svc_path} and {timer_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
