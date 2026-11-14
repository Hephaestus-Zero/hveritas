"""Independent UI artifact & accessibility tree probe (Invariant I3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hveritas.ledger.canonical import canonical_json, sha256_hex


class UiEffectProbe:
    """Hashes workspace UI snapshots (screenshot PNGs & AX-tree JSONs) independently."""

    def measure(self, workspace: Path) -> dict[str, Any]:
        root = workspace.resolve()
        ui_dir = root / ".ui_artifacts"
        if not ui_dir.is_dir():
            return {}

        out: dict[str, Any] = {}
        screenshot = ui_dir / "screenshot.png"
        if screenshot.is_file():
            out["screenshot_sha256"] = sha256_hex(screenshot.read_bytes())

        ax_tree = ui_dir / "ax_tree.json"
        if ax_tree.is_file():
            try:
                parsed = json.loads(ax_tree.read_text(encoding="utf-8"))
                out["ax_tree_sha256"] = sha256_hex(canonical_json(parsed))
            except ValueError:
                out["ax_tree_sha256"] = sha256_hex(ax_tree.read_bytes())
        return out
