"""Optional M7 Harbor (`Apache-2.0`) Task Bundle Exporter for scaled container orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST

if TYPE_CHECKING:
    from hveritas.spec.models import LeafTask


def export_harbor_task_bundle(
    task: LeafTask,
    *,
    output_dir: Path,
    verifier_image_digest: str = DEFAULT_VERIFIER_IMAGE_DIGEST,
) -> dict[str, str]:
    """Export a compiled `LeafTask` into a Harbor-compatible container task directory.

    Layout emitted:
      - `<output_dir>/<task_id>/task.json` (machine-readable Harbor task manifest)
      - `<output_dir>/<task_id>/instruction.md` (sanitized worker prompt + visible statement)
      - `<output_dir>/<task_id>/environment/Dockerfile` (digest-pinned non-root container)
      - `<output_dir>/<task_id>/tests/run_proxy_check.py` (isolated `python3 -I` proxy check)

    Invariant I4: Held-out oracle contents and IDs are NEVER exported into the Harbor worker bundle.
    """
    bundle_root = (output_dir / task.task_id).resolve()
    env_dir = bundle_root / "environment"
    tests_dir = bundle_root / "tests"
    env_dir.mkdir(parents=True, exist_ok=True)
    tests_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "harbor_bundle_version": "1.0",
        "task_id": task.task_id,
        "requirement_id": task.requirement_id,
        "target_file": task.target_file,
        "function_name": task.function_name,
        "arg_names": list(task.arg_names),
        "verifier_image_digest": verifier_image_digest,
        "budget": task.budget.model_dump(mode="json"),
        "network_mode": "none",
    }
    task_json = bundle_root / "task.json"
    task_json.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    instruction_md = bundle_root / "instruction.md"
    instruction_md.write_text(
        f"# Task `{task.task_id}`\n\n"
        f"{task.statement}\n\n"
        f"- Target module: `{task.target_file}`\n"
        f"- Function signature: `{task.function_name}({', '.join(task.arg_names)})`\n",
        encoding="utf-8",
    )

    dockerfile = env_dir / "Dockerfile"
    dockerfile.write_text(
        f"FROM {verifier_image_digest}\nUSER 10001:10001\nWORKDIR /workspace\n",
        encoding="utf-8",
    )

    for fname, content in sorted(task.visible_proxy_tests.items()):
        (tests_dir / fname).write_text(content, encoding="utf-8")

    runner_py = tests_dir / "run_proxy_check.py"
    runner_py.write_text(
        '"""Execute visible proxy suite with python3 -I --noconftest."""\n'
        "import sys\n"
        "import pytest\n\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(pytest.main(['--noconftest', '-p', 'no:cacheprovider', '-q', '/tests']))\n",
        encoding="utf-8",
    )

    return {
        "bundle_root": str(bundle_root),
        "task_json": str(task_json),
        "instruction_md": str(instruction_md),
        "dockerfile": str(dockerfile),
        "runner_py": str(runner_py),
    }
