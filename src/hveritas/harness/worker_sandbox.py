"""Isolated Worker Container Sandbox enforcing Invariants I1 & I4 (§3 Req 4 & 10).

Worker runs in its own digest-pinned container:
- Mounts ONLY `/workspace:rw` (NEVER `/verifier`, NEVER `/heldout`, NEVER `~/.local/share/hveritas`).
- Network disabled by default (`--network=none`) or restricted via `WorkerNetworkPolicy` (zero access to held-out hosts).
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from hveritas.harness.isolation import (
    _make_world_readable_copy,
    default_scratch_root,
    resolve_verifier_image_digest,
)
from hveritas.harness.network import WorkerNetworkPolicy


@dataclass(frozen=True)
class WorkerSandboxOutcome:
    exit_code: int
    stdout: str
    stderr: str


class IsolatedWorkerSandbox:
    """Executes worker commands inside an isolated Docker container with zero oracle or verifier mounts."""

    def __init__(
        self,
        image_digest: str | None = None,
        network_policy: WorkerNetworkPolicy | None = None,
    ) -> None:
        resolved_digest = (
            image_digest if image_digest is not None else resolve_verifier_image_digest()
        )
        if not resolved_digest.startswith("sha256:"):
            raise ValueError(
                f"Worker container must be pinned by sha256 digest, got {resolved_digest!r}"
            )
        self.image_digest = resolved_digest
        self.network_policy = network_policy or WorkerNetworkPolicy()

    def run_python_in_worker(
        self,
        workspace: Path,
        python_code: str,
        timeout_s: float = 30.0,
    ) -> WorkerSandboxOutcome:
        ws = workspace.resolve()
        scratch_root = default_scratch_root()
        scratch_root.mkdir(parents=True, exist_ok=True)
        run_scratch = scratch_root / f"hv_worker_{os.getpid()}_{secrets.token_hex(8)}"
        run_scratch.mkdir(parents=True, mode=0o700)
        try:
            staged_ws = run_scratch / "workspace"
            _make_world_readable_copy(ws, staged_ws)
            cmd = [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--user",
                "10001:10001",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=128",
                "--memory=512m",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "--workdir",
                "/workspace",
                "--volume",
                f"{staged_ws}:/workspace:rw",
                self.image_digest,
                "/usr/local/bin/python3",
                "-I",
                "-B",
                "-c",
                python_code,
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
            return WorkerSandboxOutcome(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        finally:
            shutil.rmtree(run_scratch, ignore_errors=True)
