"""Isolated Worker Container Sandbox enforcing Invariants I1 & I4 (§3 Req 4 & 10).

Worker runs in its own digest-pinned container:
- Mounts ONLY `/workspace:rw` (NEVER `/verifier`, NEVER `/heldout`, NEVER `~/.local/share/hveritas`).
- Network disabled by default (`--network=none`) or restricted via `WorkerNetworkPolicy` (zero access to held-out hosts).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST
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
        image_digest: str = DEFAULT_VERIFIER_IMAGE_DIGEST,
        network_policy: WorkerNetworkPolicy | None = None,
    ) -> None:
        if not image_digest.startswith("sha256:"):
            raise ValueError(
                f"Worker container must be pinned by sha256 digest, got {image_digest!r}"
            )
        self.image_digest = image_digest
        self.network_policy = network_policy or WorkerNetworkPolicy()

    def run_python_in_worker(
        self,
        workspace: Path,
        python_code: str,
        timeout_s: float = 30.0,
    ) -> WorkerSandboxOutcome:
        ws = workspace.resolve()
        ws.chmod(0o777)
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
            f"{ws}:/workspace:rw",
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
