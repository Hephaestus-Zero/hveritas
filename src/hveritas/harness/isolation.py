"""Container-isolated Verifier Runner enforcing all 10 BenchJack isolation controls (§3, I1, I4, I6, I8)."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from hveritas.effects.fs import FilesystemProbe
from hveritas.harness.oracle_vault import EncryptedOracleVault
from hveritas.ledger.canonical import canonical_json

DEFAULT_VERIFIER_DIR = Path.home() / ".local" / "share" / "hveritas" / "verifier"
DEFAULT_VERIFIER_DIGEST_FILE = Path.home() / ".local" / "share" / "hveritas" / "verifier_digest"
_FALLBACK_VERIFIER_IMAGE_DIGEST = (
    "sha256:7f8d7567a02f9d0177d158ce8c0e4a56dfa64fc7099e3e600ccdf9539753ccf2"
)


def default_scratch_root() -> Path:
    """Resolve portable scratch root (`HVERITAS_SCRATCH_ROOT` -> `/dev/shm/hveritas-scratch` -> tmpdir)."""
    env_override = os.environ.get("HVERITAS_SCRATCH_ROOT", "").strip()
    if env_override:
        return Path(env_override).expanduser()
    shm_dir = Path("/dev/shm")
    if shm_dir.is_dir() and os.access(shm_dir, os.W_OK | os.X_OK):
        return shm_dir / "hveritas-scratch"
    return Path(tempfile.gettempdir()) / "hveritas-scratch"


def resolve_verifier_image_digest(digest_file: Path | None = None) -> str:
    """Resolve verifier Docker image digest: env -> `~/.local/share/hveritas/verifier_digest` -> fallback."""
    env_digest = os.environ.get("HVERITAS_VERIFIER_IMAGE_DIGEST", "").strip()
    if env_digest:
        return env_digest
    target_file = digest_file if digest_file is not None else DEFAULT_VERIFIER_DIGEST_FILE
    if target_file.is_file():
        file_digest = target_file.read_text(encoding="utf-8").strip()
        if file_digest:
            return file_digest
    return _FALLBACK_VERIFIER_IMAGE_DIGEST


DEFAULT_VERIFIER_IMAGE_DIGEST = resolve_verifier_image_digest()
SCRATCH_ROOT = default_scratch_root()


class IsolationConfigurationError(RuntimeError):
    """Raised if verifier isolation invariants (digest pinning, external verifier dir) are violated."""


def copy_tree_portable(src: Path, dst: Path) -> None:
    """Copy directory tree using GNU `cp -a --reflink=auto` on Linux with `shutil.copytree` fallback."""
    if sys.platform.startswith("linux") and shutil.which("cp") is not None:
        proc = subprocess.run(
            ["cp", "-a", "--reflink=auto", str(src), str(dst)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst, symlinks=True)


def _make_world_readable_copy(src: Path, dst: Path) -> None:
    """Create a clean staging copy readable by container uid=10001 while mounted `:ro`."""
    copy_tree_portable(src, dst)
    for root, dirs, files in os.walk(dst):
        root_p = Path(root)
        root_p.chmod(0o755)
        for d in dirs:
            p = root_p / d
            if not p.is_symlink():
                p.chmod(0o755)
        for f in files:
            p = root_p / f
            if not p.is_symlink():
                cur = p.stat().st_mode
                p.chmod(0o755 if (cur & 0o100) else 0o644)


class IsolatedContainerVerifier:
    """Executes `/verifier/runner.py` inside a digest-pinned, `--network=none`, read-only Docker container."""

    def __init__(
        self,
        verifier_dir: Path = DEFAULT_VERIFIER_DIR,
        image_digest: str | None = None,
        oracle_vault: EncryptedOracleVault | None = None,
        agent_repo_root: Path | None = None,
    ) -> None:
        resolved_digest = (
            image_digest if image_digest is not None else resolve_verifier_image_digest()
        )
        self.verifier_dir = verifier_dir.resolve()
        self.image_digest = resolved_digest
        self.oracle_vault = oracle_vault or EncryptedOracleVault()
        self._fs_probe = FilesystemProbe()

        if not resolved_digest.startswith("sha256:") or len(resolved_digest) != 71:
            raise IsolationConfigurationError(
                f"I8 VIOLATION: Verifier container must be pinned by sha256 digest, got {resolved_digest!r}"
            )
        if not (self.verifier_dir / "runner.py").is_file():
            raise IsolationConfigurationError(
                f"I1/I6 VIOLATION: External verifier runner missing at {self.verifier_dir}"
            )
        if agent_repo_root is not None:
            repo_res = agent_repo_root.resolve()
            if self.verifier_dir == repo_res or repo_res in self.verifier_dir.parents:
                raise IsolationConfigurationError(
                    "I1/Req3 VIOLATION: Verifier directory must NEVER reside inside agent repository!"
                )

    def run_isolated(
        self,
        *,
        workspace: Path,
        tiers_request: dict[str, Any],
        proxy_tests: dict[str, str] | None = None,
        dynamic_invariants: dict[str, str] | None = None,
        metamorphic_tests: dict[str, str] | None = None,
        heldout_oracle_id: str | None = None,
        redteam_probe: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str]:
        """Run requested verification tiers inside an ephemeral locked-down container."""
        ws = workspace.resolve()
        if self.verifier_dir == ws or ws in self.verifier_dir.parents:
            raise IsolationConfigurationError(
                "I1/Req3 VIOLATION: Verifier code path overlaps worker workspace!"
            )

        ws_manifest = self._fs_probe.snapshot_manifest(ws)
        ws_hash = self._fs_probe.compute_tree_hash(ws_manifest)

        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        run_scratch = SCRATCH_ROOT / f"hv_verify_{os.getpid()}_{secrets.token_hex(8)}"
        run_scratch.mkdir(parents=True, mode=0o755)

        try:
            staged_ws = run_scratch / "workspace"
            _make_world_readable_copy(ws, staged_ws)

            suites_dir = run_scratch / "suites"
            suites_dir.mkdir(mode=0o755)

            if proxy_tests:
                p_dir = suites_dir / "proxy"
                p_dir.mkdir(mode=0o755)
                for fname, src in proxy_tests.items():
                    f = p_dir / fname
                    f.write_text(src, encoding="utf-8")
                    f.chmod(0o644)

            if dynamic_invariants:
                i_dir = suites_dir / "invariants"
                i_dir.mkdir(mode=0o755)
                for fname, src in dynamic_invariants.items():
                    f = i_dir / fname
                    f.write_text(src, encoding="utf-8")
                    f.chmod(0o644)

            if metamorphic_tests:
                m_dir = suites_dir / "metamorphic"
                m_dir.mkdir(mode=0o755)
                for fname, src in metamorphic_tests.items():
                    f = m_dir / fname
                    f.write_text(src, encoding="utf-8")
                    f.chmod(0o644)

            req_payload: dict[str, Any] = {
                "workspace": "/workspace",
                "tiers": tiers_request,
            }
            if redteam_probe:
                req_payload.update(redteam_probe)

            if "T3" in tiers_request and heldout_oracle_id:
                req_payload["heldout_mount"] = "/heldout"
                req_file = suites_dir / "request.json"
                req_file.write_text(canonical_json(req_payload), encoding="utf-8")
                req_file.chmod(0o644)
                with self.oracle_vault.ephemeral_verifier_mount(
                    heldout_oracle_id, scratch_root=run_scratch
                ) as heldout_host_dir:
                    raw = self._exec_docker(
                        staged_ws=staged_ws,
                        suites_dir=suites_dir,
                        heldout_dir=heldout_host_dir,
                    )
            else:
                req_file = suites_dir / "request.json"
                req_file.write_text(canonical_json(req_payload), encoding="utf-8")
                req_file.chmod(0o644)
                raw = self._exec_docker(
                    staged_ws=staged_ws,
                    suites_dir=suites_dir,
                    heldout_dir=None,
                )

            return raw, ws_hash
        finally:
            shutil.rmtree(run_scratch, ignore_errors=True)

    def _exec_docker(
        self,
        *,
        staged_ws: Path,
        suites_dir: Path,
        heldout_dir: Path | None,
    ) -> dict[str, Any]:
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
            "--env",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "--env",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
            "--env",
            "PYTHONNOUSERSITE=1",
            "--volume",
            f"{self.verifier_dir}:/verifier:ro",
            "--volume",
            f"{staged_ws}:/workspace:ro",
            "--volume",
            f"{suites_dir}:/suites:ro",
        ]
        if heldout_dir is not None:
            cmd.extend(["--volume", f"{heldout_dir}:/heldout:ro"])

        cmd.extend(
            [
                self.image_digest,
                "/usr/local/bin/python3",
                "-I",
                "-B",
                "/verifier/runner.py",
                "/suites/request.json",
            ]
        )
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60.0,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"Isolated verifier container failed (rc={proc.returncode}): "
                f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
            )
        return dict(json.loads(proc.stdout.strip()))
