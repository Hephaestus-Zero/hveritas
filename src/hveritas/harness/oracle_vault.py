"""Encrypted Held-Out Oracle Vault in separate repository (`~/.local/share/hveritas/hveritas-oracles`).

Enforces Invariant I4 and §3 Req 4:
- Held-out test suites are AES-256-GCM encrypted at rest in a separate repository outside `~/projects/hveritas`.
- Held-out files NEVER exist on any worker filesystem.
- Decrypted files are staged ONLY into an ephemeral `0755` container mount directory for the isolated verifier
  container (`uid=10001`, `--network=none`) during T3 evaluation and wiped immediately after.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hveritas.ledger.canonical import canonical_json

DEFAULT_ORACLES_REPO = Path.home() / ".local" / "share" / "hveritas" / "hveritas-oracles"
DEFAULT_ORACLE_KEY_FILE = Path.home() / ".local" / "share" / "hveritas" / "oracle.key"


def _write_private_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Create or overwrite `path` atomically with `0o600` permissions (no umask exposure window)."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        fh = os.fdopen(fd, "w", encoding=encoding)
    except BaseException:
        os.close(fd)
        raise
    with fh:
        fh.write(text)
    path.chmod(0o600)


class EncryptedOracleVault:
    """Manages AES-256-GCM encrypted held-out acceptance suites in a separate repository."""

    def __init__(
        self,
        repo_dir: Path = DEFAULT_ORACLES_REPO,
        key_file: Path = DEFAULT_ORACLE_KEY_FILE,
    ) -> None:
        self.repo_dir = repo_dir.resolve()
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        self.repo_dir.chmod(0o700)
        self.key_file = key_file.resolve()
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        if self.key_file.is_file():
            raw = bytes.fromhex(self.key_file.read_text(encoding="ascii").strip())
            if len(raw) == 32:
                return raw
        key = AESGCM.generate_key(bit_length=256)
        _write_private_text(self.key_file, key.hex(), encoding="ascii")
        return key

    def bundle_path(self, oracle_id: str) -> Path:
        safe_id = "".join(ch for ch in oracle_id if ch.isalnum() or ch in ("-", "_"))
        if not safe_id:
            raise ValueError(f"Invalid oracle_id: {oracle_id!r}")
        return self.repo_dir / f"{safe_id}.aesgcm"

    def store_oracle_suite(
        self,
        oracle_id: str,
        test_files: dict[str, str],
        git_commit: bool = False,
    ) -> Path:
        """Encrypt `test_files` (`test_*.py` -> source) with AES-256-GCM and write ciphertext only."""
        aes = AESGCM(self._key)
        nonce = secrets.token_bytes(12)
        aad = f"hveritas-oracle:{oracle_id}".encode()
        plaintext = canonical_json({"oracle_id": oracle_id, "files": test_files}).encode("utf-8")
        ciphertext = aes.encrypt(nonce, plaintext, aad)

        envelope = {
            "version": 1,
            "alg": "AES-256-GCM",
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex(),
        }
        out_path = self.bundle_path(oracle_id)
        _write_private_text(out_path, canonical_json(envelope), encoding="utf-8")

        if git_commit and (self.repo_dir / ".git").is_dir():
            subprocess.run(
                ["git", "add", out_path.name],
                cwd=str(self.repo_dir),
                check=False,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-m", f"oracle: seal {oracle_id}"],
                cwd=str(self.repo_dir),
                check=False,
                capture_output=True,
            )
        return out_path

    def decrypt_oracle_suite(self, oracle_id: str) -> dict[str, str]:
        """Decrypt held-out oracle suite in memory (verifier host coordinator only)."""
        path = self.bundle_path(oracle_id)
        if not path.is_file():
            raise FileNotFoundError(f"Encrypted oracle bundle not found: {oracle_id}")
        env = json.loads(path.read_text(encoding="utf-8"))
        nonce = bytes.fromhex(env["nonce_hex"])
        ciphertext = bytes.fromhex(env["ciphertext_hex"])
        aad = f"hveritas-oracle:{oracle_id}".encode()
        aes = AESGCM(self._key)
        plaintext = aes.decrypt(nonce, ciphertext, aad)
        payload = json.loads(plaintext.decode("utf-8"))
        return {str(k): str(v) for k, v in dict(payload["files"]).items()}

    @contextmanager
    def ephemeral_verifier_mount(
        self,
        oracle_id: str,
        scratch_root: Path | None = None,
    ) -> Iterator[Path]:
        """Decrypt oracle into an ephemeral directory strictly for verifier container `:ro` mount, then shred."""
        if scratch_root is None:
            from hveritas.harness.isolation import default_scratch_root

            scratch_root = default_scratch_root()
        scratch_root.mkdir(parents=True, exist_ok=True)
        mount_dir = scratch_root / f"hv_heldout_{os.getpid()}_{secrets.token_hex(8)}"
        mount_dir.mkdir(parents=True, mode=0o755)
        try:
            files = self.decrypt_oracle_suite(oracle_id)
            for rel_name, content in files.items():
                p = (mount_dir / rel_name).resolve()
                if mount_dir not in p.parents:
                    raise ValueError(f"Invalid oracle file path: {rel_name}")
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
                p.chmod(0o444)
            yield mount_dir
        finally:
            if mount_dir.exists():
                for p in mount_dir.rglob("*"):
                    if p.is_file():
                        p.chmod(0o600)
                        p.write_bytes(b"\x00" * p.stat().st_size)
                shutil.rmtree(mount_dir, ignore_errors=True)
