"""Frozen deterministic environment specification (Invariant I8)."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ZERO_DIGEST = "sha256:" + ("0" * 64)


class FrozenEnvSnapshot(BaseModel):
    """Pinned environment configuration ensuring deterministic replay across runs."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    container_digest: str
    seed: int = 20261104
    clock_start_ns: int = 1_700_000_000_000_000_000
    clock_step_ns: int = 1_000_000
    timezone: str = "UTC"
    locale: str = "C.UTF-8"
    source_date_epoch: str = "1700000000"
    extra_env: dict[str, str] = Field(default_factory=dict)

    @field_validator("container_digest")
    @classmethod
    def _validate_container_digest(cls, value: str) -> str:
        if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
            raise ValueError(
                f"I8 VIOLATION: container_digest must match '^sha256:[0-9a-f]{{64}}$', got {value!r}"
            )
        if value == _ZERO_DIGEST:
            raise ValueError("I8 VIOLATION: all-zero placeholder container_digest is forbidden")
        return value

    def to_process_env(self) -> dict[str, str]:
        """Construct clean, isolated environment dictionary for deterministic child processes."""
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TZ": self.timezone,
            "LANG": self.locale,
            "LC_ALL": self.locale,
            "PYTHONHASHSEED": str(self.seed % 4294967295),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "SOURCE_DATE_EPOCH": self.source_date_epoch,
        }
        env.update(self.extra_env)
        return env
