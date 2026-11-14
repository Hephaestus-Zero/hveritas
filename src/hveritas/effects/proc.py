"""Independent OS process execution probe (Invariant I3)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hveritas.ledger.canonical import sha256_hex


@dataclass(frozen=True)
class RawProcessOutcome:
    """OS-level subprocess outcome captured directly by the sandbox harness, never by the agent."""

    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False


class ProcessProbe:
    """Extracts deterministic, tamper-proof process execution metrics from OS outcome."""

    def measure(self, outcome: RawProcessOutcome | None) -> tuple[int | None, dict[str, Any]]:
        if outcome is None:
            return None, {}
        metrics = {
            "exit_code": outcome.exit_code,
            "stdout_bytes": len(outcome.stdout),
            "stderr_bytes": len(outcome.stderr),
            "stdout_sha256": sha256_hex(outcome.stdout),
            "stderr_sha256": sha256_hex(outcome.stderr),
            "timed_out": outcome.timed_out,
        }
        return outcome.exit_code, metrics
