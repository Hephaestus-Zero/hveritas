"""Canonical serialization, hashing, deterministic clocks, and OTel ID generation."""

from __future__ import annotations

import hashlib
import json
import random
import time
from typing import Any

from opentelemetry.sdk.trace.id_generator import IdGenerator


def canonical_json(obj: Any) -> str:
    """Deterministic UTF-8 JSON encoding with sorted keys and compact separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes | str) -> str:
    """Compute lowercase SHA-256 hex digest."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def compute_receipt_hash(
    prev_receipt_hash: str,
    envelope_dict: dict[str, Any],
    measured_dict: dict[str, Any],
) -> str:
    """Compute tamper-evident Merkle chain hash over envelope and independently measured effects.

    Note (I3): Agent claims are intentionally excluded from the authoritative state/effect chain
    or hashed in a segregated envelope only as untrusted metadata; here the receipt chain seals
    (prev_receipt_hash, envelope, measured) so claim text never alters effect identity.
    """
    payload = canonical_json(
        {
            "prev": prev_receipt_hash,
            "envelope": envelope_dict,
            "measured": measured_dict,
        }
    )
    return sha256_hex(payload)


class DeterministicClock:
    """Monotonic nanosecond clock supporting frozen/deterministic replay (I8)."""

    def __init__(self, start_ns: int | None = None, step_ns: int = 1_000_000) -> None:
        self._deterministic = start_ns is not None
        self._current_ns = start_ns if start_ns is not None else time.time_ns()
        self._step_ns = step_ns

    @property
    def is_deterministic(self) -> bool:
        return self._deterministic

    def now_ns(self) -> int:
        if self._deterministic:
            val = self._current_ns
            self._current_ns += self._step_ns
            return val
        return time.time_ns()

    def peek_ns(self) -> int:
        return self._current_ns


class SeededIdGenerator(IdGenerator):
    """Deterministic OTel Trace/Span ID generator seeded for exact replay (I8)."""

    def __init__(self, seed: int) -> None:
        self._rng = random.Random(seed)

    def generate_span_id(self) -> int:
        val = self._rng.getrandbits(64)
        return val if val != 0 else 1

    def generate_trace_id(self) -> int:
        val = self._rng.getrandbits(128)
        return val if val != 0 else 1
