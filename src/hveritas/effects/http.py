"""Independent HTTP side-effect probe backed by transport/cassette capture (Invariant I3)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hveritas.ledger.canonical import sha256_hex


@dataclass(frozen=True)
class CapturedHttpExchange:
    method: str
    uri: str
    request_body: bytes
    status_code: int
    response_body: bytes


class HttpEffectProbe:
    """Measures outbound HTTP requests and responses directly from transport cassettes."""

    def measure(self, exchanges: list[CapturedHttpExchange] | None) -> list[dict[str, Any]]:
        if not exchanges:
            return []
        return [
            {
                "method": ex.method.upper(),
                "uri": ex.uri,
                "request_body_bytes": len(ex.request_body),
                "request_body_sha256": sha256_hex(ex.request_body),
                "status_code": ex.status_code,
                "response_body_bytes": len(ex.response_body),
                "response_body_sha256": sha256_hex(ex.response_body),
            }
            for ex in exchanges
        ]
