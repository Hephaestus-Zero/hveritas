"""HTTP tool-tape recorder & offline replayer powered by `vcrpy`."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import vcr

from hveritas.effects.http import CapturedHttpExchange


def _to_bytes(val: object) -> bytes:
    if val is None:
        return b""
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return val.encode("utf-8")
    return str(val).encode("utf-8")


class VcrHttpCassetteManager:
    """Manages per-step `vcrpy` YAML cassettes for deterministic HTTP recording and replay."""

    def __init__(self, cassettes_dir: Path) -> None:
        self.cassettes_dir = cassettes_dir.resolve()
        self.cassettes_dir.mkdir(parents=True, exist_ok=True)

    def cassette_path(self, step_index: int) -> Path:
        return self.cassettes_dir / f"step_{step_index:04d}.yaml"

    @contextmanager
    def step_context(
        self,
        step_index: int,
        mode: str,  # "record" | "replay"
    ) -> Iterator[list[CapturedHttpExchange]]:
        """Enter a vcrpy context (`record` writes cassette; `replay` forbids live network)."""
        cpath = self.cassette_path(step_index)
        exchanges: list[CapturedHttpExchange] = []

        if mode == "replay" and not cpath.exists():
            # Step made zero HTTP calls during recording; enforce offline by blocking live calls
            my_vcr = vcr.VCR(
                serializer="yaml",
                record_mode="none",
                match_on=["method", "scheme", "host", "port", "path", "query"],
            )
            with my_vcr.use_cassette(str(cpath)):
                yield exchanges
            return

        vcr_mode = "all" if mode == "record" else "none"
        my_vcr = vcr.VCR(
            serializer="yaml",
            record_mode=vcr_mode,
            match_on=["method", "scheme", "host", "port", "path", "query"],
        )
        with my_vcr.use_cassette(str(cpath)) as cass:
            yield exchanges
            for req, resp in zip(cass.requests, cass.responses, strict=False):
                raw_body = resp.get("body", {}).get("string", b"")
                status_code = int(resp.get("status", {}).get("code", 0))
                exchanges.append(
                    CapturedHttpExchange(
                        method=str(req.method),
                        uri=str(req.uri),
                        request_body=_to_bytes(req.body),
                        status_code=status_code,
                        response_body=_to_bytes(raw_body),
                    )
                )
