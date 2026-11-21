"""Model Backend Layer (`M8-A`): `HxCliBackend`, `AnthropicApiBackend`, and `FakeBackend` (I10, I11, I12)."""

from __future__ import annotations

import errno
import inspect
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from hveritas.harness.isolation import SCRATCH_ROOT

PLANNER_SCRATCH_ROOT = SCRATCH_ROOT / "hveritas-planner"


class PlannerSideEffectError(RuntimeError):
    """Raised when a model planner modifies or creates files instead of returning pure JSON (I10)."""


class ModelTimeoutError(TimeoutError):
    """Raised when a model backend invocation exceeds `timeout_s`."""


class ModelProtocolError(RuntimeError):
    """Raised when a model backend returns unparseable or protocol-invalid output."""


class ModelFamilyNotDistinctError(RuntimeError):
    """Raised when `DIFFERENT_MODEL_FAMILY` resolves to the same model family as primary (I11)."""


class ModelResponse(BaseModel):
    """Immutable response envelope returned by any `ModelBackend`."""

    model_config = ConfigDict(frozen=True)

    text: str
    model: str
    family: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    elapsed_ms: float = Field(ge=0.0)
    usd: float = Field(default=0.0, ge=0.0)


@runtime_checkable
class ModelBackend(Protocol):
    """Side-effect-free planner completion protocol."""

    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str | None,
        timeout_s: float,
    ) -> ModelResponse: ...


def _parse_hx_json_stdout(stdout: str, *, stderr: str = "") -> dict[str, Any]:
    """Parse `hx --json` stdout; if noisy prefix lines exist, scan backwards from the last line."""
    stripped = stdout.strip()
    if not stripped:
        err_tail = stderr.strip()[-300:]
        detail = f": {err_tail}" if err_tail else ""
        raise ModelProtocolError(f"Empty stdout from hx CLI{detail}")

    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    for line in reversed(lines):
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue

    decoder = json.JSONDecoder()
    for pos in range(len(stdout) - 1, -1, -1):
        if stdout[pos] == "{":
            try:
                obj, _ = decoder.raw_decode(stdout, pos)
                if isinstance(obj, dict) and ("ok" in obj or "text" in obj):
                    return obj
            except json.JSONDecodeError:
                continue

    raise ModelProtocolError(f"Could not parse JSON object from hx stdout: {stdout[-500:]!r}")


class HxCliBackend:
    """Primary backend invoking `hx` headless gateway in an empty, per-call sealed scratch directory (I10)."""

    def __init__(
        self,
        *,
        hx_bin: str | Path = "hx",
        default_model: str = "muse",
        planner_scratch_root: Path = PLANNER_SCRATCH_ROOT,
        live_workspace_guard: Path | None = None,
    ) -> None:
        self.hx_bin = str(hx_bin)
        self.default_model = default_model
        self.planner_scratch_root = planner_scratch_root.resolve()
        self.live_workspace_guard = (
            live_workspace_guard.resolve() if live_workspace_guard is not None else None
        )

    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str | None,
        timeout_s: float,
    ) -> ModelResponse:
        chosen_model = model or self.default_model
        self.planner_scratch_root.mkdir(parents=True, exist_ok=True)
        sealed_dir = (self.planner_scratch_root / str(uuid.uuid4())).resolve()
        sealed_dir.mkdir(parents=True, exist_ok=False, mode=0o700)

        if self.live_workspace_guard is not None and (
            sealed_dir == self.live_workspace_guard
            or self.live_workspace_guard in sealed_dir.parents
            or sealed_dir in self.live_workspace_guard.parents
        ):
            shutil.rmtree(sealed_dir, ignore_errors=True)
            raise PlannerSideEffectError(
                f"I10 VIOLATION: Sealed planner dir {sealed_dir} overlaps live workspace!"
            )

        combined_prompt = (
            "[PLANNER-ONLY MODE — INVARIANT I10]\n"
            "Do NOT invoke any native function-calling tools (do NOT call write, edit, bash, read, "
            "search, or any tool_use block). You MUST reply directly in plain assistant text with "
            "ONLY the requested JSON object; external TapeRunner executes the planned actions.\n\n"
            f"[SYSTEM]\n{system}\n\n[USER]\n{user}"
        )
        tail_args = [
            "-m",
            chosen_model,
            "--preset",
            "minimal",
            "--no-commit",
            "--json",
            "-C",
            str(sealed_dir),
        ]
        cmd = [self.hx_bin, "-p", combined_prompt, *tail_args]

        def _is_python_entrypoint(exec_path: str) -> bool:
            p = Path(exec_path)
            if not p.is_file():
                return False
            try:
                head = p.read_bytes()[:128].splitlines()[0]
            except (OSError, IndexError):
                return False
            return head.startswith(b"#!") and b"python" in head.lower()

        def _run_via_python_stdin(exec_path: str) -> subprocess.CompletedProcess[str]:
            shim = (
                "import runpy, sys; "
                "p = sys.stdin.read(); "
                "sys.argv = [sys.argv[1], '-p', p, *sys.argv[2:]]; "
                "runpy.run_path(sys.argv[0], run_name='__main__')"
            )
            return subprocess.run(
                [sys.executable, "-c", shim, exec_path, *tail_args],
                cwd=str(sealed_dir),
                input=combined_prompt,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )

        try:
            try:
                resolved_hx = shutil.which(self.hx_bin) or self.hx_bin
                if len(combined_prompt.encode("utf-8")) > 115_000 and _is_python_entrypoint(
                    resolved_hx
                ):
                    proc = _run_via_python_stdin(resolved_hx)
                else:
                    try:
                        proc = subprocess.run(
                            cmd,
                            cwd=str(sealed_dir),
                            capture_output=True,
                            text=True,
                            timeout=timeout_s,
                            check=False,
                        )
                    except OSError as exc:
                        if exc.errno == errno.E2BIG and _is_python_entrypoint(resolved_hx):
                            proc = _run_via_python_stdin(resolved_hx)
                        else:
                            raise
            except subprocess.TimeoutExpired as exc:
                raise ModelTimeoutError(
                    f"hx call timed out after {timeout_s:.1f}s for model={chosen_model!r}"
                ) from exc
            except FileNotFoundError as exc:
                raise ModelProtocolError(
                    f"Planner binary {self.hx_bin!r} not found on PATH. "
                    "Install `hx` or run with `--backend anthropic` "
                    "(requires ANTHROPIC_API_KEY) or `--backend fake`."
                ) from exc
            except OSError as exc:
                raise ModelProtocolError(
                    f"Failed to invoke hx binary {self.hx_bin!r}: {exc}. "
                    "Alternatively run with `--backend anthropic` or `--backend fake`."
                ) from exc

            payload = _parse_hx_json_stdout(proc.stdout, stderr=proc.stderr)

            modified_files = payload.get("modified_files")
            if modified_files:
                raise PlannerSideEffectError(
                    f"I10 VIOLATION: Planner attempted to modify files: {modified_files!r}"
                )

            created_artifacts = [
                str(p.relative_to(sealed_dir))
                for p in sealed_dir.rglob("*")
                if p.is_file()
                and not any(part.startswith(".") for part in p.relative_to(sealed_dir).parts)
            ]
            if created_artifacts:
                raise PlannerSideEffectError(
                    f"I10 VIOLATION: Planner wrote files in sealed scratch dir: {created_artifacts!r}"
                )

            if payload.get("ok") is False:
                raise ModelProtocolError(
                    f"hx returned ok=false (rc={proc.returncode}): {payload!r}"
                )

            family_raw = payload.get("family")
            if not isinstance(family_raw, str) or not family_raw.strip():
                raise ModelProtocolError(f"hx JSON missing non-empty 'family' field: {payload!r}")
            if (
                "input_tokens" not in payload
                or "output_tokens" not in payload
                or "elapsed_ms" not in payload
            ):
                raise ModelProtocolError(
                    f"hx JSON missing token/timing telemetry fields: {payload!r}"
                )

            return ModelResponse(
                text=str(payload.get("text", "")),
                model=str(payload.get("model", chosen_model)),
                family=family_raw,
                input_tokens=int(payload["input_tokens"]),
                output_tokens=int(payload["output_tokens"]),
                elapsed_ms=float(payload["elapsed_ms"]),
                usd=float(payload.get("usd", 0.0) or 0.0),
            )
        finally:
            shutil.rmtree(sealed_dir, ignore_errors=True)


class AnthropicApiBackend:
    """Optional direct Anthropic Messages API backend (`ANTHROPIC_API_KEY` required)."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        default_model: str = "claude-opus-5-5",
        max_tokens: int = 4096,
    ) -> None:
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not resolved_key:
            raise ModelProtocolError(
                "AnthropicApiBackend requires ANTHROPIC_API_KEY in environment or explicit api_key"
            )
        self._api_key = resolved_key
        self.default_model = default_model
        self.max_tokens = max_tokens

    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str | None,
        timeout_s: float,
    ) -> ModelResponse:
        import anthropic

        chosen_model = model or self.default_model
        client = anthropic.Anthropic(api_key=self._api_key, timeout=timeout_s)
        t0 = time.perf_counter()
        try:
            msg = client.messages.create(
                model=chosen_model,
                max_tokens=self.max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APITimeoutError as exc:
            raise ModelTimeoutError(f"Anthropic request timed out after {timeout_s:.1f}s") from exc
        except anthropic.APIError as exc:
            raise ModelProtocolError(f"Anthropic API error: {exc}") from exc

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        chunks: list[str] = []
        for block in msg.content:
            text_attr = getattr(block, "text", None)
            if isinstance(text_attr, str):
                chunks.append(text_attr)

        return ModelResponse(
            text="\n".join(chunks),
            model=str(msg.model),
            family="claude",
            input_tokens=int(msg.usage.input_tokens),
            output_tokens=int(msg.usage.output_tokens),
            elapsed_ms=elapsed_ms,
            usd=0.0,
        )


FakeResponseSource = (
    Sequence[ModelResponse]
    | Callable[[str], ModelResponse]
    | Callable[[str, str, str | None], ModelResponse]
)


class FakeBackend:
    """Deterministic zero-network/zero-subprocess backend for fast M8 unit & integration tests."""

    def __init__(self, responses: FakeResponseSource) -> None:
        if callable(responses):
            self._callable: Callable[..., ModelResponse] | None = responses
            self._queue: list[ModelResponse] = []
        else:
            items = list(responses)
            if not items:
                raise ValueError("FakeBackend requires at least one ModelResponse")
            self._callable = None
            self._queue = items
        self._cursor = 0
        self.calls: list[dict[str, Any]] = []

    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str | None,
        timeout_s: float,
    ) -> ModelResponse:
        self.calls.append(
            {
                "system": system,
                "user": user,
                "model": model,
                "timeout_s": timeout_s,
            }
        )
        if self._callable is not None:
            sig = inspect.signature(self._callable)
            params = [
                p
                for p in sig.parameters.values()
                if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
            ]
            if len(params) >= 3:
                return self._callable(system, user, model)
            return self._callable(user)

        idx = min(self._cursor, len(self._queue) - 1)
        self._cursor += 1
        return self._queue[idx]
