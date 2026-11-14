"""LLM Worker Policy (`M8-B`): translates `WorkerContext` + read-only workspace summary into `PlannedAction`s."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST
from hveritas.ledger.models import AgentClaim, CostRecord, RunRecord
from hveritas.ledger.store import AppendOnlyLedger
from hveritas.loop.models import RepairLadderRung, WorkerContext
from hveritas.tape.session import PlannedAction, build_builtin_tool_registry
from hveritas.worker.backend import (
    ModelBackend,
    ModelFamilyNotDistinctError,
    ModelResponse,
)

ALLOWED_TOOL_NAMES: frozenset[str] = frozenset(build_builtin_tool_registry().keys())

_FENCE_JSON_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)

_OUTPUT_CONTRACT_INSTRUCTIONS = """Return ONLY a single JSON object (optionally inside a ```json fence) with this exact schema:
{
  "actions": [
    {
      "tool_name": "write_file",
      "tool_args": {"path": "relative/path.py", "content": "..."},
      "claim": {"summary": "brief intent description", "reported_success": true}
    }
  ]
}
Allowed `tool_name` values and `tool_args` schemas:
- `write_file`: `{"path": str, "content": str, "mode"?: int}`
- `patch_file`: `{"path": str, "old": str, "new": str, "count"?: int}`
- `delete_file`: `{"path": str}`
- `run_cmd`: `{"argv": list[str], "timeout"?: float}`
- `sqlite_exec`: `{"db_path": str, "sql": str, "params"?: list}`
- `http_request`: `{"url": str, "method"?: str, "body"?: str, "headers"?: dict[str, str]}`
- `noop`: `{}`
Do NOT invoke any native host function-calling tools (never call write/edit/bash/read tool_use blocks) — output the JSON plan strictly as plain assistant text.
Do NOT invent any other tool names or keys."""


@dataclass(frozen=True)
class LlmCallTelemetry:
    """Per-call telemetry recorded by `LlmWorkerPolicy` for run reporting (`M8-E`)."""

    call_index: int
    task_id: str
    repair_attempt: int
    ladder_rung: str
    requested_family_slot: str
    requested_alias: str
    resolved_model: str
    resolved_family: str
    input_tokens: int
    output_tokens: int
    elapsed_ms: float
    usd: float
    output_valid: bool


def _extract_json_dict(raw_text: str) -> tuple[dict[str, Any] | None, str]:
    """Attempt parsing in exact M8-B order: plain JSON -> ```json fence -> first `{` to last `}`."""
    stripped = raw_text.strip()
    if not stripped:
        return None, "empty model output"

    # 1. Plain JSON
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed, ""
    except json.JSONDecodeError:
        pass

    # 2. Markdown ```json ... ``` fence
    m = _FENCE_JSON_RE.search(raw_text)
    if m:
        try:
            parsed = json.loads(m.group(1))
            if isinstance(parsed, dict):
                return parsed, ""
        except json.JSONDecodeError:
            pass

    # 3. Substring from first `{` to last `}`
    first = raw_text.find("{")
    last = raw_text.rfind("}")
    if first != -1 and last > first:
        try:
            parsed = json.loads(raw_text[first : last + 1])
            if isinstance(parsed, dict):
                return parsed, ""
        except json.JSONDecodeError as exc:
            return None, f"json decode error: {exc}"

    return None, "no JSON object found in model output"


def _path_stays_in_workspace(workspace: Path, rel_path: str) -> bool:
    if not rel_path or Path(rel_path).is_absolute():
        return False
    ws_res = workspace.resolve()
    try:
        target = (ws_res / rel_path).resolve()
    except OSError:
        return False
    return target == ws_res or ws_res in target.parents


def _validate_tool_args_schema(tool_name: str, args: dict[str, Any]) -> str | None:
    """Return error reason if `args` violates schema for `tool_name`, else `None`."""
    keys = set(args.keys())
    if tool_name == "write_file":
        if not {"path", "content"} <= keys or not keys <= {"path", "content", "mode"}:
            return "write_file requires {path, content} [mode]"
        if not isinstance(args["path"], str) or not isinstance(args["content"], str):
            return "write_file path and content must be str"
        if "mode" in args and (isinstance(args["mode"], bool) or not isinstance(args["mode"], int)):
            return "write_file mode must be int"
        return None

    if tool_name == "patch_file":
        if not {"path", "old", "new"} <= keys or not keys <= {"path", "old", "new", "count"}:
            return "patch_file requires {path, old, new} [count]"
        if not all(isinstance(args[k], str) for k in ("path", "old", "new")):
            return "patch_file path/old/new must be str"
        if "count" in args and (
            isinstance(args["count"], bool) or not isinstance(args["count"], int)
        ):
            return "patch_file count must be int"
        return None

    if tool_name == "delete_file":
        if keys != {"path"} or not isinstance(args["path"], str):
            return "delete_file requires {path: str}"
        return None

    if tool_name == "run_cmd":
        if "argv" not in keys or not keys <= {"argv", "timeout"}:
            return "run_cmd requires {argv} [timeout]"
        argv = args["argv"]
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            return "run_cmd argv must be a non-empty list[str]"
        if "timeout" in args and (
            isinstance(args["timeout"], bool) or not isinstance(args["timeout"], (int, float))
        ):
            return "run_cmd timeout must be numeric"
        return None

    if tool_name == "sqlite_exec":
        if not {"db_path", "sql"} <= keys or not keys <= {"db_path", "sql", "params"}:
            return "sqlite_exec requires {db_path, sql} [params]"
        if not isinstance(args["db_path"], str) or not isinstance(args["sql"], str):
            return "sqlite_exec db_path and sql must be str"
        if "params" in args and not isinstance(args["params"], list):
            return "sqlite_exec params must be list"
        return None

    if tool_name == "http_request":
        if "url" not in keys or not keys <= {"url", "method", "body", "headers"}:
            return "http_request requires {url} [method, body, headers]"
        if not isinstance(args["url"], str):
            return "http_request url must be str"
        if "method" in args and not isinstance(args["method"], str):
            return "http_request method must be str"
        if "body" in args and args["body"] is not None and not isinstance(args["body"], str):
            return "http_request body must be str | None"
        if "headers" in args and not isinstance(args["headers"], dict):
            return "http_request headers must be dict"
        return None

    if tool_name == "noop":
        if keys:
            return "noop accepts empty tool_args only"
        return None

    return f"unknown tool_name: {tool_name!r}"


def _build_readonly_workspace_summary(
    workspace: Path,
    target_file: str,
    budget_bytes: int,
) -> str:
    """Read-only workspace snapshot: full `target_file` if present + headers of other `.py` files within byte budget."""
    ws_res = workspace.resolve()
    chunks: list[str] = []
    used = 0

    def _try_append(block: str) -> bool:
        nonlocal used
        encoded_len = len(block.encode("utf-8"))
        if used + encoded_len <= budget_bytes:
            chunks.append(block)
            used += encoded_len
            return True
        rem = budget_bytes - used
        if rem > 64:
            clipped = block.encode("utf-8")[:rem].decode("utf-8", errors="ignore")
            chunks.append(clipped)
            used = budget_bytes
        return False

    target_rel = Path(target_file)
    if not target_rel.is_absolute():
        target_abs = (ws_res / target_rel).resolve()
        if (target_abs == ws_res or ws_res in target_abs.parents) and target_abs.is_file():
            content = target_abs.read_text(encoding="utf-8", errors="replace")
            _try_append(f"### Target File: `{target_file}`\n```python\n{content}\n```\n")

    py_files = sorted(
        p
        for p in ws_res.rglob("*.py")
        if p.is_file()
        and not any(part in {".git", "__pycache__", ".venv", "venv"} for part in p.parts)
    )
    for pf in py_files:
        rel_str = str(pf.relative_to(ws_res))
        if rel_str == target_file:
            continue
        lines = pf.read_text(encoding="utf-8", errors="replace").splitlines()[:20]
        preview = "\n".join(lines)
        if not _try_append(f"### File: `{rel_str}` (preview)\n```python\n{preview}\n```\n"):
            break

    return "\n".join(chunks) if chunks else "(empty workspace)"


class LlmWorkerPolicy:
    """Side-effect-free LLM policy adapter implementing `WorkerPolicy` (Invariants I10, I11, I12, I13)."""

    def __init__(
        self,
        *,
        backend: ModelBackend,
        primary_model: str = "muse",
        worker_model: str | None = None,
        alternate_model: str = "argon",
        max_actions: int = 20,
        timeout_s: float = 180.0,
        context_file_budget_bytes: int = 24_000,
        ledger: AppendOnlyLedger | None = None,
        ledger_run_id: str | None = None,
    ) -> None:
        self.backend = backend
        self.primary_model = worker_model if worker_model is not None else primary_model
        self.alternate_model = alternate_model
        self.max_actions = max_actions
        self.timeout_s = timeout_s
        self.context_file_budget_bytes = context_file_budget_bytes
        self._ledger = ledger
        self._ledger_run_id = ledger_run_id

        self._primary_resolved_family: str | None = None
        self._alternate_resolved_family: str | None = None
        self.call_telemetry: list[LlmCallTelemetry] = []

    @property
    def primary_resolved_family(self) -> str | None:
        return self._primary_resolved_family

    @property
    def alternate_resolved_family(self) -> str | None:
        return self._alternate_resolved_family

    def build_user_prompt(self, ctx: WorkerContext, workspace: Path) -> str:
        """Assemble user prompt in exact M8-B required section order."""
        sections: list[str] = [
            f"## 1. Task Statement\n{ctx.statement}",
            (
                "## 2. API Contract\n"
                f"- Target file: `{ctx.target_file}`\n"
                f"- Function signature: `{ctx.function_name}({', '.join(ctx.arg_names)})`"
            ),
        ]

        proxy_blocks = [
            f"### `{fname}`\n```python\n{code}\n```"
            for fname, code in sorted(ctx.visible_proxy_tests.items())
        ]
        sections.append(
            "## 3. Visible Proxy Tests\n"
            + ("\n".join(proxy_blocks) if proxy_blocks else "(no proxy tests)")
        )

        ws_summary = _build_readonly_workspace_summary(
            workspace=workspace,
            target_file=ctx.target_file,
            budget_bytes=self.context_file_budget_bytes,
        )
        sections.append(f"## 4. Workspace Summary (Read-Only)\n{ws_summary}")

        if ctx.repair_attempt > 0 and ctx.attributed_cause is not None:
            cause = ctx.attributed_cause
            step_idx = cause.get("culprit_step_index", 0)
            t_name = cause.get("tool_name", "unknown")
            t_leaf = cause.get("trail_leaf", "UNKNOWN")
            expl = cause.get("explanation", "")
            sections.append(
                "## 5. Repair Briefing\n"
                f"Önceki denemede adım {step_idx} ({t_name}) hatalıydı; "
                f"TRAIL sınıfı {t_leaf}. Aynı hatayı tekrarlama.\n"
                + (f"Detay: {expl}" if expl else "")
            )

        if ctx.ladder_rung == RepairLadderRung.TIGHTER_CONSTRAINTS:
            half_budget = max(1, self.max_actions // 2)
            sections.append(
                "## 6. Tighter Constraints Escalation\n"
                f"Eylem sayısını yarıya indir (en fazla {half_budget} eylem üret) "
                f"ve YALNIZCA tek bir dosyaya (`{ctx.target_file}`) dokun."
            )

        sections.append(f"## Output Contract\n{_OUTPUT_CONTRACT_INSTRUCTIONS}")
        return "\n\n".join(sections)

    def _emit_invalid_output(
        self,
        *,
        resp: ModelResponse,
        cost: CostRecord,
        reason: str,
    ) -> list[PlannedAction]:
        raw_excerpt = resp.text[:2000]
        emitted = False
        if self._ledger is not None and self._ledger_run_id is not None:
            now_ns = time.time_ns()
            if self._ledger.get_run(self._ledger_run_id) is None:
                self._ledger.append_run(
                    RunRecord(
                        run_id=self._ledger_run_id,
                        goal="llm_worker_policy",
                        container_digest=DEFAULT_VERIFIER_IMAGE_DIGEST,
                        seed=0,
                        started_at_ns=now_ns,
                        metadata={"source": "LlmWorkerPolicy"},
                    )
                )
            self._ledger.append_event(
                self._ledger_run_id,
                "MODEL_OUTPUT_INVALID",
                now_ns,
                {"reason": reason, "raw_text": raw_excerpt, "model": resp.model},
            )
            emitted = True
        return [
            PlannedAction(
                tool_name="noop",
                tool_args={},
                claim=AgentClaim(
                    summary="model output invalid",
                    reported_success=False,
                    raw_output=raw_excerpt,
                    structured_claim={
                        "event_type": "MODEL_OUTPUT_INVALID",
                        "reason": reason,
                        "raw_text": raw_excerpt,
                        "model": resp.model,
                        "emitted_to_ledger": emitted,
                    },
                ),
                cost=cost,
            )
        ]

    def __call__(self, ctx: WorkerContext, workspace: Path) -> list[PlannedAction]:
        is_alpha = ctx.model_family == "family-alpha"
        chosen_alias = self.primary_model if is_alpha else self.alternate_model
        user_prompt = self.build_user_prompt(ctx, workspace)

        resp = self.backend.complete(
            system=ctx.system_prompt,
            user=user_prompt,
            model=chosen_alias,
            timeout_s=self.timeout_s,
        )

        # Enforce Invariant I11: model family distinctness is verified from actual response `family`, never assumed!
        if is_alpha:
            if self._primary_resolved_family is None:
                self._primary_resolved_family = resp.family
            if (
                self._alternate_resolved_family is not None
                and resp.family == self._alternate_resolved_family
            ):
                raise ModelFamilyNotDistinctError(
                    f"I11 VIOLATION: primary alias {self.primary_model!r} resolved to family "
                    f"{resp.family!r}, identical to alternate alias {self.alternate_model!r}"
                )
        else:
            if self._alternate_resolved_family is None:
                self._alternate_resolved_family = resp.family
            if (
                self._primary_resolved_family is not None
                and resp.family == self._primary_resolved_family
            ):
                raise ModelFamilyNotDistinctError(
                    f"I11 VIOLATION: DIFFERENT_MODEL_FAMILY alias {chosen_alias!r} resolved to "
                    f"family {resp.family!r}, identical to primary family {self._primary_resolved_family!r}"
                )

        # Invariant I12: exact measured tokens, elapsed_ms, and usd on the first action only
        measured_cost = CostRecord(
            input_tokens=resp.input_tokens,
            output_tokens=resp.output_tokens,
            usd=resp.usd,
            wall_ms=resp.elapsed_ms,
        )

        try:
            parsed_obj, parse_err = _extract_json_dict(resp.text)
            if parsed_obj is None:
                self._record_telemetry(ctx, chosen_alias, resp, output_valid=False)
                return self._emit_invalid_output(resp=resp, cost=measured_cost, reason=parse_err)

            raw_actions = parsed_obj.get("actions")
            if not isinstance(raw_actions, list) or len(raw_actions) == 0:
                self._record_telemetry(ctx, chosen_alias, resp, output_valid=False)
                return self._emit_invalid_output(
                    resp=resp,
                    cost=measured_cost,
                    reason="JSON must contain non-empty 'actions' list",
                )

            validated: list[PlannedAction] = []
            for item in raw_actions:
                if not isinstance(item, dict):
                    self._record_telemetry(ctx, chosen_alias, resp, output_valid=False)
                    return self._emit_invalid_output(
                        resp=resp,
                        cost=measured_cost,
                        reason="Each item in 'actions' must be a JSON object",
                    )
                t_name = item.get("tool_name")
                t_args = item.get("tool_args")
                if not isinstance(t_name, str) or t_name not in ALLOWED_TOOL_NAMES:
                    self._record_telemetry(ctx, chosen_alias, resp, output_valid=False)
                    return self._emit_invalid_output(
                        resp=resp,
                        cost=measured_cost,
                        reason=f"Unknown or disallowed tool_name: {t_name!r}",
                    )
                if not isinstance(t_args, dict):
                    self._record_telemetry(ctx, chosen_alias, resp, output_valid=False)
                    return self._emit_invalid_output(
                        resp=resp,
                        cost=measured_cost,
                        reason=f"tool_args for {t_name!r} must be a dict",
                    )
                schema_err = _validate_tool_args_schema(t_name, t_args)
                if schema_err is not None:
                    self._record_telemetry(ctx, chosen_alias, resp, output_valid=False)
                    return self._emit_invalid_output(
                        resp=resp,
                        cost=measured_cost,
                        reason=schema_err,
                    )

                raw_claim = item.get("claim")
                if isinstance(raw_claim, dict):
                    rep_succ = raw_claim.get("reported_success")
                    claim_obj = AgentClaim(
                        summary=str(raw_claim.get("summary", "")),
                        reported_success=rep_succ if isinstance(rep_succ, bool) else None,
                    )
                else:
                    claim_obj = AgentClaim()

                # Path-escape defense: convert workspace-escaping file/db actions into `noop`
                path_key = (
                    "db_path" if t_name == "sqlite_exec" else ("path" if "path" in t_args else None)
                )
                if path_key is not None and not _path_stays_in_workspace(
                    workspace, str(t_args[path_key])
                ):
                    validated.append(
                        PlannedAction(
                            tool_name="noop",
                            tool_args={},
                            claim=AgentClaim(
                                summary=f"blocked workspace-escaping path in {t_name}",
                                reported_success=False,
                            ),
                        )
                    )
                else:
                    validated.append(
                        PlannedAction(
                            tool_name=t_name,
                            tool_args=dict(t_args),
                            claim=claim_obj,
                        )
                    )

            if len(validated) > self.max_actions:
                keep_count = max(0, self.max_actions - 1)
                validated = [
                    *validated[:keep_count],
                    PlannedAction(
                        tool_name="noop",
                        tool_args={},
                        claim=AgentClaim(
                            summary=f"truncated action plan exceeding max_actions={self.max_actions}",
                            reported_success=False,
                        ),
                    ),
                ]

            # Attach measured LLM cost ONLY to action[0]; remaining actions carry zero CostRecord (I12)
            first = validated[0]
            actions_with_cost: list[PlannedAction] = [
                PlannedAction(
                    tool_name=first.tool_name,
                    tool_args=first.tool_args,
                    claim=first.claim,
                    cost=measured_cost,
                ),
                *[
                    PlannedAction(
                        tool_name=a.tool_name,
                        tool_args=a.tool_args,
                        claim=a.claim,
                        cost=CostRecord(),
                    )
                    for a in validated[1:]
                ],
            ]
        except (TypeError, ValueError, KeyError, IndexError) as exc:
            self._record_telemetry(ctx, chosen_alias, resp, output_valid=False)
            return self._emit_invalid_output(
                resp=resp,
                cost=measured_cost,
                reason=f"unexpected payload validation failure: {exc}",
            )

        self._record_telemetry(ctx, chosen_alias, resp, output_valid=True)
        return actions_with_cost

    def _record_telemetry(
        self,
        ctx: WorkerContext,
        chosen_alias: str,
        resp: ModelResponse,
        *,
        output_valid: bool,
    ) -> None:
        self.call_telemetry.append(
            LlmCallTelemetry(
                call_index=len(self.call_telemetry),
                task_id=ctx.task_id,
                repair_attempt=ctx.repair_attempt,
                ladder_rung=ctx.ladder_rung.value,
                requested_family_slot=ctx.model_family,
                requested_alias=chosen_alias,
                resolved_model=resp.model,
                resolved_family=resp.family,
                input_tokens=resp.input_tokens,
                output_tokens=resp.output_tokens,
                elapsed_ms=resp.elapsed_ms,
                usd=resp.usd,
                output_valid=output_valid,
            )
        )
