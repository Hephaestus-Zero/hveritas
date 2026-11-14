"""Spec Interview (`M9-A`): interactive goal interpretation, edge-case table, and I19 user approval."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from hveritas.ledger.models import CostRecord
from hveritas.spec.compiler import (
    _AMBIGUOUS_MARKERS_RE,
    HumanClarificationRequiredError,
    RequirementDraft,
)
from hveritas.spec.models import IOAssertion

if TYPE_CHECKING:
    from hveritas.worker.backend import ModelBackend

_FENCE_JSON_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def _extract_json_object(raw_text: str) -> tuple[dict[str, Any] | None, str]:
    stripped = raw_text.strip()
    if not stripped:
        return None, "empty model output"
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed, ""
    except json.JSONDecodeError:
        pass
    m = _FENCE_JSON_RE.search(raw_text)
    if m:
        try:
            parsed = json.loads(m.group(1))
            if isinstance(parsed, dict):
                return parsed, ""
        except json.JSONDecodeError:
            pass
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


_EXCEPTION_LITERAL_RE = re.compile(
    r"^(?:raises?\s+)?(?:ValueError|TypeError|KeyError|IndexError|"
    r"ZeroDivisionError|RuntimeError|AssertionError|OverflowError)(?:\b|\()",
    re.IGNORECASE,
)


class EdgeCase(BaseModel):
    """Explicit boundary/invalid/special input row produced during M9-A spec interview."""

    model_config = ConfigDict(frozen=True)

    args: list[Any] = Field(default_factory=list)
    input_repr: str = ""
    expected_behavior: str
    rationale: str
    category: str = "boundary"


class InterviewResult(BaseModel):
    """Structured output of `interview_goal` (never contains held-out assertions per M9-A/I15)."""

    model_config = ConfigDict(frozen=True)

    requirements: list[RequirementDraft]
    edge_cases: list[EdgeCase] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    return_type: str = "Any"
    architect_family: str = ""
    architect_model: str = ""


class InterviewSessionOutcome(BaseModel):
    """Outcome of interactive (or `--yes` unreviewed) I19 confirmation session."""

    model_config = ConfigDict(frozen=True)

    approved: bool
    result: InterviewResult
    spec_unreviewed: bool
    rounds_used: int
    correction_rounds: int
    total_cost: CostRecord
    telemetry: list[Any] = Field(default_factory=list)


def _is_exception_placeholder(expected: Any) -> bool:
    return isinstance(expected, str) and bool(_EXCEPTION_LITERAL_RE.match(expected.strip()))


def _parse_interview_requirements(raw_reqs: Any) -> tuple[list[RequirementDraft], str]:
    if not isinstance(raw_reqs, list):
        return [], "Any"

    drafts: list[RequirementDraft] = []
    inferred_return_type = "Any"
    for idx, item in enumerate(raw_reqs):
        if not isinstance(item, dict):
            continue
        req_id = str(item.get("id") or f"req_{idx + 1}").strip()
        statement = str(item.get("statement") or "").strip()
        target_file = str(item.get("target_file") or "").strip()
        function_name = str(item.get("function_name") or "").strip()
        raw_args = item.get("arg_names")
        if (
            not statement
            or not target_file
            or not function_name
            or not isinstance(raw_args, list)
            or not all(isinstance(a, str) and a.strip() for a in raw_args)
        ):
            continue

        if isinstance(item.get("return_type"), str) and item["return_type"].strip():
            inferred_return_type = str(item["return_type"]).strip()

        raw_proxy = item.get("proxy_assertions")
        proxy_assertions: list[IOAssertion] = []
        if isinstance(raw_proxy, list):
            for p_item in raw_proxy:
                if not isinstance(p_item, dict):
                    continue
                fn = str(p_item.get("function") or function_name).strip()
                args_val = p_item.get("args")
                if not isinstance(args_val, list) or "expected" not in p_item:
                    continue
                if _is_exception_placeholder(p_item["expected"]):
                    continue
                proxy_assertions.append(
                    IOAssertion(function=fn, args=args_val, expected=p_item["expected"])
                )

        raw_deps = item.get("depends_on", [])
        depends_on = (
            [str(d).strip() for d in raw_deps if isinstance(d, str) and d.strip()]
            if isinstance(raw_deps, list)
            else []
        )
        raw_constraints = item.get("constraints", [])
        constraints = (
            [str(c).strip() for c in raw_constraints if isinstance(c, str) and c.strip()]
            if isinstance(raw_constraints, list)
            else []
        )

        # M9-A hard rule: architect NEVER populates `heldout_assertions`!
        drafts.append(
            RequirementDraft(
                id=req_id,
                statement=statement,
                target_file=target_file,
                function_name=function_name,
                arg_names=[str(a).strip() for a in raw_args],
                proxy_assertions=proxy_assertions,
                heldout_assertions=[],
                depends_on=depends_on,
                constraints=constraints,
            )
        )
    return drafts, inferred_return_type


def _parse_edge_cases(raw_edges: Any) -> list[EdgeCase]:
    if not isinstance(raw_edges, list):
        return []
    edges: list[EdgeCase] = []
    for item in raw_edges:
        if not isinstance(item, dict):
            continue
        raw_args = item.get("args")
        args_list = list(raw_args) if isinstance(raw_args, list) else []
        in_repr = str(item.get("input_repr") or "").strip()
        if not in_repr and args_list:
            in_repr = ", ".join(repr(a) for a in args_list)
        expected_beh = str(item.get("expected_behavior") or "").strip()
        rationale = str(item.get("rationale") or "").strip()
        category = str(item.get("category") or "boundary").strip()
        if not expected_beh:
            continue
        edges.append(
            EdgeCase(
                args=args_list,
                input_repr=in_repr or "()",
                expected_behavior=expected_beh,
                rationale=rationale or category,
                category=category,
            )
        )
    return edges


def interview_goal(
    *,
    goal_text: str,
    backend: ModelBackend,
    architect_model: str,
    timeout_s: float = 180.0,
    feedback_history: list[str] | None = None,
) -> tuple[InterviewResult, CostRecord]:
    """Compile a natural-language goal into visible proxy requirements, edge cases, and assumptions (`M9-A`)."""
    clean_goal = goal_text.strip()
    schema_example = {
        "requirements": [
            {
                "id": "req_main",
                "statement": "Complete unambiguous behavioral contract including return value and error rules.",
                "target_file": "src/module.py",
                "function_name": "fn_name",
                "arg_names": ["arg1"],
                "return_type": "int",
                "constraints": ["stdlib only", "no network"],
                "depends_on": [],
                "proxy_assertions": [
                    {"function": "fn_name", "args": ["valid_sample"], "expected": 42}
                ],
            }
        ],
        "edge_cases": [
            {
                "args": [""],
                "input_repr": '""',
                "expected_behavior": "0",
                "rationale": "boş girdi",
                "category": "empty",
            },
            {
                "args": ["invalid"],
                "input_repr": '"invalid"',
                "expected_behavior": "ValueError",
                "rationale": "geçersiz biçim",
                "category": "garbage",
            },
        ],
        "open_questions": [],
        "assumptions": ["Explicit assumption made when reasonable and standard"],
    }

    feedback_block = ""
    if feedback_history:
        joined = "\n".join(f"- Round {i + 1}: {fb}" for i, fb in enumerate(feedback_history))
        feedback_block = (
            f"\n\nUser Corrections from Previous Interview Rounds (MUST obey):\n{joined}"
        )

    system_prompt = (
        "You are the hveritas Spec Architect (M9-A). Interpret the user's software goal into a "
        "verifiable binary specification as strict plain-text JSON.\n"
        "Rules:\n"
        "1. Produce `proxy_assertions` ONLY (2-4 concrete normal-return examples where `fn(*args) == expected`). "
        "NEVER put exception names like 'ValueError' in `proxy_assertions`; put exception cases in `edge_cases`.\n"
        "2. Do NOT generate `heldout_assertions`.\n"
        "3. Cover explicit edge cases: empty input, zero, negative, boundary, unknown unit/format, invalid value.\n"
        "4. Put genuine unresolved contradictions/ambiguities (e.g. 'TBD', '???') into `open_questions`; "
        "put standard engineering choices into `assumptions`."
    )
    user_prompt = (
        f"Goal:\n{clean_goal}{feedback_block}\n\n"
        f"Return ONLY a JSON object matching this schema:\n{json.dumps(schema_example, ensure_ascii=False, indent=2)}"
    )

    resp = backend.complete(
        system=system_prompt,
        user=user_prompt,
        model=architect_model,
        timeout_s=timeout_s,
    )
    cost = CostRecord(
        input_tokens=resp.input_tokens,
        output_tokens=resp.output_tokens,
        usd=resp.usd,
        wall_ms=resp.elapsed_ms,
    )

    parsed, parse_err = _extract_json_object(resp.text)
    open_q: list[str] = []
    if _AMBIGUOUS_MARKERS_RE.search(clean_goal) and not feedback_history:
        open_q.append(
            "Hedefte çözülmemiş belirsizlik işareti (TBD/???/belirsiz) bulundu; kesin davranış kuralı nedir?"
        )

    if parsed is None:
        open_q.append(f"Spec mimarı geçerli JSON üretemedi ({parse_err}); hedefi netleştirin.")
        return (
            InterviewResult(
                requirements=[],
                edge_cases=[],
                open_questions=open_q,
                assumptions=[],
                architect_family=resp.family,
                architect_model=resp.model,
            ),
            cost,
        )

    drafts, ret_type = _parse_interview_requirements(parsed.get("requirements"))
    edges = _parse_edge_cases(parsed.get("edge_cases"))
    raw_oq = parsed.get("open_questions", [])
    if isinstance(raw_oq, list):
        for q in raw_oq:
            if isinstance(q, str) and q.strip() and q.strip() not in open_q:
                open_q.append(q.strip())

    raw_assumptions = parsed.get("assumptions", [])
    assumptions = (
        [str(a).strip() for a in raw_assumptions if isinstance(a, str) and a.strip()]
        if isinstance(raw_assumptions, list)
        else []
    )
    if isinstance(parsed.get("return_type"), str) and parsed["return_type"].strip():
        ret_type = str(parsed["return_type"]).strip()

    if not drafts and not open_q:
        open_q.append(
            "Hedef metninden doğrulanabilir fonksiyon imzası ve proxy örnekleri çıkarılamadı."
        )

    return (
        InterviewResult(
            requirements=drafts,
            edge_cases=edges,
            open_questions=open_q,
            assumptions=assumptions,
            return_type=ret_type,
            architect_family=resp.family,
            architect_model=resp.model,
        ),
        cost,
    )


def format_interview_summary(
    result: InterviewResult,
    *,
    include_prompt: bool = True,
) -> str:
    """Render concise Turkish terminal summary (`HEDEF YORUMU`, `KENAR DURUMLAR`, `VARSAYIMLAR`) per §3/I19."""
    lines: list[str] = ["HEDEF YORUMU"]
    for req in result.requirements:
        sig = f"{req.function_name}({', '.join(req.arg_names)})"
        ret = result.return_type or "Any"
        lines.append(f"  {req.target_file} :: {sig} -> {ret}")
        lines.append(f'  "{req.statement}"')
    if not result.requirements:
        lines.append("  (geçerli gereksinim çıkarılamadı)")

    lines.append("")
    lines.append(f"KENAR DURUMLAR ({len(result.edge_cases)})")
    for ec in result.edge_cases:
        disp_in = ec.input_repr or ", ".join(repr(a) for a in ec.args)
        lines.append(f"  {disp_in:<12} -> {ec.expected_behavior:<12} {ec.rationale}")

    lines.append("")
    lines.append(f"VARSAYIMLAR ({len(result.assumptions)})")
    for assumption in result.assumptions:
        lines.append(f"  - {assumption}")

    if include_prompt:
        lines.append("Onaylıyor musun? [E/h/d(üzelt)]")
    return "\n".join(lines)


def conduct_spec_interview_session(
    *,
    goal_text: str,
    backend: ModelBackend,
    architect_model: str,
    auto_approve: bool = False,
    max_rounds: int = 3,
    timeout_s: float = 180.0,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> InterviewSessionOutcome:
    """Execute M9-A spec interview + I19 confirmation loop (up to `max_rounds`)."""
    from hveritas.worker.policy import LlmCallTelemetry

    max_r = max(1, int(max_rounds))
    feedback_history: list[str] = []
    acc_in = 0
    acc_out = 0
    acc_usd = 0.0
    acc_ms = 0.0
    telemetry: list[LlmCallTelemetry] = []
    correction_rounds = 0

    for round_idx in range(max_r):
        res, cost = interview_goal(
            goal_text=goal_text,
            backend=backend,
            architect_model=architect_model,
            timeout_s=timeout_s,
            feedback_history=feedback_history if feedback_history else None,
        )
        acc_in += cost.input_tokens
        acc_out += cost.output_tokens
        acc_usd = round(acc_usd + cost.usd, 8)
        acc_ms = round(acc_ms + cost.wall_ms, 3)
        telemetry.append(
            LlmCallTelemetry(
                call_index=len(telemetry),
                task_id="spec_interview",
                repair_attempt=round_idx,
                ladder_rung="m9_a_interview",
                requested_family_slot="architect",
                requested_alias=architect_model,
                resolved_model=res.architect_model or architect_model,
                resolved_family=res.architect_family,
                input_tokens=cost.input_tokens,
                output_tokens=cost.output_tokens,
                elapsed_ms=cost.wall_ms,
                usd=cost.usd,
                output_valid=bool(res.requirements) and not res.open_questions,
            )
        )

        if res.open_questions:
            raise HumanClarificationRequiredError(
                "Spec mülakatında çözülmemiş belirsizlikler var — insana soruluyor.",
                questions=list(res.open_questions),
                contradictions=[],
            )

        if auto_approve:
            output_fn(format_interview_summary(res, include_prompt=False))
            return InterviewSessionOutcome(
                approved=True,
                result=res,
                spec_unreviewed=True,
                rounds_used=round_idx + 1,
                correction_rounds=correction_rounds,
                total_cost=CostRecord(
                    input_tokens=acc_in, output_tokens=acc_out, usd=acc_usd, wall_ms=acc_ms
                ),
                telemetry=telemetry,
            )

        output_fn(format_interview_summary(res, include_prompt=True))
        try:
            raw_choice = input_fn("").strip().lower()
        except EOFError:
            return InterviewSessionOutcome(
                approved=False,
                result=res,
                spec_unreviewed=False,
                rounds_used=round_idx + 1,
                correction_rounds=correction_rounds,
                total_cost=CostRecord(
                    input_tokens=acc_in, output_tokens=acc_out, usd=acc_usd, wall_ms=acc_ms
                ),
                telemetry=telemetry,
            )

        if raw_choice in {"", "e", "evet", "y", "yes"}:
            return InterviewSessionOutcome(
                approved=True,
                result=res,
                spec_unreviewed=False,
                rounds_used=round_idx + 1,
                correction_rounds=correction_rounds,
                total_cost=CostRecord(
                    input_tokens=acc_in, output_tokens=acc_out, usd=acc_usd, wall_ms=acc_ms
                ),
                telemetry=telemetry,
            )

        if raw_choice in {"d", "düzelt", "duzelt"}:
            if round_idx + 1 >= max_r:
                break
            try:
                correction_note = input_fn("Düzeltme notu: ").strip()
            except EOFError:
                break
            if correction_note:
                feedback_history.append(correction_note)
                correction_rounds += 1
                continue

        # Rejected (`h` / `hayır` / invalid)
        return InterviewSessionOutcome(
            approved=False,
            result=res,
            spec_unreviewed=False,
            rounds_used=round_idx + 1,
            correction_rounds=correction_rounds,
            total_cost=CostRecord(
                input_tokens=acc_in, output_tokens=acc_out, usd=acc_usd, wall_ms=acc_ms
            ),
            telemetry=telemetry,
        )

    return InterviewSessionOutcome(
        approved=False,
        result=res,
        spec_unreviewed=False,
        rounds_used=max_r,
        correction_rounds=correction_rounds,
        total_cost=CostRecord(
            input_tokens=acc_in, output_tokens=acc_out, usd=acc_usd, wall_ms=acc_ms
        ),
        telemetry=telemetry,
    )
