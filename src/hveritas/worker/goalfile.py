"""Goal File Loader (`M8-C`): parses & validates YAML goal definitions into `(goal_text, requirements, budget)`."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from hveritas.ledger.models import CostRecord
from hveritas.loop.models import BudgetLimits
from hveritas.spec.compiler import RequirementDraft
from hveritas.spec.models import IOAssertion
from hveritas.worker.backend import ModelBackend


class GoalFileError(ValueError):
    """Raised when a YAML goal file is malformed, incomplete, or omits held-out assertions."""


def _parse_io_assertions(raw_items: Any, *, field_name: str, req_id: str) -> list[IOAssertion]:
    if not isinstance(raw_items, list) or len(raw_items) == 0:
        raise GoalFileError(
            f"Requirement {req_id!r} must define a non-empty {field_name!r} list "
            "(held-out & proxy oracles are mandatory for I3/I4 Δ gaming measurement)"
        )
    assertions: list[IOAssertion] = []
    for idx, item in enumerate(raw_items):
        if not isinstance(item, dict):
            raise GoalFileError(
                f"Requirement {req_id!r} {field_name}[{idx}] must be a mapping, got {type(item).__name__}"
            )
        try:
            assertions.append(IOAssertion.model_validate(item))
        except ValidationError as exc:
            raise GoalFileError(
                f"Invalid IOAssertion in requirement {req_id!r} {field_name}[{idx}]: {exc}"
            ) from exc
    return assertions


def _parse_requirement_draft(raw: Any, index: int) -> RequirementDraft:
    if not isinstance(raw, dict):
        raise GoalFileError(f"requirements[{index}] must be a mapping")

    req_id = raw.get("id")
    statement = raw.get("statement")
    target_file = raw.get("target_file")
    function_name = raw.get("function_name")
    arg_names = raw.get("arg_names")

    if not isinstance(req_id, str) or not req_id.strip():
        raise GoalFileError(f"requirements[{index}].id must be a non-empty string")
    if not isinstance(statement, str) or not statement.strip():
        raise GoalFileError(f"Requirement {req_id!r} statement must be a non-empty string")
    if not isinstance(target_file, str) or not target_file.strip():
        raise GoalFileError(f"Requirement {req_id!r} target_file must be a non-empty string")
    if not isinstance(function_name, str) or not function_name.strip():
        raise GoalFileError(f"Requirement {req_id!r} function_name must be a non-empty string")
    if not isinstance(arg_names, list) or not all(isinstance(a, str) and a for a in arg_names):
        raise GoalFileError(f"Requirement {req_id!r} arg_names must be list[str]")

    depends_on = raw.get("depends_on", [])
    if not isinstance(depends_on, list) or not all(isinstance(d, str) for d in depends_on):
        raise GoalFileError(f"Requirement {req_id!r} depends_on must be list[str]")

    constraints = raw.get("constraints", [])
    if not isinstance(constraints, list) or not all(isinstance(c, str) for c in constraints):
        raise GoalFileError(f"Requirement {req_id!r} constraints must be list[str]")

    proxy_assertions = _parse_io_assertions(
        raw.get("proxy_assertions"),
        field_name="proxy_assertions",
        req_id=req_id,
    )
    heldout_assertions = _parse_io_assertions(
        raw.get("heldout_assertions"),
        field_name="heldout_assertions",
        req_id=req_id,
    )

    return RequirementDraft(
        id=req_id.strip(),
        statement=statement.strip(),
        target_file=target_file.strip(),
        function_name=function_name.strip(),
        arg_names=list(arg_names),
        proxy_assertions=proxy_assertions,
        heldout_assertions=heldout_assertions,
        depends_on=list(depends_on),
        constraints=list(constraints),
    )


def load_goal_file(
    path: Path | str,
    *,
    allow_missing_requirements: bool = False,
) -> tuple[str, list[RequirementDraft], BudgetLimits]:
    """Load and validate a YAML goal file into `(goal_text, requirements, budget_limits)`."""
    goal_path = Path(path)
    if not goal_path.is_file():
        raise GoalFileError(f"Goal file does not exist: {goal_path}")

    try:
        raw_doc = yaml.safe_load(goal_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise GoalFileError(f"Invalid YAML syntax in {goal_path}: {exc}") from exc

    if not isinstance(raw_doc, dict):
        raise GoalFileError(f"Goal file root must be a YAML mapping in {goal_path}")

    goal_text = raw_doc.get("goal")
    if not isinstance(goal_text, str) or not goal_text.strip():
        raise GoalFileError(f"Goal file {goal_path} must contain a non-empty 'goal' string")

    raw_budget = raw_doc.get("budget")
    if raw_budget is None:
        budget_limits = BudgetLimits()
    elif isinstance(raw_budget, dict):
        try:
            budget_limits = BudgetLimits.model_validate(raw_budget)
        except ValidationError as exc:
            raise GoalFileError(f"Invalid 'budget' block in {goal_path}: {exc}") from exc
    else:
        raise GoalFileError(f"'budget' in {goal_path} must be a mapping")

    raw_reqs = raw_doc.get("requirements")
    if raw_reqs is None:
        if allow_missing_requirements:
            return goal_text.strip(), [], budget_limits
        raise GoalFileError(
            f"Goal file {goal_path} omits 'requirements' (pass --requirements-from-model to draft)"
        )

    if not isinstance(raw_reqs, list) or len(raw_reqs) == 0:
        if allow_missing_requirements and isinstance(raw_reqs, list) and len(raw_reqs) == 0:
            return goal_text.strip(), [], budget_limits
        raise GoalFileError(f"Goal file {goal_path} must contain a non-empty 'requirements' list")

    requirements = [_parse_requirement_draft(item, idx) for idx, item in enumerate(raw_reqs)]
    return goal_text.strip(), requirements, budget_limits


def draft_requirements_from_model(
    *,
    goal_text: str,
    backend: ModelBackend,
    model: str | None = None,
    timeout_s: float = 120.0,
) -> tuple[list[RequirementDraft] | None, CostRecord]:
    """Deprecated M8 drafter: redirects to M9-A `interview_goal` (never populates held-out assertions)."""
    from hveritas.spec.interview import interview_goal

    print(
        "[hveritas] WARNING: draft_requirements_from_model is deprecated; "
        "redirecting to M9-A interview_goal (held-out assertions require M9-B cross-family oracle).",
        file=sys.stderr,
    )
    res, cost = interview_goal(
        goal_text=goal_text,
        backend=backend,
        architect_model=model or "sonnet-claude",
        timeout_s=timeout_s,
    )
    if res.open_questions or not res.requirements:
        return None, cost
    return list(res.requirements), cost
