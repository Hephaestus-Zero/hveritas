"""Models and status enums for the hveritas Autonomous Goal Loop (`M5`, §1, §8)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hveritas.attribute.narrator import AttributionReport


class RepairLadderRung(StrEnum):
    """4-rung repair escalation ladder (§1 [8] REPAIR)."""

    SAME_MODEL = "same_model"
    TIGHTER_CONSTRAINTS = "tighter_constraints_smaller_step"
    DIFFERENT_MODEL_FAMILY = "different_model_family"
    HUMAN_ESCALATION = "human_escalation"


class LoopStopReason(StrEnum):
    """All stopping conditions defined in Architecture §8 + normal completion."""

    COMPLETED = "completed"
    BUDGET_EXCEEDED = "budget_exceeded"
    GAMING_ALARM = "gaming_alarm_hard_stop"
    HARNESS_ERROR_NOOP = "harness_error_noop_baseline"
    SPEC_UNCERTAIN_ASK_HUMAN = "spec_uncertain_ask_human"
    MUTATION_SCORE_DROPPED = "mutation_score_dropped"
    REPAIR_EXHAUSTED_HUMAN = "repair_exhausted_human"
    DIFFERENTIAL_DISAGREEMENT = "differential_disagreement"
    ORACLE_AUTHOR_COLLISION = "oracle_author_collision"


class BudgetLimits(BaseModel):
    """Run-level resource ceilings (wall-clock seconds, tokens, USD)."""

    model_config = ConfigDict(frozen=True)

    max_wall_seconds: float = 300.0
    max_tokens: int = 100_000
    max_usd: float = 2.0
    max_repair_attempts: int = 4


class BudgetUsage(BaseModel):
    """Accumulated resource usage across worker + repair steps."""

    model_config = ConfigDict(frozen=True)

    wall_seconds: float = 0.0
    total_tokens: int = 0
    total_usd: float = 0.0


class LoopResult(BaseModel):
    """Structured end-to-end outcome of `GoalLoopOrchestrator.run_goal`."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    passed: bool
    stop_reason: LoopStopReason
    committed_tasks: list[str] = Field(default_factory=list)
    remaining_tasks: list[str] = Field(default_factory=list)
    escalated_to_human: bool = False
    human_questions: list[str] = Field(default_factory=list)
    budget_usage: BudgetUsage = Field(default_factory=BudgetUsage)
    ladder_history: list[RepairLadderRung] = Field(default_factory=list)
    ladder_skips_triggered: int = 0
    delta_gaming: float | None = None
    attributions: list[dict[str, Any]] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class WorkerContext(BaseModel):
    """Context passed to a worker solver (strictly stripped of held-out oracles per I4)."""

    model_config = ConfigDict(frozen=True)

    system_prompt: str
    task_id: str
    statement: str
    target_file: str
    function_name: str
    arg_names: list[str]
    visible_proxy_tests: dict[str, str]
    ladder_rung: RepairLadderRung = RepairLadderRung.SAME_MODEL
    model_family: str = "family-alpha"
    repair_attempt: int = 0
    attributed_cause: dict[str, Any] | None = None


def serialize_attribution_report(rep: AttributionReport) -> dict[str, Any]:
    loc = rep.attribution
    return {
        "run_id": loc.run_id,
        "culprit_step_index": loc.culprit_step_index,
        "tool_name": loc.tool_name,
        "trail_group": loc.trail_group.value,
        "trail_category": loc.trail_category.value,
        "trail_leaf": loc.trail_leaf.value,
        "replays_used": loc.replays_used,
        "ace": loc.average_causal_effect,
        "ci_95": [loc.ci_low, loc.ci_high],
        "explanation": rep.explanation,
    }
