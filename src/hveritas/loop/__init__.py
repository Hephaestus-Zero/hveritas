"""Loop Orchestrator, Repair Escalation Ladder, Budgets, and §8 Stopping Conditions."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hveritas.loop.budget import BudgetExceededError, BudgetTracker
    from hveritas.loop.ladder import RepairLadderController
    from hveritas.loop.models import (
        BudgetLimits,
        BudgetUsage,
        LoopResult,
        LoopStopReason,
        RepairLadderRung,
        WorkerContext,
        serialize_attribution_report,
    )
    from hveritas.loop.orchestrator import GoalLoopOrchestrator, MutationGateHook, WorkerPolicy

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "BudgetExceededError": ("hveritas.loop.budget", "BudgetExceededError"),
    "BudgetTracker": ("hveritas.loop.budget", "BudgetTracker"),
    "RepairLadderController": ("hveritas.loop.ladder", "RepairLadderController"),
    "BudgetLimits": ("hveritas.loop.models", "BudgetLimits"),
    "BudgetUsage": ("hveritas.loop.models", "BudgetUsage"),
    "LoopResult": ("hveritas.loop.models", "LoopResult"),
    "LoopStopReason": ("hveritas.loop.models", "LoopStopReason"),
    "RepairLadderRung": ("hveritas.loop.models", "RepairLadderRung"),
    "WorkerContext": ("hveritas.loop.models", "WorkerContext"),
    "serialize_attribution_report": ("hveritas.loop.models", "serialize_attribution_report"),
    "GoalLoopOrchestrator": ("hveritas.loop.orchestrator", "GoalLoopOrchestrator"),
    "MutationGateHook": ("hveritas.loop.orchestrator", "MutationGateHook"),
    "WorkerPolicy": ("hveritas.loop.orchestrator", "WorkerPolicy"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_name, attr_name = target
    value = getattr(importlib.import_module(mod_name), attr_name)
    globals()[name] = value
    return value

__all__ = [
    "BudgetExceededError",
    "BudgetLimits",
    "BudgetTracker",
    "BudgetUsage",
    "GoalLoopOrchestrator",
    "LoopResult",
    "LoopStopReason",
    "MutationGateHook",
    "RepairLadderController",
    "RepairLadderRung",
    "WorkerContext",
    "WorkerPolicy",
    "serialize_attribution_report",
]
