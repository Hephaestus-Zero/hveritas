"""Spec Compiler, Requirement DAG, Spec Audit Gate, and Task Graph."""

from hveritas.spec.audit import SpecAuditError, SpecAuditGate, SpecAuditReport
from hveritas.spec.compiler import (
    HumanClarificationRequiredError,
    RequirementDraft,
    SpecCompiler,
    render_pytest_from_assertions,
)
from hveritas.spec.interview import (
    EdgeCase,
    InterviewResult,
    InterviewSessionOutcome,
    conduct_spec_interview_session,
    format_interview_summary,
    interview_goal,
)
from hveritas.spec.models import (
    CompiledSpec,
    IOAssertion,
    LeafTask,
    OracleCheckSpec,
    RequirementNode,
    TaskBudget,
)
from hveritas.spec.oracle_author import (
    OracleAuthorCollisionError,
    build_oracle_author_prompt,
    synthesize_heldout_oracle,
)
from hveritas.spec.task_graph import build_task_graph

__all__ = [
    "CompiledSpec",
    "EdgeCase",
    "HumanClarificationRequiredError",
    "IOAssertion",
    "InterviewResult",
    "InterviewSessionOutcome",
    "LeafTask",
    "OracleAuthorCollisionError",
    "OracleCheckSpec",
    "RequirementDraft",
    "RequirementNode",
    "SpecAuditError",
    "SpecAuditGate",
    "SpecAuditReport",
    "SpecCompiler",
    "TaskBudget",
    "build_oracle_author_prompt",
    "build_task_graph",
    "conduct_spec_interview_session",
    "format_interview_summary",
    "interview_goal",
    "render_pytest_from_assertions",
    "synthesize_heldout_oracle",
]
