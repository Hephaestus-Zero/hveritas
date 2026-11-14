"""Worker Backend & LLM Policy Layer (`M8-A`, `M8-B`, `M8-C`)."""

from hveritas.worker.backend import (
    PLANNER_SCRATCH_ROOT,
    AnthropicApiBackend,
    FakeBackend,
    HxCliBackend,
    ModelBackend,
    ModelFamilyNotDistinctError,
    ModelProtocolError,
    ModelResponse,
    ModelTimeoutError,
    PlannerSideEffectError,
)
from hveritas.worker.goalfile import GoalFileError, draft_requirements_from_model, load_goal_file
from hveritas.worker.policy import ALLOWED_TOOL_NAMES, LlmCallTelemetry, LlmWorkerPolicy
from hveritas.worker.queue_runner import process_goal_queue
from hveritas.worker.reporting import (
    build_run_report_payload,
    render_run_markdown_summary,
    verify_all_ledger_chains,
    write_run_report_bundle,
)

__all__ = [
    "ALLOWED_TOOL_NAMES",
    "PLANNER_SCRATCH_ROOT",
    "AnthropicApiBackend",
    "FakeBackend",
    "GoalFileError",
    "HxCliBackend",
    "LlmCallTelemetry",
    "LlmWorkerPolicy",
    "ModelBackend",
    "ModelFamilyNotDistinctError",
    "ModelProtocolError",
    "ModelResponse",
    "ModelTimeoutError",
    "PlannerSideEffectError",
    "build_run_report_payload",
    "draft_requirements_from_model",
    "load_goal_file",
    "process_goal_queue",
    "render_run_markdown_summary",
    "verify_all_ledger_chains",
    "write_run_report_bundle",
]
