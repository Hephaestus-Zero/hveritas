"""Immutable data models for the hveritas append-only ledger."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CostRecord(BaseModel):
    """Resource consumption for a single action or run."""

    model_config = ConfigDict(frozen=True)

    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    wall_ms: float = 0.0


class ActionEnvelope(BaseModel):
    """Pre-execution action envelope recorded before or around tool dispatch."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    step_index: int = Field(ge=0)
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    pre_state_hash: str
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    seed: int | None = None
    cost: CostRecord = Field(default_factory=CostRecord)
    timestamp_ns: int


class AgentClaim(BaseModel):
    """Untrusted self-report emitted by the worker agent (strictly segregated per I3)."""

    model_config = ConfigDict(frozen=True)

    summary: str = ""
    reported_success: bool | None = None
    raw_output: str = ""
    structured_claim: dict[str, Any] = Field(default_factory=dict)


class MeasuredEffects(BaseModel):
    """Independently probed post-action effects (authoritative ground truth per I3)."""

    model_config = ConfigDict(frozen=True)

    post_state_hash: str
    exit_code: int | None = None
    fs_diff: dict[str, Any] = Field(default_factory=dict)
    proc_metrics: dict[str, Any] = Field(default_factory=dict)
    http_effects: list[dict[str, Any]] = Field(default_factory=list)
    db_delta: dict[str, Any] = Field(default_factory=dict)
    ui_probe: dict[str, Any] = Field(default_factory=dict)


class EffectReceipt(BaseModel):
    """Post-action receipt keeping untrusted `claim` strictly separate from `measured`."""

    model_config = ConfigDict(frozen=True)

    receipt_id: str
    run_id: str
    step_index: int = Field(ge=0)
    claim: AgentClaim
    measured: MeasuredEffects
    prev_receipt_hash: str
    receipt_hash: str


class StepRecord(BaseModel):
    """Combined read model of ActionEnvelope + EffectReceipt for a single step."""

    model_config = ConfigDict(frozen=True)

    envelope: ActionEnvelope
    receipt: EffectReceipt


class SpanRecord(BaseModel):
    """Serialized OpenTelemetry GenAI semantic-convention span stored in the ledger."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    seq_no: int = Field(ge=0)
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    step_index: int | None = None
    name: str
    operation_name: str
    openinference_kind: str
    start_time_ns: int
    end_time_ns: int
    status_code: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class RunRecord(BaseModel):
    """Immutable run header in the append-only ledger."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    goal: str
    container_digest: str
    seed: int
    started_at_ns: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunEventRecord(BaseModel):
    """Append-only lifecycle/milestone/stop events for a run."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    event_seq: int = Field(ge=0)
    event_type: str
    timestamp_ns: int
    payload: dict[str, Any] = Field(default_factory=dict)
