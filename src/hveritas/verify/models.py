"""Immutable verification state and evidence models for the T0–T4 Verifier Bus."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TierId = Literal["T0", "T1", "T2", "T3", "T4"]


class CheckResult(BaseModel):
    """Single deterministic, invariant, metamorphic, held-out, or judge check outcome."""

    model_config = ConfigDict(frozen=True)

    check: str
    passed: bool
    score: float = Field(ge=0.0, le=1.0)
    details: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    """Pure output of a Verifier tier `fn(VerificationState) -> Evidence`."""

    model_config = ConfigDict(frozen=True)

    tier: TierId
    passed: bool
    score: float = Field(ge=0.0, le=1.0)
    checks: list[CheckResult] = Field(default_factory=list)
    container_digest: str
    workspace_hash: str
    runtime_audit: dict[str, Any] = Field(default_factory=dict)


class VerificationState(BaseModel):
    """Immutable input snapshot evaluated by each Verifier Bus tier."""

    model_config = ConfigDict(frozen=True)

    workspace_path: str
    proxy_tests: dict[str, str] = Field(default_factory=dict)
    dynamic_invariants: dict[str, str] = Field(default_factory=dict)
    metamorphic_tests: dict[str, str] = Field(default_factory=dict)
    t0_config: dict[str, Any] = Field(default_factory=lambda: {"compile": True})
    t1_config: dict[str, Any] = Field(default_factory=lambda: {"security_scan": True})
    heldout_oracle_id: str | None = None
    evolved_namespace: str | None = None
    requirement_dag_nodes: list[dict[str, Any]] = Field(default_factory=list)


class VerifierBusReport(BaseModel):
    """Aggregated multi-tier report across T0..T4."""

    model_config = ConfigDict(frozen=True)

    passed: bool
    tiers: dict[TierId, Evidence]
    score_proxy: float
    score_heldout: float | None = None
    delta_gaming: float | None = None
