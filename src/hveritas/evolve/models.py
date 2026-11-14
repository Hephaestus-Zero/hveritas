"""Typed models for Milestone M7: Verifier Evolution, Mutmut Gate (I9), and BenchJack Self-Audit."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from hveritas.verify.metamorphic import MetamorphicKind

_SAFE_ID_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_SAFE_SLUG_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


class EscapedBugReport(BaseModel):
    """Structured report of a fault that escaped an earlier proxy/verifier suite (Invariant I9)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    bug_id: str
    namespace: str
    target_file: str
    function_name: str
    failing_args: list[Any]
    observed_output: Any
    expected_output: Any | None = None
    min_bound: int | float | None = None
    max_bound: int | float | None = None
    bound_arg_index_upper: int | None = None
    sweep_inputs: list[list[Any]] = Field(default_factory=list)
    metamorphic_kind: MetamorphicKind | None = None
    inverse_function_name: str | None = None
    description: str = ""

    @field_validator("bug_id")
    @classmethod
    def _validate_bug_id(cls, value: str) -> str:
        if not _SAFE_ID_RE.match(value):
            raise ValueError(f"Invalid bug_id {value!r}: must match {_SAFE_ID_RE.pattern}")
        return value

    @field_validator("namespace")
    @classmethod
    def _validate_namespace(cls, value: str) -> str:
        if not _SAFE_SLUG_RE.match(value):
            raise ValueError(f"Invalid namespace {value!r}: must match {_SAFE_SLUG_RE.pattern}")
        return value

    @field_validator("function_name")
    @classmethod
    def _validate_fn_name(cls, value: str) -> str:
        if not _SAFE_ID_RE.match(value):
            raise ValueError(f"Invalid function_name {value!r}")
        return value


class SynthesizedEvolutionBundle(BaseModel):
    """Synthesized T1 dynamic invariant, T2 metamorphic relation, and regression test bundle."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    bug_id: str
    namespace: str
    t1_invariant_filename: str
    t1_invariant_source: str
    t2_metamorphic_filename: str | None = None
    t2_metamorphic_source: str | None = None
    regression_filename: str
    regression_source: str
    persisted_files: list[str] = Field(default_factory=list)
    baseline_mutation_score: float | None = None
    evolved_mutation_score: float | None = None


class MutationScoreReport(BaseModel):
    """Measured `mutmut` mutation testing report over a verifier test suite (Invariant I9)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    passed: bool
    mutation_score: float = Field(ge=0.0, le=1.0)
    baseline_score: float = Field(ge=0.0, le=1.0)
    total_mutants: int = Field(ge=0)
    killed_mutants: int = Field(ge=0)
    survived_mutants: int = Field(ge=0)
    timeout_mutants: int = Field(ge=0)
    suspicious_mutants: int = Field(ge=0)
    no_tests_mutants: int = Field(ge=0)
    surviving_keys: list[str] = Field(default_factory=list)
    elapsed_ms: float = Field(ge=0.0)


FindingDisposition = Literal[
    "unmitigated",
    "remediated",
    "architectural_control_verified",
]


class BenchJackFinding(BaseModel):
    """Single finding emitted by BenchJack `docker_analyzer`, `trust_map`, AST rules, or Bandit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scanner: Literal["benchjack_docker", "benchjack_trust_map", "benchjack_ast_rules", "bandit"]
    vulnerability_class: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    file: str
    line: int = 0
    message: str
    disposition: FindingDisposition
    mitigation_note: str = ""


class BenchJackAuditReport(BaseModel):
    """Structured BenchJack self-audit report over `hveritas` harness and isolated verifier."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_id: str
    timestamp_iso: str
    targets_scanned: list[str]
    docker_findings_count: int
    trust_boundary_conflicts_count: int
    dangerous_sinks_count: int
    ast_rule_violations_count: int
    bandit_high_count: int
    bandit_medium_count: int
    nosec_suppressions_count: int
    unmitigated_high_or_critical_count: int
    unmitigated_exploit_findings_count: int
    passed: bool
    schedule_timer_calendar: str
    findings: list[BenchJackFinding] = Field(default_factory=list)
