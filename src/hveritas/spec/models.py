"""Data models for Spec Compiler, Requirement DAG, Oracle Split, and Task Graph."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IOAssertion(BaseModel):
    """Concrete input/output assertion `(fn(*args) == expected)` used for oracle synthesis & contradiction checking."""

    model_config = ConfigDict(frozen=True)

    function: str
    args: list[Any]
    expected: Any


class OracleCheckSpec(BaseModel):
    """Test specification for either the visible in-loop proxy oracle or secret held-out oracle."""

    model_config = ConfigDict(frozen=True)

    suite_name: str
    assertions: list[IOAssertion] = Field(default_factory=list)
    custom_pytest_code: str | None = None


class RequirementNode(BaseModel):
    """Binary, independently checkable node in the Requirement DAG."""

    model_config = ConfigDict(frozen=True)

    id: str
    statement: str
    target_file: str
    function_name: str
    arg_names: list[str]
    depends_on: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    proxy_oracle: OracleCheckSpec
    heldout_oracle_id: str


class CompiledSpec(BaseModel):
    """Compiled, oracle-split specification produced from a Goal."""

    model_config = ConfigDict(frozen=True)

    spec_id: str
    goal_text: str
    nodes: list[RequirementNode]
    topological_order: list[str]


class TaskBudget(BaseModel):
    """Execution and repair budget bound to a Task Graph leaf or full run."""

    model_config = ConfigDict(frozen=True)

    max_steps: int = 20
    max_tokens: int = 50_000
    max_usd: float = 1.0
    max_wall_seconds: float = 120.0
    max_repairs: int = 3


class LeafTask(BaseModel):
    """Executable task derived from the Requirement DAG, stripped of any held-out details (I4)."""

    model_config = ConfigDict(frozen=True)

    task_id: str
    requirement_id: str
    statement: str
    target_file: str
    function_name: str
    arg_names: list[str]
    depends_on_tasks: list[str] = Field(default_factory=list)
    visible_proxy_tests: dict[str, str]
    api_contract: dict[str, Any]
    budget: TaskBudget = Field(default_factory=TaskBudget)
