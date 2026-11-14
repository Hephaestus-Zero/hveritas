"""TRAIL Fault Taxonomy (3 Groups -> 9 Categories -> 20 Leaf Types, arXiv:2505.08638) & Classifier."""

from __future__ import annotations

import ast
from enum import StrEnum
from typing import Any

from hveritas.ledger.models import StepRecord
from hveritas.tape.session import TapeStepEntry


class TrailGroup(StrEnum):
    """3 top-level TRAIL failure groups."""

    REASONING = "REASONING"
    EXECUTION = "EXECUTION"
    PLANNING = "PLANNING"


class TrailCategory(StrEnum):
    """9 mid-level TRAIL failure categories (3 per group)."""

    # REASONING
    LOGIC_AND_ARITHMETIC = "LOGIC_AND_ARITHMETIC"
    DATA_AND_TYPE_SAFETY = "DATA_AND_TYPE_SAFETY"
    CONTROL_AND_CONCURRENCY = "CONTROL_AND_CONCURRENCY"
    # EXECUTION
    TOOL_INVOCATION = "TOOL_INVOCATION"
    RESOURCE_AND_PATH_HANDLING = "RESOURCE_AND_PATH_HANDLING"
    STATE_AND_ENVIRONMENT = "STATE_AND_ENVIRONMENT"
    # PLANNING
    STEP_SEQUENCING = "STEP_SEQUENCING"
    TERMINATION_AND_BUDGET = "TERMINATION_AND_BUDGET"
    SPEC_ALIGNMENT = "SPEC_ALIGNMENT"


class TrailLeaf(StrEnum):
    """20 leaf TRAIL failure modes mapped deterministically to categories and groups."""

    # 1-2: LOGIC_AND_ARITHMETIC
    BOUNDARY_OFF_BY_ONE = "BOUNDARY_OFF_BY_ONE"
    INCORRECT_FORMULA_OR_BRANCH = "INCORRECT_FORMULA_OR_BRANCH"
    # 3-4: DATA_AND_TYPE_SAFETY
    MISSING_NULL_OR_EMPTY_GUARD = "MISSING_NULL_OR_EMPTY_GUARD"
    TYPE_OR_SCHEMA_MISMATCH = "TYPE_OR_SCHEMA_MISMATCH"
    # 5-7: CONTROL_AND_CONCURRENCY
    MISSING_AWAIT_OR_ASYNC_MISUSE = "MISSING_AWAIT_OR_ASYNC_MISUSE"
    INFINITE_OR_BROKEN_ITERATION = "INFINITE_OR_BROKEN_ITERATION"
    UNHANDLED_EXCEPTION_PATH = "UNHANDLED_EXCEPTION_PATH"
    # 8-10: TOOL_INVOCATION
    INVALID_TOOL_ARGUMENT = "INVALID_TOOL_ARGUMENT"
    WRONG_TOOL_SELECTION = "WRONG_TOOL_SELECTION"
    MALFORMED_TOOL_PAYLOAD = "MALFORMED_TOOL_PAYLOAD"
    # 11-12: RESOURCE_AND_PATH_HANDLING
    WRONG_FILE_OR_RESOURCE_PATH = "WRONG_FILE_OR_RESOURCE_PATH"
    PERMISSION_OR_SANDBOX_VIOLATION = "PERMISSION_OR_SANDBOX_VIOLATION"
    # 13-14: STATE_AND_ENVIRONMENT
    CORRUPTED_DB_OR_PERSISTENT_STATE = "CORRUPTED_DB_OR_PERSISTENT_STATE"
    UNOBSERVED_SIDE_EFFECT_ASSUMPTION = "UNOBSERVED_SIDE_EFFECT_ASSUMPTION"
    # 15-16: STEP_SEQUENCING
    WRONG_ACTION_ORDERING = "WRONG_ACTION_ORDERING"
    MISSING_PREREQUISITE_STEP = "MISSING_PREREQUISITE_STEP"
    # 17-18: TERMINATION_AND_BUDGET
    PREMATURE_STOPPING = "PREMATURE_STOPPING"
    REDUNDANT_LOOPING_NO_PROGRESS = "REDUNDANT_LOOPING_NO_PROGRESS"
    # 19-20: SPEC_ALIGNMENT
    SCOPE_DRIFT_OUT_OF_TASK = "SCOPE_DRIFT_OUT_OF_TASK"
    TEST_OVERFITTING_SHORTCUT = "TEST_OVERFITTING_SHORTCUT"


TRAIL_LEAF_PARENTS: dict[TrailLeaf, tuple[TrailGroup, TrailCategory]] = {
    TrailLeaf.BOUNDARY_OFF_BY_ONE: (TrailGroup.REASONING, TrailCategory.LOGIC_AND_ARITHMETIC),
    TrailLeaf.INCORRECT_FORMULA_OR_BRANCH: (
        TrailGroup.REASONING,
        TrailCategory.LOGIC_AND_ARITHMETIC,
    ),
    TrailLeaf.MISSING_NULL_OR_EMPTY_GUARD: (
        TrailGroup.REASONING,
        TrailCategory.DATA_AND_TYPE_SAFETY,
    ),
    TrailLeaf.TYPE_OR_SCHEMA_MISMATCH: (TrailGroup.REASONING, TrailCategory.DATA_AND_TYPE_SAFETY),
    TrailLeaf.MISSING_AWAIT_OR_ASYNC_MISUSE: (
        TrailGroup.REASONING,
        TrailCategory.CONTROL_AND_CONCURRENCY,
    ),
    TrailLeaf.INFINITE_OR_BROKEN_ITERATION: (
        TrailGroup.REASONING,
        TrailCategory.CONTROL_AND_CONCURRENCY,
    ),
    TrailLeaf.UNHANDLED_EXCEPTION_PATH: (
        TrailGroup.REASONING,
        TrailCategory.CONTROL_AND_CONCURRENCY,
    ),
    TrailLeaf.INVALID_TOOL_ARGUMENT: (TrailGroup.EXECUTION, TrailCategory.TOOL_INVOCATION),
    TrailLeaf.WRONG_TOOL_SELECTION: (TrailGroup.EXECUTION, TrailCategory.TOOL_INVOCATION),
    TrailLeaf.MALFORMED_TOOL_PAYLOAD: (TrailGroup.EXECUTION, TrailCategory.TOOL_INVOCATION),
    TrailLeaf.WRONG_FILE_OR_RESOURCE_PATH: (
        TrailGroup.EXECUTION,
        TrailCategory.RESOURCE_AND_PATH_HANDLING,
    ),
    TrailLeaf.PERMISSION_OR_SANDBOX_VIOLATION: (
        TrailGroup.EXECUTION,
        TrailCategory.RESOURCE_AND_PATH_HANDLING,
    ),
    TrailLeaf.CORRUPTED_DB_OR_PERSISTENT_STATE: (
        TrailGroup.EXECUTION,
        TrailCategory.STATE_AND_ENVIRONMENT,
    ),
    TrailLeaf.UNOBSERVED_SIDE_EFFECT_ASSUMPTION: (
        TrailGroup.EXECUTION,
        TrailCategory.STATE_AND_ENVIRONMENT,
    ),
    TrailLeaf.WRONG_ACTION_ORDERING: (TrailGroup.PLANNING, TrailCategory.STEP_SEQUENCING),
    TrailLeaf.MISSING_PREREQUISITE_STEP: (TrailGroup.PLANNING, TrailCategory.STEP_SEQUENCING),
    TrailLeaf.PREMATURE_STOPPING: (TrailGroup.PLANNING, TrailCategory.TERMINATION_AND_BUDGET),
    TrailLeaf.REDUNDANT_LOOPING_NO_PROGRESS: (
        TrailGroup.PLANNING,
        TrailCategory.TERMINATION_AND_BUDGET,
    ),
    TrailLeaf.SCOPE_DRIFT_OUT_OF_TASK: (TrailGroup.PLANNING, TrailCategory.SPEC_ALIGNMENT),
    TrailLeaf.TEST_OVERFITTING_SHORTCUT: (TrailGroup.PLANNING, TrailCategory.SPEC_ALIGNMENT),
}


def _has_unawaited_async_call(code: str, failure_output: str) -> bool:
    if "coroutine" in failure_output and (
        "was never awaited" in failure_output or "object has no attribute" in failure_output
    ):
        return True
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    async_defs = {node.name for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef)}
    if not async_defs:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            awaited_calls: set[int] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Await) and isinstance(sub.value, ast.Call):
                    awaited_calls.add(id(sub.value))
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.Call)
                    and id(sub) not in awaited_calls
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id in async_defs
                ):
                    return True
    return False


def classify_trail_fault(
    *,
    culprit_entry: TapeStepEntry,
    all_entries: list[TapeStepEntry],
    step_record: StepRecord | None,
    verifier_details: dict[str, Any],
) -> tuple[TrailGroup, TrailCategory, TrailLeaf]:
    """Deterministically classify the attributed step `k*` into the 3->9->20 TRAIL taxonomy."""
    failure_text = str(verifier_details.get("output", ""))
    idx = culprit_entry.step_index
    tool = culprit_entry.tool_name
    args = culprit_entry.tool_args

    # 1. Premature stopping: culprit is `noop` (or no side-effect action claiming completion)
    if tool == "noop":
        return (*TRAIL_LEAF_PARENTS[TrailLeaf.PREMATURE_STOPPING], TrailLeaf.PREMATURE_STOPPING)

    # 2. Wrong ordering: step failed due to missing prerequisite that appears in a LATER step!
    later_entries = all_entries[idx + 1 :]
    if culprit_entry.recorded_exit_code and culprit_entry.recorded_exit_code != 0:
        if tool == "sqlite_exec":
            sql_now = str(args.get("sql", "")).upper()
            if ("INSERT" in sql_now or "UPDATE" in sql_now or "SELECT" in sql_now) and any(
                e.tool_name == "sqlite_exec"
                and "CREATE TABLE" in str(e.tool_args.get("sql", "")).upper()
                for e in later_entries
            ):
                return (
                    *TRAIL_LEAF_PARENTS[TrailLeaf.WRONG_ACTION_ORDERING],
                    TrailLeaf.WRONG_ACTION_ORDERING,
                )
        if tool == "run_cmd":
            cmd_str = " ".join(str(x) for x in args.get("argv", []))
            if any(
                e.tool_name == "write_file" and str(e.tool_args.get("path", "")) in cmd_str
                for e in later_entries
            ):
                return (
                    *TRAIL_LEAF_PARENTS[TrailLeaf.WRONG_ACTION_ORDERING],
                    TrailLeaf.WRONG_ACTION_ORDERING,
                )

    # 3. Wrong file/resource path: `FileNotFoundError` / `ModuleNotFoundError` for expected module
    #    while `write_file` wrote a different/misspelled path at `k*`!
    if tool == "write_file" and (
        "FileNotFoundError" in failure_text or "ModuleNotFoundError" in failure_text
    ):
        return (
            *TRAIL_LEAF_PARENTS[TrailLeaf.WRONG_FILE_OR_RESOURCE_PATH],
            TrailLeaf.WRONG_FILE_OR_RESOURCE_PATH,
        )

    # 4. Invalid tool argument: tool call itself failed (`exit_code != 0` on `patch_file` / `delete_file` / bad flag)
    if (
        tool in ("patch_file", "delete_file")
        and culprit_entry.recorded_exit_code is not None
        and culprit_entry.recorded_exit_code != 0
    ):
        return (
            *TRAIL_LEAF_PARENTS[TrailLeaf.INVALID_TOOL_ARGUMENT],
            TrailLeaf.INVALID_TOOL_ARGUMENT,
        )
    if (
        step_record is not None
        and step_record.receipt.measured.exit_code not in (None, 0)
        and tool != "sqlite_exec"
    ):
        return (
            *TRAIL_LEAF_PARENTS[TrailLeaf.INVALID_TOOL_ARGUMENT],
            TrailLeaf.INVALID_TOOL_ARGUMENT,
        )

    # 5. Inspect code written/patched at `k*` + verifier failure signature for REASONING leaves
    code_written = str(args.get("content", "") or args.get("new", ""))

    if _has_unawaited_async_call(code_written, failure_text):
        return (
            *TRAIL_LEAF_PARENTS[TrailLeaf.MISSING_AWAIT_OR_ASYNC_MISUSE],
            TrailLeaf.MISSING_AWAIT_OR_ASYNC_MISUSE,
        )

    if "NoneType" in failure_text or ("AttributeError" in failure_text and "None" in failure_text):
        return (
            *TRAIL_LEAF_PARENTS[TrailLeaf.MISSING_NULL_OR_EMPTY_GUARD],
            TrailLeaf.MISSING_NULL_OR_EMPTY_GUARD,
        )

    if "TypeError" in failure_text or "ValidationError" in failure_text:
        return (
            *TRAIL_LEAF_PARENTS[TrailLeaf.TYPE_OR_SCHEMA_MISMATCH],
            TrailLeaf.TYPE_OR_SCHEMA_MISMATCH,
        )

    if "TimeoutExpired" in failure_text or culprit_entry.recorded_timed_out:
        return (
            *TRAIL_LEAF_PARENTS[TrailLeaf.INFINITE_OR_BROKEN_ITERATION],
            TrailLeaf.INFINITE_OR_BROKEN_ITERATION,
        )

    # Check AST comparison operators (`<`, `>`, `<=`, `>=`, `range(... - 1)`, `[:-1]`) for boundary/off-by-one
    try:
        tree = ast.parse(code_written)
        has_strict_ineq = any(
            isinstance(n, (ast.Lt, ast.Gt, ast.LtE, ast.GtE)) for n in ast.walk(tree)
        )
    except SyntaxError:
        has_strict_ineq = False

    if "AssertionError" in failure_text and has_strict_ineq:
        return (
            *TRAIL_LEAF_PARENTS[TrailLeaf.BOUNDARY_OFF_BY_ONE],
            TrailLeaf.BOUNDARY_OFF_BY_ONE,
        )

    if tool == "sqlite_exec":
        return (
            *TRAIL_LEAF_PARENTS[TrailLeaf.CORRUPTED_DB_OR_PERSISTENT_STATE],
            TrailLeaf.CORRUPTED_DB_OR_PERSISTENT_STATE,
        )

    return (
        *TRAIL_LEAF_PARENTS[TrailLeaf.INCORRECT_FORMULA_OR_BRANCH],
        TrailLeaf.INCORRECT_FORMULA_OR_BRANCH,
    )
