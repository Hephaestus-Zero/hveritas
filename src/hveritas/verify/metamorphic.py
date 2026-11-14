"""T2 Oracle-Free Metamorphic Relation Suite Synthesizer (`arXiv:2406.06864`)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MetamorphicKind(StrEnum):
    """Standard oracle-free metamorphic relation families."""

    PERMUTATION_INVARIANCE = "permutation_invariance"
    POSITIVE_SCALING = "positive_scaling"
    ANTI_MONOTONE_SECOND_ARG = "anti_monotone_second_arg"
    IDEMPOTENCE = "idempotence"
    ROUNDTRIP_INVERSE = "roundtrip_inverse"


class MetamorphicRelation(BaseModel):
    """Declarative oracle-free relation `R(x, T(x), f(x), f(T(x)))`."""

    model_config = ConfigDict(frozen=True)

    relation_id: str
    kind: MetamorphicKind
    target_file: str
    function_name: str
    inverse_function_name: str | None = None
    seed_inputs: list[list[Any]] = Field(default_factory=list)


def render_metamorphic_pytest_suite(relations: list[MetamorphicRelation]) -> str:
    """Compile declarative `MetamorphicRelation` specs into an isolated `/suites/metamorphic` pytest module."""
    lines = [
        "from loader import load_workspace_module",
        "",
    ]
    for idx, rel in enumerate(relations):
        fn = rel.function_name
        tfile = rel.target_file
        seeds_repr = repr(rel.seed_inputs)

        if rel.kind == MetamorphicKind.PERMUTATION_INVARIANCE:
            lines.extend(
                [
                    f"def test_meta_{idx:03d}_{rel.relation_id}():",
                    f"    mod = load_workspace_module({tfile!r})",
                    f"    for args in {seeds_repr}:",
                    "        xs = list(args[0])",
                    "        rest = args[1:]",
                    "        rev_xs = list(reversed(xs))",
                    f"        assert getattr(mod, {fn!r})(xs, *rest) == getattr(mod, {fn!r})(rev_xs, *rest)",
                    "",
                ]
            )
        elif rel.kind == MetamorphicKind.POSITIVE_SCALING:
            lines.extend(
                [
                    f"def test_meta_{idx:03d}_{rel.relation_id}():",
                    f"    mod = load_workspace_module({tfile!r})",
                    f"    for args in {seeds_repr}:",
                    "        xs = list(args[0])",
                    "        rest = args[1:]",
                    "        scaled = [x * 2 for x in xs]",
                    f"        y1 = getattr(mod, {fn!r})(xs, *rest)",
                    f"        y2 = getattr(mod, {fn!r})(scaled, *rest)",
                    "        assert abs(y2 - 2 * y1) <= 1",
                    "",
                ]
            )
        elif rel.kind == MetamorphicKind.ANTI_MONOTONE_SECOND_ARG:
            lines.extend(
                [
                    f"def test_meta_{idx:03d}_{rel.relation_id}():",
                    f"    mod = load_workspace_module({tfile!r})",
                    f"    for args in {seeds_repr}:",
                    "        first, pct = args[0], args[1]",
                    "        higher_pct = min(100, pct + 15)",
                    f"        y_low = getattr(mod, {fn!r})(first, pct)",
                    f"        y_high = getattr(mod, {fn!r})(first, higher_pct)",
                    "        assert y_high <= y_low",
                    "",
                ]
            )
        elif rel.kind == MetamorphicKind.IDEMPOTENCE:
            lines.extend(
                [
                    f"def test_meta_{idx:03d}_{rel.relation_id}():",
                    f"    mod = load_workspace_module({tfile!r})",
                    f"    for args in {seeds_repr}:",
                    f"        once = getattr(mod, {fn!r})(*args)",
                    f"        twice = getattr(mod, {fn!r})(once)",
                    "        assert twice == once",
                    "",
                ]
            )
        elif rel.kind == MetamorphicKind.ROUNDTRIP_INVERSE:
            inv = rel.inverse_function_name or fn
            lines.extend(
                [
                    f"def test_meta_{idx:03d}_{rel.relation_id}():",
                    f"    mod = load_workspace_module({tfile!r})",
                    f"    for args in {seeds_repr}:",
                    "        x = args[0]",
                    f"        encoded = getattr(mod, {fn!r})(x)",
                    f"        decoded = getattr(mod, {inv!r})(encoded)",
                    "        assert decoded == x",
                    "",
                ]
            )
    return "\n".join(lines)
