"""Spec Compiler: compiles Goals into a binary Requirement DAG with proxy/held-out split & uncertainty gate."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from hveritas.harness.oracle_vault import EncryptedOracleVault
from hveritas.ledger.canonical import canonical_json, sha256_hex
from hveritas.spec.models import (
    CompiledSpec,
    IOAssertion,
    OracleCheckSpec,
    RequirementNode,
)


class HumanClarificationRequiredError(RuntimeError):
    """Raised when a goal/spec is ambiguous, underspecified, or self-contradictory (§1, §8)."""

    def __init__(self, message: str, questions: list[str], contradictions: list[str]) -> None:
        super().__init__(message)
        self.questions = questions
        self.contradictions = contradictions


@dataclass(frozen=True)
class RequirementDraft:
    """Structured or parsed requirement clause fed into SpecCompiler."""

    id: str
    statement: str
    target_file: str
    function_name: str
    arg_names: list[str]
    proxy_assertions: list[IOAssertion]
    heldout_assertions: list[IOAssertion]
    depends_on: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)


_CONTRADICTORY_KEYWORD_PAIRS: tuple[tuple[re.Pattern[str], re.Pattern[str], str], ...] = (
    (
        re.compile(r"\b(?:offline[- ]only|no[- ]network|air[- ]?gapped)\b", re.IGNORECASE),
        re.compile(r"\b(?:fetch\s+live|external\s+http\s+api|online\s+endpoint)\b", re.IGNORECASE),
        "Goal simultaneously demands offline/no-network execution and live external HTTP calls.",
    ),
    (
        re.compile(r"\bmust\s+reject\s+negative\b", re.IGNORECASE),
        re.compile(r"\bmust\s+accept\s+negative\b", re.IGNORECASE),
        "Goal simultaneously requires rejecting and accepting negative inputs.",
    ),
    (
        re.compile(r"\bstateless\b", re.IGNORECASE),
        re.compile(r"\bpersist\s+session\s+state\s+in\s+memory\b", re.IGNORECASE),
        "Goal simultaneously requires stateless execution and persistent in-memory state.",
    ),
)

_AMBIGUOUS_MARKERS_RE = re.compile(
    r"(?:\bTBD\b|\bTODO\b|\?\?\?|belirsiz|hangisi\s+olursa|either\s+or\s+unspecified)",
    re.IGNORECASE,
)


def render_pytest_from_assertions(target_file: str, assertions: list[IOAssertion]) -> str:
    """Render deterministic, eval-free pytest suite loading module via `/verifier/loader.py`."""
    lines = [
        "from loader import load_workspace_module",
        "",
    ]
    for idx, item in enumerate(assertions):
        args_repr = ", ".join(repr(a) for a in item.args)
        exp_repr = repr(item.expected)
        lines.extend(
            [
                f"def test_case_{idx:03d}():",
                f"    mod = load_workspace_module({target_file!r})",
                f"    assert mod.{item.function}({args_repr}) == {exp_repr}",
                "",
            ]
        )
    return "\n".join(lines)


class SpecCompiler:
    """Compiles natural-language + structured goals into an oracle-split Requirement DAG.

    Invariants enforced:
    - Ambiguity/Contradiction Gate halts and escalates to human instead of guessing.
    - Held-out acceptance tests are encrypted directly into `EncryptedOracleVault` (I4);
      only `heldout_oracle_id` is stored on `RequirementNode`.
    """

    def __init__(self, oracle_vault: EncryptedOracleVault | None = None) -> None:
        self.oracle_vault = oracle_vault or EncryptedOracleVault()

    def compile(
        self,
        goal_text: str,
        requirements: list[RequirementDraft] | None = None,
        spec_id: str | None = None,
        *,
        allow_empty_heldout: bool = False,
    ) -> CompiledSpec:
        clean_goal = goal_text.strip()
        questions: list[str] = []
        contradictions: list[str] = []

        if len(clean_goal) < 10:
            questions.append("Hedef çok kısa/belirsiz: kabul kriteri ve hedef modül nedir?")

        if _AMBIGUOUS_MARKERS_RE.search(clean_goal):
            questions.append(
                "Hedefte çözülmemiş belirsizlik işareti (TBD/???/belirsiz) bulundu; kesin kural nedir?"
            )

        for pat_a, pat_b, desc in _CONTRADICTORY_KEYWORD_PAIRS:
            if pat_a.search(clean_goal) and pat_b.search(clean_goal):
                contradictions.append(desc)

        resolved_reqs = (
            requirements if requirements is not None else self._parse_nl_goal(clean_goal)
        )
        if not resolved_reqs:
            questions.append(
                "Doğal dil hedefinden ikili doğrulanabilir gereksinim çıkarılamadı; girdi/çıktı sözleşmesini belirtin."
            )

        # Inspect requirement clauses for functional I/O contradictions & constraint clashes
        for req in resolved_reqs:
            full_clause_text = " ".join([req.statement, *req.constraints])
            if _AMBIGUOUS_MARKERS_RE.search(full_clause_text):
                questions.append(f"Gereksinim {req.id!r} belirsiz ifadeler içeriyor.")
            for pat_a, pat_b, desc in _CONTRADICTORY_KEYWORD_PAIRS:
                if pat_a.search(full_clause_text) and pat_b.search(full_clause_text):
                    contradictions.append(f"[{req.id}] {desc}")

            seen_inputs: dict[str, Any] = {}
            for assertion in [*req.proxy_assertions, *req.heldout_assertions]:
                key = f"{assertion.function}:{canonical_json(assertion.args)}"
                if key in seen_inputs and seen_inputs[key] != assertion.expected:
                    contradictions.append(
                        f"[{req.id}] Çelişkili beklenen çıktı {key}: "
                        f"{seen_inputs[key]!r} vs {assertion.expected!r}"
                    )
                seen_inputs[key] = assertion.expected

            if not req.proxy_assertions:
                questions.append(f"[{req.id}] Proxy kontrolü eksik.")
            if not req.heldout_assertions and not allow_empty_heldout:
                questions.append(f"[{req.id}] Held-out kabul kriteri eksik.")

        if contradictions or questions:
            for c in contradictions:
                questions.append(f"Çelişkiyi çözün: {c}")
            raise HumanClarificationRequiredError(
                "Spec belirsiz veya çelişkili — varsayımla devam edilmiyor, insana soruluyor.",
                questions=questions,
                contradictions=contradictions,
            )

        # Build and validate Requirement DAG acyclicity
        dag = nx.DiGraph()
        req_ids = {r.id for r in resolved_reqs}
        for r in resolved_reqs:
            dag.add_node(r.id)
            for dep in r.depends_on:
                if dep not in req_ids:
                    raise HumanClarificationRequiredError(
                        f"Bilinmeyen bağımlılık düğümü: {dep!r}",
                        questions=[f"{r.id} düğümünün bağımlı olduğu {dep!r} tanımlı değil."],
                        contradictions=[],
                    )
                dag.add_edge(dep, r.id)

        if not nx.is_directed_acyclic_graph(dag):
            raise HumanClarificationRequiredError(
                "Requirement DAG döngüsel (cycle içeriyor).",
                questions=["Gereksinim bağımlılıklarındaki döngüyü kaldırın."],
                contradictions=["Cycle detected in Requirement DAG"],
            )

        topo_order = list(nx.topological_sort(dag))
        resolved_spec_id = spec_id or f"spec-{sha256_hex(clean_goal)[:12]}"

        compiled_nodes: list[RequirementNode] = []
        for r in resolved_reqs:
            if allow_empty_heldout and not r.heldout_assertions:
                oracle_id = ""
            else:
                oracle_id = f"{resolved_spec_id}_{r.id}_heldout"
                heldout_py = render_pytest_from_assertions(r.target_file, r.heldout_assertions)
                # Seal held-out tests directly into encrypted external oracle vault (I4)
                self.oracle_vault.store_oracle_suite(
                    oracle_id=oracle_id,
                    test_files={f"test_heldout_{r.id}.py": heldout_py},
                )
            proxy_py = render_pytest_from_assertions(r.target_file, r.proxy_assertions)
            compiled_nodes.append(
                RequirementNode(
                    id=r.id,
                    statement=r.statement,
                    target_file=r.target_file,
                    function_name=r.function_name,
                    arg_names=r.arg_names,
                    depends_on=r.depends_on,
                    constraints=r.constraints,
                    proxy_oracle=OracleCheckSpec(
                        suite_name=f"proxy_{r.id}",
                        assertions=r.proxy_assertions,
                        custom_pytest_code=proxy_py,
                    ),
                    heldout_oracle_id=oracle_id,
                )
            )

        return CompiledSpec(
            spec_id=resolved_spec_id,
            goal_text=clean_goal,
            nodes=compiled_nodes,
            topological_order=topo_order,
        )

    def _parse_nl_goal(self, goal_text: str) -> list[RequirementDraft]:
        """Deterministic pattern compiler for canonical NL arithmetic/string/collection goals."""
        low = goal_text.lower()
        if "discount" in low or "indirim" in low:
            return [
                RequirementDraft(
                    id="req_discount",
                    statement="Compute discounted integer total from item prices and coupon percentage.",
                    target_file="discount.py",
                    function_name="compute_total",
                    arg_names=["prices", "coupon_pct"],
                    proxy_assertions=[
                        IOAssertion(function="compute_total", args=[[100, 200], 10], expected=270),
                        IOAssertion(function="compute_total", args=[[50], 0], expected=50),
                    ],
                    heldout_assertions=[
                        IOAssertion(
                            function="compute_total", args=[[120, 80, 40], 25], expected=180
                        ),
                        IOAssertion(function="compute_total", args=[[999], 100], expected=0),
                        IOAssertion(function="compute_total", args=[[10, 20, 30], 50], expected=30),
                    ],
                )
            ]
        if "fibonacci" in low:
            return [
                RequirementDraft(
                    id="req_fib",
                    statement="Compute nth non-negative Fibonacci integer.",
                    target_file="fib.py",
                    function_name="fib",
                    arg_names=["n"],
                    proxy_assertions=[
                        IOAssertion(function="fib", args=[0], expected=0),
                        IOAssertion(function="fib", args=[6], expected=8),
                    ],
                    heldout_assertions=[
                        IOAssertion(function="fib", args=[1], expected=1),
                        IOAssertion(function="fib", args=[10], expected=55),
                        IOAssertion(function="fib", args=[15], expected=610),
                    ],
                )
            ]
        return []
