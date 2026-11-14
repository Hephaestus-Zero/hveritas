"""Cross-Family Held-Out Oracle Synthesis (`M9-B`): enforces I15 family separation & I16 prompt disjointness."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from hveritas.ledger.models import CostRecord
from hveritas.spec.compiler import RequirementDraft
from hveritas.spec.interview import EdgeCase, _extract_json_object
from hveritas.spec.models import IOAssertion

if TYPE_CHECKING:
    from hveritas.worker.backend import ModelBackend

_EXCEPTION_LITERAL_RE = re.compile(
    r"^(?:raises?\s+)?(?:ValueError|TypeError|KeyError|IndexError|"
    r"ZeroDivisionError|RuntimeError|AssertionError|OverflowError)(?:\b|\()",
    re.IGNORECASE,
)


class OracleAuthorCollisionError(RuntimeError):
    """Raised when the held-out oracle author resolves to the same model family as the worker (`I15`)."""

    def __init__(self, *, worker_family: str, oracle_family: str, oracle_model: str) -> None:
        super().__init__(
            f"I15 VIOLATION: Oracle author model {oracle_model!r} resolved to family={oracle_family!r}, "
            f"which collides with worker family={worker_family!r}. "
            "Pass --oracle-model from a distinct model family."
        )
        self.worker_family = worker_family
        self.oracle_family = oracle_family
        self.oracle_model = oracle_model


def build_oracle_author_prompt(
    *,
    requirement: RequirementDraft,
    edge_cases: list[EdgeCase],
) -> str:
    """Build strictly isolated M9-B prompt containing ONLY statement, API contract, and edge cases (`I16`).

    NEVER reads or formats `requirement.proxy_assertions`, worker prompts, or worker code.
    """
    edge_rows = [
        {
            "args": ec.args,
            "input_repr": ec.input_repr,
            "expected_behavior": ec.expected_behavior,
            "rationale": ec.rationale,
        }
        for ec in edge_cases
    ]
    schema_hint = {
        "heldout_assertions": [
            {
                "function": requirement.function_name,
                "args": ["<non_trivial_valid_input>"],
                "expected": "<exact_return_value>",
            }
        ],
        "reference_code": (
            f"def {requirement.function_name}({', '.join(requirement.arg_names)}):\n    ..."
        ),
    }
    return (
        "## 1. Behavioral Requirement Statement\n"
        f"{requirement.statement}\n"
        + (
            f"Constraints: {', '.join(requirement.constraints)}\n"
            if requirement.constraints
            else ""
        )
        + "\n## 2. API Contract\n"
        f"- Target file: `{requirement.target_file}`\n"
        f"- Function signature: `{requirement.function_name}({', '.join(requirement.arg_names)})`\n\n"
        "## 3. Edge Case Table\n"
        f"{json.dumps(edge_rows, ensure_ascii=False, indent=2)}\n\n"
        "## 4. Output Contract\n"
        "Generate 4 to 6 independent held-out `IOAssertion` test cases using non-trivial, varied valid inputs "
        "(avoid trivial textbook numbers like 100 or '1h30m' so you do not duplicate visible examples), PLUS a "
        "clean stdlib-only Python `reference_code` implementing the exact contract (used ONLY inside the isolated "
        "SpecAuditGate consistency check and never shown to the worker).\n"
        "IMPORTANT: Every item in `heldout_assertions` MUST be a normal value-returning call "
        "`fn(*args) == expected` (NEVER put exception names like 'ValueError' in `heldout_assertions`!).\n"
        f"Return ONLY JSON matching:\n{json.dumps(schema_hint, ensure_ascii=False, indent=2)}"
    )


def _is_exception_placeholder(val: Any) -> bool:
    return isinstance(val, str) and bool(_EXCEPTION_LITERAL_RE.match(val.strip()))


def synthesize_heldout_oracle(
    *,
    requirement: RequirementDraft,
    edge_cases: list[EdgeCase],
    backend: ModelBackend,
    oracle_model: str,
    worker_family: str,
    timeout_s: float = 180.0,
    reference_sink: dict[str, str] | None = None,
) -> tuple[list[IOAssertion], str, CostRecord]:
    """Synthesize held-out assertions via an independent model family (`I15`, `I16`)."""
    system_prompt = (
        "You are an independent Held-Out Oracle Author for hveritas (M9-B). "
        "You have zero visibility into the worker's code or visible proxy assertions. "
        "Reply strictly with a plain-text JSON object containing `heldout_assertions` and `reference_code`."
    )
    user_prompt = build_oracle_author_prompt(requirement=requirement, edge_cases=edge_cases)

    resp = backend.complete(
        system=system_prompt,
        user=user_prompt,
        model=oracle_model,
        timeout_s=timeout_s,
    )
    cost = CostRecord(
        input_tokens=resp.input_tokens,
        output_tokens=resp.output_tokens,
        usd=resp.usd,
        wall_ms=resp.elapsed_ms,
    )

    oracle_fam = resp.family.strip()
    worker_fam = worker_family.strip()
    if worker_fam and oracle_fam.lower() == worker_fam.lower():
        raise OracleAuthorCollisionError(
            worker_family=worker_fam,
            oracle_family=oracle_fam,
            oracle_model=oracle_model,
        )

    from hveritas.worker.backend import ModelProtocolError

    parsed, parse_err = _extract_json_object(resp.text)
    if parsed is None:
        raise ModelProtocolError(
            f"Oracle author model {oracle_model!r} returned invalid JSON: {parse_err}"
        )

    raw_items = parsed.get("heldout_assertions")
    if not isinstance(raw_items, list) or not raw_items:
        raise ModelProtocolError(
            f"Oracle author model {oracle_model!r} returned empty `heldout_assertions`"
        )

    assertions: list[IOAssertion] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        fn = str(item.get("function") or requirement.function_name).strip()
        args_val = item.get("args")
        if not isinstance(args_val, list) or "expected" not in item:
            continue
        if _is_exception_placeholder(item["expected"]):
            continue
        assertions.append(IOAssertion(function=fn, args=args_val, expected=item["expected"]))

    if not assertions:
        raise ModelProtocolError(
            f"Oracle author model {oracle_model!r} produced zero valid value-returning `IOAssertion`s"
        )

    ref_code = parsed.get("reference_code")
    if reference_sink is not None and isinstance(ref_code, str) and ref_code.strip():
        reference_sink[requirement.id] = ref_code.strip() + "\n"

    return assertions, oracle_fam, cost
