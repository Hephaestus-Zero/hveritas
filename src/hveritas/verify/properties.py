"""Mandatory 4-Block Oracle-Free Property Layer (`M9-C`, Invariant `I17`).

Blocks enforced on EVERY `hveritas run` regardless of `--assurance` level:
- C1: Metamorphic relation proposer + reference-behavior filter (`T2`)
- C2: Determinism (`f(x) == f(x)` across repeated invocations with deep-copied args)
- C3: Type & signature contract (`inspect.signature` + runtime return-type check)
- C4: Garbage-input resilience (12 adversarial/boundary inputs with 1.0s per-case timeout)
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from hveritas.harness.isolation import SCRATCH_ROOT
from hveritas.ledger.canonical import canonical_json
from hveritas.verify.bus import VerifierBus
from hveritas.verify.metamorphic import (
    MetamorphicKind,
    MetamorphicRelation,
    render_metamorphic_pytest_suite,
)
from hveritas.verify.models import VerificationState, VerifierBusReport

if TYPE_CHECKING:
    from hveritas.spec.compiler import RequirementDraft
    from hveritas.spec.interview import EdgeCase
    from hveritas.worker.backend import ModelBackend

_ORDER_SENSITIVE_RE = re.compile(
    r"\b(?:sort|sorted|sırala|first|ilk|last|son|index|indeks|prefix|suffix|head|tail|reverse)\b",
    re.IGNORECASE,
)

GARBAGE_CASE_COUNT = 12


@dataclass(frozen=True)
class OracleFreeSuite:
    """Compiled `T1` (`dynamic_invariants`) + `T2` (`metamorphic_tests`) suites for Invariant `I17`."""

    relations: list[MetamorphicRelation]
    dynamic_invariants: dict[str, str]
    metamorphic_tests: dict[str, str]
    garbage_case_count: int = GARBAGE_CASE_COUNT


def _is_num(val: Any) -> bool:
    return isinstance(val, (int, float)) and not isinstance(val, bool)


def _candidate_holds_against_proxy(
    rel: MetamorphicRelation,
    requirement: RequirementDraft,
) -> bool:
    """Fast structural + proxy-table soundness filter before container verification."""
    n_args = len(requirement.arg_names)
    if not rel.seed_inputs or any(
        not isinstance(s, list) or len(s) != n_args for s in rel.seed_inputs
    ):
        return False

    proxy_map = {
        canonical_json(a.args): a.expected
        for a in requirement.proxy_assertions
        if a.function == requirement.function_name
    }

    if rel.kind == MetamorphicKind.PERMUTATION_INVARIANCE:
        if n_args < 1 or _ORDER_SENSITIVE_RE.search(requirement.statement):
            return False
        if not all(isinstance(s[0], list) for s in rel.seed_inputs):
            return False
        for a in requirement.proxy_assertions:
            if not a.args or not isinstance(a.args[0], list):
                return False
            rev_args = [list(reversed(a.args[0])), *a.args[1:]]
            rev_key = canonical_json(rev_args)
            if rev_key in proxy_map and proxy_map[rev_key] != a.expected:
                return False
        return True

    if rel.kind == MetamorphicKind.POSITIVE_SCALING:
        if n_args < 1:
            return False
        if not all(
            isinstance(s[0], list) and all(_is_num(x) for x in s[0]) for s in rel.seed_inputs
        ):
            return False
        if not requirement.proxy_assertions or not all(
            _is_num(a.expected) and isinstance(a.args[0], list)
            for a in requirement.proxy_assertions
        ):
            return False
        for a in requirement.proxy_assertions:
            scaled_args = [[x * 2 for x in a.args[0]], *a.args[1:]]
            s_key = canonical_json(scaled_args)
            if s_key in proxy_map and abs(float(proxy_map[s_key]) - 2.0 * float(a.expected)) > 1.0:
                return False
        return True

    if rel.kind == MetamorphicKind.ANTI_MONOTONE_SECOND_ARG:
        if n_args != 2:
            return False
        if not all(_is_num(s[1]) for s in rel.seed_inputs):
            return False
        if not requirement.proxy_assertions or not all(
            len(a.args) == 2 and _is_num(a.args[1]) and _is_num(a.expected)
            for a in requirement.proxy_assertions
        ):
            return False
        for i, a1 in enumerate(requirement.proxy_assertions):
            for a2 in requirement.proxy_assertions[i + 1 :]:
                if canonical_json(a1.args[0]) == canonical_json(a2.args[0]):
                    p1, y1 = float(a1.args[1]), float(a1.expected)
                    p2, y2 = float(a2.args[1]), float(a2.expected)
                    if p1 < p2 and y2 > y1:
                        return False
                    if p2 < p1 and y1 > y2:
                        return False
        return True

    if rel.kind == MetamorphicKind.IDEMPOTENCE:
        if n_args != 1 or not requirement.proxy_assertions:
            return False
        for a in requirement.proxy_assertions:
            if type(a.expected) is not type(a.args[0]):
                return False
            twice_key = canonical_json([a.expected])
            if twice_key in proxy_map and proxy_map[twice_key] != a.expected:
                return False
        return True

    if rel.kind == MetamorphicKind.ROUNDTRIP_INVERSE:
        return bool(
            n_args == 1
            and rel.inverse_function_name
            and rel.inverse_function_name != requirement.function_name
        )

    return False


def _heuristic_candidate_relations(
    requirement: RequirementDraft,
    *,
    has_reference_code: bool,
) -> list[MetamorphicRelation]:
    """Generate deterministic candidate relations from argument shapes & proxy assertions."""
    if not requirement.proxy_assertions:
        return []
    seeds = [list(a.args) for a in requirement.proxy_assertions[:4]]
    n_args = len(requirement.arg_names)
    stmt_low = requirement.statement.lower()
    candidates: list[MetamorphicRelation] = []

    if n_args >= 1 and all(
        a.args and isinstance(a.args[0], list) for a in requirement.proxy_assertions
    ):
        if has_reference_code or any(w in stmt_low for w in ("sum", "total", "toplam")):
            candidates.append(
                MetamorphicRelation(
                    relation_id=f"{requirement.id}_perm",
                    kind=MetamorphicKind.PERMUTATION_INVARIANCE,
                    target_file=requirement.target_file,
                    function_name=requirement.function_name,
                    seed_inputs=seeds,
                )
            )
        if has_reference_code and all(
            all(_is_num(x) for x in a.args[0]) and _is_num(a.expected)
            for a in requirement.proxy_assertions
        ):
            candidates.append(
                MetamorphicRelation(
                    relation_id=f"{requirement.id}_scale",
                    kind=MetamorphicKind.POSITIVE_SCALING,
                    target_file=requirement.target_file,
                    function_name=requirement.function_name,
                    seed_inputs=seeds,
                )
            )

    if (
        n_args == 2
        and (has_reference_code or "discount" in stmt_low or "indirim" in stmt_low)
        and any(
            tok in requirement.arg_names[1].lower()
            for tok in ("pct", "percent", "discount", "rate")
        )
        and all(_is_num(a.args[1]) and _is_num(a.expected) for a in requirement.proxy_assertions)
    ):
        candidates.append(
            MetamorphicRelation(
                relation_id=f"{requirement.id}_antimonotone",
                kind=MetamorphicKind.ANTI_MONOTONE_SECOND_ARG,
                target_file=requirement.target_file,
                function_name=requirement.function_name,
                seed_inputs=seeds,
            )
        )

    idempotent_hint = any(
        w in stmt_low for w in ("idempotent", "normalize", "clamp", "strip", "trim", "dedup")
    )
    if (
        n_args == 1
        and (has_reference_code or idempotent_hint)
        and all(type(a.expected) is type(a.args[0]) for a in requirement.proxy_assertions)
    ):
        candidates.append(
            MetamorphicRelation(
                relation_id=f"{requirement.id}_idemp",
                kind=MetamorphicKind.IDEMPOTENCE,
                target_file=requirement.target_file,
                function_name=requirement.function_name,
                seed_inputs=seeds,
            )
        )

    return candidates


def _filter_against_reference_in_container(
    *,
    candidates: list[MetamorphicRelation],
    requirement: RequirementDraft,
    reference_code: str,
    bus: VerifierBus,
) -> list[MetamorphicRelation]:
    """Validate every proposed `MetamorphicRelation` against `reference_code` inside isolated container."""
    if not candidates:
        return []
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    probe_root = SCRATCH_ROOT / f"hv_meta_ref_{os.getpid()}_{secrets.token_hex(8)}"
    probe_ws = probe_root / "ws"
    probe_ws.mkdir(parents=True, mode=0o755)
    try:
        target = (probe_ws / requirement.target_file).resolve()
        if probe_ws not in target.parents and target != probe_ws:
            return []
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(reference_code, encoding="utf-8")

        from hveritas.spec.compiler import render_pytest_from_assertions

        proxy_py = render_pytest_from_assertions(
            requirement.target_file, requirement.proxy_assertions
        )
        t0_ev = bus.verify_t0(
            VerificationState(
                workspace_path=str(probe_ws),
                proxy_tests={f"test_proxy_{requirement.id}.py": proxy_py}
                if requirement.proxy_assertions
                else {},
                t0_config={"compile": True},
            )
        )
        if not t0_ev.passed:
            # Reference does not satisfy visible proxy; cannot use it as authoritative filter
            return candidates

        survivors: list[MetamorphicRelation] = []
        for idx, rel in enumerate(candidates):
            suite_code = render_metamorphic_pytest_suite([rel])
            t2_ev = bus.verify_t2(
                VerificationState(
                    workspace_path=str(probe_ws),
                    metamorphic_tests={f"test_probe_meta_{idx}.py": suite_code},
                )
            )
            if t2_ev.passed:
                survivors.append(rel)
        return survivors
    finally:
        shutil.rmtree(probe_root, ignore_errors=True)


def propose_metamorphic_relations(
    *,
    requirement: RequirementDraft,
    edge_cases: list[EdgeCase],
    backend: ModelBackend | None = None,
    architect_model: str | None = None,
    reference_code: str | None = None,
    verifier_bus: VerifierBus | None = None,
    timeout_s: float = 120.0,
) -> list[MetamorphicRelation]:
    """Propose and soundness-filter T2 metamorphic relations (`M9-C1`)."""
    raw_candidates: list[MetamorphicRelation] = []
    seen_kinds: set[tuple[MetamorphicKind, str | None]] = set()

    if backend is not None and architect_model is not None:
        allowed_kinds = [k.value for k in MetamorphicKind]
        edge_preview = [
            {"args": ec.args, "expected_behavior": ec.expected_behavior} for ec in edge_cases[:8]
        ]
        schema_example = {
            "relations": [
                {
                    "relation_id": "rel_1",
                    "kind": "permutation_invariance",
                    "inverse_function_name": None,
                    "seed_inputs": [list(requirement.proxy_assertions[0].args)]
                    if requirement.proxy_assertions
                    else [],
                }
            ]
        }
        resp = backend.complete(
            system=(
                "You propose ONLY mathematically sound metamorphic relations for software verification. "
                f"Allowed `kind` values: {allowed_kinds}. If NO relation from that exact enum strictly "
                'holds for ALL valid inputs, return `{"relations": []}`.'
            ),
            user=(
                f"Requirement: {requirement.statement}\n"
                f"Function: {requirement.function_name}({', '.join(requirement.arg_names)}) in {requirement.target_file}\n"
                f"Edge cases: {edge_preview!r}\n"
                f"Return ONLY JSON matching: {schema_example!r}"
            ),
            model=architect_model,
            timeout_s=timeout_s,
        )
        from hveritas.spec.interview import _extract_json_object

        parsed, _ = _extract_json_object(resp.text)
        if parsed is not None and isinstance(parsed.get("relations"), list):
            default_seeds = [list(a.args) for a in requirement.proxy_assertions[:3]]
            for idx, item in enumerate(parsed["relations"]):
                if not isinstance(item, dict):
                    continue
                kind_str = str(item.get("kind") or "").strip()
                if kind_str not in {k.value for k in MetamorphicKind}:
                    continue
                kind = MetamorphicKind(kind_str)
                inv_fn = (
                    str(item["inverse_function_name"]).strip()
                    if isinstance(item.get("inverse_function_name"), str)
                    and item["inverse_function_name"].strip()
                    else None
                )
                raw_seeds = item.get("seed_inputs")
                seeds = (
                    [list(s) for s in raw_seeds if isinstance(s, list)]
                    if isinstance(raw_seeds, list) and raw_seeds
                    else default_seeds
                )
                rel_id = re.sub(
                    r"[^a-zA-Z0-9_]", "_", str(item.get("relation_id") or f"m9_rel_{idx}")
                )
                cand = MetamorphicRelation(
                    relation_id=rel_id,
                    kind=kind,
                    target_file=requirement.target_file,
                    function_name=requirement.function_name,
                    inverse_function_name=inv_fn,
                    seed_inputs=seeds,
                )
                if _candidate_holds_against_proxy(cand, requirement):
                    key = (cand.kind, cand.inverse_function_name)
                    if key not in seen_kinds:
                        seen_kinds.add(key)
                        raw_candidates.append(cand)

    for h_cand in _heuristic_candidate_relations(
        requirement, has_reference_code=reference_code is not None
    ):
        if _candidate_holds_against_proxy(h_cand, requirement):
            key = (h_cand.kind, h_cand.inverse_function_name)
            if key not in seen_kinds:
                seen_kinds.add(key)
                raw_candidates.append(h_cand)

    if reference_code is not None and raw_candidates:
        bus = verifier_bus or VerifierBus()
        return _filter_against_reference_in_container(
            candidates=raw_candidates,
            requirement=requirement,
            reference_code=reference_code,
            bus=bus,
        )

    return raw_candidates


def render_determinism_pytest(requirements: list[RequirementDraft]) -> str:
    """Render `C2` determinism check (`NONDETERMINISTIC_OUTPUT` on divergent repeated calls)."""
    lines = [
        "import copy",
        "from loader import load_workspace_module",
        "",
        "def test_m9_c2_determinism():",
    ]
    for req in requirements:
        sample_inputs = [list(a.args) for a in req.proxy_assertions[:6]]
        lines.extend(
            [
                f"    mod = load_workspace_module({req.target_file!r})",
                f"    fn_name = {req.function_name!r}",
                "    fn = getattr(mod, fn_name)",
                f"    for raw_args in {sample_inputs!r}:",
                "        out1 = fn(*copy.deepcopy(raw_args))",
                "        out2 = fn(*copy.deepcopy(raw_args))",
                "        assert type(out1) is type(out2) and out1 == out2, (",
                "            f'NONDETERMINISTIC_OUTPUT in {fn_name}({raw_args!r}): {out1!r} != {out2!r}'",
                "        )",
            ]
        )
    if not requirements:
        lines.append("    assert True")
    return "\n".join(lines) + "\n"


def _expected_type_check_expr(assertions: list[Any]) -> str:
    if not assertions:
        return "True"
    has_bool = any(isinstance(a.expected, bool) for a in assertions)
    has_int = any(
        isinstance(a.expected, int) and not isinstance(a.expected, bool) for a in assertions
    )
    has_float = any(isinstance(a.expected, float) for a in assertions)
    has_str = any(isinstance(a.expected, str) for a in assertions)
    has_list = any(isinstance(a.expected, list) for a in assertions)
    has_dict = any(isinstance(a.expected, dict) for a in assertions)
    has_none = any(a.expected is None for a in assertions)

    clauses: list[str] = []
    if has_bool:
        clauses.append("isinstance(res, bool)")
    if has_int and not has_float:
        clauses.append("(isinstance(res, int) and not isinstance(res, bool))")
    elif has_float or (has_int and has_float):
        clauses.append("(isinstance(res, (int, float)) and not isinstance(res, bool))")
    if has_str:
        clauses.append("isinstance(res, str)")
    if has_list:
        clauses.append("isinstance(res, list)")
    if has_dict:
        clauses.append("isinstance(res, dict)")
    if has_none:
        clauses.append("(res is None)")
    return " or ".join(clauses) if clauses else "True"


def render_type_contract_pytest(requirements: list[RequirementDraft]) -> str:
    """Render `C3` signature & runtime return-type contract check via `inspect.signature`."""
    lines = [
        "import copy",
        "import inspect",
        "from loader import load_workspace_module",
        "",
        "def test_m9_c3_type_contract():",
    ]
    for req in requirements:
        sample_inputs = [list(a.args) for a in req.proxy_assertions[:6]]
        type_expr = _expected_type_check_expr(req.proxy_assertions)
        n_args = len(req.arg_names)
        lines.extend(
            [
                f"    mod = load_workspace_module({req.target_file!r})",
                f"    assert hasattr(mod, {req.function_name!r}), 'TYPE_CONTRACT_VIOLATION: missing function'",
                f"    fn = getattr(mod, {req.function_name!r})",
                "    assert callable(fn), 'TYPE_CONTRACT_VIOLATION: target attribute not callable'",
                "    sig = inspect.signature(fn)",
                "    params = list(sig.parameters.values())",
                "    has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)",
                "    pos_params = [",
                "        p for p in params",
                "        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)",
                "    ]",
                "    req_pos = [p for p in pos_params if p.default is inspect.Parameter.empty]",
                f"    assert len(req_pos) <= {n_args}, 'TYPE_CONTRACT_VIOLATION: too many required positional args'",
                f"    assert has_varargs or len(pos_params) >= {n_args}, 'TYPE_CONTRACT_VIOLATION: too few positional args'",
                f"    expected_names = {req.arg_names!r}",
                f"    if not has_varargs and len(pos_params) == {n_args}:",
                "        actual_names = [p.name for p in pos_params]",
                "        assert actual_names == expected_names, (",
                "            f'TYPE_CONTRACT_VIOLATION: parameter names {actual_names} != {expected_names}'",
                "        )",
                f"    for raw_args in {sample_inputs!r}:",
                "        sig.bind(*raw_args)",
                "        res = fn(*copy.deepcopy(raw_args))",
                f"        assert ({type_expr}), f'TYPE_CONTRACT_VIOLATION: unexpected return type {{type(res).__name__}} ({{res!r}})'",
            ]
        )
    if not requirements:
        lines.append("    assert True")
    return "\n".join(lines) + "\n"


def build_garbage_vectors(n_args: int) -> list[list[Any]]:
    """Build exactly 12 canonical adversarial/garbage argument vectors (`M9-C4`)."""
    atoms: list[Any] = [
        None,
        "",
        "\x00\t\r\n\x07",
        "__invalid_garbage_token__",
        -1,
        -999_999,
        0,
        10**18,
        [],
        {},
        True,
        "A" * 2048,
    ]
    assert len(atoms) == GARBAGE_CASE_COUNT
    if n_args <= 0:
        return [[] for _ in range(GARBAGE_CASE_COUNT)]
    return [[atom for _ in range(n_args)] for atom in atoms]


def render_garbage_resilience_pytest(requirements: list[RequirementDraft]) -> str:
    """Render `C4` garbage-input resilience suite (12 cases, 1.0s timeout, no hang/RecursionError/NaN)."""
    lines = [
        "import math",
        "import signal",
        "from loader import load_workspace_module",
        "",
        "class _GarbageCaseTimeoutError(BaseException):",
        "    pass",
        "",
        "def _alarm_handler(_signum, _frame):",
        "    raise _GarbageCaseTimeoutError('GARBAGE_INPUT_TIMEOUT')",
        "",
        "def test_m9_c4_garbage_resilience():",
        "    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)",
        "    try:",
    ]
    for req in requirements:
        vectors = build_garbage_vectors(len(req.arg_names))
        lines.extend(
            [
                f"        mod = load_workspace_module({req.target_file!r})",
                f"        fn = getattr(mod, {req.function_name!r})",
                f"        for vec in {vectors!r}:",
                "            signal.setitimer(signal.ITIMER_REAL, 1.0)",
                "            try:",
                "                out = fn(*vec)",
                "                if isinstance(out, float) and math.isnan(out):",
                "                    raise AssertionError(f'GARBAGE_SILENT_NAN on {vec!r}')",
                "            except _GarbageCaseTimeoutError as exc:",
                "                raise AssertionError(f'GARBAGE_TIMEOUT_HANG on {vec!r}') from exc",
                "            except (RecursionError, MemoryError) as exc:",
                "                raise AssertionError(f'GARBAGE_UNCONTROLLED_CRASH ({type(exc).__name__}) on {vec!r}') from exc",
                "            except Exception:",
                "                pass",
                "            finally:",
                "                signal.setitimer(signal.ITIMER_REAL, 0.0)",
            ]
        )
    if not requirements:
        lines.append("        assert True")
    lines.extend(
        [
            "    finally:",
            "        signal.setitimer(signal.ITIMER_REAL, 0.0)",
            "        signal.signal(signal.SIGALRM, old_handler)",
        ]
    )
    return "\n".join(lines) + "\n"


def build_oracle_free_suite(
    *,
    requirements: list[RequirementDraft],
    edge_cases: list[EdgeCase] | None = None,
    backend: ModelBackend | None = None,
    architect_model: str | None = None,
    reference_implementations: dict[str, str] | None = None,
    verifier_bus: VerifierBus | None = None,
) -> OracleFreeSuite:
    """Compile all 4 mandatory `M9-C` (`I17`) oracle-free blocks for `VerifierBus`."""
    edges = edge_cases or []
    refs = reference_implementations or {}
    all_relations: list[MetamorphicRelation] = []
    for req in requirements:
        rels = propose_metamorphic_relations(
            requirement=req,
            edge_cases=edges,
            backend=backend,
            architect_model=architect_model,
            reference_code=refs.get(req.id) or refs.get(req.target_file),
            verifier_bus=verifier_bus,
        )
        all_relations.extend(rels)

    dyn_invariants = {
        "test_m9_c2_determinism.py": render_determinism_pytest(requirements),
        "test_m9_c3_type_contract.py": render_type_contract_pytest(requirements),
        "test_m9_c4_garbage_resilience.py": render_garbage_resilience_pytest(requirements),
    }
    meta_tests = (
        {"test_m9_c1_metamorphic.py": render_metamorphic_pytest_suite(all_relations)}
        if all_relations
        else {}
    )
    return OracleFreeSuite(
        relations=all_relations,
        dynamic_invariants=dyn_invariants,
        metamorphic_tests=meta_tests,
        garbage_case_count=GARBAGE_CASE_COUNT,
    )


def extract_oracle_free_summary(
    report: VerifierBusReport,
    *,
    relation_count: int,
    garbage_case_count: int = GARBAGE_CASE_COUNT,
) -> dict[str, dict[str, Any]]:
    """Extract per-block `I17` oracle-free pass/fail telemetry from a `VerifierBusReport`."""
    t0_passed = report.tiers["T0"].passed if "T0" in report.tiers else False
    t1_ev = report.tiers.get("T1")
    t2_ev = report.tiers.get("T2")

    dyn_check = None
    api_ok = True
    if t1_ev is not None:
        for c in t1_ev.checks:
            if c.check == "dynamic_invariants":
                dyn_check = c
            elif c.check == "api_contract":
                api_ok = c.passed

    dyn_out = str(dyn_check.details.get("output", "")) if dyn_check is not None else ""
    dyn_all_ok = bool(t0_passed and dyn_check is not None and dyn_check.passed)

    if dyn_all_ok:
        c2_ok = True
        c3_ok = api_ok
        c4_ok = True
    elif not t0_passed or dyn_check is None:
        c2_ok = False
        c3_ok = False
        c4_ok = False
    else:
        c2_ok = "test_m9_c2_determinism" not in dyn_out
        c3_ok = api_ok and ("test_m9_c3_type_contract" not in dyn_out)
        c4_ok = "test_m9_c4_garbage_resilience" not in dyn_out
        if c2_ok and c3_ok and c4_ok:
            # Unattributed collection/runtime failure inside dynamic_invariants
            c2_ok = c3_ok = c4_ok = False

    meta_ok = bool(t0_passed and (t2_ev.passed if t2_ev is not None else (relation_count == 0)))
    return {
        "metamorphic": {
            "passed": meta_ok,
            "relation_count": relation_count,
            "status": "geçti" if meta_ok else "kaldı",
        },
        "determinism": {
            "passed": c2_ok,
            "status": "geçti" if c2_ok else "kaldı",
        },
        "type_contract": {
            "passed": c3_ok,
            "status": "geçti" if c3_ok else "kaldı",
        },
        "garbage_resilience": {
            "passed": c4_ok,
            "case_count": garbage_case_count,
            "status": "geçti" if c4_ok else "kaldı",
        },
    }
