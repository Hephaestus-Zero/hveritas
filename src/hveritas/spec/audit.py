"""[2] Spec Audit Gate: No-op baseline == 0, Proxy-vs-HeldOut consistency & reference check, Leakage scan (`M9-E`)."""

from __future__ import annotations

import ast
import os
import re
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hveritas.harness.isolation import SCRATCH_ROOT
from hveritas.harness.network import WorkerNetworkPolicy
from hveritas.harness.noop import NoOpBaselineRunner
from hveritas.harness.oracle_vault import EncryptedOracleVault
from hveritas.ledger.canonical import canonical_json
from hveritas.spec.compiler import HumanClarificationRequiredError
from hveritas.spec.models import CompiledSpec, IOAssertion, RequirementNode
from hveritas.verify.bus import VerifierBus
from hveritas.verify.models import VerificationState

_CONDITIONAL_OR_NONLINEAR_RE = re.compile(
    r"\b(?:if|else|ise|değilse|diğer|aksi|yoksa|other|otherwise|unless|when|"
    r"üzeri|altı|arası|fibonacci|fib|factorial|prime|asal)\b",
    re.IGNORECASE,
)

_SAFE_FORMULA_BUILTINS: frozenset[str] = frozenset(
    {"round", "abs", "min", "max", "int", "float", "len", "sum"}
)


class SpecAuditError(RuntimeError):
    """Raised when a compiled spec fails structural pre-execution audit (leakage, syntax, or empty vault)."""


@dataclass(frozen=True)
class SpecAuditReport:
    noop_score: float
    leakage_clean: bool
    oracle_consistency_clean: bool
    contradictions: list[str] = field(default_factory=list)


def _extract_heldout_assertions_from_ast(code: str) -> list[IOAssertion]:
    """Extract `IOAssertion`s from `assert mod.<fn>(...) == <expected>` using pure AST + `literal_eval`."""
    tree = ast.parse(code)
    extracted: list[IOAssertion] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue
        test = node.test
        if (
            not isinstance(test, ast.Compare)
            or len(test.ops) != 1
            or not isinstance(test.ops[0], ast.Eq)
            or len(test.comparators) != 1
        ):
            continue
        call = test.left
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Attribute)
            or not isinstance(call.func.value, ast.Name)
            or call.func.value.id != "mod"
            or call.keywords
        ):
            continue
        try:
            args_val = [ast.literal_eval(arg) for arg in call.args]
            expected_val = ast.literal_eval(test.comparators[0])
        except (ValueError, SyntaxError):
            continue
        extracted.append(
            IOAssertion(
                function=call.func.attr,
                args=args_val,
                expected=expected_val,
            )
        )
    return extracted


def _is_safe_pure_formula_ast(expr_tree: ast.Expression, allowed_vars: frozenset[str]) -> bool:
    """Verify an AST expression uses ONLY whitelisted argument names, numeric literals, and pure arithmetic."""
    uses_arg = False
    allowed_names = allowed_vars | _SAFE_FORMULA_BUILTINS
    for sub in ast.walk(expr_tree):
        if isinstance(sub, ast.Name):
            if sub.id not in allowed_names:
                return False
            if sub.id in allowed_vars:
                uses_arg = True
        elif isinstance(sub, ast.Call):
            if not isinstance(sub.func, ast.Name) or sub.func.id not in _SAFE_FORMULA_BUILTINS:
                return False
            if sub.keywords:
                return False
        elif not isinstance(
            sub,
            (
                ast.Expression,
                ast.BinOp,
                ast.UnaryOp,
                ast.Constant,
                ast.Load,
                ast.Add,
                ast.Sub,
                ast.Mult,
                ast.Div,
                ast.FloorDiv,
                ast.Mod,
                ast.Pow,
                ast.USub,
                ast.UAdd,
            ),
        ):
            return False
    return uses_arg


def _derive_unconditional_probe_candidates(
    node: RequirementNode,
    heldout_assertions: list[IOAssertion],
) -> list[str]:
    """Synthesize pure reference probe candidates for unconditional single-formula specs when no explicit ref exists."""
    if not node.arg_names or _CONDITIONAL_OR_NONLINEAR_RE.search(node.statement):
        return []

    allowed_vars = frozenset(node.arg_names)
    candidates: list[str] = []
    seen_exprs: set[str] = set()

    # 1. Safe pure formula calls embedded directly in `node.statement` (e.g. `round(amount * 0.05, 2)`)
    for fn_tok in _SAFE_FORMULA_BUILTINS:
        pattern = re.compile(rf"\b{fn_tok}\s*\([^()\n]*\)")
        for m in pattern.finditer(node.statement):
            raw_expr = m.group(0).strip()
            if raw_expr in seen_exprs:
                continue
            try:
                parsed = ast.parse(raw_expr, mode="eval")
            except SyntaxError:
                continue
            if _is_safe_pure_formula_ast(parsed, allowed_vars):
                seen_exprs.add(raw_expr)
                sig = ", ".join(node.arg_names)
                candidates.append(f"def {node.function_name}({sig}):\n    return {raw_expr}\n")

    # 2. Single-argument conflicting constant proportionality (`proxy: y = k1*x` vs `heldout: y = k2*x`)
    proxy_assertions = node.proxy_oracle.assertions
    if len(node.arg_names) == 1 and len(proxy_assertions) >= 2 and len(heldout_assertions) >= 2:
        p_ratios: list[float] = []
        h_ratios: list[float] = []
        numeric_ok = True
        for a in proxy_assertions:
            if (
                len(a.args) != 1
                or isinstance(a.args[0], bool)
                or isinstance(a.expected, bool)
                or not isinstance(a.args[0], (int, float))
                or not isinstance(a.expected, (int, float))
                or float(a.args[0]) == 0.0
            ):
                numeric_ok = False
                break
            p_ratios.append(float(a.expected) / float(a.args[0]))

        if numeric_ok:
            for a in heldout_assertions:
                if (
                    len(a.args) != 1
                    or isinstance(a.args[0], bool)
                    or isinstance(a.expected, bool)
                    or not isinstance(a.args[0], (int, float))
                    or not isinstance(a.expected, (int, float))
                    or float(a.args[0]) == 0.0
                ):
                    numeric_ok = False
                    break
                h_ratios.append(float(a.expected) / float(a.args[0]))

        if numeric_ok and p_ratios and h_ratios:
            kp = p_ratios[0]
            kh = h_ratios[0]
            if (
                all(abs(r - kp) < 1e-9 for r in p_ratios)
                and all(abs(r - kh) < 1e-9 for r in h_ratios)
                and abs(kp - kh) > 1e-6
            ):
                arg0 = node.arg_names[0]
                expr = f"round({arg0} * {kp!r}, 6)"
                if expr not in seen_exprs:
                    candidates.append(f"def {node.function_name}({arg0}):\n    return {expr}\n")

    return candidates


class SpecAuditGate:
    """Audits a CompiledSpec + starter workspace BEFORE any worker agent is allowed to execute."""

    def __init__(
        self,
        verifier_bus: VerifierBus,
        oracle_vault: EncryptedOracleVault,
        noop_runner: NoOpBaselineRunner | None = None,
    ) -> None:
        self.bus = verifier_bus
        self.vault = oracle_vault
        self.noop = noop_runner or NoOpBaselineRunner(epsilon=1e-6)

    def _evaluate_reference_in_container(
        self,
        *,
        node: RequirementNode,
        reference_source: str,
    ) -> tuple[bool, bool, float, float]:
        """Stage `reference_source` in ephemeral scratch and evaluate T0 (proxy) + T3 (held-out) in container."""
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        probe_root = SCRATCH_ROOT / f"hv_audit_ref_{os.getpid()}_{secrets.token_hex(8)}"
        probe_ws = probe_root / "ws"
        probe_ws.mkdir(parents=True, mode=0o755)
        try:
            target = (probe_ws / node.target_file).resolve()
            if probe_ws not in target.parents and target != probe_ws:
                raise SpecAuditError(f"Invalid target_file path in spec node {node.id!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(reference_source, encoding="utf-8")

            proxy_suite = {
                f"test_proxy_{node.id}.py": (node.proxy_oracle.custom_pytest_code or ""),
            }
            rep = self.bus.evaluate(
                VerificationState(
                    workspace_path=str(probe_ws),
                    proxy_tests=proxy_suite,
                    t0_config={"compile": True},
                    t1_config={"security_scan": True},
                    heldout_oracle_id=node.heldout_oracle_id,
                ),
                include_t3=True,
            )
            t0_ok = rep.tiers["T0"].passed
            t3_ok = rep.tiers["T3"].passed if "T3" in rep.tiers else False
            return t0_ok, t3_ok, rep.score_proxy, (rep.score_heldout or 0.0)
        finally:
            shutil.rmtree(probe_root, ignore_errors=True)

    def audit(
        self,
        spec: CompiledSpec,
        initial_workspace: Path,
        network_policy: WorkerNetworkPolicy | None = None,
        reference_implementations: dict[str, str] | None = None,
    ) -> SpecAuditReport:
        ws = initial_workspace.resolve()
        ref_map = reference_implementations or {}

        # 1. Leakage scan: ensure no held-out oracle IDs or held-out test sources exist in workspace
        heldout_markers: set[str] = set()
        decrypted_by_node: dict[str, dict[str, str]] = {}
        for node in spec.nodes:
            if not node.heldout_oracle_id:
                continue
            heldout_markers.add(node.heldout_oracle_id)
            decrypted = self.vault.decrypt_oracle_suite(node.heldout_oracle_id)
            decrypted_by_node[node.id] = decrypted
            for fname, code in decrypted.items():
                heldout_markers.add(fname)
                for line in code.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("assert mod."):
                        heldout_markers.add(stripped)

        for p in ws.rglob("*"):
            if not p.is_file() or ".git" in p.parts:
                continue
            if any(m in p.name for m in heldout_markers):
                raise SpecAuditError(f"Leakage detected in filename: {p.name}")
            content = p.read_text(encoding="utf-8", errors="ignore")
            for marker in heldout_markers:
                if len(marker) >= 12 and marker in content:
                    raise SpecAuditError(
                        f"I4 LEAKAGE DETECTED: Held-out marker {marker!r} found inside {p.name}"
                    )

        if network_policy is not None:
            overlap = network_policy.allowed_hosts & network_policy.oracle_hosts
            if overlap:
                raise SpecAuditError(
                    f"Network leakage risk: oracle host(s) {sorted(overlap)} listed in allowed_hosts"
                )

        # 2. Proxy vs Held-Out real consistency check (`M9-E`)
        contradictions: list[str] = []
        for node in spec.nodes:
            if not node.heldout_oracle_id:
                continue
            decrypted = decrypted_by_node.get(node.id, {})
            if not decrypted:
                raise SpecAuditError(f"Empty held-out suite for {node.id}")

            heldout_assertions: list[IOAssertion] = []
            for fname, code in sorted(decrypted.items()):
                try:
                    ast.parse(code, filename=fname)
                except SyntaxError as exc:
                    raise SpecAuditError(
                        f"Invalid Python syntax in held-out suite {fname} for {node.id}: {exc}"
                    ) from exc
                heldout_assertions.extend(_extract_heldout_assertions_from_ast(code))

            # 2a. Exact `(function, args)` input collision check between proxy and decrypted held-out
            seen_inputs: dict[str, Any] = {}
            for p_item in node.proxy_oracle.assertions:
                key = f"{p_item.function}:{canonical_json(p_item.args)}"
                if key in seen_inputs and seen_inputs[key] != p_item.expected:
                    contradictions.append(
                        f"[{node.id}] Proxy içi çelişkili beklenen çıktı ({key}): "
                        f"{seen_inputs[key]!r} vs {p_item.expected!r}"
                    )
                seen_inputs[key] = p_item.expected

            for h_item in heldout_assertions:
                key = f"{h_item.function}:{canonical_json(h_item.args)}"
                if key in seen_inputs and seen_inputs[key] != h_item.expected:
                    contradictions.append(
                        f"[{node.id}] Proxy ve held-out aynı girdi ({key}) için çelişiyor: "
                        f"proxy={seen_inputs[key]!r} vs heldout={h_item.expected!r}"
                    )
                seen_inputs[key] = h_item.expected

            # 2b. Mutual satisfiability check via isolated container (oracle reference or unambiguous spec formula)
            explicit_ref = ref_map.get(node.id) or ref_map.get(node.target_file)
            if explicit_ref is not None:
                t0_ok, t3_ok, s_proxy, s_ho = self._evaluate_reference_in_container(
                    node=node,
                    reference_source=explicit_ref,
                )
                if not t3_ok:
                    contradictions.append(
                        f"[{node.id}] Oracle referans implementasyonu kendi held-out assertion'larını "
                        f"sağlamıyor (heldout_score={s_ho})."
                    )
                elif not t0_ok:
                    contradictions.append(
                        f"[{node.id}] Oracle referans implementasyonu held-out setini sağladı "
                        f"(heldout_score={s_ho}) fakat proxy assertion'larıyla çelişti (proxy_score={s_proxy})."
                    )
            elif not contradictions:
                for probe_code in _derive_unconditional_probe_candidates(node, heldout_assertions):
                    t0_ok, t3_ok, s_proxy, s_ho = self._evaluate_reference_in_container(
                        node=node,
                        reference_source=probe_code,
                    )
                    if t0_ok and not t3_ok:
                        contradictions.append(
                            f"[{node.id}] Görünür spec/proxy kuralı (proxy_score={s_proxy}) ile "
                            f"held-out oracle (heldout_score={s_ho}) birbiriyle çelişiyor."
                        )
                        break

        if contradictions:
            questions = [f"Proxy/Held-out çelişkisini giderin: {c}" for c in contradictions]
            raise HumanClarificationRequiredError(
                "Proxy ve held-out kabul kriterleri birbiriyle çelişiyor — "
                "hile alarmı yerine insan netleştirmesi isteniyor.",
                questions=questions,
                contradictions=contradictions,
            )

        # 3. No-op baseline gate (I5): initial workspace MUST score 0 on proxy checks
        proxy_tests = {
            f"test_proxy_{node.id}.py": (node.proxy_oracle.custom_pytest_code or "")
            for node in spec.nodes
        }

        def _state_builder(path: Path) -> VerificationState:
            return VerificationState(
                workspace_path=str(path),
                proxy_tests=proxy_tests,
                t0_config={"compile": True},
                t1_config={"security_scan": True},
            )

        noop_res = self.noop.verify_baseline(ws, _state_builder, self.bus.evaluate)
        return SpecAuditReport(
            noop_score=noop_res.score,
            leakage_clean=True,
            oracle_consistency_clean=True,
            contradictions=[],
        )
