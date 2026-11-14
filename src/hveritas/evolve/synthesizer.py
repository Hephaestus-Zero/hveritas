"""Verifier Evolution Engine: synthesizes T1 invariants, T2 metamorphic relations, and regression tests from escaped bugs (Invariant I9)."""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hveritas.evolve.models import EscapedBugReport, SynthesizedEvolutionBundle
from hveritas.evolve.mutation_gate import MutmutMutationGate
from hveritas.harness.isolation import DEFAULT_VERIFIER_DIR
from hveritas.verify.metamorphic import MetamorphicRelation, render_metamorphic_pytest_suite

_FORBIDDEN_SYNTH_CALLS = frozenset({"eval", "exec", "compile", "__import__", "open"})


def _assert_safe_generated_python(code: str) -> None:
    """Verify generated pytest code parses cleanly and contains zero dangerous AST calls."""
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _FORBIDDEN_SYNTH_CALLS
        ):
            raise ValueError(f"Forbidden call {node.func.id!r} in synthesized verifier module")


def _expand_boundary_sweep(failing_args: list[Any], extra: list[list[Any]]) -> list[list[Any]]:
    """Deterministically generate boundary neighborhood test vectors around `failing_args`."""
    candidates: list[list[Any]] = [list(failing_args)]
    for idx, val in enumerate(failing_args):
        if isinstance(val, int) and not isinstance(val, bool):
            for delta in (-10, -1, 0, 1, 10):
                mutated = list(failing_args)
                mutated[idx] = val + delta
                if mutated not in candidates:
                    candidates.append(mutated)
        elif isinstance(val, list) and all(
            isinstance(x, int) and not isinstance(x, bool) for x in val
        ):
            rev = list(failing_args)
            rev[idx] = list(reversed(val))
            if rev not in candidates:
                candidates.append(rev)
    for item in extra:
        vec = list(item)
        if vec not in candidates:
            candidates.append(vec)
    return candidates


class VerifierEvolver:
    """Synthesizes and persists external verifier checks from escaped faults, guarded by `MutmutMutationGate`."""

    def __init__(
        self,
        *,
        evolved_store_dir: Path | None = None,
        mutation_gate: MutmutMutationGate | None = None,
        agent_repo_root: Path | None = None,
    ) -> None:
        default_dir = DEFAULT_VERIFIER_DIR / "evolved_invariants"
        self.evolved_store_dir = (evolved_store_dir or default_dir).resolve()
        if agent_repo_root is not None:
            repo_res = agent_repo_root.resolve()
            if self.evolved_store_dir == repo_res or repo_res in self.evolved_store_dir.parents:
                raise ValueError(
                    "I1/I6 VIOLATION: Evolved invariants directory must reside OUTSIDE agent repo"
                )
        self.mutation_gate = mutation_gate

    def synthesize_only(self, report: EscapedBugReport) -> SynthesizedEvolutionBundle:
        """Deterministically render T1 dynamic invariant, T2 metamorphic, and regression pytest modules."""
        sweep = _expand_boundary_sweep(report.failing_args, report.sweep_inputs)
        fn = report.function_name
        tfile = report.target_file
        bug = report.bug_id

        # 1. T1 Dynamic Invariant module (checks domain/range invariants across boundary sweep + escaped point)
        inv_lines: list[str] = [
            f'"""Auto-evolved T1 dynamic invariant from escaped bug `{bug}`."""',
            "",
            "from loader import load_workspace_module",
            "",
            "",
            f"def test_evolved_invariant_{bug}():",
            f"    mod = load_workspace_module({tfile!r})",
            f"    fn = getattr(mod, {fn!r})",
        ]
        if report.expected_output is not None:
            inv_lines.append(
                f"    assert fn(*{report.failing_args!r}) == {report.expected_output!r}"
            )
        else:
            inv_lines.append(
                f"    assert fn(*{report.failing_args!r}) != {report.observed_output!r}"
            )

        has_property = any(
            x is not None
            for x in (report.min_bound, report.max_bound, report.bound_arg_index_upper)
        )
        if has_property:
            inv_lines.append(f"    for args in {sweep!r}:")
            inv_lines.append("        res = fn(*args)")
            if report.min_bound is not None:
                inv_lines.append(f"        assert res >= {report.min_bound!r}")
            if report.max_bound is not None:
                inv_lines.append(f"        assert res <= {report.max_bound!r}")
            if report.bound_arg_index_upper is not None:
                idx = report.bound_arg_index_upper
                inv_lines.append(f"        assert res <= args[{idx}]")
        inv_lines.append("")
        t1_source = "\n".join(inv_lines)
        _assert_safe_generated_python(t1_source)

        # 2. T2 Oracle-free Metamorphic Relation module (when metamorphic_kind is applicable)
        t2_filename: str | None = None
        t2_source: str | None = None
        if report.metamorphic_kind is not None:
            rel = MetamorphicRelation(
                relation_id=f"evolved_{bug}",
                kind=report.metamorphic_kind,
                target_file=tfile,
                function_name=fn,
                inverse_function_name=report.inverse_function_name,
                seed_inputs=sweep,
            )
            t2_source = render_metamorphic_pytest_suite([rel])
            _assert_safe_generated_python(t2_source)
            t2_filename = f"test_evolved_meta_{bug}.py"

        # 3. Regression test module locking the exact escaped counterexample
        reg_lines = [
            f'"""Auto-evolved regression test locking escaped bug `{bug}`."""',
            "",
            "from loader import load_workspace_module",
            "",
            "",
            f"def test_evolved_regression_{bug}():",
            f"    mod = load_workspace_module({tfile!r})",
            f"    actual = getattr(mod, {fn!r})(*{report.failing_args!r})",
            f"    assert actual != {report.observed_output!r}",
        ]
        if report.expected_output is not None:
            reg_lines.append(f"    assert actual == {report.expected_output!r}")
        reg_lines.append("")
        reg_source = "\n".join(reg_lines)
        _assert_safe_generated_python(reg_source)

        return SynthesizedEvolutionBundle(
            bug_id=bug,
            namespace=report.namespace,
            t1_invariant_filename=f"test_evolved_inv_{bug}.py",
            t1_invariant_source=t1_source,
            t2_metamorphic_filename=t2_filename,
            t2_metamorphic_source=t2_source,
            regression_filename=f"test_evolved_reg_{bug}.py",
            regression_source=reg_source,
        )

    def evolve_from_escaped_bug(
        self,
        report: EscapedBugReport,
        *,
        reference_sources: dict[str, str] | None = None,
        existing_verifier_tests: dict[str, str] | None = None,
    ) -> SynthesizedEvolutionBundle:
        """Synthesize checks, enforce I9 mutation score non-regression if reference given, and persist externally."""
        bundle = self.synthesize_only(report)
        base_mut: float | None = None
        new_mut: float | None = None

        if reference_sources is not None and existing_verifier_tests is not None:
            gate = self.mutation_gate or MutmutMutationGate()
            before_rep = gate.evaluate(
                reference_sources=reference_sources,
                verifier_tests=existing_verifier_tests,
                baseline_score=gate.baseline_score,
                enforce_non_regression=False,
            )
            base_mut = before_rep.mutation_score

            combined_tests = dict(existing_verifier_tests)
            combined_tests[bundle.t1_invariant_filename] = bundle.t1_invariant_source
            combined_tests[bundle.regression_filename] = bundle.regression_source
            if bundle.t2_metamorphic_filename and bundle.t2_metamorphic_source:
                combined_tests[bundle.t2_metamorphic_filename] = bundle.t2_metamorphic_source

            # Enforces I9: raises MutationScoreRegressionError if new_score < base_mut!
            after_rep = gate.evaluate(
                reference_sources=reference_sources,
                verifier_tests=combined_tests,
                baseline_score=max(gate.baseline_score, base_mut),
                enforce_non_regression=True,
            )
            new_mut = after_rep.mutation_score
            gate.update_baseline(new_mut)

        ns_root = self.evolved_store_dir / report.namespace
        inv_dir = ns_root / "invariants"
        meta_dir = ns_root / "metamorphic"
        reg_dir = ns_root / "regression"
        for d in (ns_root, inv_dir, meta_dir, reg_dir):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o755)

        persisted: list[str] = []

        inv_path = inv_dir / bundle.t1_invariant_filename
        inv_path.write_text(bundle.t1_invariant_source, encoding="utf-8")
        inv_path.chmod(0o644)
        persisted.append(str(inv_path))

        if bundle.t2_metamorphic_filename and bundle.t2_metamorphic_source:
            meta_path = meta_dir / bundle.t2_metamorphic_filename
            meta_path.write_text(bundle.t2_metamorphic_source, encoding="utf-8")
            meta_path.chmod(0o644)
            persisted.append(str(meta_path))

        reg_path = reg_dir / bundle.regression_filename
        reg_path.write_text(bundle.regression_source, encoding="utf-8")
        reg_path.chmod(0o644)
        persisted.append(str(reg_path))

        manifest_path = ns_root / "manifest.json"
        history: list[dict[str, Any]] = []
        if manifest_path.is_file():
            history = list(json.loads(manifest_path.read_text(encoding="utf-8")))
        history.append(
            {
                "bug_id": report.bug_id,
                "description": report.description,
                "target_file": report.target_file,
                "function_name": report.function_name,
                "persisted_files": persisted,
                "baseline_mutation_score": base_mut,
                "evolved_mutation_score": new_mut,
                "timestamp_iso": datetime.now(UTC).isoformat(),
            }
        )
        manifest_path.write_text(json.dumps(history, indent=2, sort_keys=True), encoding="utf-8")
        manifest_path.chmod(0o644)

        return SynthesizedEvolutionBundle(
            bug_id=bundle.bug_id,
            namespace=bundle.namespace,
            t1_invariant_filename=bundle.t1_invariant_filename,
            t1_invariant_source=bundle.t1_invariant_source,
            t2_metamorphic_filename=bundle.t2_metamorphic_filename,
            t2_metamorphic_source=bundle.t2_metamorphic_source,
            regression_filename=bundle.regression_filename,
            regression_source=bundle.regression_source,
            persisted_files=persisted,
            baseline_mutation_score=base_mut,
            evolved_mutation_score=new_mut,
        )
