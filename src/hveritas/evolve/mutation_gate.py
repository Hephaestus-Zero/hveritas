"""Invariant I9 Mutation Score Gate powered by real `mutmut` 3.x execution."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

from hveritas.evolve.models import MutationScoreReport
from hveritas.harness.isolation import SCRATCH_ROOT

# Exact exit-code semantics from `mutmut.stats.status_by_exit_code` (mutmut 3.8.x)
_KILLED_EXIT_CODES = frozenset({1, 3, 37})
_SURVIVED_EXIT_CODES = frozenset({0})
_TIMEOUT_EXIT_CODES = frozenset({-24, 24, 36, 152, 255})
_NO_TESTS_EXIT_CODES = frozenset({5, 33})
_SKIPPED_EXIT_CODES = frozenset({34})

_LOADER_SHIM_SOURCE = '''"""Verifier loader shim for mutmut trampoline compatibility."""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType


def load_workspace_module(rel_path: str) -> ModuleType:
    """Import mutated module by dotted path so mutmut's trampoline intercepts every call."""
    mod_name = ".".join(Path(rel_path).with_suffix("").parts)
    return importlib.import_module(mod_name)
'''


class MutationScoreRegressionError(RuntimeError):
    """Raised when a candidate verifier suite change lowers the `mutmut` mutation score (I9)."""

    def __init__(self, current_score: float, baseline_score: float, survived: list[str]) -> None:
        self.current_score = current_score
        self.baseline_score = baseline_score
        self.survived = list(survived)
        super().__init__(
            f"I9 VIOLATION: Verifier mutation score dropped from {baseline_score:.4f} "
            f"to {current_score:.4f} (surviving mutants: {survived[:10]})"
        )


class MutmutMutationGate:
    """Measures verifier suite quality with `mutmut` and blocks any mutation score regression."""

    def __init__(
        self,
        *,
        baseline_score: float = 0.0,
        scratch_root: Path = SCRATCH_ROOT,
        timeout_s: float = 90.0,
    ) -> None:
        self.baseline_score = baseline_score
        self.scratch_root = scratch_root
        self.timeout_s = timeout_s

    def evaluate(
        self,
        *,
        reference_sources: dict[str, str],
        verifier_tests: dict[str, str],
        baseline_score: float | None = None,
        enforce_non_regression: bool = True,
    ) -> MutationScoreReport:
        """Run `python -m mutmut run` in an isolated staging tree and parse `.meta` mutant outcomes."""
        if not reference_sources:
            raise ValueError("reference_sources cannot be empty for mutation evaluation")
        if not verifier_tests:
            raise ValueError("verifier_tests cannot be empty for mutation evaluation")

        effective_baseline = self.baseline_score if baseline_score is None else baseline_score
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        stage_dir = self.scratch_root / f"hv_mutmut_{os.getpid()}_{secrets.token_hex(8)}"
        src_dir = stage_dir / "src"
        tests_dir = stage_dir / "tests"
        src_dir.mkdir(parents=True, mode=0o755)
        tests_dir.mkdir(parents=True, mode=0o755)

        t0 = time.perf_counter()
        try:
            for rel_name, code in sorted(reference_sources.items()):
                dest = (src_dir / rel_name).resolve()
                if src_dir.resolve() not in dest.parents:
                    raise ValueError(f"Unsafe source path {rel_name!r}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                cur_pkg = dest.parent
                while cur_pkg != src_dir and src_dir in cur_pkg.parents:
                    init_py = cur_pkg / "__init__.py"
                    if not init_py.exists():
                        init_py.write_text("", encoding="utf-8")
                    cur_pkg = cur_pkg.parent
                dest.write_text(code, encoding="utf-8")

            (tests_dir / "loader.py").write_text(_LOADER_SHIM_SOURCE, encoding="utf-8")
            for idx, (fname, test_code) in enumerate(sorted(verifier_tests.items())):
                safe_name = Path(fname).name
                if not safe_name.startswith("test_"):
                    safe_name = f"test_{idx:03d}_{safe_name}"
                if not safe_name.endswith(".py"):
                    safe_name = f"{safe_name}.py"
                (tests_dir / safe_name).write_text(test_code, encoding="utf-8")

            pyproject_txt = (
                '[project]\nname = "hv-mutmut-stage"\nversion = "0.1.0"\n\n'
                '[tool.pytest.ini_options]\npythonpath = ["src", "tests"]\n'
                'addopts = "-q --noconftest -p no:cacheprovider"\n\n'
                '[tool.mutmut]\nsource_paths = ["src"]\n'
                'pytest_add_cli_args_test_selection = ["tests"]\n'
            )
            (stage_dir / "pyproject.toml").write_text(pyproject_txt, encoding="utf-8")

            env = {
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "HOME": str(stage_dir),
                "TMPDIR": str(stage_dir),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
            }
            proc = subprocess.run(
                [sys.executable, "-m", "mutmut", "run"],
                cwd=stage_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                check=False,
            )
            mutants_root = stage_dir / "mutants"
            meta_files = sorted(mutants_root.rglob("*.meta")) if mutants_root.is_dir() else []
            if proc.returncode != 0 and not meta_files:
                raise RuntimeError(
                    f"mutmut execution failed (rc={proc.returncode}): "
                    f"stdout={proc.stdout[-800:]!r} stderr={proc.stderr[-800:]!r}"
                )

            killed = 0
            survived = 0
            timeout = 0
            suspicious = 0
            no_tests = 0
            skipped = 0
            surviving_keys: list[str] = []

            for mf in meta_files:
                meta = json.loads(mf.read_text(encoding="utf-8"))
                exit_map: dict[str, int | None] = meta.get("exit_code_by_key", {})
                for key, code_val in sorted(exit_map.items()):
                    if code_val in _KILLED_EXIT_CODES:
                        killed += 1
                    elif code_val in _SURVIVED_EXIT_CODES:
                        survived += 1
                        surviving_keys.append(key)
                    elif code_val in _TIMEOUT_EXIT_CODES:
                        timeout += 1
                    elif code_val in _NO_TESTS_EXIT_CODES:
                        no_tests += 1
                        surviving_keys.append(key)
                    elif code_val in _SKIPPED_EXIT_CODES:
                        skipped += 1
                    else:
                        suspicious += 1

            total_checkable = killed + survived + timeout + suspicious + no_tests
            total = total_checkable + skipped
            score = round((killed + timeout) / total_checkable, 6) if total_checkable > 0 else 0.0
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            passed = score + 1e-9 >= effective_baseline

            report = MutationScoreReport(
                passed=passed,
                mutation_score=score,
                baseline_score=round(effective_baseline, 6),
                total_mutants=total,
                killed_mutants=killed,
                survived_mutants=survived,
                timeout_mutants=timeout,
                suspicious_mutants=suspicious,
                no_tests_mutants=no_tests,
                surviving_keys=surviving_keys,
                elapsed_ms=elapsed_ms,
            )
            if enforce_non_regression and not passed:
                raise MutationScoreRegressionError(score, effective_baseline, surviving_keys)
            return report
        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)

    def update_baseline(self, new_score: float) -> None:
        """Ratchet baseline upward — Invariant I9 forbids lowering the mutation baseline."""
        if new_score + 1e-9 < self.baseline_score:
            raise MutationScoreRegressionError(new_score, self.baseline_score, [])
        self.baseline_score = round(new_score, 6)

    def as_orchestrator_hook(
        self,
        *,
        reference_sources: dict[str, str],
        verifier_tests_provider: Callable[[], dict[str, str]],
    ) -> Callable[[], tuple[bool, float, float]]:
        """Bind this gate into `GoalLoopOrchestrator(mutation_gate_hook=...)` (§8 Stop #6)."""

        def _hook() -> tuple[bool, float, float]:
            rep = self.evaluate(
                reference_sources=reference_sources,
                verifier_tests=verifier_tests_provider(),
                enforce_non_regression=False,
            )
            if rep.passed:
                self.update_baseline(rep.mutation_score)
            return rep.passed, rep.mutation_score, rep.baseline_score

        return _hook
