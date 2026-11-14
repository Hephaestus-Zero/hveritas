"""No-op baseline control runner enforcing Invariant I5."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from hveritas.verify.models import VerificationState, VerifierBusReport


class NoOpBaselineHarnessError(RuntimeError):
    """Raised when an untouched initial workspace scores above epsilon (broken/trivial harness)."""


@dataclass(frozen=True)
class NoOpBaselineResult:
    score: float
    epsilon: float
    valid_baseline: bool


class NoOpBaselineRunner:
    """Runs Verifier Bus against the untouched initial task state before any worker runs (I5).

    If `score_noop > epsilon`, the run is aborted as a HARNESS ERROR — never reported as agent work.
    """

    def __init__(self, epsilon: float = 1e-6) -> None:
        self.epsilon = epsilon

    def verify_baseline(
        self,
        initial_workspace: Path,
        state_builder: Callable[[Path], VerificationState],
        bus_eval: Callable[[VerificationState], VerifierBusReport],
    ) -> NoOpBaselineResult:
        state = state_builder(initial_workspace)
        report = bus_eval(state)
        # Measure proxy acceptance test score (or overall tier score when no proxy tests exist):
        # Specifically check proxy test score / overall milestone pass so a task that passes
        # without doing any work is immediately caught!
        t0 = report.tiers.get("T0")
        proxy_checks = (
            [c for c in t0.checks if c.check in ("proxy_pytest", "schema")]
            if t0 is not None
            else []
        )
        if proxy_checks:
            noop_score = sum(c.score for c in proxy_checks) / len(proxy_checks)
        else:
            noop_score = 1.0 if report.passed else 0.0

        if noop_score > self.epsilon:
            raise NoOpBaselineHarnessError(
                f"I5 HARNESS ERROR: No-op baseline scored {noop_score:.4f} > epsilon={self.epsilon:.6f}. "
                "Spec or test harness grants credit when the agent does nothing."
            )
        return NoOpBaselineResult(
            score=noop_score,
            epsilon=self.epsilon,
            valid_baseline=True,
        )
