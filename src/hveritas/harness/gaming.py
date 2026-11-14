"""Dual-Oracle Δ Gaming Alarm (`Δ = score_proxy − score_heldout`) & single-shot T3 budget (§2, I4)."""

from __future__ import annotations

from dataclasses import dataclass


class GamingAlarmError(RuntimeError):
    """Raised when `Δ = score_proxy - score_heldout > threshold` or T0–T2 pass while T3 fails (§2, §8)."""

    def __init__(
        self, score_proxy: float, score_heldout: float, delta: float, threshold: float
    ) -> None:
        super().__init__(
            f"GAMING ALARM: score_proxy={score_proxy:.3f}, score_heldout={score_heldout:.3f}, "
            f"Δ={delta:.3f} > threshold={threshold:.3f} (or held-out rejected). "
            "Hard stop — commit forbidden, escalating to human."
        )
        self.score_proxy = score_proxy
        self.score_heldout = score_heldout
        self.delta = delta
        self.threshold = threshold


class HeldOutReuseViolationError(RuntimeError):
    """Raised if code attempts to evaluate T3 held-out oracle more than once per milestone (§1)."""


@dataclass(frozen=True)
class GamingCheckDecision:
    milestone_id: str
    score_proxy: float
    score_heldout: float
    delta: float
    gaming_detected: bool
    commit_allowed: bool


class GamingAlarmMonitor:
    """Enforces at-most-once held-out evaluation per milestone and `Δ = score_proxy - score_heldout`."""

    def __init__(self, delta_threshold: float = 0.25) -> None:
        self.delta_threshold = delta_threshold
        self._evaluated_milestones: set[tuple[str, str]] = set()

    def claim_milestone_t3_slot(self, run_id: str, milestone_id: str) -> None:
        key = (run_id, milestone_id)
        if key in self._evaluated_milestones:
            raise HeldOutReuseViolationError(
                f"I4 VIOLATION: Held-out T3 oracle already evaluated once for {key}!"
            )
        self._evaluated_milestones.add(key)

    def evaluate_delta(
        self,
        *,
        milestone_id: str,
        t0_t2_passed: bool,
        t3_passed: bool,
        score_proxy: float,
        score_heldout: float,
    ) -> GamingCheckDecision:
        delta = round(score_proxy - score_heldout, 6)
        # Per §1 [6] DECIDE & §2:
        # - Δ > threshold -> building to the test -> GamingAlarmError!
        # - T0-T2 passed AND T3 failed -> GamingAlarmError (hard stop + human)!
        if delta > self.delta_threshold or (t0_t2_passed and not t3_passed):
            raise GamingAlarmError(
                score_proxy=score_proxy,
                score_heldout=score_heldout,
                delta=delta,
                threshold=self.delta_threshold,
            )
        return GamingCheckDecision(
            milestone_id=milestone_id,
            score_proxy=score_proxy,
            score_heldout=score_heldout,
            delta=delta,
            gaming_detected=False,
            commit_allowed=t0_t2_passed and t3_passed,
        )
