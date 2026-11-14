"""Repair Escalation Ladder & Consecutive Duplicate Attribution No-Progress Detector (§1 [8], §8)."""

from __future__ import annotations

from hveritas.attribute.narrator import LockedAttribution
from hveritas.loop.models import RepairLadderRung

_LADDER_ORDER: tuple[RepairLadderRung, ...] = (
    RepairLadderRung.SAME_MODEL,
    RepairLadderRung.TIGHTER_CONSTRAINTS,
    RepairLadderRung.DIFFERENT_MODEL_FAMILY,
    RepairLadderRung.HUMAN_ESCALATION,
)


class RepairLadderController:
    """Manages repair escalation and skips rungs when the exact same attribution occurs twice in a row."""

    def __init__(
        self,
        max_attempts: int = 3,
        primary_family: str = "family-alpha",
        alternate_family: str = "family-beta",
    ) -> None:
        self.max_attempts = max_attempts
        self.primary_family = primary_family
        self.alternate_family = alternate_family
        self._attempt = 0
        self._rung_idx = 0
        self._prev_sig: tuple[int, str] | None = None
        self.history: list[RepairLadderRung] = []
        self.skips_triggered = 0

    def next_rung(self, attribution: LockedAttribution) -> tuple[RepairLadderRung, str, bool]:
        """Advance repair state given latest `LockedAttribution`.

        Returns `(rung, model_family, skipped_due_to_duplicate_attribution)`.
        """
        sig = (attribution.culprit_step_index, attribution.trail_leaf.value)
        skipped = False

        if self._attempt >= self.max_attempts:
            rung = RepairLadderRung.HUMAN_ESCALATION
            self.history.append(rung)
            return rung, self.alternate_family, False

        if self._attempt == 0:
            self._rung_idx = 0  # SAME_MODEL on first repair
        elif self._prev_sig is not None and sig == self._prev_sig:
            # §8: "Aynı atıf iki kez üst üste -> onarım merdivenini atla, farklı model ailesine çık"
            skipped = True
            self.skips_triggered += 1
            diff_idx = _LADDER_ORDER.index(RepairLadderRung.DIFFERENT_MODEL_FAMILY)
            if self._rung_idx < diff_idx:
                self._rung_idx = diff_idx
            else:
                self._rung_idx = _LADDER_ORDER.index(RepairLadderRung.HUMAN_ESCALATION)
        else:
            self._rung_idx = min(self._rung_idx + 1, len(_LADDER_ORDER) - 1)

        self._prev_sig = sig
        self._attempt += 1
        rung = _LADDER_ORDER[self._rung_idx]
        self.history.append(rung)

        family = (
            self.alternate_family
            if rung in (RepairLadderRung.DIFFERENT_MODEL_FAMILY, RepairLadderRung.HUMAN_ESCALATION)
            else self.primary_family
        )
        return rung, family, skipped
