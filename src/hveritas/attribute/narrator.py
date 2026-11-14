"""(d) Type-Locked & Cryptographically Sealed Attribution Narrator (Invariant I2)."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from hveritas.attribute.taxonomy import TrailCategory, TrailGroup, TrailLeaf
from hveritas.ledger.canonical import canonical_json, sha256_hex


class AttributionTamperError(RuntimeError):
    """Raised if any code attempts to forge or mutate a LockedAttribution locus."""


def _compute_locus_seal(
    run_id: str,
    culprit_step_index: int,
    trail_group: TrailGroup,
    trail_category: TrailCategory,
    trail_leaf: TrailLeaf,
    ace: float,
    ci_low: float,
    ci_high: float,
) -> str:
    return sha256_hex(
        canonical_json(
            {
                "run_id": run_id,
                "culprit_step_index": culprit_step_index,
                "trail_group": trail_group.value,
                "trail_category": trail_category.value,
                "trail_leaf": trail_leaf.value,
                "ace": round(ace, 6),
                "ci_low": round(ci_low, 6),
                "ci_high": round(ci_high, 6),
            }
        )
    )


@dataclass(frozen=True, slots=True)
class LockedAttribution:
    """Immutable, cryptographically sealed fault attribution produced BEFORE any LLM runs (I2).

    Neither the type system (`frozen=True, slots=True`) nor runtime checks allow `AttributionNarrator`
    to alter `culprit_step_index` or `trail_leaf`.
    """

    run_id: str
    culprit_step_index: int
    tool_name: str
    trail_group: TrailGroup
    trail_category: TrailCategory
    trail_leaf: TrailLeaf
    replays_used: int
    counterfactual_pass_rate: float
    average_causal_effect: float
    ci_low: float
    ci_high: float
    seal_sha256: str

    @classmethod
    def create_sealed(
        cls,
        *,
        run_id: str,
        culprit_step_index: int,
        tool_name: str,
        trail_group: TrailGroup,
        trail_category: TrailCategory,
        trail_leaf: TrailLeaf,
        replays_used: int,
        counterfactual_pass_rate: float,
        average_causal_effect: float,
        ci_low: float,
        ci_high: float,
    ) -> LockedAttribution:
        seal = _compute_locus_seal(
            run_id=run_id,
            culprit_step_index=culprit_step_index,
            trail_group=trail_group,
            trail_category=trail_category,
            trail_leaf=trail_leaf,
            ace=average_causal_effect,
            ci_low=ci_low,
            ci_high=ci_high,
        )
        return cls(
            run_id=run_id,
            culprit_step_index=culprit_step_index,
            tool_name=tool_name,
            trail_group=trail_group,
            trail_category=trail_category,
            trail_leaf=trail_leaf,
            replays_used=replays_used,
            counterfactual_pass_rate=counterfactual_pass_rate,
            average_causal_effect=average_causal_effect,
            ci_low=ci_low,
            ci_high=ci_high,
            seal_sha256=seal,
        )

    def verify_seal(self) -> bool:
        expected = _compute_locus_seal(
            run_id=self.run_id,
            culprit_step_index=self.culprit_step_index,
            trail_group=self.trail_group,
            trail_category=self.trail_category,
            trail_leaf=self.trail_leaf,
            ace=self.average_causal_effect,
            ci_low=self.ci_low,
            ci_high=self.ci_high,
        )
        return expected == self.seal_sha256


@dataclass(frozen=True, slots=True)
class LocalStepWindow:
    """Bounded local window passed to narrator (NEVER the full trace per §4 TRAIL finding!)."""

    culprit_step_index: int
    tool_name: str
    tool_args_summary: str
    failure_excerpt: str


# NarratorTextFn returns ONLY `str` — type system prevents it from returning a step locus!
NarratorTextFn = Callable[[LockedAttribution, LocalStepWindow], str]

_STEP_CLAIM_RE = re.compile(
    r"\b(?:step|adım)\s*#?(\d+)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class AttributionReport:
    """Final attribution output pairing immutable `LockedAttribution` with human explanation."""

    attribution: LockedAttribution
    explanation: str
    narrator_attempted_override: bool = False


def default_deterministic_narrator(locked: LockedAttribution, window: LocalStepWindow) -> str:
    return (
        f"Replay bisect isolated the root-cause fault to step {locked.culprit_step_index} "
        f"(`{locked.tool_name}`: {window.tool_args_summary}). "
        f"TRAIL classification: {locked.trail_group.value} -> {locked.trail_category.value} -> "
        f"{locked.trail_leaf.value}. Counterfactual intervention achieved "
        f"ACE={locked.average_causal_effect:.2f} (95% CI [{locked.ci_low:.2f}, {locked.ci_high:.2f}])."
    )


class AttributionNarrator:
    """Generates human explanation LAST without any capability to alter `LockedAttribution` (I2)."""

    def __init__(self, text_fn: NarratorTextFn = default_deterministic_narrator) -> None:
        self._text_fn = text_fn

    def narrate(self, locked: LockedAttribution, window: LocalStepWindow) -> AttributionReport:
        if not locked.verify_seal():
            raise AttributionTamperError("LockedAttribution cryptographic seal invalid!")

        raw_narrative = self._text_fn(locked, window)

        # Verify seal STILL intact after external callable ran
        if not locked.verify_seal():
            raise AttributionTamperError("LockedAttribution tampered during narration!")

        # Detect if rogue LLM text tries to blame a different step number
        mentioned_steps = {int(m.group(1)) for m in _STEP_CLAIM_RE.finditer(raw_narrative)}
        wrong_steps = mentioned_steps - {locked.culprit_step_index}
        if wrong_steps:
            safe_narrative = default_deterministic_narrator(locked, window)
            return AttributionReport(
                attribution=locked,
                explanation=safe_narrative,
                narrator_attempted_override=True,
            )

        return AttributionReport(
            attribution=locked,
            explanation=raw_narrative,
            narrator_attempted_override=False,
        )
