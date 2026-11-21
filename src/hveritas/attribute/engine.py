"""End-to-end Attribution Pipeline: DARALT (bisect) -> DOĞRULA (CF CI) -> SINIFLA (TRAIL) -> ANLAT."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hveritas.attribute.bisect import (
    BisectResult,
    ContinuationCallable,
    ReplayBisector,
    VerifierCallable,
)
from hveritas.attribute.counterfactual import (
    CounterfactualResult,
    CounterfactualSampler,
    CounterfactualVerifier,
)
from hveritas.attribute.narrator import (
    AttributionNarrator,
    AttributionReport,
    LocalStepWindow,
    LockedAttribution,
)
from hveritas.attribute.taxonomy import classify_trail_fault
from hveritas.harness.isolation import default_scratch_root
from hveritas.ledger.canonical import canonical_json
from hveritas.ledger.store import AppendOnlyLedger
from hveritas.tape.session import TapeRunner, ToolTapeManifest


class AttributionPipeline:
    """Executes [7] ATTRIBUTE strictly in sequence: (a) bisect -> (b) CF -> (c) TRAIL -> (d) narrate."""

    def __init__(
        self,
        *,
        tape_runner: TapeRunner,
        verifier_fn: VerifierCallable,
        continuation_fn: ContinuationCallable,
        counterfactual_sampler: CounterfactualSampler,
        narrator: AttributionNarrator | None = None,
        n_counterfactuals: int = 5,
        scratch_root: Path | None = None,
    ) -> None:
        resolved_scratch = scratch_root or default_scratch_root()
        self.tape_runner = tape_runner
        self.bisector = ReplayBisector(
            tape_runner=tape_runner,
            verifier_fn=verifier_fn,
            continuation_fn=continuation_fn,
            scratch_root=resolved_scratch,
        )
        self.cf_verifier = CounterfactualVerifier(
            tape_runner=tape_runner,
            verifier_fn=verifier_fn,
            sampler_fn=counterfactual_sampler,
            suffix_continuation_fn=continuation_fn,
            scratch_root=resolved_scratch,
        )
        self.narrator = narrator or AttributionNarrator()
        self.n_counterfactuals = n_counterfactuals

    def attribute(
        self,
        *,
        manifest: ToolTapeManifest | None = None,
        ledger: AppendOnlyLedger | None = None,
        baseline_score: float = 0.0,
        known_failure_details: dict[str, Any] | None = None,
    ) -> tuple[AttributionReport, BisectResult, CounterfactualResult]:
        mf = manifest or self.tape_runner.load_manifest()

        # (a) DARALT: O(log n) deterministic replay binary search — ZERO LLM!
        bisect_res = self.bisector.bisect(
            manifest=mf,
            known_final_failure_details=known_failure_details,
        )
        k_star = bisect_res.culprit_step_index
        culprit_entry = mf.steps[k_star]

        # (b) DOĞRULA: N=5..10 seeded counterfactual interventions at k* -> Monte-Carlo CI
        cf_res = self.cf_verifier.evaluate(
            culprit_step_index=k_star,
            baseline_score=baseline_score,
            n_samples=self.n_counterfactuals,
            seed=mf.env.seed,
            manifest=mf,
        )

        # (c) SINIFLA: TRAIL 3 -> 9 -> 20 taxonomy
        step_rec = None
        if ledger is not None:
            steps = ledger.get_steps(mf.run_id)
            if k_star < len(steps):
                step_rec = steps[k_star]

        group, category, leaf = classify_trail_fault(
            culprit_entry=culprit_entry,
            all_entries=mf.steps,
            step_record=step_rec,
            verifier_details=bisect_res.final_failure_details,
        )

        total_replays = bisect_res.replays_executed + cf_res.n_samples
        locked = LockedAttribution.create_sealed(
            run_id=mf.run_id,
            culprit_step_index=k_star,
            tool_name=culprit_entry.tool_name,
            trail_group=group,
            trail_category=category,
            trail_leaf=leaf,
            replays_used=total_replays,
            counterfactual_pass_rate=cf_res.pass_rate,
            average_causal_effect=cf_res.average_causal_effect,
            ci_low=cf_res.ace_bootstrap_ci_low,
            ci_high=cf_res.ace_bootstrap_ci_high,
        )

        # (d) ANLAT: Bounded local step window only (NEVER full trace!) + immutable LockedAttribution
        args_preview = canonical_json(culprit_entry.tool_args)[:160]
        err_preview = str(bisect_res.final_failure_details.get("output", ""))[-300:]
        window = LocalStepWindow(
            culprit_step_index=k_star,
            tool_name=culprit_entry.tool_name,
            tool_args_summary=args_preview,
            failure_excerpt=err_preview,
        )
        report = self.narrator.narrate(locked, window)
        return report, bisect_res, cf_res
