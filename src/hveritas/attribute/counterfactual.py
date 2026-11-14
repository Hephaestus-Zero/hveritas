"""(b) Seeded Counterfactual Replay (`N = 5..10`) and Monte-Carlo Confidence Interval."""

from __future__ import annotations

import math
import random
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from hveritas.attribute.bisect import ContinuationCallable, VerifierCallable
from hveritas.tape.session import PlannedAction, TapeRunner, TapeStepEntry, ToolTapeManifest

# CounterfactualSampler(workspace, step_index, original_entry, rng) -> PlannedAction
CounterfactualSampler = Callable[[Path, int, TapeStepEntry, random.Random], PlannedAction]


@dataclass(frozen=True)
class CounterfactualResult:
    """Monte-Carlo causal effect estimate at suspected step `k*`."""

    step_index: int
    n_samples: int
    pass_count: int
    pass_rate: float
    wilson_ci_low: float
    wilson_ci_high: float
    baseline_score: float
    mean_counterfactual_score: float
    average_causal_effect: float
    ace_bootstrap_ci_low: float
    ace_bootstrap_ci_high: float
    sample_scores: tuple[float, ...]
    confirmed_causal: bool


def wilson_score_interval(successes: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Exact 95% Wilson score interval for binomial proportion `successes / n`."""
    if n <= 0:
        return (0.0, 0.0)
    p_hat = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    half_width = (z / denom) * math.sqrt((p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * n * n)))
    return (round(max(0.0, center - half_width), 6), round(min(1.0, center + half_width), 6))


def bootstrap_mean_ci(
    values: list[float],
    seed: int = 42,
    n_resamples: int = 2000,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Deterministic seeded percentile bootstrap confidence interval for sample mean."""
    if not values:
        return (0.0, 0.0)
    n = len(values)
    rng = random.Random(seed)
    means: list[float] = []
    for _ in range(n_resamples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    lo_idx = max(0, int((alpha / 2.0) * n_resamples))
    hi_idx = min(n_resamples - 1, int((1.0 - alpha / 2.0) * n_resamples))
    return (round(means[lo_idx], 6), round(means[hi_idx], 6))


class CounterfactualVerifier:
    """Intervenes ONLY at `culprit_step_index` with `N=5..10` seeded samples and computes MC CI."""

    def __init__(
        self,
        tape_runner: TapeRunner,
        verifier_fn: VerifierCallable,
        sampler_fn: CounterfactualSampler,
        suffix_continuation_fn: ContinuationCallable,
        scratch_root: Path = Path("/dev/shm/hephaestus-scratch"),
    ) -> None:
        self.tape_runner = tape_runner
        self.verifier_fn = verifier_fn
        self.sampler_fn = sampler_fn
        self.suffix_continuation_fn = suffix_continuation_fn
        self.scratch_root = scratch_root.resolve()
        self.scratch_root.mkdir(parents=True, exist_ok=True)

    def evaluate(
        self,
        *,
        culprit_step_index: int,
        baseline_score: float = 0.0,
        n_samples: int = 5,
        seed: int = 20261104,
        manifest: ToolTapeManifest | None = None,
    ) -> CounterfactualResult:
        if not 5 <= n_samples <= 10:
            raise ValueError(f"Architecture §4 requires N in [5, 10], got {n_samples}")

        mf = manifest or self.tape_runner.load_manifest()
        original_entry = mf.steps[culprit_step_index]

        scores: list[float] = []
        passes = 0

        for i in range(n_samples):
            sample_seed = seed + 10_000 + i
            rng = random.Random(sample_seed)
            ws = self.scratch_root / f"hv_cf_{mf.run_id}_{culprit_step_index}_{i}"
            if ws.exists():
                shutil.rmtree(ws, ignore_errors=True)
            try:
                # 1. Deterministically replay prefix [0 .. culprit_step_index) -> S_{k*}
                self.tape_runner.replay_run(
                    replay_workspace=ws,
                    ledger=None,
                    manifest=mf,
                    up_to_step=culprit_step_index,
                )
                # 2. Sample counterfactual intervention action `a'_{k*, i}` at step `k*`
                alt_action = self.sampler_fn(ws, culprit_step_index, original_entry, rng)
                handler = self.tape_runner.tools[alt_action.tool_name]
                handler(ws, alt_action.tool_args, mf.env, "record")

                # 3. Complete suffix [k* + 1 .. n)
                self.suffix_continuation_fn(
                    ws, culprit_step_index + 1, mf.steps[culprit_step_index + 1 :]
                )

                ok, score, _ = self.verifier_fn(ws)
                if ok:
                    passes += 1
                scores.append(score)
            finally:
                shutil.rmtree(ws, ignore_errors=True)

        pass_rate = round(passes / n_samples, 6)
        w_low, w_high = wilson_score_interval(passes, n_samples)
        mean_cf = sum(scores) / n_samples
        deltas = [s - baseline_score for s in scores]
        ace = round(sum(deltas) / n_samples, 6)
        ace_lo, ace_hi = bootstrap_mean_ci(deltas, seed=seed)

        return CounterfactualResult(
            step_index=culprit_step_index,
            n_samples=n_samples,
            pass_count=passes,
            pass_rate=pass_rate,
            wilson_ci_low=w_low,
            wilson_ci_high=w_high,
            baseline_score=baseline_score,
            mean_counterfactual_score=round(mean_cf, 6),
            average_causal_effect=ace,
            ace_bootstrap_ci_low=ace_lo,
            ace_bootstrap_ci_high=ace_hi,
            sample_scores=tuple(scores),
            confirmed_causal=(passes > 0 and ace_hi > 0.0),
        )
