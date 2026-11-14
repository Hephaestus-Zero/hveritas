"""(a) Deterministic O(log n) Binary Search Replay Bisect over ToolTape (ZERO LLM calls, Invariant I2)."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hveritas.tape.session import TapeRunner, TapeStepEntry, ToolTapeManifest

# VerifierCallable(workspace) -> (passed, score, details)
VerifierCallable = Callable[[Path], tuple[bool, float, dict[str, Any]]]

# ContinuationCallable(workspace, start_step_index, remaining_tape_steps) -> None
ContinuationCallable = Callable[[Path, int, list[TapeStepEntry]], None]


@dataclass(frozen=True)
class BisectResult:
    """Exact fault locus isolated purely by deterministic replay binary search."""

    culprit_step_index: int
    total_steps: int
    replays_executed: int
    probe_history: tuple[tuple[int, bool, float], ...]
    final_failure_details: dict[str, Any]


class UnbisectableRunError(RuntimeError):
    """Raised if either P(0) is already False (unviable baseline) or P(n) is True (run passed)."""


class ReplayBisector:
    """Finds the exact step `k*` where `P(k*) == True` and `P(k* + 1) == False` in `O(log n)` replays.

    Notice (I2): Zero LLM calls or heuristics exist in this class.
    """

    def __init__(
        self,
        tape_runner: TapeRunner,
        verifier_fn: VerifierCallable,
        continuation_fn: ContinuationCallable,
        scratch_root: Path = Path("/dev/shm/hephaestus-scratch"),
    ) -> None:
        self.tape_runner = tape_runner
        self.verifier_fn = verifier_fn
        self.continuation_fn = continuation_fn
        self.scratch_root = scratch_root.resolve()
        self.scratch_root.mkdir(parents=True, exist_ok=True)

    def bisect(
        self,
        manifest: ToolTapeManifest | None = None,
        known_final_failure_details: dict[str, Any] | None = None,
    ) -> BisectResult:
        mf = manifest or self.tape_runner.load_manifest()
        n = len(mf.steps)
        if n == 0:
            raise UnbisectableRunError("Cannot bisect an empty 0-step trace")

        replays = 0
        history: list[tuple[int, bool, float]] = []

        # Verify P(n) if caller didn't already supply failure details from the failed run
        if known_final_failure_details is None:
            ok_n, score_n, details_n = self._eval_prefix(mf, n, tag="pn")
            replays += 1
            history.append((n, ok_n, score_n))
            if ok_n:
                raise UnbisectableRunError("Trace passes verification at step n; nothing to bisect")
            final_details = details_n
        else:
            final_details = known_final_failure_details

        # Binary search on [0, n] maintaining invariant: P(lo) == True, P(hi) == False
        # Note: for n == 1, lo=0, hi=1 terminates in 0 bisect probes once P(0) is checked!
        lo = 0
        hi = n

        # Confirm viability at k = 0 only if needed or when n == 1; wait: during binary search,
        # if mid reaches 0 or lo stays 0 at the end, checking P(0) only when `lo == 0` at termination
        # saves 1 full replay whenever `k* > 0`!
        verified_zero = False

        while hi - lo > 1:
            mid = (lo + hi) // 2
            ok_mid, score_mid, _ = self._eval_prefix(mf, mid, tag=f"m{mid}")
            replays += 1
            history.append((mid, ok_mid, score_mid))
            if ok_mid:
                lo = mid
            else:
                hi = mid

        if lo == 0 and not verified_zero:
            ok_0, score_0, _ = self._eval_prefix(mf, 0, tag="p0")
            replays += 1
            history.append((0, ok_0, score_0))
            if not ok_0:
                raise UnbisectableRunError(
                    "P(0) is False: continuation policy cannot solve from clean initial snapshot"
                )

        return BisectResult(
            culprit_step_index=lo,
            total_steps=n,
            replays_executed=replays,
            probe_history=tuple(history),
            final_failure_details=final_details,
        )

    def _eval_prefix(
        self, mf: ToolTapeManifest, k: int, tag: str
    ) -> tuple[bool, float, dict[str, Any]]:
        ws = self.scratch_root / f"hv_bisect_{mf.run_id}_{tag}"
        if ws.exists():
            shutil.rmtree(ws, ignore_errors=True)
        try:
            self.tape_runner.replay_run(
                replay_workspace=ws,
                ledger=None,
                manifest=mf,
                up_to_step=k,
            )
            remaining = mf.steps[k:]
            self.continuation_fn(ws, k, remaining)
            return self.verifier_fn(ws)
        finally:
            shutil.rmtree(ws, ignore_errors=True)
