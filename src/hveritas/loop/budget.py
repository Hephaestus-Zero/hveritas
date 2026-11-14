"""Budget accounting tracker enforcing wall-time, token, and USD ceilings (§8)."""

from __future__ import annotations

import time

from hveritas.ledger.models import CostRecord
from hveritas.loop.models import BudgetLimits, BudgetUsage


class BudgetExceededError(RuntimeError):
    """Raised when wall-clock time, token count, or USD spend exceeds `BudgetLimits`."""

    def __init__(self, reason: str, usage: BudgetUsage, limits: BudgetLimits) -> None:
        super().__init__(reason)
        self.reason = reason
        self.usage = usage
        self.limits = limits


class BudgetTracker:
    """Tracks live wall-clock + simulated/explicit token & USD spend across loop iterations."""

    def __init__(self, limits: BudgetLimits) -> None:
        self.limits = limits
        self._t0 = time.monotonic()
        self._extra_wall_s = 0.0
        self._tokens = 0
        self._usd = 0.0

    def record_cost(self, cost: CostRecord) -> None:
        self._tokens += cost.input_tokens + cost.output_tokens
        self._usd += cost.usd
        self._extra_wall_s += cost.wall_ms / 1000.0

    def snapshot(self) -> BudgetUsage:
        live_wall = (time.monotonic() - self._t0) + self._extra_wall_s
        return BudgetUsage(
            wall_seconds=round(live_wall, 4),
            total_tokens=self._tokens,
            total_usd=round(self._usd, 6),
        )

    def check(self) -> None:
        u = self.snapshot()
        if u.wall_seconds > self.limits.max_wall_seconds:
            raise BudgetExceededError(
                f"Wall-time budget exceeded: {u.wall_seconds:.2f}s > {self.limits.max_wall_seconds:.2f}s",
                usage=u,
                limits=self.limits,
            )
        if u.total_tokens > self.limits.max_tokens:
            raise BudgetExceededError(
                f"Token budget exceeded: {u.total_tokens} > {self.limits.max_tokens}",
                usage=u,
                limits=self.limits,
            )
        if u.total_usd > self.limits.max_usd:
            raise BudgetExceededError(
                f"USD budget exceeded: ${u.total_usd:.4f} > ${self.limits.max_usd:.4f}",
                usage=u,
                limits=self.limits,
            )
