"""Composite independent post-state measurer (strictly segregated from agent claims per I3)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hveritas.effects.db import SqliteDbProbe, TableSnapshot
from hveritas.effects.fs import FileEntry, FilesystemProbe
from hveritas.effects.http import CapturedHttpExchange, HttpEffectProbe
from hveritas.effects.proc import ProcessProbe, RawProcessOutcome
from hveritas.effects.ui import UiEffectProbe
from hveritas.ledger.models import MeasuredEffects


@dataclass(frozen=True)
class PreActionObservation:
    """Environment state observed directly by probes before an action executes."""

    state_hash: str
    fs_manifest: dict[str, FileEntry]
    db_snapshots: dict[str, dict[str, TableSnapshot]]


class IndependentEffectMeasurer:
    """Orchestrates all independent probes (`fs`, `proc`, `http`, `db`, `ui`).

    Notice (I3): No method in this module accepts, imports, or inspects `AgentClaim`.
    """

    def __init__(self) -> None:
        self.fs_probe = FilesystemProbe()
        self.proc_probe = ProcessProbe()
        self.http_probe = HttpEffectProbe()
        self.db_probe = SqliteDbProbe()
        self.ui_probe = UiEffectProbe()

    def observe_pre(self, workspace: Path) -> PreActionObservation:
        fs_manifest = self.fs_probe.snapshot_manifest(workspace)
        state_hash = self.fs_probe.compute_tree_hash(fs_manifest)
        db_snaps = self.db_probe.snapshot_workspace_dbs(workspace)
        return PreActionObservation(
            state_hash=state_hash,
            fs_manifest=fs_manifest,
            db_snapshots=db_snaps,
        )

    def measure_post(
        self,
        pre: PreActionObservation,
        workspace: Path,
        process_outcome: RawProcessOutcome | None = None,
        http_exchanges: list[CapturedHttpExchange] | None = None,
    ) -> MeasuredEffects:
        post_fs = self.fs_probe.snapshot_manifest(workspace)
        post_hash = self.fs_probe.compute_tree_hash(post_fs)
        fs_diff = self.fs_probe.diff(pre.fs_manifest, post_fs)

        exit_code, proc_metrics = self.proc_probe.measure(process_outcome)
        http_effects = self.http_probe.measure(http_exchanges)

        post_db = self.db_probe.snapshot_workspace_dbs(workspace)
        db_delta = self.db_probe.diff(pre.db_snapshots, post_db)
        ui_metrics = self.ui_probe.measure(workspace)

        return MeasuredEffects(
            post_state_hash=post_hash,
            exit_code=exit_code,
            fs_diff=fs_diff,
            proc_metrics=proc_metrics,
            http_effects=http_effects,
            db_delta=db_delta,
            ui_probe=ui_metrics,
        )
