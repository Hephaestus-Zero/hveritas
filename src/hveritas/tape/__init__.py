"""Tool Tape, frozen environments, vcrpy HTTP cassettes, and Btrfs/reflink snapshots."""

from hveritas.tape.env import FrozenEnvSnapshot
from hveritas.tape.http_tape import VcrHttpCassetteManager
from hveritas.tape.session import (
    DeterminismDriftError,
    PlannedAction,
    TapeRunner,
    TapeStepEntry,
    ToolHandler,
    ToolTapeManifest,
    build_builtin_tool_registry,
)
from hveritas.tape.snapshot import SnapshotHandle, SnapshotManager, detect_fs_type

__all__ = [
    "DeterminismDriftError",
    "FrozenEnvSnapshot",
    "PlannedAction",
    "SnapshotHandle",
    "SnapshotManager",
    "TapeRunner",
    "TapeStepEntry",
    "ToolHandler",
    "ToolTapeManifest",
    "VcrHttpCassetteManager",
    "build_builtin_tool_registry",
    "detect_fs_type",
]
