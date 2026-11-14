"""Workspace environment snapshot manager using Btrfs subvolume snapshots or reflink clones."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from hveritas.effects.fs import FilesystemProbe


@dataclass(frozen=True)
class SnapshotHandle:
    snapshot_id: str
    backend: str  # "btrfs_subvolume" | "reflink_tree"
    snapshot_path: str
    tree_hash: str


def detect_fs_type(path: Path) -> str:
    """Detect underlying Linux filesystem type (`btrfs`, `tmpfs`, `ext4`, etc.)."""
    probe_dir = path if path.exists() else path.parent
    res = subprocess.run(
        ["stat", "-f", "-c", "%T", str(probe_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    return res.stdout.strip().lower() if res.returncode == 0 else "unknown"


class SnapshotManager:
    """Manages O(1) Btrfs subvolume snapshots (with reflink fallback on tmpfs)."""

    def __init__(self, snapshots_root: Path, prefer_btrfs: bool = True) -> None:
        self.snapshots_root = snapshots_root.resolve()
        self.snapshots_root.mkdir(parents=True, exist_ok=True)
        self._fs_probe = FilesystemProbe()
        fs_type = detect_fs_type(self.snapshots_root)
        self.use_btrfs = bool(prefer_btrfs and fs_type == "btrfs" and shutil.which("btrfs"))
        self._handles: dict[str, SnapshotHandle] = {}
        self._created_btrfs_paths: list[Path] = []

    @property
    def backend_name(self) -> str:
        return "btrfs_subvolume" if self.use_btrfs else "reflink_tree"

    def init_workspace(self, workspace_path: Path) -> Path:
        """Create a fresh workspace directory (or Btrfs subvolume when Btrfs backend is active)."""
        ws = workspace_path.resolve()
        if ws.exists():
            self._destroy_path(ws)
        ws.parent.mkdir(parents=True, exist_ok=True)
        if self.use_btrfs and detect_fs_type(ws.parent) == "btrfs":
            subprocess.run(
                ["btrfs", "subvolume", "create", str(ws)],
                check=True,
                capture_output=True,
                text=True,
            )
            self._created_btrfs_paths.append(ws)
        else:
            ws.mkdir(parents=True, exist_ok=True)
        return ws

    def create_snapshot(self, workspace_path: Path, snapshot_id: str) -> SnapshotHandle:
        """Capture an immutable snapshot of `workspace_path` and seal its Merkle hash."""
        ws = workspace_path.resolve()
        snap_dest = self.snapshots_root / snapshot_id
        if snap_dest.exists():
            self._destroy_path(snap_dest)

        manifest = self._fs_probe.snapshot_manifest(ws)
        tree_hash = self._fs_probe.compute_tree_hash(manifest)

        if self.use_btrfs and self._is_btrfs_subvolume(ws):
            subprocess.run(
                ["btrfs", "subvolume", "snapshot", "-r", str(ws), str(snap_dest)],
                check=True,
                capture_output=True,
                text=True,
            )
            self._created_btrfs_paths.append(snap_dest)
            backend = "btrfs_subvolume"
        else:
            subprocess.run(
                ["cp", "-a", "--reflink=auto", str(ws), str(snap_dest)],
                check=True,
                capture_output=True,
                text=True,
            )
            backend = "reflink_tree"

        handle = SnapshotHandle(
            snapshot_id=snapshot_id,
            backend=backend,
            snapshot_path=str(snap_dest),
            tree_hash=tree_hash,
        )
        self._handles[snapshot_id] = handle
        return handle

    def restore_snapshot(self, handle: SnapshotHandle, target_workspace: Path) -> Path:
        """Materialize a writable workspace from `handle` and verify Merkle hash integrity."""
        target = target_workspace.resolve()
        if target.exists():
            self._destroy_path(target)
        target.parent.mkdir(parents=True, exist_ok=True)

        snap_src = Path(handle.snapshot_path)
        if (
            handle.backend == "btrfs_subvolume"
            and detect_fs_type(target.parent) == "btrfs"
            and self._is_btrfs_subvolume(snap_src)
        ):
            subprocess.run(
                ["btrfs", "subvolume", "snapshot", str(snap_src), str(target)],
                check=True,
                capture_output=True,
                text=True,
            )
            self._created_btrfs_paths.append(target)
        else:
            subprocess.run(
                ["cp", "-a", "--reflink=auto", str(snap_src), str(target)],
                check=True,
                capture_output=True,
                text=True,
            )

        restored_manifest = self._fs_probe.snapshot_manifest(target)
        restored_hash = self._fs_probe.compute_tree_hash(restored_manifest)
        if restored_hash != handle.tree_hash:
            raise RuntimeError(
                f"Snapshot restore integrity mismatch for {handle.snapshot_id}: "
                f"expected {handle.tree_hash}, got {restored_hash}"
            )
        return target

    def cleanup(self) -> None:
        """Clean up any Btrfs subvolumes/snapshots or directory clones created by this manager."""
        for p in reversed(self._created_btrfs_paths):
            if p.exists():
                self._destroy_path(p)
        self._created_btrfs_paths.clear()
        if self.snapshots_root.exists():
            self._destroy_path(self.snapshots_root)

    def _is_btrfs_subvolume(self, path: Path) -> bool:
        if not path.is_dir():
            return False
        # In Linux fs/btrfs/btrfs_inode.h, every Btrfs subvolume root has st_ino == 256
        return detect_fs_type(path) == "btrfs" and path.stat().st_ino == 256

    def _destroy_path(self, path: Path) -> None:
        if not path.exists():
            return
        if self._is_btrfs_subvolume(path):
            res = subprocess.run(
                ["btrfs", "subvolume", "delete", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                subprocess.run(
                    ["sudo", "-n", "btrfs", "subvolume", "delete", str(path)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            return
        shutil.rmtree(path, ignore_errors=True)
