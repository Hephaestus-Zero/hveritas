"""Independent filesystem Merkle state and diff probe (Invariant I3)."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hveritas.ledger.canonical import canonical_json, sha256_hex

DEFAULT_IGNORE_NAMES = frozenset(
    {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
)


@dataclass(frozen=True)
class FileEntry:
    rel_path: str
    kind: str  # "file" | "symlink"
    mode: int
    size: int
    content_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "kind": self.kind,
            "mode": self.mode,
            "size": self.size,
            "content_sha256": self.content_sha256,
        }


class FilesystemProbe:
    """Measures workspace filesystem state directly from OS inodes/bytes (zero agent input)."""

    def __init__(self, ignore_names: frozenset[str] = DEFAULT_IGNORE_NAMES) -> None:
        self.ignore_names = ignore_names

    def snapshot_manifest(self, workspace: Path) -> dict[str, FileEntry]:
        root = workspace.resolve()
        manifest: dict[str, FileEntry] = {}
        if not root.exists():
            return manifest

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in self.ignore_names)
            for fname in sorted(filenames):
                if fname in self.ignore_names:
                    continue
                full = Path(dirpath) / fname
                rel = full.relative_to(root).as_posix()
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    target = os.readlink(full)
                    digest = sha256_hex(target)
                    manifest[rel] = FileEntry(
                        rel_path=rel,
                        kind="symlink",
                        mode=0o777,
                        size=len(target.encode("utf-8")),
                        content_sha256=digest,
                    )
                elif stat.S_ISREG(st.st_mode):
                    raw = full.read_bytes()
                    # Normalize permission bit tracking to executable vs standard regular file
                    exec_bit = 0o755 if (st.st_mode & stat.S_IXUSR) else 0o644
                    manifest[rel] = FileEntry(
                        rel_path=rel,
                        kind="file",
                        mode=exec_bit,
                        size=len(raw),
                        content_sha256=sha256_hex(raw),
                    )
        return manifest

    def compute_tree_hash(self, manifest: dict[str, FileEntry]) -> str:
        ordered = [manifest[k].to_dict() for k in sorted(manifest.keys())]
        return sha256_hex(canonical_json(ordered))

    def diff(
        self,
        pre: dict[str, FileEntry],
        post: dict[str, FileEntry],
    ) -> dict[str, Any]:
        pre_keys = set(pre.keys())
        post_keys = set(post.keys())

        added = sorted(post_keys - pre_keys)
        deleted = sorted(pre_keys - post_keys)
        modified = sorted(
            k for k in (pre_keys & post_keys) if pre[k].to_dict() != post[k].to_dict()
        )
        changed_hashes = {k: post[k].content_sha256 for k in sorted(set(added) | set(modified))}
        return {
            "added": added,
            "modified": modified,
            "deleted": deleted,
            "file_hashes": changed_hashes,
        }
