"""Safe module loader for isolated verifier test suites (Invariants I1, I6)."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType


def workspace_root() -> Path:
    return Path(os.environ.get("HVERITAS_WORKSPACE", "/workspace")).resolve()


def load_workspace_module(rel_path: str, module_name: str = "target_mod") -> ModuleType:
    """Load a specific Python file from the read-only `/workspace` mount without polluting `sys.path`."""
    ws = workspace_root()
    target = (ws / rel_path).resolve()
    if target != ws and ws not in target.parents:
        raise ValueError(f"Attempted path escape outside workspace: {rel_path!r}")
    if not target.is_file():
        raise FileNotFoundError(f"Workspace module not found: {rel_path}")
    spec = importlib.util.spec_from_file_location(module_name, str(target))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create module spec for {rel_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
