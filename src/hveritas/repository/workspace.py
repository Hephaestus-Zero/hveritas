"""Safe immutable source staging, unified path/secret policy, and atomic action application."""

from __future__ import annotations

import codecs
import difflib
import fnmatch
import hashlib
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from hveritas.spec.repository_context import (
    contains_secret_content,
    is_excluded_dir_name,
    is_secret_filename,
)

CONFIG_FILES = frozenset(
    {
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "pytest.ini",
        "tox.ini",
        "noxfile.py",
        ".coveragerc",
        "requirements.txt",
        "Makefile",
        "makefile",
        ".pre-commit-config.yaml",
    }
)
PROTECTED_CONFIG_GLOBS = (
    "*.toml",
    "*.ini",
    "*.cfg",
    "*.yaml",
    "*.yml",
    "requirements*.txt",
    "*.lock",
    "*.lockb",
    "*-lock.json",
    "*.lock.json",
    "lock",
    "Pipfile",
    "Gemfile.lock",
)
ALWAYS_IMMUTABLE_NAMES = frozenset({"conftest.py", "sitecustomize.py", "usercustomize.py"})

MAX_ACTIONS = 20
MAX_FILE_BYTES = 200_000
MAX_TOTAL_BYTES = 600_000
MAX_READ_FILES = 10
MAX_READ_BYTES = 20_000
MAX_CUMULATIVE_READ_BYTES = 200_000
MAX_CUMULATIVE_WRITE_BYTES = 1_200_000
MAX_SNAPSHOT_SOURCE_BYTES = 2_000_000

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_LINE_RANGE_SPEC_RE = re.compile(r"^(.+):(\d+)-(\d+)$")


class WorkspaceError(RuntimeError):
    """Unsafe source/destination layout (overlap, collision, symlink, special file, hardlink)."""


class SchemaViolationError(ValueError):
    """Worker or oracle JSON violated the strict schema or relative-path syntax."""


class ActionError(ValueError):
    """Worker action batch rejected by workspace policy, patch uniqueness, or byte budget."""


@dataclass(frozen=True)
class WorkspacePolicy:
    """Explicit opt-in policy for test/configuration mutability (immutable by default)."""

    allow_test_edits: bool = False
    allow_config_edits: bool = False


DEFAULT_WORKSPACE_POLICY = WorkspacePolicy()


@dataclass(frozen=True)
class ValidatedRunPaths:
    """Preflight-validated paths guaranteed non-overlapping before any filesystem write."""

    run_id: str
    source: Path
    work_root: Path
    run_dir: Path
    report_out: Path


@dataclass(frozen=True)
class Action:
    """Single validated file mutation action (`write_file` or `patch_file`)."""

    kind: str  # "write_file" | "patch_file"
    path: str
    content: str = ""
    old_text: str = ""
    new_text: str = ""


@dataclass(frozen=True)
class AppliedActionReceipt:
    """Audit receipt for one applied action with before/after content SHA-256 digests."""

    tool_name: str
    path: str
    before_sha256: str | None
    after_sha256: str
    bytes_written: int


def is_secret(name: str) -> bool:
    """Return True if filename or directory name matches secret policy."""
    return is_secret_filename(name)


def is_test_path(rel: str) -> bool:
    """Return True if ``rel`` is a test file or under a ``test``/``tests`` directory."""
    p = PurePosixPath(rel)
    return (
        p.name.startswith("test_")
        or p.name == "test.py"
        or p.name.endswith("_test.py")
        or p.name == "conftest.py"
        or any(part in ("tests", "test") for part in p.parts[:-1])
    )


def _is_config_path(rel: str) -> bool:
    p = PurePosixPath(rel)
    name = p.name
    return (
        name in CONFIG_FILES
        or rel.startswith(".github/")
        or any(fnmatch.fnmatch(name, pattern) for pattern in PROTECTED_CONFIG_GLOBS)
    )


def is_protected(
    rel: str,
    original_files: frozenset[str],
    *,
    policy: WorkspacePolicy = DEFAULT_WORKSPACE_POLICY,
) -> bool:
    """Return True if ``rel`` is protected against worker modification under ``policy``."""
    p = PurePosixPath(rel)
    name = p.name
    if name in ALWAYS_IMMUTABLE_NAMES or name.endswith(".pth"):
        return True
    if _is_config_path(rel) and not policy.allow_config_edits:
        return True
    if rel in original_files and is_test_path(rel) and not policy.allow_test_edits:
        return True
    if rel not in original_files and is_test_path(rel) and not policy.allow_test_edits:
        valid_new_test = (
            len(p.parts) >= 2
            and p.parts[0] == "tests"
            and p.name.startswith("test_")
            and p.suffix == ".py"
            and p.name != "__init__.py"
        )
        return not valid_new_test
    return False


def _overlap(a: Path, b: Path) -> bool:
    return a == b or a in b.parents or b in a.parents


def _check_no_symlink_components(path: Path, label: str) -> Path:
    abs_path = Path(os.path.abspath(path))
    cur = Path("/")
    for part in abs_path.parts[1:]:
        if part.startswith("-") and cur == Path("/"):
            raise WorkspaceError(f"option-like root segment in {label}: {path}")
        cur = cur / part
        if cur.is_symlink():
            raise WorkspaceError(f"symlink in {label} path: {cur}")
    return abs_path


def validate_run_id(raw: object) -> str:
    """Validate ``run_id`` before constructing any filesystem path."""
    if not isinstance(raw, str) or not _RUN_ID_RE.fullmatch(raw):
        raise WorkspaceError(
            f"invalid run_id {raw!r}: must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,127}}$"
        )
    if ".." in raw:
        raise WorkspaceError(f"invalid run_id {raw!r}: '..' forbidden")
    return raw


def validate_run_paths(
    *,
    source: object,
    work_root: object,
    run_id: object,
    report_out: object = None,
) -> ValidatedRunPaths:
    """Validate ``run_id``, ``source``, ``work_root``, ``run_dir``, and ``report_out`` preflight.

    Performs zero filesystem writes; raises ``WorkspaceError`` on any unsafe layout.
    """
    clean_run_id = validate_run_id(run_id)
    if source is None or (isinstance(source, str) and not source.strip()):
        raise WorkspaceError("initial-workspace is required in repository mode")
    if work_root is None or (isinstance(work_root, str) and not work_root.strip()):
        raise WorkspaceError("work-root is required in repository mode")

    raw_src_str = str(source)
    raw_wr_str = str(work_root)
    if "\x00" in raw_src_str or "\x00" in raw_wr_str:
        raise WorkspaceError("NUL byte in workspace path")
    if raw_src_str.lstrip().startswith("-") or raw_wr_str.lstrip().startswith("-"):
        raise WorkspaceError("path must not start with '-' (option injection guard)")

    src_abs = _check_no_symlink_components(Path(raw_src_str), "initial_workspace")
    if not src_abs.exists() or not src_abs.is_dir():
        raise WorkspaceError(f"initial-workspace is not an existing directory: {source}")
    src_resolved = src_abs.resolve(strict=True)

    wr_abs = _check_no_symlink_components(Path(raw_wr_str), "work_root")
    if wr_abs.exists() and not wr_abs.is_dir():
        raise WorkspaceError(f"work_root exists and is not a directory: {work_root}")
    run_dir_abs = _check_no_symlink_components(wr_abs / clean_run_id, "run_dir")

    if _overlap(src_resolved, run_dir_abs):
        raise WorkspaceError(
            f"source and run_dir overlap forbidden: source={src_resolved} run_dir={run_dir_abs}"
        )
    if run_dir_abs.exists() or run_dir_abs.is_symlink():
        raise WorkspaceError(f"run directory already exists (refusing overwrite): {run_dir_abs}")

    if report_out is None:
        report_abs = run_dir_abs / "report.json"
    else:
        rep_str = str(report_out)
        if not rep_str.strip() or "\x00" in rep_str or rep_str.lstrip().startswith("-"):
            raise WorkspaceError(f"invalid report_out path: {report_out!r}")
        report_abs = _check_no_symlink_components(Path(rep_str), "report_out")
        if Path(rep_str).name.startswith("-"):
            raise WorkspaceError(f"report_out filename must not start with '-': {report_out!r}")
        if report_abs.exists() and report_abs.is_dir():
            raise WorkspaceError(f"report_out points to an existing directory: {report_abs}")
        if _overlap(src_resolved, report_abs) and (
            report_abs == src_resolved or src_resolved in report_abs.parents
        ):
            raise WorkspaceError(
                f"report_out must not write inside source repository: {report_abs}"
            )

    return ValidatedRunPaths(
        run_id=clean_run_id,
        source=src_resolved,
        work_root=wr_abs,
        run_dir=run_dir_abs,
        report_out=report_abs,
    )


def _is_virtualenv_dir(dir_path: Path) -> bool:
    cfg = dir_path / "pyvenv.cfg"
    try:
        st = os.lstat(cfg)
        return stat.S_ISREG(st.st_mode)
    except OSError:
        return False


def _copy_regular_nofollow(src_file: Path, dst_file: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(src_file, flags)
    with os.fdopen(fd, "rb") as reader:
        st = os.fstat(reader.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise WorkspaceError(f"special file refused during copy: {src_file}")
        if st.st_nlink > 1:
            raise WorkspaceError(f"hardlink refused during copy: {src_file}")
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        with dst_file.open("wb") as writer:
            shutil.copyfileobj(reader, writer)


def safe_copy(source: Path, dest: Path) -> list[str]:
    """Copy ``source`` to fresh ``dest`` without following symlinks or descending into skipped dirs.

    Policy on non-excluded source entries:
    - Symlinks (files or directories): fail closed (``WorkspaceError``).
    - Special files (FIFO, socket, block/char device): fail closed (``WorkspaceError``).
    - Multi-link hardlinks (``st_nlink > 1``): fail closed (``WorkspaceError``).
    - Excluded VCS/virtualenv/cache dirs and secret-named files: omitted before copy.
    """
    src_abs = _check_no_symlink_components(source, "source")
    dst_abs = _check_no_symlink_components(dest, "destination")
    if not src_abs.exists() or not src_abs.is_dir():
        raise WorkspaceError(f"source is not a directory: {source}")
    src = src_abs.resolve(strict=True)
    if _overlap(src, dst_abs):
        raise WorkspaceError(f"source/destination overlap: {src} vs {dst_abs}")
    if dst_abs.exists() or dst_abs.is_symlink():
        raise WorkspaceError(f"destination already exists: {dst_abs}")

    plan: list[str] = []
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        cur_dir = src / rel_dir if rel_dir else src
        with os.scandir(cur_dir) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            st = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                raise WorkspaceError(f"symlink refused: {rel}")
            if stat.S_ISDIR(st.st_mode):
                if is_excluded_dir_name(entry.name) or _is_virtualenv_dir(Path(entry.path)):
                    continue
                stack.append(rel)
            elif stat.S_ISREG(st.st_mode):
                if st.st_nlink > 1:
                    raise WorkspaceError(f"hardlink refused: {rel}")
                if is_secret_filename(entry.name) or entry.name.endswith((".pyc", ".pyo")):
                    continue
                plan.append(rel)
            else:
                raise WorkspaceError(f"special file refused: {rel}")

    dst_abs.mkdir(parents=True, exist_ok=False)
    sorted_plan = sorted(plan)
    for rel in sorted_plan:
        _copy_regular_nofollow(src / rel, dst_abs / rel)
    return sorted_plan


def list_files(root: Path) -> list[str]:
    """Return sorted relative POSIX file paths in ``root``, excluding skipped dirs."""
    out: list[str] = []
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        cur_dir = root / rel_dir if rel_dir else root
        if not cur_dir.is_dir() or cur_dir.is_symlink():
            continue
        with os.scandir(cur_dir) as it:
            for entry in it:
                rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if is_excluded_dir_name(entry.name) or _is_virtualenv_dir(Path(entry.path)):
                        continue
                    stack.append(rel)
                elif entry.is_file(follow_symlinks=False):
                    if entry.name.endswith((".pyc", ".pyo")):
                        continue
                    out.append(rel)
    return sorted(out)


def is_python_repository(root: Path) -> bool:
    """Return True if ``root`` has Python project metadata or Python source/test files."""
    files = list_files(root)
    py_markers = {"pyproject.toml", "setup.py", "setup.cfg", "pytest.ini"}
    return any(PurePosixPath(f).name in py_markers or f.endswith(".py") for f in files)


def discover_test_files(root: Path) -> list[str]:
    """Discover pytest test files deterministically inside ``root`` (excluding ``conftest.py``)."""
    out: list[str] = []
    for rel in list_files(root):
        p = PurePosixPath(rel)
        if p.suffix != ".py" or p.name in {"conftest.py", "__init__.py"}:
            continue
        if p.name.startswith("test_") or p.name.endswith("_test.py") or p.name == "test.py":
            out.append(rel)
    return sorted(out)


def hash_manifest(root: Path) -> dict[str, str]:
    """Return ``{rel_path: sha256_hex}`` for every tracked regular file in ``root``."""
    return {rel: hashlib.sha256((root / rel).read_bytes()).hexdigest() for rel in list_files(root)}


def tree_hash(root: Path) -> str:
    """Compute a canonical tree digest over ``(path, content_sha256)`` pairs."""
    h = hashlib.sha256()
    for rel, digest in sorted(hash_manifest(root).items()):
        h.update(rel.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
    return h.hexdigest()


def changed_files(original: Path, candidate: Path) -> list[str]:
    """Return sorted relative paths whose existence or SHA-256 content differs."""
    orig_m = hash_manifest(original)
    cand_m = hash_manifest(candidate)
    all_paths = sorted(set(orig_m) | set(cand_m))
    return [rel for rel in all_paths if orig_m.get(rel) != cand_m.get(rel)]


def changed_source_files(original: Path, candidate: Path) -> list[str]:
    """Return non-test files whose content SHA-256 differs (meaningful source/code change)."""
    return [rel for rel in changed_files(original, candidate) if not is_test_path(rel)]


def added_test_files(original: Path, candidate: Path) -> list[str]:
    """Return newly added pytest files present in ``candidate`` and absent in ``original``."""
    orig_set = set(list_files(original))
    return [rel for rel in discover_test_files(candidate) if rel not in orig_set]


def render_unified_diff(original: Path, candidate: Path) -> str:
    """Render an inspectable unified diff across all content-changed files."""
    chunks: list[str] = []
    for rel in changed_files(original, candidate):
        a_path = original / rel
        b_path = candidate / rel
        a_lines = (
            a_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            if a_path.is_file()
            else []
        )
        b_lines = (
            b_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            if b_path.is_file()
            else []
        )
        diff = difflib.unified_diff(
            a_lines,
            b_lines,
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
        chunks.append("".join(diff))
    return "".join(chunks)


def validate_rel(rel: object, *, error_cls: type[Exception] = ActionError) -> str:
    """Validate a workspace-relative POSIX path, rejecting traversal, options, secrets, and excluded dirs."""
    if not isinstance(rel, str) or not rel or len(rel) > 300 or "\\" in rel or "\0" in rel:
        raise error_cls(f"invalid path: {rel!r}")
    p = PurePosixPath(rel)
    parts = rel.split("/")
    if (
        p.is_absolute()
        or rel.startswith("-")
        or any(part in ("..", ".", "") or part.startswith("-") for part in parts)
    ):
        raise error_cls(f"path escapes workspace: {rel!r}")
    if any(is_excluded_dir_name(part) for part in p.parts[:-1]) or is_secret_filename(p.name):
        raise error_cls(f"path in excluded/secret area: {rel!r}")
    if is_excluded_dir_name(p.name):
        raise error_cls(f"path in excluded/secret area: {rel!r}")
    return p.as_posix()


def _resolve_inside(root: Path, rel: str) -> Path:
    cur = root
    for part in PurePosixPath(rel).parts:
        cur = cur / part
        if cur.is_symlink():
            raise ActionError(f"symlink in path: {rel}")
    return cur


def read_snapshots(
    root: Path,
    paths: list[object],
    *,
    max_files: int = MAX_READ_FILES,
    max_file_bytes: int = MAX_READ_BYTES,
    remaining_budget_bytes: int = MAX_CUMULATIVE_READ_BYTES,
) -> tuple[dict[str, str], int]:
    """Read bounded UTF-8 file snapshots (or 1-indexed ``path:start-end`` slices) under ``repository_context`` policy."""
    out: dict[str, str] = {}
    used_bytes = 0
    for raw in paths[:max_files]:
        raw_path: object = raw
        start_line: int | None = None
        end_line: int | None = None
        key_suffix = ""
        if isinstance(raw, str):
            m = _LINE_RANGE_SPEC_RE.match(raw)
            if m is not None:
                raw_path = m.group(1)
                start_line = int(m.group(2))
                end_line = int(m.group(3))
                key_suffix = f":{start_line}-{end_line}"
                if start_line < 1 or end_line < start_line:
                    out[raw[:200]] = "<rejected: invalid line range>"
                    continue
        try:
            rel = validate_rel(raw_path, error_cls=ActionError)
            p = _resolve_inside(root, rel)
        except ActionError as exc:
            out[str(raw)[:200]] = f"<rejected: {exc}>"
            continue
        snap_key = f"{rel}{key_suffix}"
        if not p.is_file():
            out[snap_key] = "<missing>"
            continue
        cap = min(max_file_bytes, max(0, remaining_budget_bytes - used_bytes))
        if cap <= 0:
            out[snap_key] = "<rejected: cumulative read byte budget exhausted>"
            continue
        if start_line is None:
            raw_bytes = p.read_bytes()
            prefix = raw_bytes[:cap]
            try:
                text = codecs.getincrementaldecoder("utf-8")().decode(
                    prefix, final=len(prefix) == len(raw_bytes)
                )
            except UnicodeError:
                out[snap_key] = "<rejected: binary or invalid UTF-8 file>"
                continue
            if contains_secret_content(text):
                out[snap_key] = "<rejected: secret content policy>"
                continue
            used_bytes += len(prefix)
            out[snap_key] = text
        else:
            assert end_line is not None
            if p.stat().st_size > MAX_SNAPSHOT_SOURCE_BYTES:
                out[snap_key] = (
                    f"<rejected: file exceeds {MAX_SNAPSHOT_SOURCE_BYTES} bytes for line slicing>"
                )
                continue
            raw_bytes = p.read_bytes()
            try:
                full_text = raw_bytes.decode("utf-8")
            except UnicodeError:
                out[snap_key] = "<rejected: binary or invalid UTF-8 file>"
                continue
            if contains_secret_content(full_text):
                out[snap_key] = "<rejected: secret content policy>"
                continue
            all_lines = full_text.splitlines(keepends=True)
            sliced_raw = "".join(all_lines[start_line - 1 : end_line]).encode("utf-8")
            prefix = sliced_raw[:cap]
            text = codecs.getincrementaldecoder("utf-8")().decode(
                prefix, final=len(prefix) == len(sliced_raw)
            )
            used_bytes += len(prefix)
            out[snap_key] = text
    return out, used_bytes


def parse_actions(
    raw: object,
    *,
    max_actions: int = MAX_ACTIONS,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> list[Action]:
    """Parse and strictly validate action list under the single unified contract:

    - ``write_file(path, content)``
    - ``patch_file(path, old_text, new_text)``
    """
    if not isinstance(raw, list):
        raise SchemaViolationError("actions must be a list")
    if len(raw) > max_actions:
        raise ActionError(f"too many actions ({len(raw)} > {max_actions})")
    total = 0
    out: list[Action] = []
    for item in raw:
        if not isinstance(item, dict):
            raise SchemaViolationError("action must be an object")
        if set(item) != {"tool_name", "tool_args"} or not isinstance(item.get("tool_args"), dict):
            raise SchemaViolationError("action requires exactly tool_name and tool_args")
        kind = item["tool_name"]
        args = item["tool_args"]
        if kind not in {"write_file", "patch_file"}:
            raise SchemaViolationError(f"unsupported action tool_name: {kind!r}")
        path = validate_rel(args.get("path"), error_cls=SchemaViolationError)
        if kind == "write_file":
            if set(args) != {"path", "content"} or not isinstance(args.get("content"), str):
                raise SchemaViolationError("write_file requires exact string fields: path, content")
            content = args["content"]
            size = len(content.encode("utf-8"))
            act = Action("write_file", path=path, content=content)
        else:
            if set(args) != {"path", "old_text", "new_text"}:
                raise SchemaViolationError(
                    "patch_file requires exact string fields: path, old_text, new_text"
                )
            old_text = args.get("old_text")
            new_text = args.get("new_text")
            if not isinstance(old_text, str) or not old_text or not isinstance(new_text, str):
                raise SchemaViolationError(
                    "patch_file requires non-empty string old_text and string new_text"
                )
            size = len(old_text.encode("utf-8")) + len(new_text.encode("utf-8"))
            act = Action("patch_file", path=path, old_text=old_text, new_text=new_text)
        if size > max_file_bytes:
            raise ActionError(
                f"action exceeds per-file byte limit ({size} > {max_file_bytes}): {path}"
            )
        total += size
        out.append(act)
    if total > max_total_bytes:
        raise ActionError(f"actions exceed round byte budget ({total} > {max_total_bytes})")
    return out


def apply_actions(
    root: Path,
    actions: list[Action],
    original_files: frozenset[str],
    *,
    policy: WorkspacePolicy = DEFAULT_WORKSPACE_POLICY,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> list[AppliedActionReceipt]:
    """Validate and apply an entire action batch atomically on a staging copy, then swap in.

    If any action fails validation or application, ``root`` remains completely unchanged.
    """
    if not actions:
        return []

    # Phase 1: pre-validate protected policy for every action before touching disk.
    for act in actions:
        validate_rel(act.path, error_cls=ActionError)
        if is_protected(act.path, original_files, policy=policy):
            raise ActionError(f"protected path (tests/conftest/config immutable): {act.path}")

    staging = root.with_name(root.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(root, staging, symlinks=False)
    receipts: list[AppliedActionReceipt] = []
    try:
        for act in actions:
            target = _resolve_inside(staging, act.path)
            before_sha: str | None = None
            if target.exists():
                if not target.is_file():
                    raise ActionError(f"target exists and is not a regular file: {act.path}")
                before_sha = hashlib.sha256(target.read_bytes()).hexdigest()

            if act.kind == "write_file":
                encoded = act.content.encode("utf-8")
                if len(encoded) > max_file_bytes:
                    raise ActionError(f"resulting file too large: {act.path}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(encoded)
            elif act.kind == "patch_file":
                if not target.is_file():
                    raise ActionError(f"patch target missing: {act.path}")
                try:
                    current = target.read_text(encoding="utf-8")
                except UnicodeDecodeError as exc:
                    raise ActionError(f"patch target is not UTF-8 text: {act.path}") from exc
                matches = current.count(act.old_text)
                if matches != 1:
                    raise ActionError(
                        f"patch 'old_text' must match exactly once in {act.path} (found {matches})"
                    )
                updated = current.replace(act.old_text, act.new_text, 1)
                encoded = updated.encode("utf-8")
                if len(encoded) > max_file_bytes:
                    raise ActionError(f"resulting file too large: {act.path}")
                target.write_bytes(encoded)
            else:
                raise ActionError(f"unsupported action kind: {act.kind!r}")

            after_sha = hashlib.sha256(encoded).hexdigest()
            receipts.append(
                AppliedActionReceipt(
                    tool_name=act.kind,
                    path=act.path,
                    before_sha256=before_sha,
                    after_sha256=after_sha,
                    bytes_written=len(encoded),
                )
            )
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    backup = root.with_name(root.name + ".prev")
    if backup.exists():
        shutil.rmtree(backup)
    root.rename(backup)
    try:
        staging.rename(root)
    except BaseException:
        if not root.exists() and backup.exists():
            backup.rename(root)
        raise
    finally:
        shutil.rmtree(backup, ignore_errors=True)
    return receipts
