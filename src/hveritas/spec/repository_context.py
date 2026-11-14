"""Bounded repository evidence without executing repository code or following links.

Output is JSON; source text is untrusted data, never instructions. Hashes cover
only the raw prefix actually read (``hash_scope`` makes this explicit).
"""

from __future__ import annotations

import codecs
import fnmatch
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

_EXCLUDED = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".cache",
        "node_modules",
        "dist",
        "build",
        ".tox",
        ".nox",
        ".direnv",
        ".hypothesis",
        ".eggs",
        "htmlcov",
        ".idea",
        ".vscode",
        "_hveritas_oracle",
        ".ssh",
        ".aws",
        ".azure",
        ".gnupg",
    }
)
_EXCLUDED_DIR_PREFIXES = (".venv-", ".venv_", "venv-", "venv_", ".tox-", ".nox-")
_SECRET_GLOBS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".netrc",
    ".pypirc",
    ".npmrc",
    "credentials*",
    "*.p12",
    "*.pfx",
    "*.keystore",
    "secrets",
    "secrets.*",
    ".secrets",
)
_SECRET_NAME = re.compile(
    r"(^\.env|credential|secret|password"
    r"|[._-](?:keys?|tokens?)(?:[._-]|$)"
    r"|^(?:keys?|tokens?)(?:[_-]|$|\.(?:json|ya?ml|toml|ini|cfg|conf|txt|csv|env|bak|db|sqlite\d*|dat|bin|der|crt|cer)$)"
    r"|^id_(?:rsa|dsa|ecdsa|ed25519)|\.(?:pem|key|p12|pfx|keystore)$)",
    re.IGNORECASE,
)
_SECRET_CONTENT = re.compile(
    r"-----BEGIN [^\n]*PRIVATE KEY-----|"
    r"(?i:(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)"
    r"\s*[\"\']?\s*[:=]\s*(?:[\"\'][^\"\'\n]+[\"\']|[^\s\"\'\n,;}]+))|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}"
)
_SOURCE = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".go",
        ".rs",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".java",
        ".kt",
        ".rb",
        ".php",
        ".swift",
        ".sh",
        ".sql",
        ".md",
        ".rst",
        ".txt",
        ".toml",
        ".yaml",
        ".yml",
        ".json",
        ".xml",
        ".html",
        ".css",
    }
)
_ENTRY = frozenset(
    {
        "__main__.py",
        "main.py",
        "cli.py",
        "app.py",
        "index.ts",
        "index.js",
        "main.go",
        "main.rs",
        "package.json",
        "pyproject.toml",
        "cargo.toml",
        "go.mod",
        "makefile",
        "readme.md",
    }
)


def is_excluded_dir_name(name: str) -> bool:
    """Return True if directory ``name`` is VCS, virtualenv, cache, or secret metadata."""
    low = name.lower()
    return (
        low in _EXCLUDED
        or low.startswith(_EXCLUDED_DIR_PREFIXES)
        or low.endswith(".egg-info")
        or is_secret_filename(name)
    )


def is_secret_filename(name: str) -> bool:
    """Return True if file/directory ``name`` matches conservative secret filename rules."""
    low = name.lower()
    return bool(_SECRET_NAME.search(name)) or any(
        fnmatch.fnmatch(low, pat) for pat in _SECRET_GLOBS
    )


def contains_secret_content(text: str) -> bool:
    """Return True if ``text`` contains NUL bytes or conservative inline secret markers."""
    return "\x00" in text or bool(_SECRET_CONTENT.search(text))


def _root_fd(workspace: Path) -> int:
    """Open every component without following even an ancestor symlink."""
    path = Path(os.path.abspath(workspace))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _is_virtualenv_dir_fd(dir_fd: int) -> bool:
    """Detect Python virtual environments via ``pyvenv.cfg`` without following symlinks."""
    try:
        st = os.stat("pyvenv.cfg", dir_fd=dir_fd, follow_symlinks=False)
        return stat.S_ISREG(st.st_mode)
    except OSError:
        return False


def build_repository_context(
    workspace: Path,
    goal: str,
    max_bytes: int = 120000,
    *,
    max_files: int = 64,
    max_file_bytes: int = 8192,
    max_entries: int = 10000,
    max_depth: int = 24,
) -> str:
    """Return deterministic, UTF-8-byte-bounded JSON evidence.

    Limits include JSON overhead. Budgets below 256 bytes are rejected. At most
    ``max_files`` files are read, each up to ``max_file_bytes`` bytes. Discovery
    stops at ``max_entries`` entries or ``max_depth`` levels. Missing, unreadable,
    non-directory and symlink workspaces raise ValueError (no fallback to cwd).
    Symlinks, special files, hardlinks, binary/non-UTF-8 and suspicious files are
    omitted. Secret detection is conservative, not a general DLP guarantee.
    """
    limits = (max_bytes, max_files, max_file_bytes, max_entries, max_depth)
    if any(type(n) is not int or n <= 0 for n in limits) or max_bytes < 256:
        raise ValueError("Invalid repository context limits")
    if not isinstance(goal, str):
        raise TypeError("goal must be text")
    try:
        root = _root_fd(workspace)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("Invalid or unsafe workspace") from exc
    candidates: list[str] = []
    visited = 0
    discovery_truncated = False

    def discover(fd: int, prefix: str, depth: int) -> None:
        nonlocal visited, discovery_truncated
        with os.scandir(fd) as entries:
            names = sorted(entry.name for entry in entries)
        for name in names:
            if visited >= max_entries:
                discovery_truncated = True
                break
            visited += 1
            if is_excluded_dir_name(name) or is_secret_filename(name):
                continue
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                relative = prefix + name
                if stat.S_ISDIR(info.st_mode):
                    if depth >= max_depth:
                        discovery_truncated = True
                        continue
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        if _is_virtualenv_dir_fd(child):
                            continue
                        discover(child, relative + "/", depth + 1)
                    finally:
                        os.close(child)
                elif (
                    stat.S_ISREG(info.st_mode)
                    and info.st_nlink == 1
                    and (Path(name).suffix.lower() in _SOURCE or name.lower() in _ENTRY)
                ):
                    candidates.append(relative)
            except OSError:
                discovery_truncated = True

    def read_prefix(relative: str) -> tuple[bytes, int]:
        fd = os.dup(root)
        try:
            parts = relative.split("/")
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(file_fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise OSError("Unsafe file")
                return stream.read(max_file_bytes), info.st_size
        finally:
            os.close(fd)

    # Never echo the goal: it may itself contain credentials or hostile text.
    words = set(re.findall(r"[a-z0-9_./-]+", goal[:16384].lower()))
    tokens = {word for word in words if len(word) > 2}

    def rank(path: str) -> tuple[int, int, str]:
        low = path.lower()
        hint = sum(1 for token in tokens if token in low)
        useful = (
            Path(low).name in _ENTRY
            or "tests/" in low
            or Path(low).name.startswith("test_")
            or ".test." in low
        )
        return (-hint, -int(useful), path)

    records: list[dict[str, Any]] = []
    skipped = 0
    try:
        discover(root, "", 0)
        for relative in sorted(candidates, key=rank)[:max_files]:
            try:
                raw, size = read_prefix(relative)
                # Permit only an incomplete trailing UTF-8 character at a
                # bounded prefix boundary; malformed bytes still fail closed.
                text = codecs.getincrementaldecoder("utf-8")().decode(raw, final=len(raw) == size)
                if contains_secret_content(text):
                    skipped += 1
                    continue
            except (OSError, UnicodeError):
                skipped += 1
                continue
            records.append(
                {
                    "path": relative,
                    "size_bytes": size,
                    "read_bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "hash_scope": "full" if len(raw) == size else "prefix",
                    "truncated": len(raw) < size,
                    "excerpt": text,
                }
            )
    except OSError as exc:
        raise ValueError("Cannot read workspace") from exc
    finally:
        os.close(root)

    omitted_files = max(0, len(candidates) - len(records))
    result: dict[str, Any] = {
        "format": "repository-context-v1",
        "manifest": records,
        "discovery_truncated": discovery_truncated,
        "omitted_files": omitted_files,
        "skipped_files": skipped,
        "output_truncated": False,
    }

    def render() -> str:
        return json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    output = render()
    # Preserve higher-ranked evidence; shrink lower-ranked excerpts first.
    while len(output.encode("utf-8")) > max_bytes and records:
        result["output_truncated"] = True
        last = records[-1]
        excerpt = str(last["excerpt"])
        if excerpt:
            last["excerpt"] = excerpt[: len(excerpt) // 2]
            last["truncated"] = True
        else:
            records.pop()
            omitted_files += 1
            result["omitted_files"] = omitted_files
        output = render()
    return output
