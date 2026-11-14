"""Safety and evidence contracts for repository context collection."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from hveritas.spec.repository_context import build_repository_context


def put(root: Path, name: str, text: str = "def useful():\n    return 42\n") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_actual_source_manifest_hash_and_determinism(tmp_path):
    raw = "def calculate(value):\n    return value * 2\n"
    put(tmp_path, "src/calculate.py", raw)
    put(tmp_path, "tests/test_calculate.py", "assert calculate(3) == 6\n")
    first = build_repository_context(tmp_path, "Fix src/calculate.py")
    assert first == build_repository_context(tmp_path, "Fix src/calculate.py")
    data = json.loads(first)
    record = data["manifest"][0]
    assert record["path"] == "src/calculate.py"
    assert record["excerpt"] == raw
    assert record["sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    assert record["hash_scope"] == "full"
    assert not record["truncated"]
    assert any(r["path"].startswith("tests/") for r in data["manifest"])


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".env.local",
        "credentials.json",
        "private.key",
        "server.pem",
        "id_rsa",
        "api_keys.json",
        "api_keys.py",
        "keys.json",
        "tokens.txt",
        ".git/config",
        ".venv/config.py",
        "__pycache__/cached.py",
        "node_modules/index.js",
        ".aws/config",
    ],
)
def test_secret_and_cache_names_excluded(tmp_path, name):
    put(tmp_path, name, "DO_NOT_DISCLOSE")
    put(tmp_path, "main.py")
    put(tmp_path, "ui/keys.py", "class Key:\n    pass\n")
    output = build_repository_context(tmp_path, name)
    assert "DO_NOT_DISCLOSE" not in output
    assert sorted(r["path"] for r in json.loads(output)["manifest"]) == ["main.py", "ui/keys.py"]


def test_secret_content_binary_and_hardlinks_excluded(tmp_path):
    put(tmp_path, "ordinary.py", 'api_key = "sensitive-literal"\n')
    put(tmp_path, "material.txt", "-----BEGIN RSA PRIVATE KEY-----\nHIDDEN")
    (tmp_path / "binary.py").write_bytes(b"\x00BINARY")
    (tmp_path / "bad.py").write_bytes(b"\xffINVALID")
    original = put(tmp_path, "original.py", "HARDLINK_CONTENT")
    os.link(original, tmp_path / "duplicate.py")
    data = json.loads(build_repository_context(tmp_path, "ordinary"))
    assert data["manifest"] == []
    assert data["skipped_files"] >= 4


def test_symlinks_inside_outside_and_directory_cycles(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = put(tmp_path, "external.py", "OUTSIDE_SECRET")
    source = put(root, "main.py", "SAFE_SOURCE")
    (root / "outside.py").symlink_to(outside)
    (root / "inside.py").symlink_to(source)
    (root / "cycle").symlink_to(root, target_is_directory=True)
    (root / "external").symlink_to(tmp_path, target_is_directory=True)
    (root / "broken.py").symlink_to(root / "missing")
    output = build_repository_context(root, "outside inside")
    assert "OUTSIDE_SECRET" not in output
    assert [r["path"] for r in json.loads(output)["manifest"]] == ["main.py"]


def test_goal_and_entrypoint_test_selection(tmp_path):
    for i in range(12):
        put(tmp_path, f"aaa{i}.py")
    put(tmp_path, "src/widgets/renderer.py", "def render_widget(): pass\n")
    put(tmp_path, "main.py", "def main(): pass\n")
    put(tmp_path, "tests/test_widget.py", "def test_widget(): pass\n")
    data = json.loads(build_repository_context(tmp_path, "src/widgets/renderer.py", max_files=3))
    paths = [r["path"] for r in data["manifest"]]
    assert paths == ["src/widgets/renderer.py", "main.py", "tests/test_widget.py"]
    assert data["omitted_files"] == 12


@pytest.mark.parametrize("budget", [256, 300, 512, 1000, 4000])
def test_byte_bounds_unicode_and_truncation(tmp_path, budget):
    for i in range(5):
        put(tmp_path, f"file{i}.py", "# café λ\n" * 1000)
    output = build_repository_context(tmp_path, "", budget, max_file_bytes=100)
    assert len(output.encode("utf-8")) <= budget
    assert output == build_repository_context(tmp_path, "", budget, max_file_bytes=100)
    data = json.loads(output)
    assert data["output_truncated"] or any(r["truncated"] for r in data["manifest"])
    for record in data["manifest"]:
        assert record["hash_scope"] == "prefix"
        assert record["read_bytes"] <= 100
        assert (
            record["sha256"]
            == hashlib.sha256((tmp_path / record["path"]).read_bytes()[:100]).hexdigest()
        )


def test_discovery_and_depth_limits(tmp_path):
    for i in range(10):
        put(tmp_path, f"f{i}.py")
    put(tmp_path, "deep/deeper/source.py")
    data = json.loads(build_repository_context(tmp_path, "", max_entries=3))
    assert data["discovery_truncated"]
    assert len(data["manifest"]) <= 3
    data = json.loads(build_repository_context(tmp_path, "", max_depth=1))
    assert data["discovery_truncated"]
    assert "deep/deeper/source.py" not in [r["path"] for r in data["manifest"]]


def test_invalid_workspaces_fail_closed(tmp_path):
    file = put(tmp_path, "file.py")
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    for workspace in (tmp_path / "missing", file, link, link / "subdir"):
        with pytest.raises(ValueError, match="workspace"):
            build_repository_context(workspace, "")


@pytest.mark.parametrize(
    "limits",
    [
        {"max_bytes": 0},
        {"max_bytes": 255},
        {"max_bytes": True},
        {"max_files": 0},
        {"max_file_bytes": -1},
        {"max_entries": 0},
        {"max_depth": 0},
    ],
)
def test_invalid_limits(tmp_path, limits):
    with pytest.raises(ValueError):
        build_repository_context(tmp_path, "", **limits)


def test_empty_workspace_and_no_commands(tmp_path, monkeypatch):
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("Repository collection must not execute commands")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    assert json.loads(build_repository_context(tmp_path, ""))["manifest"] == []
    put(tmp_path, "main.py", 'print("do not execute")\n')
    assert json.loads(build_repository_context(tmp_path, ""))["manifest"]


def test_unquoted_credentials_and_partial_utf8(tmp_path):
    put(tmp_path, "config.yaml", "password: highly-sensitive\n")
    put(tmp_path, "unicode.py", "# éééééééé\n")
    data = json.loads(build_repository_context(tmp_path, "", max_file_bytes=5))
    unicode_record = next(r for r in data["manifest"] if r["path"] == "unicode.py")
    assert unicode_record["excerpt"] == "# é"
    assert unicode_record["truncated"]
    output = build_repository_context(tmp_path, "")
    assert "highly-sensitive" not in output
    assert "config.yaml" not in output
