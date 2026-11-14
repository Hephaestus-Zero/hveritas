"""Isolated container verifier runner (`~/.local/share/hveritas/verifier/runner.py`).

Executed ONLY inside the network-disabled, read-only, non-root verifier container with
`/usr/local/bin/python3 -I -B /verifier/runner.py /suites/request.json`.

Enforces Invariants I1, I6, I7:
- Never shares process, writable path, or LLM call with worker agent.
- Uses `python3 -I` and fixed `PATH=/usr/local/bin:/usr/bin:/bin`.
- Never collects pytest from `/workspace`, disables `conftest.py` and plugin autoload.
- Never invokes `eval` or `exec` on agent outputs; parses JSON + JSONSchema only.
"""

from __future__ import annotations

import ast
import html.parser
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import jsonschema

PINNED_PATH = "/usr/local/bin:/usr/bin:/bin"
PINNED_PYTHON = "/usr/local/bin/python3"


def _clean_env(workspace: Path) -> dict[str, str]:
    return {
        "PATH": PINNED_PATH,
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "HVERITAS_WORKSPACE": str(workspace),
    }


def check_compile(workspace: Path) -> dict[str, Any]:
    py_files = sorted(p for p in workspace.rglob("*.py") if ".git" not in p.parts)
    errors: list[str] = []
    for p in py_files:
        try:
            src = p.read_text(encoding="utf-8")
            ast.parse(src, filename=str(p.relative_to(workspace)))
        except (SyntaxError, UnicodeDecodeError) as exc:
            errors.append(f"{p.relative_to(workspace)}: {exc}")
    passed = len(errors) == 0 and len(py_files) > 0
    return {
        "check": "compile",
        "passed": passed,
        "score": 1.0 if passed else 0.0,
        "files_checked": len(py_files),
        "errors": errors,
    }


def check_typecheck(workspace: Path) -> dict[str, Any]:
    py_files = sorted(p for p in workspace.rglob("*.py") if ".git" not in p.parts)
    if not py_files:
        return {"check": "typecheck", "passed": False, "score": 0.0, "errors": ["no python files"]}
    cmd = [
        PINNED_PYTHON,
        "-I",
        "-B",
        "-m",
        "mypy",
        "--cache-dir=/tmp/mypy_cache",
        "--config-file=/verifier/mypy.ini",
        "--explicit-package-bases",
        *[str(p) for p in py_files],
    ]
    proc = subprocess.run(
        cmd,
        cwd="/tmp",
        env=_clean_env(workspace),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    passed = proc.returncode == 0
    return {
        "check": "typecheck",
        "passed": passed,
        "score": 1.0 if passed else 0.0,
        "stdout": proc.stdout[-2000:],
        "stderr": proc.stderr[-2000:],
    }


def check_lint(workspace: Path) -> dict[str, Any]:
    py_files = sorted(p for p in workspace.rglob("*.py") if ".git" not in p.parts)
    if not py_files:
        return {"check": "lint", "passed": False, "score": 0.0, "errors": ["no python files"]}
    cmd = [
        "/usr/local/bin/ruff",
        "check",
        "--no-cache",
        "--isolated",
        *[str(p) for p in py_files],
    ]
    proc = subprocess.run(
        cmd,
        cwd="/tmp",
        env=_clean_env(workspace),
        capture_output=True,
        text=True,
        timeout=20.0,
        check=False,
    )
    passed = proc.returncode == 0
    return {
        "check": "lint",
        "passed": passed,
        "score": 1.0 if passed else 0.0,
        "stdout": proc.stdout[-2000:],
        "stderr": proc.stderr[-2000:],
    }


def check_schema(workspace: Path, spec: dict[str, Any]) -> dict[str, Any]:
    """Validate structured JSON output strictly via `json.loads` + JSONSchema (never `eval`/`exec`)."""
    rel_file = str(spec["file"])
    schema = dict(spec["schema"])
    expected_equals = spec.get("expected_equals")
    target = (workspace / rel_file).resolve()
    if target != workspace and workspace not in target.parents:
        return {"check": "schema", "passed": False, "score": 0.0, "errors": ["path escape"]}
    if not target.is_file():
        return {
            "check": "schema",
            "passed": False,
            "score": 0.0,
            "errors": [f"missing artifact: {rel_file}"],
        }
    try:
        raw_text = target.read_text(encoding="utf-8")
        if len(raw_text) > 1_048_576:
            return {"check": "schema", "passed": False, "score": 0.0, "errors": ["artifact > 1MB"]}
        parsed = json.loads(raw_text)
        jsonschema.validate(instance=parsed, schema=schema)
        if expected_equals is not None and parsed != expected_equals:
            return {
                "check": "schema",
                "passed": False,
                "score": 0.0,
                "errors": [f"value mismatch: got {parsed!r}"],
            }
        return {"check": "schema", "passed": True, "score": 1.0, "errors": []}
    except (ValueError, jsonschema.ValidationError) as exc:
        return {"check": "schema", "passed": False, "score": 0.0, "errors": [str(exc)]}


def run_pytest_suite(workspace: Path, suite_dir: Path, label: str) -> dict[str, Any]:
    """Execute isolated pytest suite located OUTSIDE `/workspace` (`--noconftest`, `python3 -I`)."""
    test_files = sorted(suite_dir.glob("test_*.py"))
    if not test_files:
        return {
            "check": label,
            "passed": True,
            "score": 1.0,
            "passed_count": 0,
            "failed_count": 0,
            "note": "empty suite",
        }

    cmd = [
        PINNED_PYTHON,
        "-I",
        "-B",
        "-c",
        (
            "import sys; sys.path.insert(0, '/verifier'); "
            "import pytest; "
            f"sys.exit(pytest.main(['--noconftest', '-p', 'no:cacheprovider', "
            f"'--basetemp=/tmp/pytest_{label}', '--rootdir={suite_dir}', '-q', '{suite_dir}']))"
        ),
    ]
    proc = subprocess.run(
        cmd,
        cwd="/tmp",
        env=_clean_env(workspace),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    out = proc.stdout + "\n" + proc.stderr
    m_pass = re.search(r"(\d+)\s+passed", out)
    m_fail = re.search(r"(\d+)\s+(?:failed|error)", out)
    passed_n = int(m_pass.group(1)) if m_pass else 0
    failed_n = int(m_fail.group(1)) if m_fail else 0
    total = passed_n + failed_n
    if proc.returncode == 0 and total > 0:
        score = 1.0
        ok = True
    elif total > 0:
        score = passed_n / total
        ok = False
    else:
        score = 0.0
        ok = False

    return {
        "check": label,
        "passed": ok,
        "score": round(score, 6),
        "passed_count": passed_n,
        "failed_count": failed_n,
        "exit_code": proc.returncode,
        "output": out[-3000:],
    }


def check_api_contract(workspace: Path, contracts: list[dict[str, Any]]) -> dict[str, Any]:
    """T1 Invariant: AST-level public function/class contract check (zero execution)."""
    errors: list[str] = []
    for c in contracts:
        rel = str(c["file"])
        target = (workspace / rel).resolve()
        if not target.is_file():
            errors.append(f"missing contract file {rel}")
            continue
        try:
            tree = ast.parse(target.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            errors.append(f"syntax error in {rel}: {exc}")
            continue
        funcs = {
            node.name: [a.arg for a in node.args.args]
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for fn_name, expected_args in dict(c.get("functions", {})).items():
            if fn_name not in funcs:
                errors.append(f"{rel}: missing function {fn_name}")
            elif expected_args is not None and funcs[fn_name] != list(expected_args):
                errors.append(
                    f"{rel}:{fn_name} args {funcs[fn_name]} != expected {expected_args}"
                )
    passed = len(errors) == 0
    return {
        "check": "api_contract",
        "passed": passed,
        "score": 1.0 if passed else 0.0,
        "errors": errors,
    }


def check_security_invariants(workspace: Path, forbidden_calls: list[str]) -> dict[str, Any]:
    """T1 Invariant: Static AST scan prohibiting dangerous calls (`eval`, `exec`, `os.system`, etc.)."""
    bad_set = set(forbidden_calls or ["eval", "exec", "os.system"])
    violations: list[str] = []
    for p in sorted(workspace.rglob("*.py")):
        if ".git" in p.parts:
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in bad_set:
                    violations.append(f"{p.relative_to(workspace)}:{node.lineno}:{node.func.id}")
                elif isinstance(node.func, ast.Attribute) and isinstance(
                    node.func.value, ast.Name
                ):
                    qual = f"{node.func.value.id}.{node.func.attr}"
                    if qual in bad_set:
                        violations.append(f"{p.relative_to(workspace)}:{node.lineno}:{qual}")
    passed = len(violations) == 0
    return {
        "check": "security_scan",
        "passed": passed,
        "score": 1.0 if passed else 0.0,
        "violations": violations,
    }


class _HtmlAxeAuditParser(html.parser.HTMLParser):
    """Structural WCAG / axe-core baseline audit on workspace HTML artifacts."""

    def __init__(self) -> None:
        super().__init__()
        self.has_html_lang = False
        self.has_title = False
        self.in_title = False
        self.title_text = ""
        self.ids_seen: set[str] = set()
        self.violations: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        el_id = attr_map.get("id")
        if el_id:
            if el_id in self.ids_seen:
                self.violations.append(f"duplicate-id:{el_id}")
            self.ids_seen.add(el_id)
        if tag.lower() == "html" and attr_map.get("lang", "").strip():
            self.has_html_lang = True
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "img" and "alt" not in attr_map:
            self.violations.append("image-alt:missing-alt")
        if tag.lower() == "input":
            itype = attr_map.get("type", "text").lower()
            if itype not in {"hidden", "submit", "button"} and not (
                attr_map.get("aria-label") or attr_map.get("id")
            ):
                self.violations.append("label:unlabeled-input")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False
            if self.title_text.strip():
                self.has_title = True

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_text += data


def check_ui_axe_invariants(workspace: Path, html_files: list[str]) -> dict[str, Any]:
    violations: list[str] = []
    for rel in html_files:
        target = (workspace / rel).resolve()
        if not target.is_file():
            violations.append(f"{rel}:missing-html")
            continue
        parser = _HtmlAxeAuditParser()
        parser.feed(target.read_text(encoding="utf-8", errors="replace"))
        if not parser.has_html_lang:
            violations.append(f"{rel}:html-has-lang")
        if not parser.has_title:
            violations.append(f"{rel}:document-title")
        violations.extend(f"{rel}:{v}" for v in parser.violations)
    passed = len(violations) == 0
    return {
        "check": "axe_ui_invariant",
        "passed": passed,
        "score": 1.0 if passed else 0.0,
        "violations": violations,
    }


def check_perf_budget(workspace: Path, perf_spec: dict[str, Any]) -> dict[str, Any]:
    rel_mod = str(perf_spec["file"])
    fn_name = str(perf_spec["function"])
    args_json = json.dumps(perf_spec.get("args", []))
    max_ms = float(perf_spec.get("max_ms", 500.0))

    code = (
        "import json, sys, time; sys.path.insert(0, '/verifier'); "
        "from loader import load_workspace_module; "
        f"mod = load_workspace_module({rel_mod!r}); "
        f"args = json.loads({args_json!r}); "
        "t0 = time.perf_counter(); "
        f"getattr(mod, {fn_name!r})(*args); "
        "dt = (time.perf_counter() - t0) * 1000.0; "
        "print(json.dumps({'elapsed_ms': dt}))"
    )
    t_wall = time.perf_counter()
    proc = subprocess.run(
        [PINNED_PYTHON, "-I", "-B", "-c", code],
        cwd="/tmp",
        env=_clean_env(workspace),
        capture_output=True,
        text=True,
        timeout=max(2.0, max_ms / 1000.0 * 4.0),
        check=False,
    )
    elapsed_ms = (time.perf_counter() - t_wall) * 1000.0
    if proc.returncode == 0:
        try:
            elapsed_ms = float(json.loads(proc.stdout.strip())["elapsed_ms"])
        except (ValueError, KeyError):
            pass
    passed = proc.returncode == 0 and elapsed_ms <= max_ms
    return {
        "check": "perf_budget",
        "passed": passed,
        "score": 1.0 if passed else 0.0,
        "elapsed_ms": round(elapsed_ms, 3),
        "max_ms": max_ms,
        "stderr": proc.stderr[-1000:],
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: runner.py <request.json>"}))
        return 2

    # Enforce Python -I runtime invariant (I6)
    if not sys.flags.isolated:
        print(json.dumps({"error": "I6 VIOLATION: runner.py must run under python3 -I"}))
        return 3

    req_path = Path(sys.argv[1])
    req = json.loads(req_path.read_text(encoding="utf-8"))
    workspace = Path(req.get("workspace", "/workspace")).resolve()
    suites_root = req_path.parent

    results: dict[str, Any] = {
        "runtime_audit": {
            "uid": os.getuid(),
            "gid": os.getgid(),
            "python_isolated": bool(sys.flags.isolated),
            "path": os.environ.get("PATH", ""),
            "pythonpath": os.environ.get("PYTHONPATH"),
        },
        "tiers": {},
    }

    tiers_req = req.get("tiers", {})

    # T0 Deterministic
    if "T0" in tiers_req:
        t0_cfg = tiers_req["T0"]
        t0_checks: list[dict[str, Any]] = []
        if t0_cfg.get("compile", True):
            t0_checks.append(check_compile(workspace))
        if t0_cfg.get("typecheck", False):
            t0_checks.append(check_typecheck(workspace))
        if t0_cfg.get("lint", False):
            t0_checks.append(check_lint(workspace))
        for schema_spec in t0_cfg.get("schemas", []):
            t0_checks.append(check_schema(workspace, schema_spec))
        proxy_dir = suites_root / "proxy"
        if proxy_dir.is_dir():
            t0_checks.append(run_pytest_suite(workspace, proxy_dir, "proxy_pytest"))
        t0_score = (
            sum(float(c["score"]) for c in t0_checks) / len(t0_checks) if t0_checks else 1.0
        )
        t0_passed = all(bool(c["passed"]) for c in t0_checks)
        results["tiers"]["T0"] = {
            "passed": t0_passed,
            "score": round(t0_score, 6),
            "checks": t0_checks,
        }

    # T1 Invariant
    if "T1" in tiers_req:
        t1_cfg = tiers_req["T1"]
        t1_checks: list[dict[str, Any]] = []
        if t1_cfg.get("api_contracts"):
            t1_checks.append(check_api_contract(workspace, t1_cfg["api_contracts"]))
        if t1_cfg.get("security_scan", True):
            t1_checks.append(
                check_security_invariants(workspace, t1_cfg.get("forbidden_calls", []))
            )
        if t1_cfg.get("html_files"):
            t1_checks.append(check_ui_axe_invariants(workspace, t1_cfg["html_files"]))
        if t1_cfg.get("perf_budget"):
            t1_checks.append(check_perf_budget(workspace, t1_cfg["perf_budget"]))
        inv_dir = suites_root / "invariants"
        if inv_dir.is_dir():
            t1_checks.append(run_pytest_suite(workspace, inv_dir, "dynamic_invariants"))
        t1_score = (
            sum(float(c["score"]) for c in t1_checks) / len(t1_checks) if t1_checks else 1.0
        )
        t1_passed = all(bool(c["passed"]) for c in t1_checks)
        results["tiers"]["T1"] = {
            "passed": t1_passed,
            "score": round(t1_score, 6),
            "checks": t1_checks,
        }

    # T2 Metamorphic
    if "T2" in tiers_req:
        meta_dir = suites_root / "metamorphic"
        c_meta = run_pytest_suite(workspace, meta_dir, "metamorphic_suite")
        results["tiers"]["T2"] = {
            "passed": bool(c_meta["passed"]),
            "score": float(c_meta["score"]),
            "checks": [c_meta],
        }

    # T3 Held-out Oracle (mounted only inside isolated verifier container during milestone evaluation)
    if "T3" in tiers_req:
        heldout_dir = Path(req.get("heldout_mount", "/heldout")).resolve()
        c_ho = run_pytest_suite(workspace, heldout_dir, "heldout_oracle")
        results["tiers"]["T3"] = {
            "passed": bool(c_ho["passed"]),
            "score": float(c_ho["score"]),
            # Held-out raw traceback details are redacted so worker never learns secret test cases (I4)
            "checks": [
                {
                    "check": "heldout_oracle",
                    "passed": bool(c_ho["passed"]),
                    "score": float(c_ho["score"]),
                    "passed_count": c_ho["passed_count"],
                    "failed_count": c_ho["failed_count"],
                }
            ],
        }

    # Optional diagnostic probe used ONLY by red-team suite to test container restrictions
    if "redteam_probe" in req:
        probe_kind = str(req["redteam_probe"])
        probe_res: dict[str, Any] = {"kind": probe_kind, "exploited": False}
        try:
            if probe_kind == "network_egress":
                import socket

                host, port = req["target_host"], int(req["target_port"])
                with socket.create_connection((host, port), timeout=1.0) as s:
                    s.sendall(b"ping")
                probe_res["exploited"] = True
            elif probe_kind == "write_workspace":
                (workspace / "_exploit_write.txt").write_text("pwned", encoding="utf-8")
                probe_res["exploited"] = True
            elif probe_kind == "root_or_caps":
                status_txt = Path("/proc/self/status").read_text(encoding="utf-8")
                m_cap = re.search(r"CapEff:\s*([0-9a-fA-F]+)", status_txt)
                cap_eff = int(m_cap.group(1), 16) if m_cap else 0
                probe_res["uid"] = os.getuid()
                probe_res["cap_eff"] = cap_eff
                probe_res["exploited"] = os.getuid() == 0 or cap_eff != 0
        except (OSError, ValueError, RuntimeError) as exc:
            probe_res["blocked_error"] = f"{type(exc).__name__}: {exc}"
        results["redteam_probe"] = probe_res

    print(json.dumps(results, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
