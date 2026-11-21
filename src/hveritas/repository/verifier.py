"""Hardened Docker pytest verifier for repository goals with tamper-resistant evidence parsing."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST, SCRATCH_ROOT

ORACLE_DIR_NAME = "_hveritas_oracle"
PER_RUN_TIMEOUT_S = 120.0
GLOBAL_TIMEOUT_S = 900.0
STDOUT_LIMIT = 4000

_PINNED_DIGEST_ONLY_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PINNED_REPO_DIGEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")

_HV_CHILD = r"""
import json
import os
import sys

import pytest


def _norm(nodeid: str) -> str:
    if nodeid.startswith("/oracle/"):
        return "_hveritas_oracle/" + nodeid[len("/oracle/"):]
    if nodeid.startswith("../oracle/"):
        return "_hveritas_oracle/" + nodeid[len("../oracle/"):]
    if nodeid.startswith("oracle/"):
        return "_hveritas_oracle/" + nodeid[len("oracle/"):]
    idx = nodeid.find("/oracle/")
    if idx != -1:
        return "_hveritas_oracle/" + nodeid[idx + len("/oracle/"):]
    return nodeid


def _make_plugin(pipe_fd: int):
    collected: list[str] = []
    collection_errors: list[dict[str, str]] = []
    states: dict[str, dict[str, object]] = {}

    class _VerifierPlugin:
        def pytest_collection_modifyitems(self, session, config, items):
            for item in items:
                collected.append(_norm(item.nodeid))

        def pytest_collectreport(self, report):
            if report.failed:
                collection_errors.append(
                    {
                        "nodeid": _norm(report.nodeid or "<collect>"),
                        "longrepr": str(report.longrepr)[-1500:],
                    }
                )

        def pytest_runtest_logreport(self, report):
            nid = _norm(report.nodeid)
            st = states.setdefault(
                nid,
                {
                    "setup_failed": False,
                    "setup_skipped": False,
                    "setup_wasxfail": False,
                    "call_ran": False,
                    "call_passed": False,
                    "call_failed": False,
                    "call_skipped": False,
                    "call_wasxfail": False,
                    "teardown_failed": False,
                },
            )
            was_xfail = hasattr(report, "wasxfail")
            if report.when == "setup":
                if report.failed:
                    st["setup_failed"] = True
                elif report.skipped:
                    st["setup_skipped"] = True
                    st["setup_wasxfail"] = was_xfail
            elif report.when == "call":
                st["call_ran"] = True
                st["call_wasxfail"] = was_xfail
                if report.passed:
                    st["call_passed"] = True
                elif report.failed:
                    st["call_failed"] = True
                elif report.skipped:
                    st["call_skipped"] = True
            elif report.when == "teardown" and report.failed:
                st["teardown_failed"] = True

        def pytest_sessionfinish(self, session, exitstatus):
            passed: list[str] = []
            failed: list[str] = []
            errors: list[str] = []
            skipped: list[str] = []
            xfailed: list[str] = []
            xpassed: list[str] = []

            for nid in collected:
                st = states.get(nid)
                if st is None:
                    continue
                if st["setup_failed"]:
                    errors.append(nid)
                elif st["setup_skipped"]:
                    if st["setup_wasxfail"]:
                        xfailed.append(nid)
                    else:
                        skipped.append(nid)
                elif st["call_ran"]:
                    if st["call_failed"]:
                        failed.append(nid)
                    elif st["call_skipped"]:
                        if st["call_wasxfail"]:
                            xfailed.append(nid)
                        else:
                            skipped.append(nid)
                    elif st["call_passed"]:
                        if st["teardown_failed"]:
                            errors.append(nid)
                        elif st["call_wasxfail"]:
                            xpassed.append(nid)
                        else:
                            passed.append(nid)
                elif st["teardown_failed"]:
                    errors.append(nid)

            payload = json.dumps(
                {
                    "session_finished": True,
                    "session_exitstatus": int(exitstatus),
                    "collected": collected,
                    "passed": passed,
                    "failed": failed,
                    "errors": errors,
                    "skipped": skipped,
                    "xfailed": xfailed,
                    "xpassed": xpassed,
                    "collection_errors": collection_errors,
                }
            ).encode("utf-8")
            view = memoryview(payload)
            while view:
                written = os.write(pipe_fd, view)
                view = view[written:]
            os.close(pipe_fd)

    return _VerifierPlugin()


def _main() -> int:
    cfg = json.loads(sys.argv[1])
    sys.argv[:] = ["pytest"]
    pipe_fd = int(cfg["pipe_fd"])
    ws_dir = str(cfg["ws_dir"])
    src_dir = os.path.join(ws_dir, "src")
    sys_paths = [ws_dir]
    if os.path.isdir(src_dir):
        sys_paths.insert(0, src_dir)
    sys.path[:0] = sys_paths
    os.chdir(ws_dir)
    plugin = _make_plugin(pipe_fd)
    pytest_args = list(cfg["pytest_args"])
    return int(pytest.main(pytest_args, plugins=[plugin]))


if __name__ == "__main__":
    raise SystemExit(_main())
"""

_HV_SUPERVISOR = r"""
import json
import os
import secrets
import shutil
import subprocess
import sys


def _tail(path: str, limit: int = 4000) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - limit))
        return fh.read().decode("utf-8", "replace")


def main() -> int:
    req = json.loads(sys.argv[1])
    nonce = str(req["nonce"])
    run_tok = secrets.token_hex(8)
    ws_dir = f"/tmp/ws_{run_tok}"
    out_file = f"/tmp/out_{run_tok}"
    err_file = f"/tmp/err_{run_tok}"
    shutil.copytree("/workspace", ws_dir, symlinks=False)

    paths = list(req.get("paths", []))
    oracle_only = bool(req.get("oracle_only", False))
    has_oracle = os.path.isdir("/oracle")
    if has_oracle:
        paths.append("/oracle")

    pytest_args = ["-q", "-p", "no:cacheprovider", "--basetemp", f"/tmp/pt_{run_tok}"]
    if oracle_only and has_oracle:
        pytest_args.extend(["--noconftest", "--confcutdir=/oracle"])
    elif has_oracle:
        pytest_args.append("--confcutdir=/oracle")
    pytest_args.extend(paths)

    r_fd, w_fd = os.pipe()
    child_cfg = json.dumps(
        {
            "pipe_fd": w_fd,
            "ws_dir": ws_dir,
            "pytest_args": pytest_args,
        }
    )
    child_cmd = [sys.executable, "-I", "-B", "/hv_verifier/_hv_child.py", child_cfg]
    child_env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    with open(out_file, "wb") as out_fh, open(err_file, "wb") as err_fh:
        proc = subprocess.Popen(
            child_cmd,
            cwd=ws_dir,
            env=child_env,
            stdout=out_fh,
            stderr=err_fh,
            pass_fds=(w_fd,),
        )
        os.close(w_fd)
        chunks: list[bytes] = []
        while True:
            buf = os.read(r_fd, 65536)
            if not buf:
                break
            chunks.append(buf)
        os.close(r_fd)
        returncode = proc.wait()

    raw_pipe = b"".join(chunks).decode("utf-8", "replace").strip()
    if raw_pipe:
        try:
            res = json.loads(raw_pipe)
        except json.JSONDecodeError:
            res = {"session_finished": False, "pipe_parse_error": True}
    else:
        res = {"session_finished": False}

    res["exit_code"] = int(returncode)
    res["stdout"] = _tail(out_file)
    res["stderr"] = _tail(err_file)
    sys.stdout.write(f"HV_RESULT_{nonce}=" + json.dumps(res) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""


class VerifierBudgetExceeded(RuntimeError):
    """Global verifier wall-clock budget exhausted."""


def validate_pinned_image_ref(image_digest: str) -> str:
    """Validate that a container image reference is SHA-256 digest-pinned.

    Supports both ``sha256:<64hex>`` (used by ``DEFAULT_VERIFIER_IMAGE_DIGEST``)
    and ``<repo>@sha256:<64hex>`` OCI digest references. Unpinned tags fail closed.
    """
    if not isinstance(image_digest, str) or image_digest.startswith("-"):
        raise ValueError(
            f"invalid verifier image reference (must be sha256 digest-pinned): {image_digest!r}"
        )
    if _PINNED_DIGEST_ONLY_RE.fullmatch(image_digest) or _PINNED_REPO_DIGEST_RE.fullmatch(
        image_digest
    ):
        return image_digest
    raise ValueError(
        f"verifier image must be sha256 digest-pinned (sha256:<64hex> or <repo>@sha256:<64hex>), "
        f"got {image_digest!r}"
    )


@dataclass(frozen=True)
class PytestOutcome:
    """Typed, fail-closed result of one isolated container pytest invocation."""

    status: str  # "ok" | "timeout" | "error"
    exit_code: int
    collected: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    collection_errors: tuple[str, ...] = ()
    stdout: str = ""
    elapsed_s: float = 0.0
    command: tuple[str, ...] = field(default_factory=tuple)
    skipped: tuple[str, ...] = ()
    stderr: str = ""
    passed_ids: tuple[str, ...] | None = None
    errors: tuple[str, ...] = ()
    xfailed: tuple[str, ...] = ()
    xpassed: tuple[str, ...] = ()
    failure_kind: str = ""
    evidence_valid: bool = True

    def __post_init__(self) -> None:
        if self.passed_ids is None:
            if (
                self.status == "ok"
                and self.evidence_valid
                and not self.collection_errors
                and not self.errors
            ):
                excluded = (
                    set(self.failed) | set(self.skipped) | set(self.xfailed) | set(self.xpassed)
                )
                computed = tuple(nid for nid in self.collected if nid not in excluded)
            else:
                computed = ()
            object.__setattr__(self, "passed_ids", computed)

    @property
    def passed(self) -> frozenset[str]:
        if self.status != "ok" or not self.evidence_valid or self.passed_ids is None:
            return frozenset()
        return frozenset(self.passed_ids)

    @property
    def missing_dependency(self) -> bool:
        if self.failure_kind == "missing_dependency":
            return True
        if any(
            marker in err
            for err in self.collection_errors
            for marker in ("ModuleNotFoundError", "ImportError")
        ):
            return True
        return bool(
            self.errors
            and any(
                marker in stream
                for stream in (self.stdout, self.stderr)
                for marker in ("ModuleNotFoundError", "ImportError")
            )
        )

    def to_summary_dict(self) -> dict[str, Any]:
        """Serialize typed verification outcome for reports and events."""
        return {
            "status": self.status,
            "failure_kind": self.failure_kind,
            "evidence_valid": self.evidence_valid,
            "exit_code": self.exit_code,
            "tests_collected": list(self.collected),
            "tests_passed": sorted(self.passed),
            "tests_failed": list(self.failed),
            "tests_errors": list(self.errors),
            "tests_skipped": list(self.skipped),
            "tests_xfailed": list(self.xfailed),
            "tests_xpassed": list(self.xpassed),
            "collection_errors": list(self.collection_errors),
            "missing_dependency": self.missing_dependency,
            "elapsed_s": round(self.elapsed_s, 4),
        }


class RepositoryVerifier(Protocol):
    """Protocol implemented by ``DockerRepositoryVerifier`` and deterministic test doubles."""

    def run_pytest(
        self, workspace: Path, test_paths: list[str], oracle_dir: Path | None = None
    ) -> PytestOutcome: ...


class DockerRepositoryVerifier:
    """Isolated Docker pytest verifier (`--network none`, `--read-only`, `uid=10001`, `cap-drop ALL`)."""

    def __init__(
        self,
        image_digest: str = DEFAULT_VERIFIER_IMAGE_DIGEST,
        *,
        per_run_timeout_s: float = PER_RUN_TIMEOUT_S,
        global_timeout_s: float = GLOBAL_TIMEOUT_S,
        scratch_root: Path = SCRATCH_ROOT,
        docker_bin: str = "docker",
    ) -> None:
        self.image_digest = validate_pinned_image_ref(image_digest)
        self.per_run_timeout_s = min(max(float(per_run_timeout_s), 0.001), 180.0)
        self.global_timeout_s = min(max(float(global_timeout_s), 0.001), 900.0)
        self.scratch_root = scratch_root
        self.docker_bin = docker_bin
        self.used_s = 0.0

    def build_command(
        self,
        staged_ws: Path,
        test_paths: list[str],
        oracle_dir: Path | None,
        name: str,
        *,
        verifier_dir: Path | None = None,
        nonce: str = "00000000000000000000000000000000",
    ) -> list[str]:
        v_dir = verifier_dir if verifier_dir is not None else staged_ws.parent / "verifier"
        cmd = [
            self.docker_bin,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--user",
            "10001:10001",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--cpus",
            "2",
            "--memory",
            "1g",
            "--memory-swap",
            "1g",
            "--pids-limit",
            "256",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=512m",
            "--env",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "--env",
            "HOME=/tmp",
            "--env",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
            "--env",
            "PYTHONNOUSERSITE=1",
            "--env",
            "PYTHONHASHSEED=0",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--volume",
            f"{staged_ws}:/workspace:ro",
            "--volume",
            f"{v_dir}:/hv_verifier:ro",
        ]
        if oracle_dir is not None:
            cmd += ["--volume", f"{oracle_dir}:/oracle:ro"]
        req = {
            "paths": list(test_paths),
            "oracle_dir": ORACLE_DIR_NAME,
            "oracle_only": bool(oracle_dir is not None and not test_paths),
            "nonce": nonce,
        }
        cmd += [
            self.image_digest,
            "/usr/local/bin/python3",
            "-I",
            "-B",
            "/hv_verifier/_hv_supervisor.py",
            json.dumps(req),
        ]
        return cmd

    def _stage_verifier_runtime(self, verifier_dir: Path) -> None:
        verifier_dir.mkdir(parents=True, mode=0o755)
        sup_path = verifier_dir / "_hv_supervisor.py"
        child_path = verifier_dir / "_hv_child.py"
        sup_path.write_text(_HV_SUPERVISOR, encoding="utf-8")
        child_path.write_text(_HV_CHILD, encoding="utf-8")
        sup_path.chmod(0o444)
        child_path.chmod(0o444)

    def run_pytest(
        self, workspace: Path, test_paths: list[str], oracle_dir: Path | None = None
    ) -> PytestOutcome:
        remaining = self.global_timeout_s - self.used_s
        if remaining <= 0:
            raise VerifierBudgetExceeded(
                f"global verifier budget {self.global_timeout_s}s exhausted"
            )
        timeout = min(self.per_run_timeout_s, remaining)
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        stage_root = self.scratch_root / f"hv_repo_{os.getpid()}_{secrets.token_hex(6)}"
        staged_ws = stage_root / "workspace"
        verifier_dir = stage_root / "verifier"
        name = f"hv-repo-{secrets.token_hex(6)}"
        nonce = secrets.token_hex(16)
        clean_env = {k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ}
        try:
            stage_root.mkdir(parents=True, mode=0o755)
            shutil.copytree(workspace, staged_ws, symlinks=False)
            for p in [staged_ws, *staged_ws.rglob("*")]:
                if p.is_dir():
                    p.chmod(0o755)
                else:
                    cur = p.stat().st_mode
                    p.chmod(0o755 if (cur & 0o100) else 0o644)
            self._stage_verifier_runtime(verifier_dir)

            cmd = self.build_command(
                staged_ws,
                test_paths,
                oracle_dir,
                name,
                verifier_dir=verifier_dir,
                nonce=nonce,
            )
            start = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                    env=clean_env,
                )
            except subprocess.TimeoutExpired as exc:
                self._cleanup_timed_out_container(name, clean_env)
                self.used_s += max(time.monotonic() - start, timeout)
                out = exc.stdout or b""
                text = out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)
                return PytestOutcome(
                    status="timeout",
                    exit_code=-1,
                    stdout=text[-STDOUT_LIMIT:],
                    elapsed_s=timeout,
                    command=tuple(cmd[:-1]),
                    failure_kind="timeout",
                    evidence_valid=False,
                )
            except OSError as exc:
                self.used_s += time.monotonic() - start
                return PytestOutcome(
                    status="error",
                    exit_code=-1,
                    stderr=str(exc)[-STDOUT_LIMIT:],
                    elapsed_s=0.0,
                    command=tuple(cmd[:-1]),
                    failure_kind="infra_error",
                    evidence_valid=False,
                )

            elapsed = time.monotonic() - start
            self.used_s += elapsed
            return parse_container_output(
                proc.returncode,
                proc.stdout,
                proc.stderr,
                elapsed,
                cmd,
                expected_nonce=nonce,
            )
        finally:
            shutil.rmtree(stage_root, ignore_errors=True)

    def _cleanup_timed_out_container(self, name: str, env: dict[str, str]) -> None:
        for action in (["rm", "-f", name], ["kill", name]):
            try:
                subprocess.run(
                    [self.docker_bin, *action],
                    capture_output=True,
                    check=False,
                    timeout=5,
                    env=env,
                )
            except (subprocess.TimeoutExpired, OSError):
                pass


def _as_str_tuple(raw: object) -> tuple[str, ...] | None:
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        return None
    return tuple(raw)


def parse_container_output(
    returncode: int,
    stdout: str,
    stderr: str,
    elapsed: float,
    cmd: list[str],
    *,
    expected_nonce: str | None = None,
) -> PytestOutcome:
    """Parse and fail-closed validate supervisor container output.

    Rejects missing/wrong nonce markers, incomplete sessions (`os._exit(0)`),
    missing `passed` lists, unaccounted collected test IDs, and exit-code contradictions.
    """
    prefix = f"HV_RESULT_{expected_nonce}=" if expected_nonce else "HV_RESULT="
    cmd_head = tuple(cmd[:-1]) if len(cmd) > 1 else tuple(cmd)
    tail = (stdout + stderr)[-STDOUT_LIMIT:]

    if returncode != 0:
        return PytestOutcome(
            status="error",
            exit_code=returncode,
            stdout=stdout[-STDOUT_LIMIT:],
            stderr=stderr[-STDOUT_LIMIT:],
            elapsed_s=elapsed,
            command=cmd_head,
            failure_kind="infra_error",
            evidence_valid=False,
        )

    matching_lines = [ln for ln in stdout.splitlines() if ln.startswith(prefix)]
    if len(matching_lines) != 1:
        return PytestOutcome(
            status="error",
            exit_code=returncode,
            stdout=tail,
            stderr=stderr[-STDOUT_LIMIT:],
            elapsed_s=elapsed,
            command=cmd_head,
            failure_kind="corrupt_evidence",
            evidence_valid=False,
        )

    try:
        res = json.loads(matching_lines[0][len(prefix) :])
    except json.JSONDecodeError:
        return PytestOutcome(
            status="error",
            exit_code=returncode,
            stdout=tail,
            stderr=stderr[-STDOUT_LIMIT:],
            elapsed_s=elapsed,
            command=cmd_head,
            failure_kind="corrupt_evidence",
            evidence_valid=False,
        )

    if not isinstance(res, dict) or res.get("session_finished") is not True:
        return PytestOutcome(
            status="error",
            exit_code=int(res.get("exit_code", -1)) if isinstance(res, dict) else -1,
            stdout=str(res.get("stdout", tail))[-STDOUT_LIMIT:] if isinstance(res, dict) else tail,
            stderr=str(res.get("stderr", stderr))[-STDOUT_LIMIT:]
            if isinstance(res, dict)
            else stderr[-STDOUT_LIMIT:],
            elapsed_s=elapsed,
            command=cmd_head,
            failure_kind="corrupt_evidence",
            evidence_valid=False,
        )

    collected = _as_str_tuple(res.get("collected"))
    passed_ids = _as_str_tuple(res.get("passed"))
    failed = _as_str_tuple(res.get("failed"))
    errors = _as_str_tuple(res.get("errors", []))
    skipped = _as_str_tuple(res.get("skipped", []))
    xfailed = _as_str_tuple(res.get("xfailed", []))
    xpassed = _as_str_tuple(res.get("xpassed", []))
    raw_col_err = res.get("collection_errors", [])
    raw_exit = res.get("exit_code")

    if (
        collected is None
        or passed_ids is None
        or failed is None
        or errors is None
        or skipped is None
        or xfailed is None
        or xpassed is None
        or not isinstance(raw_col_err, list)
        or not isinstance(raw_exit, int)
        or isinstance(raw_exit, bool)
    ):
        return PytestOutcome(
            status="error",
            exit_code=-1,
            stdout=str(res.get("stdout", tail))[-STDOUT_LIMIT:],
            stderr=str(res.get("stderr", stderr))[-STDOUT_LIMIT:],
            elapsed_s=elapsed,
            command=cmd_head,
            failure_kind="corrupt_evidence",
            evidence_valid=False,
        )

    col_errors: list[str] = []
    for item in raw_col_err:
        if isinstance(item, dict):
            col_errors.append(f"{item.get('nodeid')}: {item.get('longrepr')}")
        elif isinstance(item, str):
            col_errors.append(item)
        else:
            return PytestOutcome(
                status="error",
                exit_code=raw_exit,
                stdout=str(res.get("stdout", ""))[-STDOUT_LIMIT:],
                stderr=str(res.get("stderr", ""))[-STDOUT_LIMIT:],
                elapsed_s=elapsed,
                command=cmd_head,
                failure_kind="corrupt_evidence",
                evidence_valid=False,
            )

    cap_stdout = str(res.get("stdout", ""))[-STDOUT_LIMIT:]
    cap_stderr = str(res.get("stderr", ""))[-STDOUT_LIMIT:]

    if col_errors:
        is_missing_dep = any(
            marker in err for err in col_errors for marker in ("ModuleNotFoundError", "ImportError")
        )
        return PytestOutcome(
            status="error",
            exit_code=raw_exit if raw_exit != 0 else 2,
            collected=collected,
            failed=failed,
            collection_errors=tuple(col_errors),
            stdout=cap_stdout,
            stderr=cap_stderr,
            elapsed_s=elapsed,
            command=cmd_head,
            skipped=skipped,
            passed_ids=(),
            errors=errors,
            xfailed=xfailed,
            xpassed=xpassed,
            failure_kind="missing_dependency" if is_missing_dep else "collection_error",
            evidence_valid=True,
        )

    buckets = (passed_ids, failed, errors, skipped, xfailed, xpassed)
    total_bucket_items = sum(len(b) for b in buckets)
    union_accounted = set().union(*buckets)
    collected_set = set(collected)

    if (
        len(collected_set) != len(collected)
        or total_bucket_items != len(union_accounted)
        or union_accounted != collected_set
    ):
        return PytestOutcome(
            status="error",
            exit_code=raw_exit,
            collected=collected,
            failed=failed,
            stdout=cap_stdout,
            stderr=cap_stderr,
            elapsed_s=elapsed,
            command=cmd_head,
            skipped=skipped,
            passed_ids=(),
            errors=errors,
            xfailed=xfailed,
            xpassed=xpassed,
            failure_kind="corrupt_evidence",
            evidence_valid=False,
        )

    if len(collected) == 0:
        if raw_exit not in (0, 5):
            return PytestOutcome(
                status="error",
                exit_code=raw_exit,
                stdout=cap_stdout,
                stderr=cap_stderr,
                elapsed_s=elapsed,
                command=cmd_head,
                failure_kind="infra_error",
                evidence_valid=False,
            )
        return PytestOutcome(
            status="ok",
            exit_code=raw_exit,
            collected=(),
            stdout=cap_stdout,
            stderr=cap_stderr,
            elapsed_s=elapsed,
            command=cmd_head,
            passed_ids=(),
            failure_kind="zero_tests",
            evidence_valid=True,
        )

    has_bad = bool(failed or errors)
    if (raw_exit == 0 and has_bad) or (raw_exit != 0 and not has_bad):
        return PytestOutcome(
            status="error",
            exit_code=raw_exit,
            collected=collected,
            failed=failed,
            stdout=cap_stdout,
            stderr=cap_stderr,
            elapsed_s=elapsed,
            command=cmd_head,
            skipped=skipped,
            passed_ids=(),
            errors=errors,
            xfailed=xfailed,
            xpassed=xpassed,
            failure_kind="corrupt_evidence",
            evidence_valid=False,
        )

    setup_missing_dep = (
        bool(errors)
        and not failed
        and any(
            marker in stream
            for stream in (cap_stdout, cap_stderr)
            for marker in ("ModuleNotFoundError", "ImportError")
        )
    )
    return PytestOutcome(
        status="ok",
        exit_code=raw_exit,
        collected=collected,
        failed=failed,
        collection_errors=(),
        stdout=cap_stdout,
        stderr=cap_stderr,
        elapsed_s=elapsed,
        command=cmd_head,
        skipped=skipped,
        passed_ids=passed_ids,
        errors=errors,
        xfailed=xfailed,
        xpassed=xpassed,
        failure_kind="missing_dependency"
        if setup_missing_dep
        else ("test_failure" if has_bad else ""),
        evidence_valid=True,
    )
