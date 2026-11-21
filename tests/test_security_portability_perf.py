"""Regression tests for security fixes, portability helpers, lazy imports, and deferred Parquet flush."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from hveritas.cli import main as cli_main
from hveritas.harness.isolation import (
    copy_tree_portable,
    default_scratch_root,
    resolve_verifier_image_digest,
)
from hveritas.harness.oracle_vault import EncryptedOracleVault
from hveritas.harness.worker_sandbox import IsolatedWorkerSandbox
from hveritas.ledger import (
    ActionEnvelope,
    AgentClaim,
    AppendOnlyLedger,
    CostRecord,
    MeasuredEffects,
    RunRecord,
    sha256_hex,
)
from hveritas.verify.bus import RequirementDagJudge
from hveritas.worker.backend import HxCliBackend, ModelProtocolError

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_verifier_runner_module() -> Any:
    runner_path = REPO_ROOT / "external_bundles" / "verifier" / "runner.py"
    spec = importlib.util.spec_from_file_location("hv_verifier_runner_test", runner_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_requirement_dag_judge_rejects_workspace_escape(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("SECRET_TOKEN_XYZ\n", encoding="utf-8")
    symlink_escape = ws / "link_out.txt"
    symlink_escape.symlink_to(outside)

    llm_called = False

    def spy_judge(_stmt: str, _clean: str) -> tuple[bool, str]:
        nonlocal llm_called
        llm_called = True
        return True, "SECRET_TOKEN_XYZ"

    judge = RequirementDagJudge(llm_judge_fn=spy_judge)
    results = judge.evaluate(
        ws,
        [
            {
                "id": "rel_escape",
                "evidence_file": "../outside_secret.txt",
                "required_tokens": ["SECRET_TOKEN_XYZ"],
            },
            {
                "id": "abs_escape",
                "evidence_file": str(outside),
                "required_tokens": ["SECRET_TOKEN_XYZ"],
            },
            {
                "id": "symlink_escape",
                "evidence_file": "link_out.txt",
                "required_tokens": ["SECRET_TOKEN_XYZ"],
            },
        ],
    )
    assert len(results) == 3
    for res in results:
        assert res.passed is False
        assert "escapes workspace" in str(res.details.get("error", ""))
    assert llm_called is False


def test_verifier_check_api_contract_rejects_path_escape(tmp_path: Path) -> None:
    runner = _load_verifier_runner_module()
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    outside = tmp_path / "outside.py"
    outside.write_text("def leak(x):\n    return x\n", encoding="utf-8")
    (ws / "link.py").symlink_to(outside)

    ok_res = runner.check_api_contract(ws, [{"file": "ok.py", "functions": {"add": ["a", "b"]}}])
    assert ok_res["passed"] is True

    for bad_rel in ("../outside.py", str(outside), "link.py"):
        bad_res = runner.check_api_contract(
            ws, [{"file": bad_rel, "functions": {"leak": ["x"]}}]
        )
        assert bad_res["passed"] is False
        assert any("path escape" in err for err in bad_res["errors"])


def test_verifier_run_pytest_suite_passes_args_via_sys_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _load_verifier_runner_module()
    ws = tmp_path / "ws"
    ws.mkdir()
    suite_dir = tmp_path / "suite_dir"
    suite_dir.mkdir()
    (suite_dir / "test_sample.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")

    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="1 passed in 0.01s\n", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    malicious_label = "x']; import os; os.system('pwn'); #"
    res = runner.run_pytest_suite(ws, suite_dir, malicious_label)
    assert res["passed"] is True

    cmd = captured["cmd"]
    code_idx = cmd.index("-c") + 1
    code_str = cmd[code_idx]
    assert malicious_label not in code_str
    assert str(suite_dir) not in code_str
    assert cmd[code_idx + 1 :] == [malicious_label, str(suite_dir)]


def test_oracle_vault_creates_key_and_bundle_atomically_0600(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = os.open
    open_calls: list[tuple[str, int, int]] = []

    def tracking_open(path: Any, flags: int, mode: int = 0o777, *args: Any, **kwargs: Any) -> int:
        open_calls.append((str(path), flags, mode))
        return real_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)
    old_umask = os.umask(0o000)
    try:
        key_file = tmp_path / "oracle.key"
        vault = EncryptedOracleVault(repo_dir=tmp_path / "oracles", key_file=key_file)
        bundle = vault.store_oracle_suite("sec_test", {"test_a.py": "def test_a(): assert True\n"})
    finally:
        os.umask(old_umask)

    assert (key_file.stat().st_mode & 0o777) == 0o600
    assert (bundle.stat().st_mode & 0o777) == 0o600
    key_opens = [c for c in open_calls if Path(c[0]) == key_file.resolve()]
    bundle_opens = [c for c in open_calls if Path(c[0]) == bundle.resolve()]
    assert key_opens and key_opens[0][2] == 0o600
    assert bundle_opens and bundle_opens[0][2] == 0o600


def test_worker_sandbox_never_chmods_host_workspace_to_0777(tmp_path: Path) -> None:
    ws = tmp_path / "private_ws"
    ws.mkdir(mode=0o700)
    ws.chmod(0o700)
    (ws / "hello.txt").write_text("hi-from-host\n", encoding="utf-8")
    (ws / "hello.txt").chmod(0o600)

    sandbox = IsolatedWorkerSandbox()
    outcome = sandbox.run_python_in_worker(
        ws,
        "import pathlib; print(pathlib.Path('/workspace/hello.txt').read_text().strip())",
    )
    assert outcome.exit_code == 0, outcome.stderr
    assert outcome.stdout.strip() == "hi-from-host"
    assert (ws.stat().st_mode & 0o777) == 0o700
    assert (ws.stat().st_mode & 0o002) == 0


def test_default_scratch_root_and_portable_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    custom = tmp_path / "custom_scratch"
    monkeypatch.setenv("HVERITAS_SCRATCH_ROOT", str(custom))
    assert default_scratch_root() == custom

    monkeypatch.delenv("HVERITAS_SCRATCH_ROOT", raising=False)
    monkeypatch.setattr(os, "access", lambda *_args, **_kwargs: False)
    assert default_scratch_root() == Path(tempfile.gettempdir()) / "hveritas-scratch"

    # Force macOS/BSD fallback branch of copy_tree_portable
    src = tmp_path / "src_tree"
    src.mkdir()
    (src / "a.txt").write_text("alpha", encoding="utf-8")
    (src / "link_a.txt").symlink_to("a.txt")
    dst = tmp_path / "dst_tree"
    monkeypatch.setattr(sys, "platform", "darwin")
    copy_tree_portable(src, dst)
    assert (dst / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert (dst / "link_a.txt").is_symlink()


def test_setup_verifier_cli_and_digest_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "hv_share"
    rc = cli_main(["setup-verifier", "--dest", str(dest)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert Path(payload["dest"]) == dest.resolve()
    assert (dest / "verifier" / "runner.py").is_file()
    assert (dest / "benchjack_tools" / "trust_map.py").is_file()

    digest_file = dest / "verifier_digest"
    file_digest = "sha256:" + ("1" * 64)
    env_digest = "sha256:" + ("2" * 64)
    digest_file.write_text(file_digest + "\n", encoding="utf-8")

    monkeypatch.delenv("HVERITAS_VERIFIER_IMAGE_DIGEST", raising=False)
    assert resolve_verifier_image_digest(digest_file=digest_file) == file_digest

    monkeypatch.setenv("HVERITAS_VERIFIER_IMAGE_DIGEST", env_digest)
    assert resolve_verifier_image_digest(digest_file=digest_file) == env_digest


def test_missing_hx_binary_suggests_alternative_backends(tmp_path: Path) -> None:
    backend = HxCliBackend(
        hx_bin="nonexistent_hx_binary_xyz_999",
        planner_scratch_root=tmp_path / "planner_scratch",
    )
    with pytest.raises(ModelProtocolError) as exc_info:
        backend.complete(system="sys", user="usr", model="muse", timeout_s=5.0)
    msg = str(exc_info.value)
    assert "--backend anthropic" in msg
    assert "--backend fake" in msg


def test_lazy_imports_avoid_inspect_ai_and_pyarrow() -> None:
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    proc_cli = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys, hveritas.cli; "
                "assert 'inspect_ai' not in sys.modules, 'inspect_ai eagerly imported by cli'; "
                "assert 'pyarrow' not in sys.modules, 'pyarrow eagerly imported by cli'"
            ),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_cli.returncode == 0, proc_cli.stderr

    proc_loop = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys, hveritas.loop.models; "
                "assert 'inspect_ai' not in sys.modules, 'inspect_ai eagerly imported by loop.models'"
            ),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_loop.returncode == 0, proc_loop.stderr


def test_ledger_defers_parquet_writes_until_flush_or_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = AppendOnlyLedger(tmp_path / "ledger")
    sync_count = 0
    orig_sync = ledger._sync_steps_parquet

    def counted_sync() -> None:
        nonlocal sync_count
        sync_count += 1
        orig_sync()

    monkeypatch.setattr(ledger, "_sync_steps_parquet", counted_sync)
    ledger.append_run(
        RunRecord(
            run_id="deferred-run",
            goal="Verify deferred parquet flush",
            container_digest="sha256:" + ("a" * 64),
            seed=1,
            started_at_ns=1,
        )
    )
    h = sha256_hex("init")
    for idx in range(25):
        nh = sha256_hex(f"{h}:{idx}")
        env = ActionEnvelope(
            run_id="deferred-run",
            step_index=idx,
            trace_id="0" * 32,
            span_id=f"{idx:016x}",
            pre_state_hash=h,
            tool_name="write_file",
            tool_args={"idx": idx},
            seed=idx,
            cost=CostRecord(),
            timestamp_ns=1000 + idx,
        )
        ledger.append_step(
            env,
            AgentClaim(summary=f"s{idx}", reported_success=True),
            MeasuredEffects(post_state_hash=nh, exit_code=0),
        )
        h = nh

    assert sync_count == 0
    steps_pq = ledger.get_steps("deferred-run", source="parquet")
    assert sync_count == 1
    assert steps_pq == ledger.get_steps("deferred-run", source="sqlite")
    # Calling digest_bundle/close when already clean triggers 0 extra parquet writes
    digests = ledger.digest_bundle()
    assert "steps_parquet" in digests
    ledger.close()
    assert sync_count == 1
