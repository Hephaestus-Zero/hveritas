"""Repository-goal route: unit, mocked integration, adversarial, and CLI dispatch contracts.

No candidate code is ever executed on the host: ``TextVerifier`` decides pass/fail purely by
inspecting file text (``# REQUIRE <path> :: <needle>`` markers inside test files).
Real Docker execution is covered separately in ``tests/test_repository_docker_integration.py``.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hveritas import cli as cli_mod
from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST
from hveritas.repository import (
    DockerRepositoryVerifier,
    PytestOutcome,
    RepositoryRunner,
    WorkspaceError,
    WorkspacePolicy,
    apply_actions,
    changed_files,
    parse_actions,
    run_repository_goal,
    safe_copy,
)
from hveritas.repository import run as run_mod
from hveritas.repository.verifier import VerifierBudgetExceeded, parse_container_output
from hveritas.worker.backend import ModelProtocolError, ModelResponse

_REQ = re.compile(r"^# REQUIRE (\S+) :: (.+)$", re.MULTILINE)
_TEST = re.compile(r"^def (test_\w+)", re.MULTILINE)

PINNED_REPO_IMG = "img@sha256:" + ("a" * 64)


def write_action(path: str, content: str) -> dict[str, object]:
    return {"tool_name": "write_file", "tool_args": {"path": path, "content": content}}


def patch_action(path: str, old_text: str, new_text: str) -> dict[str, object]:
    return {
        "tool_name": "patch_file",
        "tool_args": {"path": path, "old_text": old_text, "new_text": new_text},
    }


def proposal(actions: list[object], test_paths: list[str] | None = None, done: bool = True) -> str:
    return json.dumps(
        {
            "summary": "change",
            "acceptance_criteria": ["goal met"],
            "test_paths": test_paths or [],
            "actions": actions,
            "done": done,
        }
    )


def oracle_text(
    tests: dict[str, str],
    *,
    goal_kind: str | None = None,
    structural_checks: list[dict[str, object]] | None = None,
) -> str:
    payload: dict[str, object] = {"tests": tests}
    if goal_kind is not None:
        payload["goal_kind"] = goal_kind
    if structural_checks is not None:
        payload["structural_checks"] = structural_checks
    return json.dumps(payload)


ORACLE_SUITE = {
    "test_add.py": "# REQUIRE src/calc.py :: return a + b\ndef test_add():\n    pass\n",
    "test_version.py": "# REQUIRE src/util.py :: VERSION = 2\ndef test_version():\n    pass\n",
}


# ------------------------------------------------------------------ fakes
class FakeBackend:
    def __init__(
        self,
        oracle: list[str],
        worker: list[str | Exception],
        oracle_family: str = "anthropic",
        worker_family: str | list[str] = "openai",
    ) -> None:
        self.oracle = list(oracle)
        self.worker = list(worker)
        self.oracle_family = oracle_family
        self.worker_family = worker_family
        self.calls: list[dict[str, object]] = []
        self._worker_idx = 0

    def complete(
        self, *, system: str, user: str, model: str | None, timeout_s: float
    ) -> ModelResponse:
        is_oracle = system == run_mod.ORACLE_SYSTEM
        self.calls.append(
            {"role": "oracle" if is_oracle else "worker", "user": user, "model": model}
        )
        if is_oracle:
            if not self.oracle:
                raise AssertionError("unexpected oracle call")
            return ModelResponse(
                text=self.oracle.pop(0),
                model=str(model or f"{self.oracle_family}-m"),
                family=self.oracle_family,
                input_tokens=10,
                output_tokens=5,
                elapsed_ms=1.0,
            )
        if not self.worker:
            raise AssertionError("unexpected worker call")
        item = self.worker.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(self.worker_family, list):
            fam = self.worker_family[min(self._worker_idx, len(self.worker_family) - 1)]
        else:
            fam = self.worker_family
        self._worker_idx += 1
        return ModelResponse(
            text=item,
            model=str(model or f"{fam}-m"),
            family=fam,
            input_tokens=10,
            output_tokens=5,
            elapsed_ms=1.0,
        )


class FakeVault:
    def __init__(self) -> None:
        self.suites: dict[str, dict[str, str]] = {}
        self.mounts = 0

    def store_oracle_suite(
        self, oracle_id: str, suite: dict[str, str], git_commit: bool = False
    ) -> None:
        self.suites[oracle_id] = dict(suite)

    @contextlib.contextmanager
    def ephemeral_verifier_mount(self, oracle_id: str, scratch_root: Path):
        self.mounts += 1
        d = Path(scratch_root) / f"mount_{os.getpid()}_{self.mounts}"
        d.mkdir(parents=True, exist_ok=True)
        for name, src in self.suites[oracle_id].items():
            (d / name).write_text(src, encoding="utf-8")
        try:
            yield d
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TextVerifier:
    """Decides outcomes from file text only; never imports or executes workspace code."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str], bool]] = []

    @staticmethod
    def _met(ws: Path, text: str) -> bool:
        for path, needle in _REQ.findall(text):
            target = ws / path
            if not target.is_file() or needle not in target.read_text(encoding="utf-8"):
                return False
        return "assert False" not in text

    def run_pytest(
        self, workspace: Path, test_paths: list[str], oracle_dir: Path | None = None
    ) -> PytestOutcome:
        self.calls.append((str(workspace), list(test_paths), oracle_dir is not None))
        files: list[tuple[str, str]] = []
        for rel in test_paths:
            p = workspace / rel
            if not p.exists():
                continue
            for f in [p] if p.is_file() else sorted(p.rglob("test_*.py")):
                files.append((f.relative_to(workspace).as_posix(), f.read_text(encoding="utf-8")))
        if oracle_dir is not None:
            for f in sorted(Path(oracle_dir).glob("*.py")):
                files.append((f"_hveritas_oracle/{f.name}", f.read_text(encoding="utf-8")))
        collected: list[str] = []
        failed: list[str] = []
        skipped: list[str] = []
        for rel, text in files:
            if "# COLLECTION_ERROR" in text:
                return PytestOutcome(
                    "error",
                    2,
                    collection_errors=(f"{rel}: SyntaxError: boom",),
                    failure_kind="collection_error",
                )
            if "# MISSING_DEP" in text:
                return PytestOutcome(
                    "error",
                    2,
                    collection_errors=(
                        f"{rel}: ModuleNotFoundError: No module named 'nonexistent_pkg'",
                    ),
                    failure_kind="missing_dependency",
                )
            is_skip = "# SKIP_ALL" in text
            ok = self._met(workspace, text)
            for name in _TEST.findall(text):
                nid = f"{rel}::{name}"
                collected.append(nid)
                if is_skip:
                    skipped.append(nid)
                elif not ok:
                    failed.append(nid)
        passed = tuple(
            nid for nid in collected if nid not in set(failed) and nid not in set(skipped)
        )
        return PytestOutcome(
            "ok",
            1 if failed else (5 if not collected else 0),
            collected=tuple(collected),
            failed=tuple(failed),
            skipped=tuple(skipped),
            passed_ids=passed,
        )


# ------------------------------------------------------------------ fixtures
CALC = "def add(a, b):\n    return a - b\n\n\ndef sub(a, b):\n    return a - b\n"
UTIL = "VERSION = 1\n"
VISIBLE = "# REQUIRE src/calc.py :: def sub\ndef test_sub():\n    pass\n"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    src = tmp_path / "repo"
    (src / "src").mkdir(parents=True)
    (src / "tests").mkdir()
    (src / "src/calc.py").write_text(CALC, encoding="utf-8")
    (src / "src/util.py").write_text(UTIL, encoding="utf-8")
    (src / "tests/test_calc.py").write_text(VISIBLE, encoding="utf-8")
    return src


def make_args(tmp_path: Path, repo: Path, **kw: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "goal": "Fix add in src/calc.py and bump VERSION to 2 in src/util.py",
        "initial_workspace": str(repo),
        "work_root": str(tmp_path / "runs"),
        "run_id": "r1",
        "max_repository_rounds": 3,
        "dry_run": False,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def ctx(ws: Path, goal: str, max_bytes: int) -> str:
    return "CTX:" + ",".join(sorted(p.name for p in ws.rglob("*.py")))


def execute(
    tmp_path: Path,
    repo: Path,
    backend: FakeBackend,
    verifier: TextVerifier | None = None,
    vault: FakeVault | None = None,
    entry: str = "runner",
    **kw: object,
):
    args = make_args(tmp_path, repo, **kw)
    actual_verifier = verifier or TextVerifier()
    actual_vault = vault or FakeVault()
    if entry == "runner":
        runner = RepositoryRunner(
            args, backend, verifier=actual_verifier, vault=actual_vault, context_builder=ctx
        )
        code = runner.run()
    else:
        code = run_repository_goal(
            args, backend, verifier=actual_verifier, vault=actual_vault, context_builder=ctx
        )
    report = json.loads((tmp_path / "runs" / str(args.run_id) / "report.json").read_text())
    return code, report, actual_verifier, actual_vault


FIX = [
    patch_action("src/calc.py", "return a - b\n\n\ndef sub", "return a + b\n\n\ndef sub"),
    write_action("src/util.py", "VERSION = 2\n"),
]


# ------------------------------------------------------------------ core contract tests
@pytest.mark.parametrize("entry", ["runner", "function"])
def test_multi_file_success(tmp_path: Path, repo: Path, entry: str) -> None:
    assert "tool_name" in run_mod.WORKER_SYSTEM
    assert "old_text" in run_mod.WORKER_SYSTEM
    be = FakeBackend([oracle_text(ORACLE_SUITE)], [proposal(FIX)])
    code, report, verifier, vault = execute(tmp_path, repo, be, entry=entry)
    assert code == 0 and report["status"] == "accepted"
    assert report["changed_files"] == ["src/calc.py", "src/util.py"]
    assert all(v for k, v in report["gates"].items() if k.startswith("gate_"))
    assert report["oracle"]["files"] == sorted(ORACLE_SUITE)
    # Source repository untouched; candidate holds the edit
    assert (repo / "src/calc.py").read_text(encoding="utf-8") == CALC
    cand = tmp_path / "runs/r1/workspace/src/calc.py"
    assert "return a + b" in cand.read_text(encoding="utf-8")
    # Visible test run NEVER had /oracle mounted; oracle ran in separate invocation
    assert any(has_orc is False for _, _, has_orc in verifier.calls)
    assert any(paths == [] and has_orc is True for _, paths, has_orc in verifier.calls)
    # Oracle content never reaches the worker prompt or report
    worker_users = [str(c["user"]) for c in be.calls if c["role"] == "worker"]
    assert worker_users and all("REQUIRE src/util.py" not in u for u in worker_users)
    assert "REQUIRE src/util.py" not in json.dumps(report)
    assert vault.mounts >= 2
    assert (tmp_path / "runs/r1/report.md").is_file()
    assert (tmp_path / "runs/r1/patch.diff").is_file()
    events = [
        json.loads(line)["event"]
        for line in (tmp_path / "runs/r1/events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert "oracle_sealed" in events and events[-1] == "run_finished"


def test_read_request_then_repair_same_worker_multi_round(tmp_path: Path, repo: Path) -> None:
    """Same worker family across 3 rounds must NOT trigger false family collision."""
    partial = [write_action("src/util.py", "VERSION = 2\n")]
    be = FakeBackend(
        [oracle_text(ORACLE_SUITE)],
        [
            json.dumps({"read_files": ["src/calc.py", "../etc/passwd"]}),
            proposal(partial),
            proposal(FIX[:1]),
        ],
        oracle_family="claude",
        worker_family="gemini",
    )
    code, report, *_ = execute(tmp_path, repo, be)
    assert code == 0 and report["status"] == "accepted"
    statuses = [r["status"] for r in report["rounds"]]
    assert statuses == ["read_files", "applied", "applied"]
    worker_users = [str(c["user"]) for c in be.calls if c["role"] == "worker"]
    assert "REQUESTED FILE SNAPSHOTS" in worker_users[1] and "return a - b" in worker_users[1]
    assert "<rejected" in worker_users[1]
    assert "hidden acceptance checks passing: 1/2" in worker_users[2]
    assert report["rounds"][1]["gates"]["gate_oracle_pass"] is False


@pytest.mark.parametrize(
    ("oracle_fam", "worker_fam"),
    [
        ("Anthropic", " anthropic "),
        ("anthropic", "claude"),
        ("google", "gemini"),
        ("claude", ""),
        ("claude", "unknown"),
    ],
)
def test_family_collision_and_unknown_family_fail_closed(
    tmp_path: Path, repo: Path, oracle_fam: str, worker_fam: str
) -> None:
    be = FakeBackend(
        [oracle_text(ORACLE_SUITE)],
        [proposal(FIX)],
        oracle_family=oracle_fam,
        worker_family=worker_fam,
    )
    code, report, *_ = execute(tmp_path, repo, be)
    assert code == 1 and report["status"] == "failed"
    assert "FamilyCollisionError" in report["reason"]
    assert (tmp_path / "runs/r1/workspace/src/calc.py").read_text(encoding="utf-8") == CALC


def test_worker_failover_checks_runtime_family(tmp_path: Path, repo: Path) -> None:
    """Failover to a 3rd family succeeds; failover returning oracle's family fails closed."""
    # Case 1: Failover from gemini -> openai while oracle is claude => accepted
    be_ok = FakeBackend(
        [oracle_text(ORACLE_SUITE)],
        [ModelProtocolError("primary transient error"), proposal(FIX)],
        oracle_family="claude",
        worker_family=["openai"],
    )
    code_ok, rep_ok, *_ = execute(
        tmp_path, repo, be_ok, run_id="failover_ok", alternate_model="luna"
    )
    assert code_ok == 0 and rep_ok["status"] == "accepted"
    assert rep_ok["models"]["failover_used"] is True
    assert rep_ok["models"]["worker_family"] == "openai"

    # Case 2: Failover alias claims distinct name, but runtime response.family collides with oracle!
    be_bad = FakeBackend(
        [oracle_text(ORACLE_SUITE)],
        [ModelProtocolError("primary transient error"), proposal(FIX)],
        oracle_family="claude",
        worker_family=["anthropic"],
    )
    code_bad, rep_bad, *_ = execute(
        tmp_path, repo, be_bad, run_id="failover_collision", alternate_model="disguised-claude"
    )
    assert code_bad == 1 and rep_bad["status"] == "failed"
    assert "FamilyCollisionError" in rep_bad["reason"]


@pytest.mark.parametrize(
    "path", ["tests/test_calc.py", "conftest.py", "tests/conftest.py", "pyproject.toml"]
)
def test_immutable_paths_rejected_atomically(tmp_path: Path, repo: Path, path: str) -> None:
    bad = [write_action("src/util.py", "VERSION = 2\n"), write_action(path, "x = 1\n")]
    be = FakeBackend([oracle_text(ORACLE_SUITE)], [proposal(bad), proposal(FIX)])
    code, report, *_ = execute(tmp_path, repo, be)
    assert report["rounds"][0]["status"] == "rejected_actions"
    assert code == 0
    assert (tmp_path / "runs/r1/workspace/tests/test_calc.py").read_text(
        encoding="utf-8"
    ) == VISIBLE
    worker_users = [str(c["user"]) for c in be.calls if c["role"] == "worker"]
    assert "Actions rejected (nothing applied)" in worker_users[1]


def test_atomic_batch_rolls_back_earlier_writes_on_later_patch_failure(repo: Path) -> None:
    """Direct workspace test: if action #2 fails patch uniqueness, action #1 leaves zero trace."""
    orig_files = frozenset(["src/calc.py", "src/util.py", "tests/test_calc.py"])
    actions = parse_actions(
        [
            write_action("src/util.py", "VERSION = 99\n"),
            patch_action(
                "src/calc.py", "return a - b", "return a + b"
            ),  # matches TWICE -> rejected!
        ]
    )
    with pytest.raises(ValueError, match="exactly once"):
        apply_actions(repo, actions, orig_files)
    assert (repo / "src/util.py").read_text(encoding="utf-8") == UTIL


def test_explicit_workspace_policy_required_for_test_or_config_edits(
    tmp_path: Path, repo: Path
) -> None:
    dest = tmp_path / "copy"
    copied = frozenset(safe_copy(repo, dest))
    edit_cfg = parse_actions([write_action("pyproject.toml", "[project]\nname='x'\n")])
    with pytest.raises(ValueError, match="protected path"):
        apply_actions(dest, edit_cfg, copied, policy=WorkspacePolicy())
    receipts = apply_actions(
        dest, edit_cfg, copied, policy=WorkspacePolicy(allow_config_edits=True)
    )
    assert len(receipts) == 1 and receipts[0].path == "pyproject.toml"


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[1, 2]",
        json.dumps({"summary": "s", "actions": []}),
        json.dumps(
            {
                "summary": "s",
                "acceptance_criteria": [],
                "test_paths": [],
                "actions": [],
                "done": True,
                "x": 1,
            }
        ),
        json.dumps(
            {"summary": 1, "acceptance_criteria": [], "test_paths": [], "actions": [], "done": True}
        ),
        json.dumps({"read_files": []}),
        proposal([write_action("../escape.py", "x")]),
        proposal([write_action("-option.py", "x")]),
        proposal([{"type": "shell", "path": "a.py", "cmd": "rm -rf /"}]),
        # Legacy 'old'/'new' keys rejected under unified patch_file(path, old_text, new_text) contract
        proposal(
            [
                {
                    "tool_name": "patch_file",
                    "tool_args": {"path": "src/util.py", "old": "1", "new": "2"},
                }
            ]
        ),
    ],
)
def test_schema_violations_are_rejected(tmp_path: Path, repo: Path, text: str) -> None:
    be = FakeBackend([oracle_text(ORACLE_SUITE)], [text, proposal(FIX)])
    code, report, *_ = execute(tmp_path, repo, be)
    assert report["rounds"][0]["status"] == "invalid_schema"
    assert code == 0


def test_fenced_json_accepted(tmp_path: Path, repo: Path) -> None:
    be = FakeBackend(
        ["```json\n" + oracle_text(ORACLE_SUITE) + "\n```"],
        ["```\n" + proposal(FIX) + "\n```"],
    )
    code, _report, *_ = execute(tmp_path, repo, be)
    assert code == 0


def test_baseline_regression_ids_and_frozen_manifest_block_acceptance(
    tmp_path: Path, repo: Path
) -> None:
    """Worker cannot narrow frozen manifest via proposal test_paths; breaking test_sub fails."""
    breaking = [
        *FIX,
        patch_action("src/calc.py", "def sub(a, b):\n    return a - b\n", ""),
        write_action("tests/test_extra.py", "def test_extra():\n    pass\n"),
    ]
    # Worker passes ONLY tests/test_extra.py in proposal.test_paths attempting to hide tests/test_calc.py!
    be = FakeBackend([oracle_text(ORACLE_SUITE)], [proposal(breaking, ["tests/test_extra.py"])])
    code, report, *_ = execute(tmp_path, repo, be, max_repository_rounds=1)
    assert code == 1 and report["status"] == "failed"
    assert report["baseline"]["tests_collected"] == ["tests/test_calc.py::test_sub"]
    assert report["baseline"]["tests_failed"] == []
    gates = report["gates"]
    assert gates["gate_no_regressions"] is False
    assert gates["gate_oracle_pass"] is True


def test_newly_skipped_baseline_test_blocks_acceptance(tmp_path: Path, repo: Path) -> None:
    class _SkipInjectingVerifier(TextVerifier):
        def run_pytest(self, workspace, test_paths, oracle_dir=None):
            out = super().run_pytest(workspace, test_paths, oracle_dir)
            if oracle_dir is None and len(self.calls) > 1:
                return PytestOutcome(
                    "ok",
                    0,
                    collected=out.collected,
                    skipped=out.collected,
                    passed_ids=(),
                )
            return out

    be = FakeBackend([oracle_text(ORACLE_SUITE)], [proposal(FIX)])
    code, report, *_ = execute(
        tmp_path, repo, be, verifier=_SkipInjectingVerifier(), max_repository_rounds=1
    )
    assert code == 1 and report["gates"]["gate_no_regressions"] is False
    assert "regressed_passed_ids" in report["gate_reasons"]["gate_no_regressions"]


def test_failing_added_test_blocks_acceptance(tmp_path: Path, repo: Path) -> None:
    acts = [*FIX, write_action("tests/test_new.py", "def test_new():\n    assert False\n")]
    be = FakeBackend([oracle_text(ORACLE_SUITE)], [proposal(acts, ["tests/test_new.py"])])
    code, report, *_ = execute(tmp_path, repo, be, max_repository_rounds=1)
    assert code == 1 and report["gates"]["gate_added_tests_pass"] is False


def test_empty_added_test_file_blocks_acceptance(tmp_path: Path, repo: Path) -> None:
    acts = [*FIX, write_action("tests/test_empty.py", "# zero test functions\nx = 1\n")]
    be = FakeBackend([oracle_text(ORACLE_SUITE)], [proposal(acts, ["tests/test_empty.py"])])
    code, report, *_ = execute(tmp_path, repo, be, max_repository_rounds=1)
    assert code == 1 and report["gates"]["gate_added_tests_pass"] is False


@pytest.mark.parametrize(
    ("marker", "expected_needle"),
    [
        ("# zero tests\n", "zero tests"),
        ("# COLLECTION_ERROR\ndef test_a(): pass\n", "collection error"),
        ("# MISSING_DEP\ndef test_a(): pass\n", "missing dependency"),
    ],
)
def test_baseline_zero_collection_and_dependency_errors_blocked(
    tmp_path: Path, repo: Path, marker: str, expected_needle: str
) -> None:
    (repo / "tests/test_calc.py").write_text(marker, encoding="utf-8")
    be = FakeBackend([], [])
    code, report, *_ = execute(tmp_path, repo, be)
    assert code == 2 and report["status"] == "blocked"
    assert expected_needle in report["reason"]
    assert be.calls == []


def test_non_python_repository_blocked(tmp_path: Path) -> None:
    js_repo = tmp_path / "js_repo"
    js_repo.mkdir()
    (js_repo / "index.js").write_text("console.log(1);\n", encoding="utf-8")
    be = FakeBackend([], [])
    code, report, *_ = execute(tmp_path, js_repo, be)
    assert code == 2 and report["status"] == "blocked"
    assert "Python" in report["reason"]


@pytest.mark.parametrize(
    "bad",
    [
        oracle_text({}),
        json.dumps({"tests": {"evil/../x.py": "def test_a(): pass"}}),
        json.dumps({"tests": {"conftest.py": "x"}}),
        "garbage",
    ],
)
def test_oracle_zero_or_invalid_tests_blocked(tmp_path: Path, repo: Path, bad: str) -> None:
    be = FakeBackend([bad], [])
    code, report, *_ = execute(tmp_path, repo, be)
    assert code == 2 and report["status"] == "blocked"
    assert "oracle response invalid" in report["reason"]
    assert not [c for c in be.calls if c["role"] == "worker"]


def test_non_discriminating_oracle_blocked(tmp_path: Path, repo: Path) -> None:
    suite = {"test_trivial.py": "# REQUIRE src/util.py :: VERSION\ndef test_trivial():\n    pass\n"}
    be = FakeBackend([oracle_text(suite)], [])
    code, report, *_ = execute(tmp_path, repo, be)
    assert code == 2 and "non-discriminating" in report["reason"]


def test_refactor_goal_kind_allows_passing_baseline_oracle_with_ast_structural_gate(
    tmp_path: Path, repo: Path
) -> None:
    """Behavior-preserving refactor: oracle passes on baseline; AST structural checks gate acceptance."""
    refactor_oracle = {
        "test_behavior.py": "# REQUIRE src/calc.py :: sub(\ndef test_sub_preserved():\n    pass\n"
    }
    struct_checks = [
        {"kind": "module_exists", "path": "src/ops.py"},
        {"kind": "symbol_defined", "path": "src/ops.py", "symbols": ["sub_impl"]},
        {
            "kind": "symbol_imported_from",
            "path": "src/calc.py",
            "module": "ops",
            "symbols": ["sub_impl"],
        },
    ]
    refactor_actions = [
        write_action("src/ops.py", "def sub_impl(a, b):\n    return a - b\n"),
        write_action(
            "src/calc.py",
            "from ops import sub_impl\n\n\ndef add(a, b):\n    return a - b\n\n\ndef sub(a, b):\n    return sub_impl(a, b)\n",
        ),
    ]
    be = FakeBackend(
        [oracle_text(refactor_oracle, goal_kind="refactor", structural_checks=struct_checks)],
        [proposal(refactor_actions)],
    )
    code, report, *_ = execute(tmp_path, repo, be, goal_kind="refactor")
    assert code == 0 and report["status"] == "accepted"
    assert report["gates"]["gate_structural_criteria"] is True
    assert report["gates"]["gate_oracle_pass"] is True


def test_refactor_line_count_only_structural_check_rejected(tmp_path: Path, repo: Path) -> None:
    refactor_oracle = {
        "test_behavior.py": "# REQUIRE src/calc.py :: def sub\ndef test_sub_preserved():\n    pass\n"
    }
    line_only = [{"kind": "max_file_lines", "path": "src/calc.py", "max_lines": 3}]
    be = FakeBackend(
        [oracle_text(refactor_oracle, goal_kind="refactor", structural_checks=line_only)],
        [],
    )
    code, report, *_ = execute(tmp_path, repo, be, goal_kind="refactor")
    assert code == 2 and report["status"] == "blocked"
    assert "max_file_lines alone" in report["reason"]


def test_noop_worker_never_accepted_and_content_hash_diff_accurate(
    tmp_path: Path, repo: Path
) -> None:
    be = FakeBackend([oracle_text(ORACLE_SUITE)], [proposal([]), proposal([])])
    code, report, *_ = execute(tmp_path, repo, be, max_repository_rounds=2)
    assert code == 1 and report["status"] == "failed"
    assert report["gates"]["gate_code_changed"] is False
    assert report["changed_files"] == []

    # Direct hash-diff check: modifying an existing file WITHOUT adding/removing paths is detected!
    copy_a = tmp_path / "copy_a"
    copy_b = tmp_path / "copy_b"
    safe_copy(repo, copy_a)
    safe_copy(repo, copy_b)
    (copy_b / "src/util.py").write_text("VERSION = 2\n", encoding="utf-8")
    assert changed_files(copy_a, copy_b) == ["src/util.py"]


def test_round_limit_with_clean_progress_reports_partial(tmp_path: Path, repo: Path) -> None:
    """When round limit expires after clean non-regressing partial work, status is 'partial' (exit 3)."""
    half_done = [write_action("src/util.py", "VERSION = 2\n")]
    be = FakeBackend([oracle_text(ORACLE_SUITE)], [proposal(half_done, done=False)])
    code, report, *_ = execute(tmp_path, repo, be, max_repository_rounds=1)
    assert code == 3 and report["status"] == "partial"
    assert report["changed_files"] == ["src/util.py"]
    assert report["pending_steps"]
    assert report["required_evidence"]


def test_dry_run_makes_no_model_or_verifier_calls(tmp_path: Path, repo: Path) -> None:
    be = FakeBackend([], [])
    code, report, verifier, vault = execute(tmp_path, repo, be, dry_run=True)
    assert code == 0 and report["status"] == "dry_run"
    assert be.calls == [] and verifier.calls == [] and vault.suites == {}
    assert (tmp_path / "runs/r1/original/src/calc.py").read_text(encoding="utf-8") == CALC


@pytest.mark.parametrize(
    ("kw", "needle"),
    [
        ({"resume": "x"}, "resume"),
        ({"assurance": "high"}, "standard only"),
        ({"include_t2": True}, "include-t2"),
        ({"goal": "  "}, "goal is empty"),
        ({"initial_workspace": None}, "initial-workspace"),
        ({"max_repository_rounds": 99}, "1..20"),
    ],
)
def test_preflight_blocks(tmp_path: Path, repo: Path, kw: dict[str, object], needle: str) -> None:
    code, report, *_ = execute(tmp_path, repo, FakeBackend([], []), **kw)
    assert code == 2 and needle in report["reason"]


def test_existing_run_dir_and_unsafe_paths_make_zero_writes(tmp_path: Path, repo: Path) -> None:
    existing = tmp_path / "runs/r1"
    existing.mkdir(parents=True)
    sentinel = existing / "keep.txt"
    sentinel.write_text("untouched", encoding="utf-8")
    args = make_args(tmp_path, repo)
    assert (
        run_repository_goal(
            args,
            FakeBackend([], []),
            verifier=TextVerifier(),
            vault=FakeVault(),
            context_builder=ctx,
        )
        == 2
    )
    assert list(existing.iterdir()) == [sentinel]

    # Traversal run_id, report_out inside source repo, and source/work_root overlap
    for bad_kw in [
        {"run_id": "../escape"},
        {"run_id": "-flag"},
        {"report_out": str(repo / "leak_report.json")},
        {"work_root": str(repo)},
    ]:
        bad_args = make_args(tmp_path, repo, **bad_kw)
        assert (
            run_repository_goal(
                bad_args,
                FakeBackend([], []),
                verifier=TextVerifier(),
                vault=FakeVault(),
                context_builder=ctx,
            )
            == 2
        )
    assert not (repo / "leak_report.json").exists()


def test_workspace_refuses_symlinks_hardlinks_and_special_files_but_skips_venvs(
    tmp_path: Path, repo: Path
) -> None:
    # A .venv-dev directory containing symlinks MUST be skipped cleanly without scanning
    venv_bin = repo / ".venv-dev" / "bin"
    venv_bin.mkdir(parents=True)
    (repo / ".venv-dev" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (venv_bin / "python").symlink_to("/usr/bin/python3")
    clean_dst = tmp_path / "clean_copy"
    copied = safe_copy(repo, clean_dst)
    assert "src/calc.py" in copied
    assert not any(".venv-dev" in p for p in copied)

    # 1) Symlink inside source tree -> refused
    sym_repo = tmp_path / "sym_repo"
    shutil.copytree(clean_dst, sym_repo)
    (sym_repo / "src/evil.py").symlink_to("/etc/passwd")
    with pytest.raises(WorkspaceError, match="symlink"):
        safe_copy(sym_repo, tmp_path / "out_sym")

    # 2) Hardlink inside source tree -> refused
    hl_repo = tmp_path / "hl_repo"
    shutil.copytree(clean_dst, hl_repo)
    os.link(hl_repo / "src/util.py", hl_repo / "src/hardlinked.py")
    with pytest.raises(WorkspaceError, match="hardlink"):
        safe_copy(hl_repo, tmp_path / "out_hl")

    # 3) Unix domain socket / FIFO special file inside source tree -> refused
    fifo_repo = tmp_path / "fifo_repo"
    shutil.copytree(clean_dst, fifo_repo)
    os.mkfifo(fifo_repo / "src/named_pipe")
    with pytest.raises(WorkspaceError, match="special file"):
        safe_copy(fifo_repo, tmp_path / "out_fifo")
    sock_path = Path(f"/dev/shm/hv_sock_{os.getpid()}")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind(str(sock_path))
    finally:
        s.close()
        sock_path.unlink(missing_ok=True)


# ------------------------------------------------------------------ docker verifier (mocked + adversarial)
def test_unpinned_docker_images_rejected() -> None:
    for unpinned in ["img", "python:3.12", "hveritas-verifier:latest", "img@sha256:abc", "-bad"]:
        with pytest.raises(ValueError, match="sha256"):
            DockerRepositoryVerifier(unpinned)
    # Both canonical pinned formats succeed
    assert (
        DockerRepositoryVerifier(DEFAULT_VERIFIER_IMAGE_DIGEST).image_digest
        == DEFAULT_VERIFIER_IMAGE_DIGEST
    )
    assert DockerRepositoryVerifier(PINNED_REPO_IMG).image_digest == PINNED_REPO_IMG


def test_docker_build_command_hardening() -> None:
    v = DockerRepositoryVerifier(PINNED_REPO_IMG, docker_bin="docker")
    cmd = v.build_command(Path("/stage/ws"), ["tests"], Path("/orc"), "hv-x", nonce="deadbeef" * 4)
    joined = " ".join(cmd)
    for flag in [
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "no-new-privileges",
        "--user 10001:10001",
        "--pids-limit 256",
        "/stage/ws:/workspace:ro",
        "/hv_verifier:ro",
        "/orc:/oracle:ro",
    ]:
        assert flag in joined
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert PINNED_REPO_IMG in cmd
    assert json.loads(cmd[-1])["paths"] == ["tests"]
    no_oracle = v.build_command(Path("/stage/ws"), [], None, "hv-y")
    assert "/oracle:ro" not in " ".join(no_oracle)


def test_docker_run_pytest_parses_nonced_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.py").write_text("x = 1\n", encoding="utf-8")
    seen: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **_kw: object) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        nonce = json.loads(cmd[-1])["nonce"]
        res = {
            "session_finished": True,
            "collected": ["t::a", "t::b"],
            "passed": ["t::a"],
            "failed": ["t::b"],
            "errors": [],
            "skipped": [],
            "xfailed": [],
            "xpassed": [],
            "collection_errors": [],
            "exit_code": 1,
        }
        return subprocess.CompletedProcess(
            cmd, 0, f"noise\nHV_RESULT_{nonce}=" + json.dumps(res) + "\n", ""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    v = DockerRepositoryVerifier(DEFAULT_VERIFIER_IMAGE_DIGEST, scratch_root=tmp_path / "scratch")
    out = v.run_pytest(ws, ["t"])
    assert out.status == "ok" and out.passed == frozenset({"t::a"})
    assert seen["cmd"][0] == "docker"
    assert list((tmp_path / "scratch").iterdir()) == []  # staging cleaned


def test_docker_timeout_and_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **_kw: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if cmd[1] == "run":
            raise subprocess.TimeoutExpired(cmd, 1, output=b"partial")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    ws = tmp_path / "ws"
    ws.mkdir()
    v = DockerRepositoryVerifier(
        DEFAULT_VERIFIER_IMAGE_DIGEST,
        scratch_root=tmp_path / "s",
        per_run_timeout_s=1,
        global_timeout_s=1,
    )
    out = v.run_pytest(ws, [])
    assert out.status == "timeout"
    assert any(c[1] in ("rm", "kill") for c in calls[1:]) and calls[-1][1] == "kill"
    with pytest.raises(VerifierBudgetExceeded):
        v.run_pytest(ws, [])


def test_parse_container_output_rejects_spoofed_or_incomplete_evidence() -> None:
    nonce = "11223344556677889900aabbccddeeff"
    cmd = ["docker", "run", "req"]
    assert parse_container_output(125, "", "boom", 0.1, cmd, expected_nonce=nonce).status == "error"
    assert (
        parse_container_output(0, "no marker", "", 0.1, cmd, expected_nonce=nonce).status == "error"
    )

    # Candidate stdout spoofing un-nonced HV_RESULT= or wrong nonce -> rejected!
    fake = json.dumps(
        {
            "session_finished": True,
            "collected": ["t::a"],
            "passed": ["t::a"],
            "failed": [],
            "collection_errors": [],
            "exit_code": 0,
        }
    )
    spoof_out = parse_container_output(0, f"HV_RESULT={fake}\n", "", 0.1, cmd, expected_nonce=nonce)
    assert spoof_out.status == "error" and spoof_out.passed == frozenset()

    # Missing 'passed' field -> never defaults to passed!
    missing_passed = json.dumps(
        {"session_finished": True, "collected": ["t::a"], "failed": [], "exit_code": 0}
    )
    mp_out = parse_container_output(
        0, f"HV_RESULT_{nonce}={missing_passed}\n", "", 0.1, cmd, expected_nonce=nonce
    )
    assert mp_out.status == "error" and mp_out.passed == frozenset()

    # Unaccounted collected item (early pytest.exit / partial execution) -> rejected!
    partial_exec = json.dumps(
        {
            "session_finished": True,
            "collected": ["t::a", "t::b"],
            "passed": ["t::a"],
            "failed": [],
            "collection_errors": [],
            "exit_code": 0,
        }
    )
    pe_out = parse_container_output(
        0, f"HV_RESULT_{nonce}={partial_exec}\n", "", 0.1, cmd, expected_nonce=nonce
    )
    assert pe_out.status == "error" and pe_out.failure_kind == "corrupt_evidence"

    # Contradictory exit_code=0 when failed is non-empty -> rejected!
    contradict = json.dumps(
        {
            "session_finished": True,
            "collected": ["t::a"],
            "passed": [],
            "failed": ["t::a"],
            "collection_errors": [],
            "exit_code": 0,
        }
    )
    ct_out = parse_container_output(
        0, f"HV_RESULT_{nonce}={contradict}\n", "", 0.1, cmd, expected_nonce=nonce
    )
    assert ct_out.status == "error" and ct_out.passed == frozenset()


# ------------------------------------------------------------------ CLI dispatch tests
def test_cli_repository_dispatch_and_exit_codes(
    tmp_path: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1) --repository --dry-run via real CLI entrypoint returns 0 and status=dry_run
    rc_dry = cli_mod.main(
        [
            "run",
            "--repository",
            "--dry-run",
            "--initial-workspace",
            str(repo),
            "--work-root",
            str(tmp_path / "cli_runs"),
            "--run-id",
            "cli_dry",
            "--goal",
            "Inspect and fix calc",
        ]
    )
    assert rc_dry == 0
    rep_dry = json.loads((tmp_path / "cli_runs/cli_dry/report.json").read_text(encoding="utf-8"))
    assert rep_dry["status"] == "dry_run"

    # 2) --repository with unsupported --assurance fast returns 2 (blocked)
    rc_blk = cli_mod.main(
        [
            "run",
            "--repository",
            "--assurance",
            "fast",
            "--initial-workspace",
            str(repo),
            "--work-root",
            str(tmp_path / "cli_runs"),
            "--run-id",
            "cli_blk",
            "--goal",
            "Fix calc",
            "--backend",
            "fake",
        ]
    )
    assert rc_blk == 2
    rep_blk = json.loads((tmp_path / "cli_runs/cli_blk/report.json").read_text(encoding="utf-8"))
    assert rep_blk["status"] == "blocked"

    # 3) --repository full fake-responses flow through CLI main() with TextVerifier
    monkeypatch.setattr(
        "hveritas.repository.run.DockerRepositoryVerifier", lambda **_kw: TextVerifier()
    )
    responses_file = tmp_path / "fake_responses.json"
    responses_file.write_text(
        json.dumps(
            [
                {
                    "text": oracle_text(ORACLE_SUITE),
                    "model": "sonnet-claude",
                    "family": "claude",
                    "input_tokens": 20,
                    "output_tokens": 10,
                    "elapsed_ms": 2.0,
                },
                {
                    "text": proposal(FIX),
                    "model": "argon",
                    "family": "gemini",
                    "input_tokens": 30,
                    "output_tokens": 15,
                    "elapsed_ms": 3.0,
                },
            ]
        ),
        encoding="utf-8",
    )
    rc_acc = cli_mod.main(
        [
            "run",
            "--repository",
            "--backend",
            "fake",
            "--fake-responses",
            str(responses_file),
            "--initial-workspace",
            str(repo),
            "--work-root",
            str(tmp_path / "cli_runs"),
            "--run-id",
            "cli_acc",
            "--goal",
            "Fix add in src/calc.py and bump VERSION to 2 in src/util.py",
        ]
    )
    assert rc_acc == 0
    rep_acc = json.loads((tmp_path / "cli_runs/cli_acc/report.json").read_text(encoding="utf-8"))
    assert rep_acc["status"] == "accepted"


def test_cli_verifier_image_pinning_and_fixture_missing_dep(tmp_path: Path, repo: Path) -> None:
    from hveritas.cli import main

    rc_bad = main(
        [
            "run",
            "--repository",
            "--dry-run",
            "--verifier-image",
            "python:3.12-slim",
            "--initial-workspace",
            str(repo),
            "--work-root",
            str(tmp_path / "runs"),
            "--run-id",
            "unpinned_img",
            "--goal",
            "Fix add",
        ]
    )
    assert rc_bad == 2
    rep_bad = json.loads((tmp_path / "runs/unpinned_img/report.json").read_text(encoding="utf-8"))
    assert rep_bad["status"] == "blocked"
    assert "verifier_image" in rep_bad["reason"]

    pinned = "local/verifier@sha256:" + ("b" * 64)
    rc_ok = main(
        [
            "run",
            "--repository",
            "--dry-run",
            "--verifier-image",
            pinned,
            "--initial-workspace",
            str(repo),
            "--work-root",
            str(tmp_path / "runs"),
            "--run-id",
            "pinned_img",
            "--goal",
            "Fix add",
        ]
    )
    assert rc_ok == 0
    rep_ok = json.loads((tmp_path / "runs/pinned_img/report.json").read_text(encoding="utf-8"))
    assert rep_ok["verifier_image"] == pinned


def test_safe_copy_preserves_code_keys_module_and_drops_secrets(tmp_path: Path) -> None:
    src = tmp_path / "src_repo"
    (src / "ui").mkdir(parents=True)
    (src / "ui/keys.py").write_text("class Key:\n    pass\n", encoding="utf-8")
    (src / "api_keys.py").write_text("SECRET = 'x'\n", encoding="utf-8")
    (src / "keys.json").write_text("{}", encoding="utf-8")
    copied = safe_copy(src, tmp_path / "dst_repo")
    assert copied == ["ui/keys.py"]


def test_hx_cli_backend_handles_prompt_exceeding_max_arg_strlen(tmp_path: Path) -> None:
    from hveritas.worker.backend import HxCliBackend

    fake_hx = tmp_path / "fake_hx.py"
    fake_hx.write_text(
        "#!/usr/bin/env python3\n"
        "import argparse, json, sys\n"
        "ap = argparse.ArgumentParser()\n"
        "ap.add_argument('-p', '--prompt', required=True)\n"
        "ap.add_argument('-m', '--model', default='argon')\n"
        "ap.add_argument('--preset', default='minimal')\n"
        "ap.add_argument('--no-commit', action='store_true')\n"
        "ap.add_argument('--json', action='store_true')\n"
        "ap.add_argument('-C', '--cwd', default='.')\n"
        "ns = ap.parse_args()\n"
        "print(json.dumps({\n"
        "  'ok': True,\n"
        "  'text': json.dumps({'prompt_len': len(ns.prompt)}),\n"
        "  'model': ns.model,\n"
        "  'family': 'gemini',\n"
        "  'input_tokens': 100,\n"
        "  'output_tokens': 10,\n"
        "  'elapsed_ms': 5.0,\n"
        "}))\n",
        encoding="utf-8",
    )
    fake_hx.chmod(0o755)
    backend = HxCliBackend(hx_bin=fake_hx, planner_scratch_root=tmp_path / "scratch")
    huge_user = "X" * 150_000
    resp = backend.complete(system="sys", user=huge_user, model="argon", timeout_s=15.0)
    assert resp.family == "gemini"
    assert json.loads(resp.text)["prompt_len"] > 150_000


def test_read_snapshots_line_range_slicing_and_secret_policy(tmp_path: Path) -> None:
    from hveritas.repository.workspace import read_snapshots

    big = tmp_path / "pkg" / "large.py"
    big.parent.mkdir(parents=True)
    lines = [f"def fn_{i}() -> int:\n    return {i}\n" for i in range(1, 1501)]
    big.write_text("".join(lines), encoding="utf-8")
    assert big.stat().st_size > 20_000

    secret_file = tmp_path / "pkg" / "client_cfg.py"
    secret_file.write_text(
        "API_KEY = 'ghp_" + "abcdefghijklmnopqrstuvwxyz123456'\n"
        + "".join(f"x_{i} = {i}\n" for i in range(1, 50)),
        encoding="utf-8",
    )

    snaps, n_bytes = read_snapshots(
        tmp_path,
        [
            "pkg/large.py:2401-2404",
            "pkg/large.py:10-5",
            "pkg/client_cfg.py:20-30",
        ],
    )
    assert (
        snaps["pkg/large.py:2401-2404"]
        == "def fn_1201() -> int:\n    return 1201\ndef fn_1202() -> int:\n    return 1202\n"
    )
    assert snaps["pkg/large.py:10-5"] == "<rejected: invalid line range>"
    assert snaps["pkg/client_cfg.py:20-30"] == "<rejected: secret content policy>"
    assert n_bytes == len(snaps["pkg/large.py:2401-2404"].encode("utf-8"))
