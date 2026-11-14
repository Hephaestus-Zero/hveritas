# Hveritas Repository Mode — Architectural Contract & Invariants

Repository mode (`hveritas run --repository ...`) is an **explicitly opted-in, additive** execution flow for verifying bounded changes on existing multi-file Python repositories while keeping the default function-task pipeline (`M0`–`M9`) 100% backward compatible.

---

## 1. Module Responsibilities (Single Source of Truth)

| Module | Single Responsibility |
|---|---|
| `src/hveritas/spec/repository_context.py` | Bounded, deterministic, `O_NOFOLLOW`-pinned read-only repository evidence (`repository-context-v1`) + shared directory/secret classification helpers. Never executes code or follows symlinks. |
| `src/hveritas/repository/workspace.py` | Preflight path validation (`validate_run_paths`), immutable source copy (`safe_copy`), symlink/special-file/hardlink refusal, `read_snapshots` under the unified secret/path policy, strict `Action` schema (`parse_actions`), explicit `WorkspacePolicy`, atomic staging (`apply_actions` with before/after SHA-256 digests), and SHA-256 content-diff calculation. |
| `src/hveritas/repository/verifier.py` | Isolated Docker `pytest` execution (`DockerRepositoryVerifier`), read-only `/hv_verifier` supervisor + CSPRNG nonce channel (`HV_RESULT_<nonce>=`), container cleanup on timeout, and typed `PytestOutcome` parsing with fail-closed evidence completeness checks. |
| `src/hveritas/repository/run.py` | `RepositoryRunner` + `run_repository_goal`: preflight & dry-run, frozen baseline manifest, cross-family Oracle synthesis & vault sealing, AST structural checks (`evaluate_structural_checks`), bounded multi-round `context -> proposal -> validate -> stage -> verify -> feedback -> repair` loop, global wall-clock/byte/call budgets, append-only `events.jsonl`, and sanitized `report.json` / `report.md`. |
| `src/hveritas/cli.py` | Explicit `--repository` mode flags (`--repository`, `--goal-kind`, `--max-repository-rounds`, `--test-paths`, `--structural-criteria`, `--repo-wall-timeout`, `--repo-test-timeout`), validation, and consistent exit-code dispatch without altering legacy `hveritas run`. |

---

## 2. Non-Negotiable Repository-Mode Invariants (`R1`–`R12`)

- **`R1` (Preflight Before Side-Effects):** `run_id`, `initial_workspace`, `work_root`, `run_dir`, and `report_out` are validated *before* any directory or file is created. Existing `run_dir`, path traversal, option-prefix `-`, symlink ancestors, `source`/`run_dir` overlap, and `report_out` inside `source` fail closed (`blocked`, exit `2`).
- **`R2` (Source Immutability & Link/Special-File Policy):** `initial_workspace` is never mutated. Excluded cache/VCS/virtualenv directories (`.git`, `.venv*`, `venv*`, `pyvenv.cfg` roots, `node_modules`, `__pycache__`, etc.) are skipped *before* descent. Any symlink, FIFO/socket/device special file, or multi-link hardlink (`st_nlink > 1`) in the non-excluded source tree raises `WorkspaceError`.
- **`R3` (Side-Effect-Free JSON Planner):** Model backends never execute host tools or shell commands. Repository excerpts are framed as untrusted data, never system instructions.
- **`R4` (Single Strict Action Schema & Atomic Batch):** Only `write_file(path, content)` and `patch_file(path, old_text, new_text)` exist across prompts, parsers, tests, and reports. Unknown keys, type mismatches, traversal paths, and non-unique patches fail closed. Every round stages onto a sibling copy and swaps atomically; if action `k` fails, actions `0..k-1` leave zero trace.
- **`R5` (Protected Test & Config Infrastructure):** Under default `WorkspacePolicy(allow_test_edits=False, allow_config_edits=False)`, existing test files, `conftest.py`, `sitecustomize.py`, `usercustomize.py`, `.github/**`, and build/test configs (`pyproject.toml`, `pytest.ini`, `*.toml`, `*.ini`, `*.cfg`, `*.yaml`, `*.yml`, lockfiles) are immutable. Adding *new* `tests/**/test_*.py` files is permitted and gated by `gate_added_tests_pass`.
- **`R6` (Frozen Regression Manifest & Node-ID Gate):** Baseline test files are frozen before worker execution (`proposal.test_paths` can union additional tests, never narrow the frozen manifest). Acceptance requires: `0` disappeared baseline test IDs, `100%` of baseline-passing IDs still in `passed`, `0` new failures, `0` new skips, and pre-existing baseline failures named explicitly.
- **`R7` (Fail-Closed Typed Verification):** Missing fields, missing nonce marker, incomplete test accounting (`passed | failed | errors | skipped | xfailed | xpassed != collected`), `session_finished != True`, zero collected tests, collection errors, missing dependencies, and timeouts are never treated as success.
- **`R8` (Pinned Container Isolation & Cleanup):** Candidate code never runs on the host. `DockerRepositoryVerifier` accepts only SHA-256-pinned images (`sha256:<64hex>` or `<repo>@sha256:<64hex>`), runs with `--network none --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges`, resource limits, sanitized env, `:ro` mounts, and kills timed-out containers.
- **`R9` (Runtime Cross-Family Oracle Independence):** Oracle runs *before* the worker, sees only goal + original `repository_context`, is sealed in `EncryptedOracleVault`, and its normalized runtime `response.family` must be known, non-empty, and distinct from every worker (and failover worker) response's `response.family`. Two worker rounds from the same worker family never trigger a false collision.
- **`R10` (Separate Visible vs Oracle Container Executions):** Visible regression + worker-added tests run with `/oracle` **unmounted** (`oracle_dir=None`). Oracle suites run in a separate container invocation (`test_paths=[]`, `oracle_dir` mounted `:ro`, `--noconftest`), and worker repair prompts receive only aggregate pass counts (`hidden acceptance checks passing: K/N`), never raw oracle code or assertion tracebacks.
- **`R11` (Goal-Kind Discrimination & Structural Criteria):** `behavior_change` goals require the oracle suite to discriminate (fail at least one test on `original`). `refactor` goals allow behavioral oracle tests to pass on `original`, but require pre-registered semantic AST `structural_checks` that are unsatisfied on `original` and satisfied on `candidate` (line-count reduction alone is rejected).
- **`R12` (Content-Hash Diffs & Honest Partial/Scope Reporting):** `changed_files` is computed from `(path, sha256)` content differences, never filename set differences. Hitting round/wall-clock limits with non-regressing partial progress yields `status="partial"` (`exit=3`) with explicit `pending_steps` and `required_evidence`, never `"accepted"`.

---

## 3. Schemas & Exit Codes

### 3.1 Worker Turn JSON Schema
Either a bounded file-read request:
```json
{
  "read_files": ["src/pkg/mod.py"]
}
```
or an action proposal:
```json
{
  "summary": "Concise change summary",
  "acceptance_criteria": ["Testable criterion 1"],
  "test_paths": ["tests/test_new_case.py"],
  "actions": [
    {
      "tool_name": "write_file",
      "tool_args": {
        "path": "src/pkg/helper.py",
        "content": "..."
      }
    },
    {
      "tool_name": "patch_file",
      "tool_args": {
        "path": "src/pkg/mod.py",
        "old_text": "exact unique snippet",
        "new_text": "replacement snippet"
      }
    }
  ],
  "done": true
}
```

### 3.2 Oracle JSON Schema
```json
{
  "goal_kind": "behavior_change",
  "acceptance_criteria": ["Independent behavioral/structural criterion"],
  "tests": {
    "test_independent_contract.py": "def test_contract():\n    ..."
  },
  "structural_checks": []
}
```
(`goal_kind`, `acceptance_criteria`, and `structural_checks` are optional in `"behavior_change"` mode; `"structural_checks"` is required when `goal_kind == "refactor"` unless supplied via `--structural-criteria`.)

### 3.3 Outcome Statuses & Exit Codes

| `report["status"]` | CLI Exit Code | Meaning |
|---|---:|---|
| `accepted` | `0` | Meaningful source change + all regression, added-test, oracle, and structural gates passed. |
| `dry_run` | `0` | Preflight + immutable staging + Python/test discovery succeeded; zero model/container calls made. |
| `failed` | `1` | Candidate failed verification gates, made zero code changes (`no-op`), or collided with oracle family. |
| `blocked` | `2` | Preflight/path/collision error, unsupported CLI flag, non-Python/zero-test/broken baseline, or invalid/non-discriminating oracle. |
| `partial` | `3` | Round or global wall-clock budget exhausted after valid non-regressing progress; `pending_steps` and `required_evidence` recorded. |

---

## 4. Honest Security & Scope Boundaries

1. **Same-Process Python `pytest` Boundary:** Mounting `/hv_verifier:ro`, capturing `pytest` stdout/stderr to files, using a per-run CSPRNG `HV_RESULT_<nonce>=` supervisor marker, an unlinked/popped pipe FD, and strict `collected == terminal_outcomes` accounting defeat stdout spoofing, predictable `/tmp/hv_result.json` overwrites, and `os._exit(0)` early-exit tricks. However, `pytest` imports candidate Python code in the same `uid=10001` interpreter process; this prevents opportunistic tampering and host escape, **not** cryptographic separation against arbitrary in-process Python memory introspection.
2. **Oracle Confidentiality Boundary:** Oracle suites are AES-256-GCM encrypted at rest on the host, never mounted during visible/worker-added test runs, and never echoed in worker prompts or reports. During the dedicated oracle container run (`--network none`, `--read-only`, `--noconftest`), `/oracle` is mounted `:ro` inside the container so `pytest` can execute it; confidentiality relies on network/filesystem isolation and aggregate-only runner feedback rather than hardware/process separation from imported candidate library code.
3. **Secret Filtering Boundary:** Filename patterns (`.env*`, `*.pem`, `*.key`, `credentials*`, `secrets*`, `id_rsa*`, `api_keys*`, `keys.json`, `tokens.txt`, etc. — while preserving ordinary source modules like `keys.py`/`tokens.py` unless inline secret literals appear) and content patterns (PEM private keys, `api_key`/`password`/`secret`/`token` assignments, `AKIA...`, `ghp_...`) prevent common credential leaks into prompts and containers, but are conservative heuristics—**not** a general-purpose DLP guarantee for custom secret formats.
4. **Regression Scope Boundary:** Repository mode verifies Python/`pytest` repositories using the packages pre-installed in the pinned offline verifier container. When `--test-paths` restricts verification to a subset of tests, `report.json` and `report.md` mark `regression_scope = "scoped_subset"` and list unexecuted repository test files explicitly; partial test scope never implies whole-repository feature preservation.
