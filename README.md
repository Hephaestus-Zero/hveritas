# hveritas — Container-Isolated Multi-Tier Verification & Differential Fuzzing Harness

[![CI](https://github.com/Hephaestus-Zero/hveritas/actions/workflows/ci.yml/badge.svg)](https://github.com/Hephaestus-Zero/hveritas/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`hveritas` is an adversarial software verification and security auditing harness designed to validate untrusted or autonomously synthesized code under strict epistemic isolation. Instead of trusting self-reported tool outputs or single-family LLM judges, `hveritas` enforces network-isolated container execution, encrypted held-out test vaults, deterministic fault bisection, static security analysis (`Bandit`), mutation testing (`mutmut`), and cross-family differential fuzzing.

## Core Security & Verification Architecture

- **`src/hveritas/harness/` — Isolated Execution & Anti-Gaming Controls:**
  - Digest-pinned `--network=none` Docker verification sandboxes (`I1`, `I6`) with read-only verifier mounts (`/hv_verifier:ro`) and CSPRNG execution nonces.
  - **AES-256-GCM** encrypted held-out oracle vault (`I4`) preventing test-suite leakage or reward hacking (`Δ = score_proxy − score_heldout`).
  - Sanitized judge boundary (`I7`) and mandatory no-op baseline checks (`I5`).
- **`src/hveritas/repository/` — Safe Repository Staging (`R1`–`R12`):**
  - `O_NOFOLLOW` immutable workspace copying (`safe_copy`) refusing symlinks, special device nodes, and hardlink escapes.
  - Automatic secret-boundary filtering (`.env*`, `*.pem`, `*.key`, `credentials*`, token patterns) before any model context assembly.
- **`src/hveritas/verify/` — Multi-Tier Verifier Bus (`T0`–`T4`):**
  - `T0` AST/structural & static safety checks, `T1` unit/contract oracles, `T2` metamorphic relation synthesis, `T3` 200-seed multi-family differential fuzzing (`I18`), and `T4` `inspect_ai` scorer integration.
- **`src/hveritas/attribute/` — `O(log n)` Replay Bisection:**
  - Deterministic `ToolTape` + `vcrpy` offline replay (`I8`) with `O(log n)` counterfactual fault attribution and TRAIL failure taxonomy classification.
- **`src/hveritas/evolve/` — Self-Auditing Verifier Hardening:**
  - `mutmut` mutation-score non-regression gate (`I9`) and scheduled **Bandit** SAST + harness self-audit (`m7-audit`).
- **`src/hveritas/ledger/` — Tamper-Evident Telemetry:**
  - Append-only SQLite + Parquet execution ledger with OpenTelemetry GenAI semantic conventions.

## Installation & Test Suite

Requires Python `>= 3.12` and Docker (for `--network=none` container-isolated verifier execution).

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[all,dev]"  # or `pip install -e .` plus extras: [t4], [audit], [anthropic]

# Provision out-of-tree verifier & BenchJack audit bundles (Invariant I1), build the Docker image,
# and persist its digest to ~/.local/share/hveritas/verifier_digest
.venv/bin/hveritas setup-verifier --build-image

# Run static linter, typechecker, and full verification test suite (including isolated Docker e2e)
.venv/bin/ruff check src tests
.venv/bin/mypy src
.venv/bin/pytest -v
```

## CLI Usage

```bash
# Provision out-of-tree verifier bundles and build digest-pinned Docker image
hveritas setup-verifier --build-image

# Preflight repository audit & dry-run verification (0 external API calls)
hveritas run --repository --dry-run \
  --initial-workspace /path/to/target-repo \
  --goal "Validate parser edge cases and boundary conditions"

# Run with direct Anthropic Messages API backend (when `hx` gateway is not installed)
export ANTHROPIC_API_KEY="sk-ant-..."
hveritas run --backend anthropic --goal "Implement strict parser validation"

# Run Bandit SAST + BenchJack verifier self-audit
hveritas m7-audit \
  --markdown-out /tmp/self_audit.md \
  --json-out /tmp/self_audit.json

# Run replay-bisect attribution evaluation
hveritas m4-eval --report-out /tmp/attribution_eval.json
```

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — Formal verification invariants (`I1`–`I19`) and multi-tier evidence model.
- [`docs/repository_mode.md`](docs/repository_mode.md) — Repository containment contract (`R1`–`R12`), `O_NOFOLLOW` staging, secret redaction rules, and exit codes.

## License

MIT License — Copyright (c) 2026 Hephaestus-Zero.
