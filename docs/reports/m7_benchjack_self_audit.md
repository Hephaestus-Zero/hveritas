# BenchJack Harness Self-Audit Report (`M7`)

- **Audit ID:** `bjaudit_20261114T091839Z`
- **Timestamp (UTC):** `2026-11-14T09:18:39.772556+00:00`
- **Overall Verdict:** **PASS (0 unmitigated exploits)**
- **Scheduled Timer Cadence:** `OnCalendar=daily` (`systemd` user timer)
- **Targets Scanned:**
  - `src/hveritas`
  - `~/.local/share/hveritas/verifier`

## Summary Metrics

| Scanner / Check | Count | Gate Requirement |
|---|---:|---|
| BenchJack `docker_analyzer.py` (V1, V2, V8) | 0 | `== 0` |
| BenchJack `trust_map.py` Trust Boundary Conflicts (V1) | 0 | `== 0` |
| BenchJack `trust_map.py` Dangerous Sinks (`eval`/`exec`/`pickle`, V3) | 0 | `== 0` |
| BenchJack AST Rules (V3 `shell=True`/`yaml.load`, V6 `except: return True`) | 0 | `== 0` |
| Bandit `HIGH` Severity Findings | 0 | `== 0` |
| Bandit `MEDIUM` Severity Findings (all reviewed) | 20 | `0 unmitigated` |
| `#nosec` Suppressions | 0 | `== 0` |
| **Unmitigated Exploit Findings** | **0** | **`== 0`** |

## Remediation During Initial Self-Audit

- **`[B310 / SSRF-LocalFile]` (`src/hveritas/tape/session.py`):** Initial Bandit + BenchJack scan flagged `urllib.request.urlopen()` inside `tool_http_request` because Python's `urlopen` permits `file://` URLs by default. Remediated prior to M7 sign-off by replacing `urllib.request.urlopen` with `http.client.HTTPConnection` / `HTTPSConnection` gated by explicit `scheme in {'http', 'https'}` validation (verified 0 regression on M1 `vcrpy` byte-identical replay).

## Detailed Finding Disposition Log

| Scanner | Class | Severity | Location | Disposition | Notes |
|---|---|---|---|---|---|
| `benchjack_trust_map` | `V7` | `MEDIUM` | `verifier.py:532` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `verifier.py:582` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `backend.py:184` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `backend.py:203` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `self_audit.py:213` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `self_audit.py:243` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `self_audit.py:347` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `mutation_gate.py:132` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `worker_sandbox.py:73` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `isolation.py:212` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `oracle_vault.py:84` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `oracle_vault.py:90` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `heldout_faults.py:503` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `fault_suite.py:386` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `session.py:137` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `snapshot.py:24` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `snapshot.py:56` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `snapshot.py:78` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `snapshot.py:87` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `snapshot.py:117` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `snapshot.py:125` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `snapshot.py:160` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `snapshot.py:167` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `runner.py:81` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `runner.py:111` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `runner.py:188` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `benchjack_trust_map` | `V7` | `MEDIUM` | `runner.py:372` | `architectural_control_verified` | Runs either on host trusted binaries (btrfs/git/docker) or inside digest-pinned --network=none uid=10001 python3 -I container. |
| `bandit` | `B108` | `MEDIUM` | `bisect.py:46` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `counterfactual.py:80` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `engine.py:43` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `fault_suite.py:388` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `heldout_faults.py:505` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `cli.py:833` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `cli.py:986` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B608` | `MEDIUM` | `db.py:66` | `architectural_control_verified` | Read-only (?mode=ro) SQLite schema introspection over double-quote escaped sqlite_master table identifiers; zero untrusted value interpolation. |
| `bandit` | `B108` | `MEDIUM` | `isolation.py:21` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `isolation.py:185` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `oracle_vault.py:116` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `worker_sandbox.py:61` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `verifier.py:18` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `verifier.py:450` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `runner.py:35` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `runner.py:36` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `runner.py:83` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `runner.py:113` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `runner.py:190` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
| `bandit` | `B108` | `MEDIUM` | `runner.py:374` | `architectural_control_verified` | Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or <scratch_root>/<pid>_<csprng_hex> per workspace directive. |
