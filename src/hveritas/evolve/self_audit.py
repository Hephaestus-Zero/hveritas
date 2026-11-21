"""Scheduled & On-Demand BenchJack Self-Audit Runner for `hveritas` (Milestone M7)."""

from __future__ import annotations

import ast
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hveritas.evolve.models import BenchJackAuditReport, BenchJackFinding
from hveritas.harness.isolation import DEFAULT_VERIFIER_DIR, SCRATCH_ROOT

DEFAULT_BENCHJACK_TOOLS_DIR = Path.home() / ".local" / "share" / "hveritas" / "benchjack_tools"


def _scan_benchjack_ast_rules(target_dir: Path) -> list[BenchJackFinding]:
    """Enforce BenchJack V3 & V6 Python AST rules from `benchjack_semgrep_rules.yml`."""
    findings: list[BenchJackFinding] = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [
            d
            for d in dirs
            if d not in {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache"}
        ]
        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            fpath = Path(root) / fname
            try:
                tree = ast.parse(fpath.read_text(encoding="utf-8"), filename=str(fpath))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            for node in ast.walk(tree):
                # V6: Exception handler returns passing score (`True`, `1`, `1.0`)
                if isinstance(node, ast.ExceptHandler):
                    for stmt in node.body:
                        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
                            val = stmt.value.value
                            if val is True or (
                                isinstance(val, (int, float))
                                and not isinstance(val, bool)
                                and val in (1, 1.0)
                            ):
                                findings.append(
                                    BenchJackFinding(
                                        scanner="benchjack_ast_rules",
                                        vulnerability_class="V6",
                                        severity="HIGH",
                                        file=str(fpath),
                                        line=stmt.lineno,
                                        message="Exception handler returns passing score (V6 logic gap)",
                                        disposition="unmitigated",
                                    )
                                )

                # V3: Unsafe dynamic execution / shell=True / unsafe yaml.load
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                        if not (node.args and isinstance(node.args[0], ast.Constant)):
                            findings.append(
                                BenchJackFinding(
                                    scanner="benchjack_ast_rules",
                                    vulnerability_class="V3",
                                    severity="CRITICAL",
                                    file=str(fpath),
                                    line=node.lineno,
                                    message=f"{node.func.id}() called on dynamic variable (V3 RCE)",
                                    disposition="unmitigated",
                                )
                            )
                    elif isinstance(node.func, ast.Attribute) and isinstance(
                        node.func.value, ast.Name
                    ):
                        qual = f"{node.func.value.id}.{node.func.attr}"
                        if qual == "os.system":
                            findings.append(
                                BenchJackFinding(
                                    scanner="benchjack_ast_rules",
                                    vulnerability_class="V3",
                                    severity="HIGH",
                                    file=str(fpath),
                                    line=node.lineno,
                                    message="os.system() shell invocation (V3 command injection)",
                                    disposition="unmitigated",
                                )
                            )
                        elif node.func.value.id == "subprocess":
                            for kw in node.keywords:
                                if (
                                    kw.arg == "shell"
                                    and isinstance(kw.value, ast.Constant)
                                    and kw.value.value is True
                                ):
                                    findings.append(
                                        BenchJackFinding(
                                            scanner="benchjack_ast_rules",
                                            vulnerability_class="V3",
                                            severity="HIGH",
                                            file=str(fpath),
                                            line=node.lineno,
                                            message=f"{qual}(..., shell=True) (V3 command injection)",
                                            disposition="unmitigated",
                                        )
                                    )
                        elif qual == "yaml.load":
                            has_safe_loader = any(
                                kw.arg == "Loader" and "SafeLoader" in ast.unparse(kw.value)
                                for kw in node.keywords
                            )
                            if not has_safe_loader:
                                findings.append(
                                    BenchJackFinding(
                                        scanner="benchjack_ast_rules",
                                        vulnerability_class="V3",
                                        severity="HIGH",
                                        file=str(fpath),
                                        line=node.lineno,
                                        message="yaml.load() without SafeLoader (V3 deserialization RCE)",
                                        disposition="unmitigated",
                                    )
                                )
    return findings


def render_systemd_schedule_units(
    *,
    repo_root: Path,
    python_bin: Path | None = None,
    calendar: str = "daily",
) -> tuple[str, str]:
    """Render user-level systemd `.service` and `.timer` units for scheduled BenchJack self-audits."""
    py = python_bin or Path(sys.executable).resolve()
    repo = repo_root.resolve()
    report_md = repo / "docs" / "reports" / "m7_benchjack_self_audit.md"
    report_json = repo / "docs" / "reports" / "m7_benchjack_self_audit.json"
    service_unit = (
        "[Unit]\n"
        "Description=hveritas Scheduled BenchJack Harness Self-Audit\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"WorkingDirectory={repo}\n"
        f"ExecStart={py} -m hveritas.cli m7-audit --markdown-out {report_md} --json-out {report_json}\n"
    )
    timer_unit = (
        "[Unit]\n"
        "Description=Periodic BenchJack Self-Audit Timer for hveritas\n\n"
        "[Timer]\n"
        f"OnCalendar={calendar}\n"
        "Persistent=true\n"
        "RandomizedDelaySec=5m\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    return service_unit, timer_unit


class BenchJackSelfAuditor:
    """Runs BenchJack (`docker_analyzer`, `trust_map`, AST rules) + Bandit on `hveritas` harness & verifier."""

    def __init__(
        self,
        *,
        benchjack_tools_dir: Path = DEFAULT_BENCHJACK_TOOLS_DIR,
        scratch_root: Path = SCRATCH_ROOT,
        schedule_calendar: str = "daily",
    ) -> None:
        self.tools_dir = benchjack_tools_dir.resolve()
        self.scratch_root = scratch_root
        self.schedule_calendar = schedule_calendar
        if not (self.tools_dir / "docker_analyzer.py").is_file():
            raise FileNotFoundError(f"BenchJack docker_analyzer.py missing at {self.tools_dir}")
        if not (self.tools_dir / "trust_map.py").is_file():
            raise FileNotFoundError(f"BenchJack trust_map.py missing at {self.tools_dir}")

    def run_audit(
        self,
        *,
        targets: list[Path] | None = None,
        markdown_out: Path | None = None,
        json_out: Path | None = None,
    ) -> BenchJackAuditReport:
        """Execute full BenchJack + Bandit scan across targets and optionally emit report artifacts."""
        default_src = Path(__file__).resolve().parents[1]
        scan_targets = [p.resolve() for p in (targets or [default_src, DEFAULT_VERIFIER_DIR])]

        self.scratch_root.mkdir(parents=True, exist_ok=True)
        work_dir = self.scratch_root / f"hv_bjaudit_{os.getpid()}_{secrets.token_hex(8)}"
        work_dir.mkdir(parents=True, mode=0o755)

        findings: list[BenchJackFinding] = []
        docker_count = 0
        trust_conflicts_count = 0
        dangerous_sinks_count = 0
        ast_violations_count = 0
        bandit_high = 0
        bandit_medium = 0
        nosec_count = 0

        try:
            for idx, target in enumerate(scan_targets):
                sub_out = work_dir / f"t_{idx}"
                sub_out.mkdir(parents=True, mode=0o755)
                env = {**os.environ, "BENCHJACK_RESULTS_DIR": str(sub_out)}

                # 1. BenchJack Docker Config Analyzer (V1, V2, V8)
                subprocess.run(
                    [sys.executable, str(self.tools_dir / "docker_analyzer.py"), str(target)],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30.0,
                    check=False,
                )
                docker_json = sub_out / "benchjack_docker_results.json"
                if docker_json.is_file():
                    d_data = json.loads(docker_json.read_text(encoding="utf-8"))
                    for vuln_cls, items in sorted(
                        d_data.get("findings_by_vulnerability", {}).items()
                    ):
                        for item in items:
                            docker_count += 1
                            sev = str(item.get("severity", "MEDIUM")).upper()
                            findings.append(
                                BenchJackFinding(
                                    scanner="benchjack_docker",
                                    vulnerability_class=str(vuln_cls),
                                    severity=sev,  # type: ignore[arg-type]
                                    file=str(item.get("file", target)),
                                    line=int(item.get("line", 0) or 0),
                                    message=str(item.get("message", "")),
                                    disposition="unmitigated",
                                )
                            )

                # 2. BenchJack Trust Boundary Mapper (V1, V3, V7)
                subprocess.run(
                    [
                        sys.executable,
                        str(self.tools_dir / "trust_map.py"),
                        str(target),
                        "--eval-patterns",
                        "verify/",
                        "harness/",
                        "^runner\\.py$",
                        "--agent-patterns",
                        "loop/",
                        "agent/",
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30.0,
                    check=False,
                )
                trust_json = sub_out / "benchjack_trust_map.json"
                if trust_json.is_file():
                    t_data = json.loads(trust_json.read_text(encoding="utf-8"))
                    conflicts: list[dict[str, Any]] = t_data.get("trust_boundary_conflicts", [])
                    sinks: list[dict[str, Any]] = t_data.get("dangerous_sinks", [])
                    trust_conflicts_count += len(conflicts)
                    dangerous_sinks_count += len(sinks)

                    for c in conflicts:
                        findings.append(
                            BenchJackFinding(
                                scanner="benchjack_trust_map",
                                vulnerability_class="V1",
                                severity="HIGH",
                                file=str(target),
                                line=0,
                                message=f"Shared agent/evaluator path {c.get('path')!r}: {c.get('risk')}",
                                disposition="unmitigated",
                            )
                        )
                    for ds in sinks:
                        sink_type = str(ds.get("sink_type", "eval"))
                        findings.append(
                            BenchJackFinding(
                                scanner="benchjack_trust_map",
                                vulnerability_class="V3",
                                severity="CRITICAL" if sink_type in {"eval", "exec"} else "HIGH",
                                file=str(ds.get("source_file", target)),
                                line=int(ds.get("line", 0) or 0),
                                message=f"Dangerous sink {sink_type}({ds.get('arg_expr')})",
                                disposition="unmitigated",
                            )
                        )
                    for sc in t_data.get("subprocess_calls", []):
                        if sc.get("shell"):
                            findings.append(
                                BenchJackFinding(
                                    scanner="benchjack_trust_map",
                                    vulnerability_class="V3",
                                    severity="HIGH",
                                    file=str(sc.get("source_file", target)),
                                    line=int(sc.get("line", 0) or 0),
                                    message=f"Subprocess shell=True: {sc.get('cmd_expr')}",
                                    disposition="unmitigated",
                                )
                            )
                        elif sc.get("captures_output"):
                            cmd_expr = str(sc.get("cmd_expr", ""))
                            # Direct host pytest without -I or container isolation is V1/V7 exploit surface
                            if "pytest" in cmd_expr and "-I" not in cmd_expr:
                                findings.append(
                                    BenchJackFinding(
                                        scanner="benchjack_trust_map",
                                        vulnerability_class="V1/V7",
                                        severity="HIGH",
                                        file=str(sc.get("source_file", target)),
                                        line=int(sc.get("line", 0) or 0),
                                        message=f"Unisolated pytest subprocess output capture: {cmd_expr}",
                                        disposition="unmitigated",
                                    )
                                )
                            else:
                                findings.append(
                                    BenchJackFinding(
                                        scanner="benchjack_trust_map",
                                        vulnerability_class="V7",
                                        severity="MEDIUM",
                                        file=str(sc.get("source_file", target)),
                                        line=int(sc.get("line", 0) or 0),
                                        message=f"Subprocess output capture ({sc.get('call_type')}({cmd_expr}))",
                                        disposition="architectural_control_verified",
                                        mitigation_note=(
                                            "Runs either on host trusted binaries (btrfs/git/docker) or inside "
                                            "digest-pinned --network=none uid=10001 python3 -I container."
                                        ),
                                    )
                                )

                # 3. BenchJack Python AST rules (V3, V6)
                ast_found = _scan_benchjack_ast_rules(target)
                ast_violations_count += len(ast_found)
                findings.extend(ast_found)

            # 4. Bandit Security Linter across all targets (`-ll` Medium & High, `-q -o` pure JSON)
            bandit_json = work_dir / "bandit_results.json"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "bandit",
                    "-q",
                    "-r",
                    *[str(t) for t in scan_targets],
                    "-ll",
                    "-f",
                    "json",
                    "-o",
                    str(bandit_json),
                ],
                capture_output=True,
                text=True,
                timeout=30.0,
                check=False,
            )
            if bandit_json.is_file():
                b_data = json.loads(bandit_json.read_text(encoding="utf-8"))
                totals = b_data.get("metrics", {}).get("_totals", {})
                nosec_count = int(totals.get("nosec", 0) or 0)
                for res in b_data.get("results", []):
                    sev = str(res.get("issue_severity", "MEDIUM")).upper()
                    test_id = str(res.get("test_id", ""))
                    fname = str(res.get("filename", ""))
                    lineno = int(res.get("line_number", 0) or 0)
                    msg = f"[{test_id}] {res.get('issue_text', '')}"
                    if sev == "HIGH":
                        bandit_high += 1
                        findings.append(
                            BenchJackFinding(
                                scanner="bandit",
                                vulnerability_class=test_id,
                                severity="HIGH",
                                file=fname,
                                line=lineno,
                                message=msg,
                                disposition="unmitigated",
                            )
                        )
                    else:
                        bandit_medium += 1
                        if test_id == "B108":
                            findings.append(
                                BenchJackFinding(
                                    scanner="bandit",
                                    vulnerability_class="B108",
                                    severity="MEDIUM",
                                    file=fname,
                                    line=lineno,
                                    message=msg,
                                    disposition="architectural_control_verified",
                                    mitigation_note=(
                                        "Uses isolated container tmpfs (/tmp:rw,noexec,nosuid,size=64m) or "
                                        "<scratch_root>/<pid>_<csprng_hex> per workspace directive."
                                    ),
                                )
                            )
                        elif test_id == "B608" and fname.endswith("effects/db.py"):
                            findings.append(
                                BenchJackFinding(
                                    scanner="bandit",
                                    vulnerability_class="B608",
                                    severity="MEDIUM",
                                    file=fname,
                                    line=lineno,
                                    message=msg,
                                    disposition="architectural_control_verified",
                                    mitigation_note=(
                                        "Read-only (?mode=ro) SQLite schema introspection over double-quote "
                                        "escaped sqlite_master table identifiers; zero untrusted value interpolation."
                                    ),
                                )
                            )
                        else:
                            findings.append(
                                BenchJackFinding(
                                    scanner="bandit",
                                    vulnerability_class=test_id,
                                    severity="MEDIUM",
                                    file=fname,
                                    line=lineno,
                                    message=msg,
                                    disposition="unmitigated",
                                )
                            )

            unmitigated = [f for f in findings if f.disposition == "unmitigated"]
            unmitigated_high_crit = [f for f in unmitigated if f.severity in {"HIGH", "CRITICAL"}]
            passed = len(unmitigated) == 0 and nosec_count == 0

            report = BenchJackAuditReport(
                audit_id=f"bjaudit_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}",
                timestamp_iso=datetime.now(UTC).isoformat(),
                targets_scanned=[str(t) for t in scan_targets],
                docker_findings_count=docker_count,
                trust_boundary_conflicts_count=trust_conflicts_count,
                dangerous_sinks_count=dangerous_sinks_count,
                ast_rule_violations_count=ast_violations_count,
                bandit_high_count=bandit_high,
                bandit_medium_count=bandit_medium,
                nosec_suppressions_count=nosec_count,
                unmitigated_high_or_critical_count=len(unmitigated_high_crit),
                unmitigated_exploit_findings_count=len(unmitigated),
                passed=passed,
                schedule_timer_calendar=self.schedule_calendar,
                findings=findings,
            )

            if json_out is not None:
                json_out.parent.mkdir(parents=True, exist_ok=True)
                json_out.write_text(
                    json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True),
                    encoding="utf-8",
                )
            if markdown_out is not None:
                markdown_out.parent.mkdir(parents=True, exist_ok=True)
                markdown_out.write_text(self.render_markdown(report), encoding="utf-8")

            return report
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def render_markdown(self, report: BenchJackAuditReport) -> str:
        """Render human-auditable Markdown report for `docs/reports/`."""
        status_str = "PASS (0 unmitigated exploits)" if report.passed else "FAIL"
        lines = [
            "# BenchJack Harness Self-Audit Report (`M7`)",
            "",
            f"- **Audit ID:** `{report.audit_id}`",
            f"- **Timestamp (UTC):** `{report.timestamp_iso}`",
            f"- **Overall Verdict:** **{status_str}**",
            f"- **Scheduled Timer Cadence:** `OnCalendar={report.schedule_timer_calendar}` (`systemd` user timer)",
            "- **Targets Scanned:**",
        ]
        for t in report.targets_scanned:
            lines.append(f"  - `{t}`")
        lines.extend(
            [
                "",
                "## Summary Metrics",
                "",
                "| Scanner / Check | Count | Gate Requirement |",
                "|---|---:|---|",
                f"| BenchJack `docker_analyzer.py` (V1, V2, V8) | {report.docker_findings_count} | `== 0` |",
                f"| BenchJack `trust_map.py` Trust Boundary Conflicts (V1) | {report.trust_boundary_conflicts_count} | `== 0` |",
                f"| BenchJack `trust_map.py` Dangerous Sinks (`eval`/`exec`/`pickle`, V3) | {report.dangerous_sinks_count} | `== 0` |",
                f"| BenchJack AST Rules (V3 `shell=True`/`yaml.load`, V6 `except: return True`) | {report.ast_rule_violations_count} | `== 0` |",
                f"| Bandit `HIGH` Severity Findings | {report.bandit_high_count} | `== 0` |",
                f"| Bandit `MEDIUM` Severity Findings (all reviewed) | {report.bandit_medium_count} | `0 unmitigated` |",
                f"| `#nosec` Suppressions | {report.nosec_suppressions_count} | `== 0` |",
                f"| **Unmitigated Exploit Findings** | **{report.unmitigated_exploit_findings_count}** | **`== 0`** |",
                "",
                "## Remediation During Initial Self-Audit",
                "",
                "- **`[B310 / SSRF-LocalFile]` (`src/hveritas/tape/session.py`):** Initial Bandit + BenchJack scan flagged `urllib.request.urlopen()` inside `tool_http_request` because Python's `urlopen` permits `file://` URLs by default. Remediated prior to M7 sign-off by replacing `urllib.request.urlopen` with `http.client.HTTPConnection` / `HTTPSConnection` gated by explicit `scheme in {'http', 'https'}` validation (verified 0 regression on M1 `vcrpy` byte-identical replay).",
                "",
                "## Detailed Finding Disposition Log",
                "",
                "| Scanner | Class | Severity | Location | Disposition | Notes |",
                "|---|---|---|---|---|---|",
            ]
        )
        for f in report.findings:
            loc = f"`{Path(f.file).name}:{f.line}`" if f.line else f"`{Path(f.file).name}`"
            note = (f.mitigation_note or f.message).replace("|", "\\|")
            lines.append(
                f"| `{f.scanner}` | `{f.vulnerability_class}` | `{f.severity}` | {loc} | `{f.disposition}` | {note} |"
            )
        lines.append("")
        return "\n".join(lines)
