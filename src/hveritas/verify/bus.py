"""Multi-tier Verifier Bus (`T0..T4`) as pure `fn(VerificationState) -> Evidence` + `inspect_ai.scorer`."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from inspect_ai.scorer import Scorer

from hveritas.effects.fs import FilesystemProbe
from hveritas.harness.isolation import IsolatedContainerVerifier
from hveritas.harness.sanitize import sanitize_judge_input
from hveritas.verify.models import (
    CheckResult,
    Evidence,
    TierId,
    VerificationState,
    VerifierBusReport,
)

TierVerifierFn = Callable[[VerificationState], Evidence]


class RequirementDagJudge:
    """T4 Requirement-DAG Agent-as-Judge (2410.10934): per-node evidence check on sanitized inputs.

    Invariants enforced:
    - Every artifact text is scrubbed via `sanitize_judge_input` before inspection or LLM call (I7).
    - Every node verdict MUST include concrete `file:line` evidence; ungrounded claims fail.
    - Topological DAG dependencies propagate failures from parent requirement nodes to children.
    - T4 runs LAST and can NEVER pass a milestone on its own if any of T0..T3 failed (§1, §5).
    """

    def __init__(
        self,
        llm_judge_fn: Callable[[str, str], tuple[bool, str]] | None = None,
    ) -> None:
        self._llm_judge_fn = llm_judge_fn

    def evaluate(self, workspace: Path, dag_nodes: list[dict[str, Any]]) -> list[CheckResult]:
        if not dag_nodes:
            return []
        ws = workspace.resolve()
        checks: list[CheckResult] = []
        passed_by_id: dict[str, bool] = {}

        for node in dag_nodes:
            node_id = str(node["id"])
            deps = [str(d) for d in node.get("depends_on", [])]
            unmet_deps = [d for d in deps if not passed_by_id.get(d, False)]
            if unmet_deps:
                passed_by_id[node_id] = False
                checks.append(
                    CheckResult(
                        check=f"dag_node:{node_id}",
                        passed=False,
                        score=0.0,
                        details={"unmet_parent_dependencies": unmet_deps, "evidence": []},
                    )
                )
                continue

            rel_file = str(node.get("evidence_file", ""))
            required_tokens = [str(t) for t in node.get("required_tokens", [])]
            forbidden_tokens = [str(t) for t in node.get("forbidden_tokens", [])]

            target = (ws / rel_file).resolve() if rel_file else None
            if target is not None and target != ws and ws not in target.parents:
                passed_by_id[node_id] = False
                checks.append(
                    CheckResult(
                        check=f"dag_node:{node_id}",
                        passed=False,
                        score=0.0,
                        details={
                            "error": f"evidence file escapes workspace: {rel_file!r}",
                            "evidence": [],
                        },
                    )
                )
                continue
            if target is None or not target.is_file():
                passed_by_id[node_id] = False
                checks.append(
                    CheckResult(
                        check=f"dag_node:{node_id}",
                        passed=False,
                        score=0.0,
                        details={"error": f"missing evidence file {rel_file!r}", "evidence": []},
                    )
                )
                continue

            raw_text = target.read_text(encoding="utf-8", errors="replace")
            sanitized = sanitize_judge_input(raw_text)
            clean = sanitized.clean_text
            clean_lines = clean.splitlines()

            missing = [tok for tok in required_tokens if tok not in clean]
            present_forbidden = [tok for tok in forbidden_tokens if tok in clean]

            evidence_citations: list[str] = []
            for tok in required_tokens:
                for line_no, line_txt in enumerate(clean_lines, start=1):
                    if tok in line_txt:
                        evidence_citations.append(f"{rel_file}:{line_no}:{tok}")
                        break

            llm_verdict = True
            llm_cited_snippet = ""
            if self._llm_judge_fn is not None:
                # Judge receives ONLY sanitized `clean` text — never raw untrusted HTML/comments!
                llm_verdict, llm_cited_snippet = self._llm_judge_fn(
                    str(node.get("statement", node_id)),
                    clean,
                )
                if llm_cited_snippet and llm_cited_snippet in clean:
                    for line_no, line_txt in enumerate(clean_lines, start=1):
                        if llm_cited_snippet in line_txt:
                            evidence_citations.append(f"{rel_file}:{line_no}:{llm_cited_snippet}")
                            break
                elif llm_verdict and not evidence_citations:
                    # Ungrounded LLM verdict without verifiable snippet in clean artifact is rejected!
                    llm_verdict = False

            evidence_citations = list(dict.fromkeys(evidence_citations))
            has_evidence = len(evidence_citations) > 0
            passed = bool(llm_verdict and has_evidence and not missing and not present_forbidden)
            passed_by_id[node_id] = passed
            checks.append(
                CheckResult(
                    check=f"dag_node:{node_id}",
                    passed=passed,
                    score=1.0 if passed else 0.0,
                    details={
                        "evidence": evidence_citations,
                        "missing": missing,
                        "forbidden_found": present_forbidden,
                        "sanitized_injection_attempt": sanitized.had_injection_attempt,
                        "stripped_reasons": list(sanitized.stripped_reasons),
                    },
                )
            )
        return checks


class VerifierBus:
    """Executes T0..T4 verification tiers strictly isolated from the worker generator."""

    def __init__(
        self,
        container_verifier: IsolatedContainerVerifier | None = None,
        judge: RequirementDagJudge | None = None,
        evolved_store_dir: Path | None = None,
    ) -> None:
        self.container = container_verifier or IsolatedContainerVerifier()
        self.judge = judge or RequirementDagJudge()
        self._fs_probe = FilesystemProbe()
        self.evolved_store_dir = (
            evolved_store_dir.resolve()
            if evolved_store_dir is not None
            else (self.container.verifier_dir / "evolved_invariants")
        )

    def _load_evolved_files(self, namespace: str | None, subdir: str) -> dict[str, str]:
        if not namespace:
            return {}
        ns_dir = self.evolved_store_dir / namespace / subdir
        if not ns_dir.is_dir():
            return {}
        loaded: dict[str, str] = {}
        for p in sorted(ns_dir.glob("test_*.py")):
            loaded[p.name] = p.read_text(encoding="utf-8")
        return loaded

    def verify_t0(self, state: VerificationState) -> Evidence:
        """Pure `fn(VerificationState) -> Evidence` for T0 Deterministic tier."""
        raw, ws_hash = self.container.run_isolated(
            workspace=Path(state.workspace_path),
            tiers_request={"T0": state.t0_config},
            proxy_tests=state.proxy_tests,
        )
        return self._parse_tier_evidence("T0", raw, ws_hash)

    def verify_t1(self, state: VerificationState) -> Evidence:
        """Pure `fn(VerificationState) -> Evidence` for T1 Invariant tier."""
        merged_inv = {
            **self._load_evolved_files(state.evolved_namespace, "invariants"),
            **state.dynamic_invariants,
        }
        raw, ws_hash = self.container.run_isolated(
            workspace=Path(state.workspace_path),
            tiers_request={"T1": state.t1_config},
            dynamic_invariants=merged_inv,
        )
        return self._parse_tier_evidence("T1", raw, ws_hash)

    def verify_t2(self, state: VerificationState) -> Evidence:
        """Pure `fn(VerificationState) -> Evidence` for T2 Metamorphic tier."""
        merged_meta = {
            **self._load_evolved_files(state.evolved_namespace, "metamorphic"),
            **state.metamorphic_tests,
        }
        raw, ws_hash = self.container.run_isolated(
            workspace=Path(state.workspace_path),
            tiers_request={"T2": {}},
            metamorphic_tests=merged_meta,
        )
        return self._parse_tier_evidence("T2", raw, ws_hash)

    def verify_t3(self, state: VerificationState) -> Evidence:
        """Pure `fn(VerificationState) -> Evidence` for T3 Held-Out Oracle tier (1x per milestone)."""
        if not state.heldout_oracle_id:
            raise ValueError("T3 requires `heldout_oracle_id`")
        raw, ws_hash = self.container.run_isolated(
            workspace=Path(state.workspace_path),
            tiers_request={"T3": {}},
            heldout_oracle_id=state.heldout_oracle_id,
        )
        return self._parse_tier_evidence("T3", raw, ws_hash)

    def verify_t4(self, state: VerificationState) -> Evidence:
        """Pure `fn(VerificationState) -> Evidence` for T4 Requirement-DAG Judge (never alone)."""
        ws = Path(state.workspace_path).resolve()
        ws_hash = self._fs_probe.compute_tree_hash(self._fs_probe.snapshot_manifest(ws))
        checks = self.judge.evaluate(ws, state.requirement_dag_nodes)
        if not checks:
            return Evidence(
                tier="T4",
                passed=False,
                score=0.0,
                checks=[],
                container_digest=self.container.image_digest,
                workspace_hash=ws_hash,
                runtime_audit={"note": "T4 cannot pass without requirement_dag_nodes"},
            )
        score = sum(c.score for c in checks) / len(checks)
        passed = all(c.passed for c in checks)
        return Evidence(
            tier="T4",
            passed=passed,
            score=round(score, 6),
            checks=checks,
            container_digest=self.container.image_digest,
            workspace_hash=ws_hash,
            runtime_audit={"sanitized": True},
        )

    def evaluate(
        self,
        state: VerificationState,
        include_t2: bool = False,
        include_t3: bool = False,
        include_t4: bool = False,
    ) -> VerifierBusReport:
        """Run T0–T4 in a single batched container pass for T0–T3 + sanitized T4 last.

        Enforces: T4 NEVER passes a milestone on its own! If T4 is enabled without at least one
        deterministic/oracle tier passing, or if any prior tier fails, overall `passed` is False.
        """
        tiers_req: dict[str, Any] = {
            "T0": state.t0_config,
            "T1": state.t1_config,
        }
        if include_t2:
            tiers_req["T2"] = {}
        if include_t3 and state.heldout_oracle_id:
            tiers_req["T3"] = {}

        merged_inv = {
            **self._load_evolved_files(state.evolved_namespace, "invariants"),
            **state.dynamic_invariants,
        }
        merged_meta = {
            **self._load_evolved_files(state.evolved_namespace, "metamorphic"),
            **state.metamorphic_tests,
        }
        if merged_meta and "T2" not in tiers_req and include_t2:
            tiers_req["T2"] = {}

        raw, ws_hash = self.container.run_isolated(
            workspace=Path(state.workspace_path),
            tiers_request=tiers_req,
            proxy_tests=state.proxy_tests,
            dynamic_invariants=merged_inv,
            metamorphic_tests=merged_meta,
            heldout_oracle_id=state.heldout_oracle_id if include_t3 else None,
        )

        tiers_out: dict[TierId, Evidence] = {
            "T0": self._parse_tier_evidence("T0", raw, ws_hash),
            "T1": self._parse_tier_evidence("T1", raw, ws_hash),
        }
        if include_t2:
            tiers_out["T2"] = self._parse_tier_evidence("T2", raw, ws_hash)
        if include_t3 and state.heldout_oracle_id:
            tiers_out["T3"] = self._parse_tier_evidence("T3", raw, ws_hash)
        if include_t4:
            tiers_out["T4"] = self.verify_t4(state)

        non_judge_tiers = [ev for tid, ev in tiers_out.items() if tid != "T4"]
        overall_passed = bool(non_judge_tiers) and all(ev.passed for ev in tiers_out.values())

        t0_ev = tiers_out["T0"]
        proxy_checks = [c for c in t0_ev.checks if c.check == "proxy_pytest"]
        score_proxy = proxy_checks[0].score if proxy_checks else t0_ev.score
        score_heldout = tiers_out["T3"].score if "T3" in tiers_out else None
        delta = round(score_proxy - score_heldout, 6) if score_heldout is not None else None

        return VerifierBusReport(
            passed=overall_passed,
            tiers=tiers_out,
            score_proxy=score_proxy,
            score_heldout=score_heldout,
            delta_gaming=delta,
        )

    def evaluate_t4_only_attempt(self, state: VerificationState) -> VerifierBusReport:
        """Explicitly rejects any attempt to pass a milestone using T4 Judge alone (§1, M6)."""
        t4_ev = self.verify_t4(state)
        return VerifierBusReport(
            passed=False,  # Hard invariant: T4 can NEVER pass alone!
            tiers={"T4": t4_ev},
            score_proxy=0.0,
            score_heldout=None,
            delta_gaming=None,
        )

    def _parse_tier_evidence(self, tier: TierId, raw: dict[str, Any], ws_hash: str) -> Evidence:
        tier_data = raw["tiers"][tier]
        checks = [
            CheckResult(
                check=str(c["check"]),
                passed=bool(c["passed"]),
                score=float(c["score"]),
                details={k: v for k, v in c.items() if k not in ("check", "passed", "score")},
            )
            for c in tier_data.get("checks", [])
        ]
        return Evidence(
            tier=tier,
            passed=bool(tier_data["passed"]),
            score=float(tier_data["score"]),
            checks=checks,
            container_digest=self.container.image_digest,
            workspace_hash=ws_hash,
            runtime_audit=dict(raw.get("runtime_audit", {})),
        )


def inspect_tier_scorer(tier_fn: TierVerifierFn) -> Scorer:
    """Bridge any hveritas `fn(VerificationState) -> Evidence` tier into an `inspect_ai` Scorer."""
    try:
        from inspect_ai.scorer import Score, Target, accuracy, scorer
        from inspect_ai.solver import TaskState
    except ImportError as exc:
        raise ImportError(
            "inspect_ai is required for inspect_tier_scorer; "
            "install with `pip install 'hveritas[t4]'`."
        ) from exc

    @scorer(metrics=[accuracy()])
    def _factory() -> Scorer:
        async def score(state: TaskState, target: Target) -> Score:
            ver_state = VerificationState.model_validate(state.metadata["verification_state"])
            ev = tier_fn(ver_state)
            return Score(
                value=1.0 if ev.passed else 0.0,
                answer=target.text,
                explanation=f"Tier {ev.tier} passed={ev.passed} score={ev.score}",
                metadata=ev.model_dump(mode="json"),
            )

        return score

    return _factory()
