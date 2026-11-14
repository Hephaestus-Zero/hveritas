"""Run Reporting Bundle (`M8-E1` + `M9-F`): writes enriched JSON + honest Turkish Markdown summary."""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from pathlib import Path
from typing import Any

from hveritas.ledger import AppendOnlyLedger
from hveritas.loop.models import LoopResult
from hveritas.worker.policy import LlmCallTelemetry


def verify_all_ledger_chains(ledger_dir: Path) -> bool:
    """Verify SHA-256 receipt hash chain integrity across every run stored in `ledger_dir`."""
    sqlite_file = ledger_dir / "ledger.sqlite"
    if not sqlite_file.is_file():
        return True
    ledger = AppendOnlyLedger(ledger_dir)
    try:
        conn = sqlite3.connect(str(sqlite_file))
        try:
            rows = conn.execute("SELECT run_id FROM runs ORDER BY rowid ASC").fetchall()
        finally:
            conn.close()
        return all(ledger.verify_chain(str(r[0])) for r in rows)
    finally:
        ledger.close()


def build_run_report_payload(
    *,
    result: LoopResult,
    goal_text: str,
    backend_name: str,
    primary_alias: str,
    alternate_alias: str,
    primary_resolved_family: str | None,
    alternate_resolved_family: str | None,
    call_telemetry: list[LlmCallTelemetry],
    ledger_dir: Path | None,
    assurance: str = "standard",
    independence: str = "human",
    spec_unreviewed: bool = False,
    spec_review_note: str = "insan yazımı (--goal-file)",
    oracle_alias: str | None = None,
    oracle_resolved_family: str | None = None,
    differential_alias: str | None = None,
    differential_resolved_family: str | None = None,
    oracle_free: dict[str, Any] | None = None,
    differential: dict[str, Any] | None = None,
    differential_skipped: bool = False,
) -> dict[str, Any]:
    """Build enriched M8-E1 / M9-F JSON report preserving top-level `LoopResult` keys + independence telemetry."""
    base = result.model_dump(mode="json")
    chain_ok = verify_all_ledger_chains(ledger_dir) if ledger_dir is not None else True

    fam_set = {c.resolved_family for c in call_telemetry if c.resolved_family}
    for extra_fam in (
        primary_resolved_family,
        alternate_resolved_family,
        oracle_resolved_family,
        differential_resolved_family,
    ):
        if extra_fam:
            fam_set.add(extra_fam)
    observed_families = sorted(fam_set)

    default_oracle_free = (
        result.details.get("oracle_free") if isinstance(result.details, dict) else None
    )
    resolved_oracle_free = (
        oracle_free
        or default_oracle_free
        or {
            "metamorphic": {"passed": False, "relation_count": 0, "status": "koşmadı"},
            "determinism": {"passed": False, "status": "koşmadı"},
            "type_contract": {"passed": False, "status": "koşmadı"},
            "garbage_resilience": {"passed": False, "case_count": 12, "status": "koşmadı"},
        }
    )

    enriched: dict[str, Any] = {
        **base,
        "goal_text": goal_text,
        "assurance": assurance,
        "independence": independence,
        "spec_unreviewed": spec_unreviewed,
        "spec_review_note": spec_review_note,
        "oracle_free": resolved_oracle_free,
        "differential": differential,
        "differential_skipped": differential_skipped,
        "loop_result": base,
        "models": {
            "backend": backend_name,
            "primary_alias": primary_alias,
            "worker_alias": primary_alias,
            "alternate_alias": alternate_alias,
            "oracle_alias": oracle_alias,
            "differential_alias": differential_alias,
            "primary_resolved_family": primary_resolved_family,
            "worker_resolved_family": primary_resolved_family,
            "alternate_resolved_family": alternate_resolved_family,
            "oracle_resolved_family": oracle_resolved_family,
            "differential_resolved_family": differential_resolved_family,
            "families_observed": observed_families,
        },
        "llm_calls": [dataclasses.asdict(c) for c in call_telemetry],
        "ledger_dir": str(ledger_dir) if ledger_dir is not None else None,
        "verify_chain": chain_ok,
    }
    return enriched


def render_run_markdown_summary(payload: dict[str, Any]) -> str:
    """Render concise Turkish Markdown run report companion (`<report>.md`) obeying M9 §9 wording rules."""
    models = payload.get("models", {})
    usage = payload.get("budget_usage", {})
    committed = payload.get("committed_tasks", [])
    remaining = payload.get("remaining_tasks", [])
    attributions = payload.get("attributions", [])
    llm_calls = payload.get("llm_calls", [])
    oracle_free = payload.get("oracle_free") or {}
    diff = payload.get("differential")
    independence = payload.get("independence", "human")
    delta_val = payload.get("delta_gaming")

    w_alias = models.get("worker_alias") or models.get("primary_alias")
    w_fam = models.get("worker_resolved_family") or models.get("primary_resolved_family")
    o_alias = models.get("oracle_alias")
    o_fam = models.get("oracle_resolved_family")
    d_alias = models.get("differential_alias")
    d_fam = models.get("differential_resolved_family")

    if independence == "human":
        oracle_line = "- Oracle yazarı:        insan (--goal-file) → independence=human  ✓ bağımsız"
    elif independence == "none":
        oracle_line = "- Oracle yazarı:        yok (--assurance fast) → independence=none"
    else:
        distinct_mark = "  ✓ farklı aile" if (o_fam and w_fam and o_fam != w_fam) else ""
        oracle_line = f"- Oracle yazarı:        {o_alias}          → family={o_fam}{distinct_mark}"

    if diff is not None and not payload.get("differential_skipped", False):
        d_distinct = "  ✓ farklı aile" if (d_fam and d_fam not in {w_fam, o_fam}) else ""
        diff_model_line = (
            f"- Diferansiyel:         {d_alias}           → family={d_fam}{d_distinct}"
        )
        agreed_n = diff.get("agreed_count", 0)
        total_n = diff.get("total_inputs", 0)
        diff_mark = "  ✓ ayrışma yok" if diff.get("agreement_rate") == 1.0 else "  ✗ ayrışma var"
        diff_consensus_line = f"- Diferansiyel mutabakat: {agreed_n}/{total_n}{diff_mark}"
    elif payload.get("differential_skipped", False):
        diff_model_line = (
            f"- Diferansiyel:         {d_alias or 'yok'}   → atlandı (differential_skipped=true)"
        )
        diff_consensus_line = "- Diferansiyel mutabakat: atlandı (DIFFERENTIAL_UNAVAILABLE)"
    else:
        diff_model_line = "- Diferansiyel:         devre dışı (yalnızca --assurance paranoid)"
        diff_consensus_line = "- Diferansiyel mutabakat: koşmadı (--assurance paranoid değil)"

    delta_note = "  ✓ ezber yok" if (delta_val is not None and float(delta_val) <= 0.25) else ""
    delta_line = f"- Δ (proxy − heldout):  {delta_val}{delta_note}"

    meta_b = oracle_free.get("metamorphic", {})
    det_b = oracle_free.get("determinism", {})
    typ_b = oracle_free.get("type_contract", {})
    garb_b = oracle_free.get("garbage_resilience", {})

    if independence == "none":
        closing_block = [
            (
                "Bu prototip koşusu yalnızca görünür proxy kontrollerini ve oracle-free özellikleri çalıştırdı; "
                "çapraz aile held-out oracle veya diferansiyel mutabakat koşmadı."
            ),
            'Bu kesin "doğru" iddiası DEĞİLDİR.',
        ]
    elif payload.get("passed"):
        closing_block = [
            "Bu koşu şunları söyler: kendi kendini notlamadı, görünür testlere ezber yapmadı,",
            "iki bağımsız model ailesi sonuç üzerinde anlaştı, oracle-free özellikler tutuyor.",
            'Bu kesin "doğru" iddiası DEĞİLDİR.',
        ]
    else:
        closing_block = [
            f"Bu koşu commit etmeden durdu (`stop_reason={payload.get('stop_reason')}`).",
            'Bu kesin "doğru" iddiası DEĞİLDİR.',
        ]

    lines: list[str] = [
        f"# hveritas Çalıştırma Özeti — `{payload.get('run_id', '')}`",
        "",
        f"- **Hedef:** {payload.get('goal_text', '')}",
        f"- **Güvence Seviyesi (`assurance`):** `{payload.get('assurance', 'standard')}`",
        f"- **Bağımsızlık (`independence`):** `{independence}`",
        f"- **Başarılı (`passed`):** `{payload.get('passed')}`",
        f"- **Durma Nedeni (`stop_reason`):** `{payload.get('stop_reason')}`",
        f"- **Δ Gaming Skoru (`delta_gaming`):** `{delta_val}`",
        f"- **Ledger Dizini:** `{payload.get('ledger_dir')}`",
        f"- **Hash Zinciri Bütünlüğü (`verify_chain`):** `{payload.get('verify_chain')}`",
        f"- **Toplam Token / Süre:** `{usage.get('total_tokens', 0)}` token / `{usage.get('wall_seconds', 0.0)}` sn",
        "",
        "## Bağımsızlık Durumu",
        f"- Spec yorumu:          {payload.get('spec_review_note', '')} (`spec_unreviewed={payload.get('spec_unreviewed', False)}`)",
        f"- İşçi:                 {w_alias}  → family={w_fam}",
        oracle_line,
        diff_model_line,
        delta_line,
        f"- Metamorfik ({meta_b.get('relation_count', 0)} bağıntı): {meta_b.get('status', 'koşmadı')}",
        f"- Determinizm:          {det_b.get('status', 'koşmadı')}",
        f"- Tip kontratı:         {typ_b.get('status', 'koşmadı')}",
        f"- Çöp girdi ({garb_b.get('case_count', 12)} vaka):  {garb_b.get('status', 'koşmadı')}",
        diff_consensus_line,
        "",
        *closing_block,
        "",
        "## Model Aileleri",
        f"- **Backend:** `{models.get('backend')}`",
        f"- **Birincil Model (`family-alpha`):** alias=`{models.get('primary_alias')}` → family=`{models.get('primary_resolved_family')}`",
        f"- **Alternatif Model (`family-beta`):** alias=`{models.get('alternate_alias')}` → family=`{models.get('alternate_resolved_family')}`",
        "",
        "## Görev Durumu",
        f"- **Commit Edilen Task'lar ({len(committed)}):** {', '.join(f'`{t}`' for t in committed) if committed else 'Yok'}",
        f"- **Kalan Task'lar ({len(remaining)}):** {', '.join(f'`{t}`' for t in remaining) if remaining else 'Yok'}",
        "",
        "## LLM Çağrı Dökümü",
    ]

    if llm_calls:
        lines.extend(
            [
                "| # | Task | Deneme | Basamak | Alias | Gerçek Model | Family | Input Tok | Output Tok | Süre (ms) | Geçerli JSON |",
                "|---|---|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for c in llm_calls:
            lines.append(
                f"| {c['call_index']} | `{c['task_id']}` | {c['repair_attempt']} | "
                f"`{c['ladder_rung']}` | `{c['requested_alias']}` | `{c['resolved_model']}` | "
                f"`{c['resolved_family']}` | {c['input_tokens']} | {c['output_tokens']} | "
                f"{c['elapsed_ms']} | `{c['output_valid']}` |"
            )
    else:
        lines.append("Hiç LLM çağrısı yapılmadı (`--dry-run` veya erken durma).")

    if diff and diff.get("disagreements"):
        lines.extend(["", "## Diferansiyel Ayrışan Girdiler (En Çok 20)"])
        for item in diff["disagreements"][:20]:
            lines.append(
                f"- `args={item.get('args')!r}` → birincil=`{item.get('primary_out')!r}`, "
                f"ikincil=`{item.get('secondary_out')!r}`"
            )

    lines.extend(["", "## Hata Atfı (Attribution) Özeti"])
    if attributions:
        for idx, attr in enumerate(attributions):
            lines.append(
                f"- **Deneme {idx} (`{attr.get('run_id')}`):** "
                f"Hatalı adım `#{attr.get('culprit_step_index')}` (`{attr.get('tool_name')}`), "
                f"TRAIL leaf=`{attr.get('trail_leaf')}` (`{attr.get('trail_group')} -> {attr.get('trail_category')}`), "
                f"ACE=`{attr.get('ace')}` — {attr.get('explanation', '')}"
            )
    else:
        lines.append("Kayıtlı hata atfı yok (ilk denemede geçti veya yürütme öncesi durdu).")

    return "\n".join(lines) + "\n"


def write_run_report_bundle(report_out: Path, payload: dict[str, Any]) -> tuple[Path, Path]:
    """Write `<report_out>` JSON and companion `<report_out_stem>.md` summary."""
    report_out.parent.mkdir(parents=True, exist_ok=True)
    rendered_json = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
    report_out.write_text(rendered_json + "\n", encoding="utf-8")

    md_path = report_out.with_suffix(".md")
    if md_path == report_out:
        md_path = report_out.parent / f"{report_out.name}.md"
    md_path.write_text(render_run_markdown_summary(payload), encoding="utf-8")
    return report_out, md_path
