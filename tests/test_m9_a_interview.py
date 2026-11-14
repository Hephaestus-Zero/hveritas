"""M9-A tests: `interview_goal`, terminal summary formatting, and I19 user confirmation loop."""

from __future__ import annotations

import json

import pytest

from hveritas.spec import (
    HumanClarificationRequiredError,
    conduct_spec_interview_session,
    format_interview_summary,
    interview_goal,
)
from hveritas.worker import FakeBackend, ModelResponse


def _architect_payload(
    *,
    statement: str = "Süre metnini saniyeye çevirir. Boş metin 0 döndürür.",
    assumptions: list[str] | None = None,
    open_questions: list[str] | None = None,
    sneaky_heldout: bool = False,
) -> str:
    req: dict[str, object] = {
        "id": "req_duration",
        "statement": statement,
        "target_file": "src/duration.py",
        "function_name": "parse_duration",
        "arg_names": ["text"],
        "return_type": "int",
        "constraints": ["stdlib only"],
        "depends_on": [],
        "proxy_assertions": [
            {"function": "parse_duration", "args": ["1h30m"], "expected": 5400},
            {"function": "parse_duration", "args": ["90"], "expected": 90},
            # Exception string placeholder should be stripped automatically from IOAssertions
            {"function": "parse_duration", "args": ["abc"], "expected": "ValueError"},
        ],
    }
    if sneaky_heldout:
        req["heldout_assertions"] = [
            {"function": "parse_duration", "args": ["2h"], "expected": 7200}
        ]
    return json.dumps(
        {
            "requirements": [req],
            "edge_cases": [
                {
                    "args": [""],
                    "input_repr": '""',
                    "expected_behavior": "0",
                    "rationale": "boş girdi",
                    "category": "empty",
                },
                {
                    "args": ["abc"],
                    "input_repr": '"abc"',
                    "expected_behavior": "ValueError",
                    "rationale": "çöp girdi",
                    "category": "garbage",
                },
            ],
            "open_questions": open_questions or [],
            "assumptions": assumptions or ["Negatif süre geçersiz kabul edildi"],
        },
        ensure_ascii=False,
    )


def test_interview_goal_builds_frozen_result_and_strips_heldout_from_architect() -> None:
    backend = FakeBackend(
        [
            ModelResponse(
                text=_architect_payload(sneaky_heldout=True),
                model="claude-sonnet-4-6",
                family="claude",
                input_tokens=310,
                output_tokens=140,
                elapsed_ms=25.0,
                usd=0.002,
            )
        ]
    )
    res, cost = interview_goal(
        goal_text="parse_duration yaz: '1h30m' gibi süreleri saniyeye çevirsin",
        backend=backend,
        architect_model="sonnet-claude",
    )

    assert len(res.requirements) == 1
    req = res.requirements[0]
    assert req.target_file == "src/duration.py"
    assert req.function_name == "parse_duration"
    assert req.arg_names == ["text"]
    assert len(req.proxy_assertions) == 2
    # Architect MUST NEVER populate held-out assertions (M9-A / I15)
    assert req.heldout_assertions == []
    assert len(res.edge_cases) == 2
    assert res.architect_family == "claude"
    assert cost.input_tokens == 310
    assert cost.output_tokens == 140

    rendered = format_interview_summary(res)
    assert "HEDEF YORUMU" in rendered
    assert "src/duration.py :: parse_duration(text) -> int" in rendered
    assert "KENAR DURUMLAR (2)" in rendered
    assert "VARSAYIMLAR (1)" in rendered
    assert "Onaylıyor musun? [E/h/d(üzelt)]" in rendered


def test_i19_confirmation_rejection_correction_round_and_yes_bypass() -> None:
    # 1. Without `--yes`, user pressing `h` rejects spec before any worker runs
    b_reject = FakeBackend(
        [
            ModelResponse(
                text=_architect_payload(),
                model="claude-sonnet-4-6",
                family="claude",
                input_tokens=100,
                output_tokens=50,
                elapsed_ms=10.0,
            )
        ]
    )
    printed: list[str] = []
    out_reject = conduct_spec_interview_session(
        goal_text="parse_duration fonksiyonunu yaz: süre metnini saniyeye çevirsin",
        backend=b_reject,
        architect_model="sonnet-claude",
        auto_approve=False,
        input_fn=lambda _p: "h",
        output_fn=printed.append,
    )
    assert out_reject.approved is False
    assert out_reject.spec_unreviewed is False
    assert any("Onaylıyor musun? [E/h/d(üzelt)]" in s for s in printed)

    # 2. User chooses `d` (düzelt), supplies correction, then approves `E` on round 2
    seen_users: list[str] = []

    def _responder(_sys: str, usr: str, _model: str | None) -> ModelResponse:
        seen_users.append(usr)
        if "Gün ('d') soneki desteklensin" in usr:
            txt = _architect_payload(
                statement="Süre metnini saniyeye çevirir ('d', 'h', 'm').",
                assumptions=["1d = 86400 saniye"],
            )
        else:
            txt = _architect_payload(assumptions=["Gün ('d') soneki kapsam dışı"])
        return ModelResponse(
            text=txt,
            model="claude-sonnet-4-6",
            family="claude",
            input_tokens=120,
            output_tokens=60,
            elapsed_ms=12.0,
        )

    inputs = iter(["d", "Gün ('d') soneki desteklensin", "E"])
    out_corr = conduct_spec_interview_session(
        goal_text="parse_duration fonksiyonunu yaz: süre metnini saniyeye çevirsin",
        backend=FakeBackend(_responder),
        architect_model="sonnet-claude",
        auto_approve=False,
        max_rounds=3,
        input_fn=lambda _p: next(inputs),
        output_fn=lambda _s: None,
    )
    assert out_corr.approved is True
    assert out_corr.spec_unreviewed is False
    assert out_corr.rounds_used == 2
    assert out_corr.correction_rounds == 1
    assert out_corr.total_cost.input_tokens == 240
    assert "1d = 86400 saniye" in out_corr.result.assumptions

    # 3. `--yes` (`auto_approve=True`) never calls `input_fn` and records `spec_unreviewed=True`
    def _forbidden_input(_prompt: str) -> str:
        raise AssertionError("input_fn must not be called when auto_approve=True (--yes)")

    out_yes = conduct_spec_interview_session(
        goal_text="parse_duration fonksiyonunu yaz: süre metnini saniyeye çevirsin",
        backend=FakeBackend(_responder),
        architect_model="sonnet-claude",
        auto_approve=True,
        input_fn=_forbidden_input,
        output_fn=lambda _s: None,
    )
    assert out_yes.approved is True
    assert out_yes.spec_unreviewed is True

    # 4. Open questions escalate via HumanClarificationRequiredError
    b_ambig = FakeBackend(
        [
            ModelResponse(
                text=_architect_payload(open_questions=["Ondalık saat desteklenecek mi?"]),
                model="claude-sonnet-4-6",
                family="claude",
                input_tokens=80,
                output_tokens=40,
                elapsed_ms=8.0,
            )
        ]
    )
    with pytest.raises(HumanClarificationRequiredError) as exc_info:
        conduct_spec_interview_session(
            goal_text="parse_duration fonksiyonunu yaz: süre metnini saniyeye çevirsin",
            backend=b_ambig,
            architect_model="sonnet-claude",
            auto_approve=True,
            output_fn=lambda _s: None,
        )
    assert "Ondalık saat desteklenecek mi?" in exc_info.value.questions
