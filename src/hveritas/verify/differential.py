"""3rd-Family Differential Fuzz Consensus (`M9-D`, Invariant `I18`)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from hveritas.harness.isolation import SCRATCH_ROOT
from hveritas.ledger.canonical import canonical_json
from hveritas.ledger.models import CostRecord
from hveritas.verify.bus import VerifierBus
from hveritas.verify.models import VerificationState

if TYPE_CHECKING:
    from hveritas.spec.compiler import RequirementDraft
    from hveritas.spec.interview import EdgeCase
    from hveritas.worker.backend import ModelBackend

_CODE_FENCE_RE = re.compile(r"```(?:python)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
_DIFF_MARKER = "DIFF_SUMMARY_JSON:"


class DifferentialReport(BaseModel):
    """Structured outcome of `run_differential_check` (`M9-D`, `I18`)."""

    model_config = ConfigDict(frozen=True)

    agreement_rate: float = Field(ge=0.0, le=1.0)
    agreed_count: int = Field(ge=0)
    total_inputs: int = Field(ge=0)
    disagreements: list[dict[str, Any]] = Field(default_factory=list)
    secondary_family: str = ""
    secondary_model: str = ""
    differential_skipped: bool = False
    status: str = "AGREED"
    warning: str = ""
    cost: CostRecord = Field(default_factory=CostRecord)


def build_differential_prompt(
    *,
    requirement: RequirementDraft,
    edge_cases: list[EdgeCase] | None = None,
) -> str:
    """Build strictly isolated 3rd-family prompt (`I16`: zero worker code, zero proxy/held-out assertions)."""
    edge_rows = [
        {
            "args": ec.args,
            "input_repr": ec.input_repr,
            "expected_behavior": ec.expected_behavior,
            "rationale": ec.rationale,
        }
        for ec in (edge_cases or [])
    ]
    schema_hint = {
        "code": (f"def {requirement.function_name}({', '.join(requirement.arg_names)}):\n    ...")
    }
    return (
        "## 1. Behavioral Requirement Statement\n"
        f"{requirement.statement}\n"
        + (
            f"Constraints: {', '.join(requirement.constraints)}\n"
            if requirement.constraints
            else ""
        )
        + "\n## 2. API Contract\n"
        f"- Target module: `{requirement.target_file}`\n"
        f"- Function signature: `{requirement.function_name}({', '.join(requirement.arg_names)})`\n\n"
        "## 3. Edge Cases\n"
        f"{json.dumps(edge_rows, ensure_ascii=False, indent=2)}\n\n"
        "## 4. Output Contract\n"
        "Write a complete, standalone Python 3.12 stdlib-only implementation of the module. "
        f"Return ONLY a JSON object matching:\n{json.dumps(schema_hint, ensure_ascii=False, indent=2)}"
    )


def _extract_secondary_python_code(raw_text: str, fn_name: str) -> str | None:
    from hveritas.spec.interview import _extract_json_object

    parsed, _ = _extract_json_object(raw_text)
    if parsed is not None:
        if isinstance(parsed.get("code"), str) and f"def {fn_name}" in parsed["code"]:
            return str(parsed["code"]).strip() + "\n"
        actions = parsed.get("actions")
        if isinstance(actions, list):
            for act in actions:
                if isinstance(act, dict) and act.get("tool_name") == "write_file":
                    t_args = act.get("tool_args")
                    if (
                        isinstance(t_args, dict)
                        and isinstance(t_args.get("content"), str)
                        and f"def {fn_name}" in t_args["content"]
                    ):
                        return str(t_args["content"]).strip() + "\n"

    m = _CODE_FENCE_RE.search(raw_text)
    if m and f"def {fn_name}" in m.group(1):
        return m.group(1).strip() + "\n"
    if f"def {fn_name}" in raw_text:
        return raw_text.strip() + "\n"
    return None


def _infer_arg_kind(requirement: RequirementDraft, pos: int) -> str:
    for a in requirement.proxy_assertions:
        if pos < len(a.args):
            val = a.args[pos]
            if isinstance(val, bool):
                return "bool"
            if isinstance(val, int):
                return "int"
            if isinstance(val, float):
                return "float"
            if isinstance(val, str):
                return "str"
            if isinstance(val, list):
                return "list_num"
    arg_low = requirement.arg_names[pos].lower()
    if any(k in arg_low for k in ("text", "str", "code", "name", "duration", "token", "fmt")):
        return "str"
    if any(k in arg_low for k in ("items", "prices", "values", "nums", "list", "xs")):
        return "list_num"
    if any(k in arg_low for k in ("price", "rate", "ratio", "amount")):
        return "float"
    return "int"


def _det_int(seed: int, label: str, lo: int, hi: int) -> int:
    digest = hashlib.sha256(f"{seed}:{label}".encode()).digest()
    span = hi - lo + 1
    return lo + (int.from_bytes(digest[:8], "big") % span)


def _generate_arg_value(
    *,
    kind: str,
    idx: int,
    pos: int,
    seed: int,
    statement_low: str,
) -> Any:
    tag = f"{idx}:{pos}"
    if kind == "bool":
        return (idx + pos) % 2 == 0
    if kind == "int":
        boundaries = [0, 1, -1, 2, 5, 10, 50, 100, -10, 999]
        if idx < len(boundaries):
            return boundaries[idx]
        return _det_int(seed, tag, -50, 500)
    if kind == "float":
        boundaries_f = [0.0, 1.0, -1.0, 0.5, 10.0, 99.95, 100.0, 250.5, -5.0, 1000.0]
        if idx < len(boundaries_f):
            return boundaries_f[idx]
        raw = _det_int(seed, tag, -2000, 50_000)
        return round(raw / 100.0, 2)
    if kind == "list_num":
        if idx == 0:
            return []
        if idx == 1:
            return [0]
        length = _det_int(seed, f"{tag}:len", 1, 6)
        return [_det_int(seed, f"{tag}:el:{j}", 0, 300) for j in range(length)]

    # `str` domain: blend boundary strings, duration-like strings, coupon/code tokens, and invalid strings
    is_duration = any(
        w in statement_low for w in ("duration", "süre", "saniye", "dakika", "1h", "saat")
    )
    if is_duration:
        fixed_str = [
            "",
            "0",
            "0h",
            "0m",
            "0h0m",
            "1h",
            "1m",
            "90",
            "45m",
            "1h30m",
            "2h15m",
            "10h5m",
            "-5m",
            "-10",
            "abc",
            "10d",
            "1h-5m",
            "3.5h",
            "  ",
            "120",
        ]
        if idx < len(fixed_str):
            return fixed_str[idx]
        mode = idx % 5
        h = _det_int(seed, f"{tag}:h", 0, 48)
        m = _det_int(seed, f"{tag}:m", 0, 120)
        s = _det_int(seed, f"{tag}:s", 0, 7200)
        if mode == 0:
            return f"{h}h{m}m"
        if mode == 1:
            return f"{h}h"
        if mode == 2:
            return f"{m}m"
        if mode == 3:
            return str(s)
        bad_pool = [f"-{h}h", f"{h}x", f"{m}s_bad", f"h{m}m", f"{h}h{m}m_extra"]
        return bad_pool[h % len(bad_pool)]

    generic_fixed = ["", "0", "1", "SAVE10", "OTHER", "VIP", "UNKNOWN", "-1", "abc", "test"]
    if idx < len(generic_fixed):
        return generic_fixed[idx]
    n = _det_int(seed, tag, 0, 999)
    pool = [f"CODE_{n}", str(n), f"item_{n % 20}", "", f"-{n}"]
    return pool[idx % len(pool)]


def generate_fuzz_inputs(
    *,
    requirement: RequirementDraft,
    edge_cases: list[EdgeCase] | None,
    n_fuzz_inputs: int,
    seed: int,
) -> list[list[Any]]:
    """Deterministically generate `n_fuzz_inputs` vectors from `seed`, boundaries, and `edge_cases`."""
    n_args = len(requirement.arg_names)
    if n_fuzz_inputs <= 0:
        return []
    kinds = [_infer_arg_kind(requirement, p) for p in range(n_args)]
    stmt_low = requirement.statement.lower()

    vectors: list[list[Any]] = []
    seen: set[str] = set()

    def _add(vec: list[Any]) -> None:
        if len(vec) != n_args or len(vectors) >= n_fuzz_inputs:
            return
        k = canonical_json(vec)
        if k not in seen:
            seen.add(k)
            vectors.append(vec)

    for ec in edge_cases or []:
        if len(ec.args) == n_args:
            _add(list(ec.args))

    cursor = 0
    max_iters = max(n_fuzz_inputs * 12, 500)
    while len(vectors) < n_fuzz_inputs and cursor < max_iters:
        vec = [
            _generate_arg_value(
                kind=kinds[p],
                idx=cursor,
                pos=p,
                seed=seed,
                statement_low=stmt_low,
            )
            for p in range(n_args)
        ]
        _add(vec)
        cursor += 1

    # Pad deterministically if domain cardinality (e.g. single bool) is smaller than `n_fuzz_inputs`
    while len(vectors) < n_fuzz_inputs and vectors:
        vectors.append(list(vectors[len(vectors) % len(vectors)]))
    return vectors[:n_fuzz_inputs]


def _render_differential_harness_pytest(
    *,
    rel_target_file: str,
    function_name: str,
    fuzz_inputs: list[list[Any]],
) -> str:
    p_rel = f"primary/{rel_target_file}"
    s_rel = f"secondary/{rel_target_file}"
    return (
        "import copy\n"
        "import json\n"
        "import signal\n"
        "from loader import load_workspace_module\n\n"
        "class _DiffTimeout(BaseException):\n"
        "    pass\n\n"
        "def _on_alarm(_sig, _frm):\n"
        "    raise _DiffTimeout('TIMEOUT')\n\n"
        "def _norm_call(fn, raw_args):\n"
        "    signal.setitimer(signal.ITIMER_REAL, 0.5)\n"
        "    try:\n"
        "        val = fn(*copy.deepcopy(raw_args))\n"
        "        if isinstance(val, float):\n"
        "            return ('return', 'float', round(val, 6))\n"
        "        return ('return', type(val).__name__, val)\n"
        "    except _DiffTimeout:\n"
        "        return ('timeout', 'TimeoutError', None)\n"
        "    except Exception as exc:\n"
        "        return ('raise', type(exc).__name__, None)\n"
        "    finally:\n"
        "        signal.setitimer(signal.ITIMER_REAL, 0.0)\n\n"
        "def _fmt_out(norm_tuple):\n"
        "    kind, typ, val = norm_tuple\n"
        "    if kind == 'return':\n"
        "        return val\n"
        "    return f'raises {typ}'\n\n"
        "def test_m9_d_differential_consensus():\n"
        "    old_h = signal.signal(signal.SIGALRM, _on_alarm)\n"
        "    try:\n"
        f"        mod_p = load_workspace_module({p_rel!r}, module_name='diff_primary_mod')\n"
        f"        mod_s = load_workspace_module({s_rel!r}, module_name='diff_secondary_mod')\n"
        f"        fn_p = getattr(mod_p, {function_name!r})\n"
        f"        fn_s = getattr(mod_s, {function_name!r})\n"
        f"        inputs = {fuzz_inputs!r}\n"
        "        agreed = 0\n"
        "        disagreements = []\n"
        "        for vec in inputs:\n"
        "            out_p = _norm_call(fn_p, vec)\n"
        "            out_s = _norm_call(fn_s, vec)\n"
        "            if out_p == out_s:\n"
        "                agreed += 1\n"
        "            else:\n"
        "                if len(disagreements) < 20:\n"
        "                    disagreements.append({\n"
        "                        'args': vec,\n"
        "                        'primary_out': _fmt_out(out_p),\n"
        "                        'secondary_out': _fmt_out(out_s),\n"
        "                    })\n"
        "        if disagreements:\n"
        "            payload = {'agreed': agreed, 'total': len(inputs), 'disagreements': disagreements}\n"
        f"            raise AssertionError('{_DIFF_MARKER}' + json.dumps(payload, ensure_ascii=False))\n"
        "    finally:\n"
        "        signal.setitimer(signal.ITIMER_REAL, 0.0)\n"
        "        signal.signal(signal.SIGALRM, old_h)\n"
    )


def _unavailable_report(
    reason: str, *, sec_family: str = "", sec_model: str = "", cost: CostRecord | None = None
) -> DifferentialReport:
    msg = f"DIFFERENTIAL_UNAVAILABLE: {reason}"
    print(f"[hveritas] WARNING: {msg}", file=sys.stderr)
    return DifferentialReport(
        agreement_rate=1.0,
        agreed_count=0,
        total_inputs=0,
        disagreements=[],
        secondary_family=sec_family,
        secondary_model=sec_model,
        differential_skipped=True,
        status="DIFFERENTIAL_UNAVAILABLE",
        warning=msg,
        cost=cost or CostRecord(),
    )


def run_differential_check(
    *,
    primary_ws: Path,
    requirement: RequirementDraft,
    backend: ModelBackend,
    differential_model: str,
    worker_family: str,
    oracle_family: str,
    n_fuzz_inputs: int = 200,
    seed: int = 20261104,
    edge_cases: list[EdgeCase] | None = None,
    verifier_bus: VerifierBus | None = None,
    timeout_s: float = 180.0,
) -> DifferentialReport:
    """Compare primary implementation against an independent 3rd-family implementation on `n_fuzz_inputs` (`I18`)."""
    primary_target = (primary_ws.resolve() / requirement.target_file).resolve()
    if not primary_target.is_file():
        return _unavailable_report(
            f"Primary target file missing at {requirement.target_file!r}",
            sec_model=differential_model,
        )

    system_prompt = (
        "You are an independent Differential Reference Engineer for hveritas (M9-D). "
        'Implement the requested Python module cleanly using stdlib only, returning ONLY JSON `{"code": "..."}`.'
    )
    user_prompt = build_differential_prompt(requirement=requirement, edge_cases=edge_cases)

    try:
        resp = backend.complete(
            system=system_prompt,
            user=user_prompt,
            model=differential_model,
            timeout_s=timeout_s,
        )
    except (RuntimeError, TimeoutError, ValueError, OSError) as exc:
        return _unavailable_report(
            f"3rd-family model {differential_model!r} call failed ({type(exc).__name__}: {exc})",
            sec_model=differential_model,
        )

    cost = CostRecord(
        input_tokens=resp.input_tokens,
        output_tokens=resp.output_tokens,
        usd=resp.usd,
        wall_ms=resp.elapsed_ms,
    )
    sec_fam = resp.family.strip()
    if worker_family and sec_fam.lower() == worker_family.strip().lower():
        return _unavailable_report(
            f"Model {differential_model!r} resolved to family={sec_fam!r}, colliding with worker family={worker_family!r}",
            sec_family=sec_fam,
            sec_model=resp.model,
            cost=cost,
        )
    if oracle_family and sec_fam.lower() == oracle_family.strip().lower():
        return _unavailable_report(
            f"Model {differential_model!r} resolved to family={sec_fam!r}, colliding with oracle family={oracle_family!r}",
            sec_family=sec_fam,
            sec_model=resp.model,
            cost=cost,
        )

    sec_code = _extract_secondary_python_code(resp.text, requirement.function_name)
    if sec_code is None:
        return _unavailable_report(
            f"3rd-family model {differential_model!r} did not return valid Python defining {requirement.function_name!r}",
            sec_family=sec_fam,
            sec_model=resp.model,
            cost=cost,
        )

    fuzz_inputs = generate_fuzz_inputs(
        requirement=requirement,
        edge_cases=edge_cases,
        n_fuzz_inputs=n_fuzz_inputs,
        seed=seed,
    )
    bus = verifier_bus or VerifierBus()

    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    stage_root = SCRATCH_ROOT / f"hv_diff_{os.getpid()}_{secrets.token_hex(8)}"
    stage_ws = stage_root / "ws"
    (stage_ws / "primary").mkdir(parents=True, mode=0o755)
    (stage_ws / "secondary").mkdir(parents=True, mode=0o755)

    try:
        shutil.copytree(primary_ws.resolve(), stage_ws / "primary", dirs_exist_ok=True)
        sec_file = (stage_ws / "secondary" / requirement.target_file).resolve()
        sec_file.parent.mkdir(parents=True, exist_ok=True)
        sec_file.write_text(sec_code, encoding="utf-8")

        t0_ev = bus.verify_t0(
            VerificationState(
                workspace_path=str(stage_ws / "secondary"),
                t0_config={"compile": True},
            )
        )
        if not t0_ev.passed:
            return _unavailable_report(
                f"3rd-family implementation from {differential_model!r} failed syntax compilation",
                sec_family=sec_fam,
                sec_model=resp.model,
                cost=cost,
            )

        diff_pytest = _render_differential_harness_pytest(
            rel_target_file=requirement.target_file,
            function_name=requirement.function_name,
            fuzz_inputs=fuzz_inputs,
        )
        t1_ev = bus.verify_t1(
            VerificationState(
                workspace_path=str(stage_ws),
                dynamic_invariants={"test_m9_differential.py": diff_pytest},
                t1_config={"security_scan": False},
            )
        )
        if t1_ev.passed:
            return DifferentialReport(
                agreement_rate=1.0,
                agreed_count=len(fuzz_inputs),
                total_inputs=len(fuzz_inputs),
                disagreements=[],
                secondary_family=sec_fam,
                secondary_model=resp.model,
                differential_skipped=False,
                status="AGREED",
                cost=cost,
            )

        raw_out = "\n".join(str(c.details.get("output", "")) for c in t1_ev.checks)
        marker_idx = raw_out.find(_DIFF_MARKER)
        if marker_idx != -1:
            from hveritas.spec.interview import _extract_json_object

            after = raw_out[marker_idx + len(_DIFF_MARKER) :]
            parsed_diff, _ = _extract_json_object(after)
            if parsed_diff is not None:
                agreed_n = int(parsed_diff.get("agreed", 0))
                total_n = max(1, int(parsed_diff.get("total", len(fuzz_inputs))))
                dis_list = list(parsed_diff.get("disagreements", []))[:20]
                return DifferentialReport(
                    agreement_rate=round(agreed_n / total_n, 6),
                    agreed_count=agreed_n,
                    total_inputs=total_n,
                    disagreements=dis_list,
                    secondary_family=sec_fam,
                    secondary_model=resp.model,
                    differential_skipped=False,
                    status="DIFFERENTIAL_DISAGREEMENT",
                    cost=cost,
                )

        return DifferentialReport(
            agreement_rate=0.0,
            agreed_count=0,
            total_inputs=len(fuzz_inputs),
            disagreements=[
                {
                    "args": [],
                    "primary_out": "execution_error",
                    "secondary_out": raw_out[-300:],
                }
            ],
            secondary_family=sec_fam,
            secondary_model=resp.model,
            differential_skipped=False,
            status="DIFFERENTIAL_DISAGREEMENT",
            cost=cost,
        )
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)
