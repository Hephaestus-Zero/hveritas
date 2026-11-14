"""Real Docker end-to-end and adversarial integration tests for repository mode.

Executes real Python code and real ``pytest`` assertions inside the digest-pinned
``--network none --read-only --user 10001:10001`` verifier container (never on host).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from hveritas import cli as cli_mod
from hveritas.harness.isolation import DEFAULT_VERIFIER_IMAGE_DIGEST
from hveritas.harness.oracle_vault import EncryptedOracleVault
from hveritas.repository import DockerRepositoryVerifier, hash_manifest

PRICING_PY = """from ledger_calc.discounts import apply_tier_discount


def compute_invoice_total(items: list[tuple[int, float]], tier: str) -> float:
    subtotal = 0.0
    for qty, unit_price in items:
        if qty < 0 or unit_price < 0:
            raise ValueError("negative item")
        subtotal += qty * unit_price
    discounted = apply_tier_discount(subtotal, tier)
    # Buggy rounding + duplicated tax calculation
    tax = discounted * 0.20
    return int((discounted + tax) * 100) / 100.0
"""

DISCOUNTS_PY = """def apply_tier_discount(amount: float, tier: str) -> float:
    rates = {"standard": 0.0, "silver": 0.05, "gold": 0.10}
    if tier not in rates:
        raise ValueError(f"unknown tier: {tier}")
    return amount * (1.0 - rates[tier])
"""

CONFTEST_PY = """import pytest


@pytest.fixture
def sample_cart() -> list[tuple[int, float]]:
    return [(2, 10.0), (1, 5.0)]
"""

VISIBLE_TEST_PY = """import pytest
from ledger_calc.pricing import compute_invoice_total


def test_standard_invoice_with_conftest_fixture(sample_cart: list[tuple[int, float]]) -> None:
    assert compute_invoice_total(sample_cart, "standard") == 30.0


def test_negative_item_rejected() -> None:
    with pytest.raises(ValueError):
        compute_invoice_total([(-1, 5.0)], "standard")
"""


@pytest.fixture
def real_fixture_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "fixture_repo"
    (repo / "src/ledger_calc").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "ledger-calc"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (repo / "src/ledger_calc/__init__.py").write_text(
        "from ledger_calc.pricing import compute_invoice_total\n__all__ = ['compute_invoice_total']\n",
        encoding="utf-8",
    )
    (repo / "src/ledger_calc/pricing.py").write_text(PRICING_PY, encoding="utf-8")
    (repo / "src/ledger_calc/discounts.py").write_text(DISCOUNTS_PY, encoding="utf-8")
    (repo / "tests/conftest.py").write_text(CONFTEST_PY, encoding="utf-8")
    (repo / "tests/test_pricing.py").write_text(VISIBLE_TEST_PY, encoding="utf-8")
    return repo


def test_real_docker_cli_end_to_end_refactor_with_repair_and_oracle_vault(
    tmp_path: Path, real_fixture_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Full CLI -> EncryptedOracleVault -> DockerRepositoryVerifier e2e proof:

    - Real multi-file refactor across 3 modules (`money.py`, `discounts.py`, `pricing.py`)
      plus a worker-added test (`tests/test_money_units.py`).
    - Real repository `tests/conftest.py` fixture (`sample_cart`) used in baseline & candidate.
    - Round 0 introduces a subtle rounding bug + fails 1 of 2 oracle checks -> rejected.
    - Round 1 repairs `money.py` using aggregate feedback -> all gates pass (`accepted`, exit 0).
    - Source repository remains byte-for-byte unchanged.
    """
    pre_source_hashes = hash_manifest(real_fixture_repo)

    vault_dir = tmp_path / "vault_repo"
    vault_key = tmp_path / "vault.key"
    monkeypatch.setattr(
        "hveritas.repository.run.EncryptedOracleVault",
        lambda: EncryptedOracleVault(repo_dir=vault_dir, key_file=vault_key),
    )

    # Independent cross-family oracle tests:
    # 1) Half-even/standard 2-decimal rounding on fractional cent tax (19.99 * 0.95 * 1.20 = 22.7886 -> 22.79, whereas truncation in original gave 22.78!)
    # 2) New `platinum` tier (15% discount) + clean extracted `ledger_calc.money.round_currency` helper!
    oracle_suite = {
        "test_independent_oracle.py": (
            "from ledger_calc.money import round_currency\n"
            "from ledger_calc.pricing import compute_invoice_total\n\n"
            "def test_fractional_cent_rounds_nearest() -> None:\n"
            "    assert compute_invoice_total([(1, 19.99)], 'silver') == 22.79\n"
            "    assert round_currency(22.7886) == 22.79\n\n"
            "def test_platinum_tier_supported() -> None:\n"
            "    assert compute_invoice_total([(2, 50.0)], 'platinum') == 102.0\n"
        )
    }

    # Round 0 worker attempt: extracts `money.py` and adds `platinum`, BUT leaves `int(x * 100) / 100.0` truncation in `round_currency`!
    round0_proposal = {
        "summary": "Extract money helper and add platinum tier (still truncating cents)",
        "acceptance_criteria": ["round_currency extracted", "platinum tier added"],
        "test_paths": ["tests/test_money_units.py"],
        "actions": [
            {
                "tool_name": "write_file",
                "tool_args": {
                    "path": "src/ledger_calc/money.py",
                    "content": (
                        "TAX_RATE = 0.20\n\n"
                        "def round_currency(value: float) -> float:\n"
                        "    return int(value * 100) / 100.0\n"
                    ),
                },
            },
            {
                "tool_name": "write_file",
                "tool_args": {
                    "path": "src/ledger_calc/discounts.py",
                    "content": (
                        "TIER_RATES: dict[str, float] = {\n"
                        '    "standard": 0.0,\n'
                        '    "silver": 0.05,\n'
                        '    "gold": 0.10,\n'
                        '    "platinum": 0.15,\n'
                        "}\n\n"
                        "def apply_tier_discount(amount: float, tier: str) -> float:\n"
                        "    if tier not in TIER_RATES:\n"
                        '        raise ValueError(f"unknown tier: {tier}")\n'
                        "    return amount * (1.0 - TIER_RATES[tier])\n"
                    ),
                },
            },
            {
                "tool_name": "write_file",
                "tool_args": {
                    "path": "src/ledger_calc/pricing.py",
                    "content": (
                        "from ledger_calc.discounts import apply_tier_discount\n"
                        "from ledger_calc.money import TAX_RATE, round_currency\n\n"
                        "def compute_invoice_total(items: list[tuple[int, float]], tier: str) -> float:\n"
                        "    subtotal = 0.0\n"
                        "    for qty, unit_price in items:\n"
                        "        if qty < 0 or unit_price < 0:\n"
                        '            raise ValueError("negative item")\n'
                        "        subtotal += qty * unit_price\n"
                        "    discounted = apply_tier_discount(subtotal, tier)\n"
                        "    return round_currency(discounted * (1.0 + TAX_RATE))\n"
                    ),
                },
            },
            {
                "tool_name": "write_file",
                "tool_args": {
                    "path": "tests/test_money_units.py",
                    "content": (
                        "from ledger_calc.pricing import compute_invoice_total\n\n"
                        "def test_gold_tier() -> None:\n"
                        "    assert compute_invoice_total([(1, 100.0)], 'gold') == 108.0\n"
                    ),
                },
            },
        ],
        "done": True,
    }

    # Round 1 worker repair: patches `round_currency` in `src/ledger_calc/money.py` to `round(value, 2)`!
    round1_repair = {
        "summary": "Fix round_currency to use standard 2-decimal rounding instead of truncation",
        "acceptance_criteria": ["nearest-cent rounding accurate"],
        "test_paths": ["tests/test_money_units.py"],
        "actions": [
            {
                "tool_name": "patch_file",
                "tool_args": {
                    "path": "src/ledger_calc/money.py",
                    "old_text": "    return int(value * 100) / 100.0\n",
                    "new_text": "    return round(value + 1e-12, 2)\n",
                },
            }
        ],
        "done": True,
    }

    fake_responses_path = tmp_path / "responses.json"
    fake_responses_path.write_text(
        json.dumps(
            [
                {
                    "text": json.dumps(
                        {
                            "goal_kind": "behavior_change",
                            "acceptance_criteria": [
                                "Nearest-cent rounding via ledger_calc.money.round_currency",
                                "Support platinum 15% discount tier",
                            ],
                            "tests": oracle_suite,
                        }
                    ),
                    "model": "sonnet-claude",
                    "family": "claude",
                    "input_tokens": 220,
                    "output_tokens": 140,
                    "elapsed_ms": 15.0,
                },
                {
                    "text": json.dumps(round0_proposal),
                    "model": "argon",
                    "family": "gemini",
                    "input_tokens": 310,
                    "output_tokens": 260,
                    "elapsed_ms": 20.0,
                },
                {
                    "text": json.dumps(round1_repair),
                    "model": "argon",
                    "family": "gemini",
                    "input_tokens": 350,
                    "output_tokens": 90,
                    "elapsed_ms": 12.0,
                },
            ]
        ),
        encoding="utf-8",
    )

    work_root = tmp_path / "runs"
    rc = cli_mod.main(
        [
            "run",
            "--repository",
            "--backend",
            "fake",
            "--fake-responses",
            str(fake_responses_path),
            "--initial-workspace",
            str(real_fixture_repo),
            "--work-root",
            str(work_root),
            "--run-id",
            "docker_e2e_1",
            "--max-repository-rounds",
            "3",
            "--goal",
            "Extract ledger_calc.money.round_currency with nearest-cent rounding and add platinum (15%) tier while preserving existing invoice behavior.",
        ]
    )

    assert rc == 0
    # 1) Original source repo is 100% immutable
    assert hash_manifest(real_fixture_repo) == pre_source_hashes

    # 2) Encrypted oracle ciphertext exists in vault; zero plaintext oracle files on host
    bundle = vault_dir / "repo_docker_e2e_1.aesgcm"
    assert bundle.is_file()
    assert "round_currency" not in bundle.read_text(encoding="utf-8")

    # 3) Inspect report.json, report.md, patch.diff, and events.jsonl
    run_dir = work_root / "docker_e2e_1"
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["status"] == "accepted"
    assert report["exit_code"] == 0
    assert report["changed_source_files"] == [
        "src/ledger_calc/discounts.py",
        "src/ledger_calc/money.py",
        "src/ledger_calc/pricing.py",
    ]
    assert report["added_test_files"] == ["tests/test_money_units.py"]
    assert all(report["gates"].values())

    # Baseline ran real conftest fixture test inside Docker
    assert report["baseline"]["tests_passed"] == [
        "tests/test_pricing.py::test_negative_item_rejected",
        "tests/test_pricing.py::test_standard_invoice_with_conftest_fixture",
    ]
    # Round 0 failed oracle (1/2 passing: platinum passed, fractional cent rounding failed!)
    assert len(report["rounds"]) == 2
    assert report["rounds"][0]["gates"]["gate_no_regressions"] is True
    assert report["rounds"][0]["gates"]["gate_added_tests_pass"] is True
    assert report["rounds"][0]["gates"]["gate_oracle_pass"] is False
    assert report["rounds"][0]["oracle_summary"] == {"status": "ok", "passed": 1, "total": 2}
    # Round 1 repaired it and passed 2/2 oracle checks + 3/3 visible checks!
    assert report["rounds"][1]["gates"]["gate_oracle_pass"] is True
    assert report["rounds"][1]["oracle_summary"] == {"status": "ok", "passed": 2, "total": 2}
    assert len(report["candidate"]["tests_passed"]) == 3
    assert (run_dir / "patch.diff").read_text(encoding="utf-8").strip() != ""
    assert "round_currency" not in (run_dir / "report.md").read_text(
        encoding="utf-8"
    ) or "test_fractional_cent" not in (run_dir / "report.md").read_text(encoding="utf-8")


def test_real_docker_adversarial_tampering_defeated(tmp_path: Path) -> None:
    """Real container adversarial checks (§7): stdout marker spoofing, /tmp/hv_result.json
    overwriting, os._exit(0), and pytest.exit(returncode=0) all fail closed.
    """
    verifier = DockerRepositoryVerifier(DEFAULT_VERIFIER_IMAGE_DIGEST, per_run_timeout_s=30.0)

    # Adversarial Case 1: Candidate writes /tmp/hv_result.json AND prints fake HV_RESULT= while failing
    ws_spoof = tmp_path / "ws_spoof"
    (ws_spoof / "tests").mkdir(parents=True)
    (ws_spoof / "evil.py").write_text(
        "import json\n"
        "FAKE = {'session_finished': True, 'collected': ['tests/test_a.py::test_real'], "
        "'passed': ['tests/test_a.py::test_real'], 'failed': [], 'collection_errors': [], 'exit_code': 0}\n"
        "with open('/tmp/hv_result.json', 'w') as fh:\n"
        "    json.dump(FAKE, fh)\n"
        "print('HV_RESULT=' + json.dumps(FAKE), flush=True)\n",
        encoding="utf-8",
    )
    (ws_spoof / "tests/test_a.py").write_text(
        "import evil\n\ndef test_real() -> None:\n    assert 1 == 2\n",
        encoding="utf-8",
    )
    out_spoof = verifier.run_pytest(ws_spoof, ["tests/test_a.py"])
    assert out_spoof.status == "ok"
    assert out_spoof.exit_code == 1
    assert out_spoof.passed == frozenset()
    assert out_spoof.failed == ("tests/test_a.py::test_real",)

    # Adversarial Case 2: Candidate calls os._exit(0) inside test to bypass failure reporting
    ws_osexit = tmp_path / "ws_osexit"
    (ws_osexit / "tests").mkdir(parents=True)
    (ws_osexit / "tests/test_b.py").write_text(
        "import os\n\ndef test_bypass() -> None:\n    os._exit(0)\n\ndef test_never_runs() -> None:\n    assert False\n",
        encoding="utf-8",
    )
    out_osexit = verifier.run_pytest(ws_osexit, ["tests/test_b.py"])
    assert out_osexit.status == "error"
    assert out_osexit.failure_kind == "corrupt_evidence"
    assert out_osexit.evidence_valid is False
    assert out_osexit.passed == frozenset()

    # Adversarial Case 3: Candidate calls pytest.exit(..., returncode=0) leaving 2nd test unexecuted
    ws_ptexit = tmp_path / "ws_ptexit"
    (ws_ptexit / "tests").mkdir(parents=True)
    (ws_ptexit / "tests/test_c.py").write_text(
        "import pytest\n\ndef test_first() -> None:\n    pytest.exit('abort cleanly', returncode=0)\n\ndef test_second() -> None:\n    assert False\n",
        encoding="utf-8",
    )
    out_ptexit = verifier.run_pytest(ws_ptexit, ["tests/test_c.py"])
    assert out_ptexit.status == "error"
    assert out_ptexit.failure_kind == "corrupt_evidence"
    assert out_ptexit.evidence_valid is False
    assert out_ptexit.passed == frozenset()


def test_real_docker_timeout_cleans_up_container(tmp_path: Path) -> None:
    """Real container timeout kills and removes container so zero hv-repo-* containers linger."""
    ws_hang = tmp_path / "ws_hang"
    (ws_hang / "tests").mkdir(parents=True)
    (ws_hang / "tests/test_hang.py").write_text(
        "import time\n\ndef test_sleep() -> None:\n    time.sleep(30)\n",
        encoding="utf-8",
    )
    verifier = DockerRepositoryVerifier(DEFAULT_VERIFIER_IMAGE_DIGEST, per_run_timeout_s=1.5)
    out = verifier.run_pytest(ws_hang, ["tests/test_hang.py"])
    assert out.status == "timeout"
    assert out.passed == frozenset()

    idx = out.command.index("--name")
    container_name = out.command[idx + 1]
    ps = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{container_name}$", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert ps.stdout.strip() == ""


def test_real_docker_behavior_preserving_refactor_with_structural_gate(
    tmp_path: Path, real_fixture_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real Docker proof for `--goal-kind refactor`:

    - Oracle behavioral suite passes on `original` (preserving exact existing behavior).
    - Pre-registered AST `structural_checks` fail on `original` and pass on `candidate`.
    """
    vault_dir = tmp_path / "vault_ref"
    vault_key = tmp_path / "vault_ref.key"
    monkeypatch.setattr(
        "hveritas.repository.run.EncryptedOracleVault",
        lambda: EncryptedOracleVault(repo_dir=vault_dir, key_file=vault_key),
    )

    structural_file = tmp_path / "structural.json"
    structural_file.write_text(
        json.dumps(
            [
                {"kind": "module_exists", "path": "src/ledger_calc/tax.py"},
                {
                    "kind": "symbol_defined",
                    "path": "src/ledger_calc/tax.py",
                    "symbols": ["add_vat"],
                },
                {
                    "kind": "symbol_imported_from",
                    "path": "src/ledger_calc/pricing.py",
                    "module": "ledger_calc.tax",
                    "symbols": ["add_vat"],
                },
            ]
        ),
        encoding="utf-8",
    )

    oracle_refactor_suite = {
        "test_preserved_behavior.py": (
            "from ledger_calc.pricing import compute_invoice_total\n\n"
            "def test_gold_and_silver_preserved() -> None:\n"
            "    assert compute_invoice_total([(2, 50.0)], 'gold') == 108.0\n"
            "    assert compute_invoice_total([(1, 20.0)], 'silver') == 22.8\n"
        )
    }

    worker_refactor = {
        "summary": "Extract VAT calculation into ledger_calc.tax.add_vat while preserving invoice behavior",
        "acceptance_criteria": ["add_vat extracted and imported", "behavior identical"],
        "test_paths": [],
        "actions": [
            {
                "tool_name": "write_file",
                "tool_args": {
                    "path": "src/ledger_calc/tax.py",
                    "content": (
                        "VAT_RATE = 0.20\n\n"
                        "def add_vat(discounted: float) -> float:\n"
                        "    tax = discounted * VAT_RATE\n"
                        "    return int((discounted + tax) * 100) / 100.0\n"
                    ),
                },
            },
            {
                "tool_name": "write_file",
                "tool_args": {
                    "path": "src/ledger_calc/pricing.py",
                    "content": (
                        "from ledger_calc.discounts import apply_tier_discount\n"
                        "from ledger_calc.tax import add_vat\n\n"
                        "def compute_invoice_total(items: list[tuple[int, float]], tier: str) -> float:\n"
                        "    subtotal = 0.0\n"
                        "    for qty, unit_price in items:\n"
                        "        if qty < 0 or unit_price < 0:\n"
                        '            raise ValueError("negative item")\n'
                        "        subtotal += qty * unit_price\n"
                        "    return add_vat(apply_tier_discount(subtotal, tier))\n"
                    ),
                },
            },
        ],
        "done": True,
    }

    responses_path = tmp_path / "refactor_responses.json"
    responses_path.write_text(
        json.dumps(
            [
                {
                    "text": json.dumps({"goal_kind": "refactor", "tests": oracle_refactor_suite}),
                    "model": "sonnet-claude",
                    "family": "claude",
                    "input_tokens": 180,
                    "output_tokens": 90,
                    "elapsed_ms": 10.0,
                },
                {
                    "text": json.dumps(worker_refactor),
                    "model": "argon",
                    "family": "gemini",
                    "input_tokens": 240,
                    "output_tokens": 160,
                    "elapsed_ms": 12.0,
                },
            ]
        ),
        encoding="utf-8",
    )

    rc = cli_mod.main(
        [
            "run",
            "--repository",
            "--goal-kind",
            "refactor",
            "--structural-criteria",
            str(structural_file),
            "--backend",
            "fake",
            "--fake-responses",
            str(responses_path),
            "--initial-workspace",
            str(real_fixture_repo),
            "--work-root",
            str(tmp_path / "runs"),
            "--run-id",
            "docker_refactor_1",
            "--goal",
            "Extract VAT logic into src/ledger_calc/tax.py (add_vat) while preserving behavior.",
        ]
    )
    assert rc == 0
    rep = json.loads((tmp_path / "runs/docker_refactor_1/report.json").read_text(encoding="utf-8"))
    assert rep["status"] == "accepted"
    assert rep["gates"]["gate_structural_criteria"] is True
    assert rep["gates"]["gate_oracle_pass"] is True
    assert rep["oracle"]["baseline_passed"] == 1
