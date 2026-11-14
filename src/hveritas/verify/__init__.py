"""Multi-tier Verifier Bus (`T0..T4`), Metamorphic Relations (`T2`), and `inspect_ai` scorer integration."""

from hveritas.verify.bus import (
    RequirementDagJudge,
    TierVerifierFn,
    VerifierBus,
    inspect_tier_scorer,
)
from hveritas.verify.differential import (
    DifferentialReport,
    build_differential_prompt,
    generate_fuzz_inputs,
    run_differential_check,
)
from hveritas.verify.metamorphic import (
    MetamorphicKind,
    MetamorphicRelation,
    render_metamorphic_pytest_suite,
)
from hveritas.verify.models import (
    CheckResult,
    Evidence,
    TierId,
    VerificationState,
    VerifierBusReport,
)
from hveritas.verify.properties import (
    GARBAGE_CASE_COUNT,
    OracleFreeSuite,
    build_garbage_vectors,
    build_oracle_free_suite,
    extract_oracle_free_summary,
    propose_metamorphic_relations,
    render_determinism_pytest,
    render_garbage_resilience_pytest,
    render_type_contract_pytest,
)

__all__ = [
    "GARBAGE_CASE_COUNT",
    "CheckResult",
    "DifferentialReport",
    "Evidence",
    "MetamorphicKind",
    "MetamorphicRelation",
    "OracleFreeSuite",
    "RequirementDagJudge",
    "TierId",
    "TierVerifierFn",
    "VerificationState",
    "VerifierBus",
    "VerifierBusReport",
    "build_differential_prompt",
    "build_garbage_vectors",
    "build_oracle_free_suite",
    "extract_oracle_free_summary",
    "generate_fuzz_inputs",
    "inspect_tier_scorer",
    "propose_metamorphic_relations",
    "render_determinism_pytest",
    "render_garbage_resilience_pytest",
    "render_metamorphic_pytest_suite",
    "render_type_contract_pytest",
    "run_differential_check",
]
