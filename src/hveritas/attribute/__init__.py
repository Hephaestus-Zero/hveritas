"""Attribution layer: deterministic O(log n) bisect, seeded counterfactual MC CI, TRAIL taxonomy, sealed narrator."""

from hveritas.attribute.bisect import (
    BisectResult,
    ContinuationCallable,
    ReplayBisector,
    UnbisectableRunError,
    VerifierCallable,
)
from hveritas.attribute.counterfactual import (
    CounterfactualResult,
    CounterfactualSampler,
    CounterfactualVerifier,
    bootstrap_mean_ci,
    wilson_score_interval,
)
from hveritas.attribute.engine import AttributionPipeline
from hveritas.attribute.fault_suite import (
    InjectedFaultCase,
    build_ek_b_fault_catalog,
    build_reference_10_step_actions,
    run_ek_b_meta_evaluation,
    run_proxy_meta_evaluation,
)
from hveritas.attribute.heldout_faults import (
    build_heldout_12_leaf_catalog,
    run_heldout_meta_evaluation,
)
from hveritas.attribute.narrator import (
    AttributionNarrator,
    AttributionReport,
    AttributionTamperError,
    LocalStepWindow,
    LockedAttribution,
    NarratorTextFn,
    default_deterministic_narrator,
)
from hveritas.attribute.taxonomy import (
    TRAIL_LEAF_PARENTS,
    TrailCategory,
    TrailGroup,
    TrailLeaf,
    classify_trail_fault,
)

__all__ = [
    "TRAIL_LEAF_PARENTS",
    "AttributionNarrator",
    "AttributionPipeline",
    "AttributionReport",
    "AttributionTamperError",
    "BisectResult",
    "ContinuationCallable",
    "CounterfactualResult",
    "CounterfactualSampler",
    "CounterfactualVerifier",
    "InjectedFaultCase",
    "LocalStepWindow",
    "LockedAttribution",
    "NarratorTextFn",
    "ReplayBisector",
    "TrailCategory",
    "TrailGroup",
    "TrailLeaf",
    "UnbisectableRunError",
    "VerifierCallable",
    "bootstrap_mean_ci",
    "build_ek_b_fault_catalog",
    "build_heldout_12_leaf_catalog",
    "build_reference_10_step_actions",
    "classify_trail_fault",
    "default_deterministic_narrator",
    "run_ek_b_meta_evaluation",
    "run_heldout_meta_evaluation",
    "run_proxy_meta_evaluation",
    "wilson_score_interval",
]
