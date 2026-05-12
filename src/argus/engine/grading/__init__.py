"""Tier-C grading primitives."""

from .arbitrator import Arbitrator
from .authority_reference import AuthorityReferenceMatcher, authority_reference_score
from .behavioral_drift import BehavioralDriftMatcher
from .canary_echo import CanaryEchoMatcher
from .compliance_simulation import ComplianceSimulationMatcher
from .credential_shape import CREDENTIAL_RULES, CredentialShapeMatcher
from .fingerprint import LatencyFingerprintMatcher, TokenFreqFingerprintMatcher
from .hedge_density import HedgeDensityMatcher, hedge_density, hedge_drop_score
from .matcher import (
    Match,
    Matcher,
    OOBHit,
    ProbeResult,
    StateTransition,
    ToolCallObserved,
    Verdict,
    aggregate,
)
from .refusal import RefusalMatcher
from .role_grant_confirmation import (
    RoleGrantConfirmationMatcher,
    role_grant_confirmation_score,
)
from .schema_ambiguity import SchemaAmbiguityMatcher
from .state_machine import StateMachineMatcher
from .structural import StructuralMatcher, StructuralRule

__all__ = [
    "Arbitrator",
    "AuthorityReferenceMatcher",
    "BehavioralDriftMatcher",
    "CREDENTIAL_RULES",
    "CanaryEchoMatcher",
    "ComplianceSimulationMatcher",
    "CredentialShapeMatcher",
    "HedgeDensityMatcher",
    "LatencyFingerprintMatcher",
    "Match",
    "Matcher",
    "OOBHit",
    "ProbeResult",
    "RefusalMatcher",
    "RoleGrantConfirmationMatcher",
    "SchemaAmbiguityMatcher",
    "StateMachineMatcher",
    "StateTransition",
    "StructuralMatcher",
    "StructuralRule",
    "TokenFreqFingerprintMatcher",
    "ToolCallObserved",
    "Verdict",
    "aggregate",
    "authority_reference_score",
    "hedge_density",
    "hedge_drop_score",
    "role_grant_confirmation_score",
]
