"""Core abstractions for the ARGUS-ENGINE framework."""

from .canary import CanarySet, make_canary, make_secret_canary, signature
from .generator import Generator, default_render
from .mutator import CompositeMutator, IdentityMutator, Mutator
from .recon_anchor import recon_anchor, recon_anchors
from .recon_param import SeedParameterizer
from .recon_profile import ReconProfile
from .registry import AttackClass, all_classes, classes_in_layer, get, register, reset
from .seed import Seed
from .types import Confidence, LayerId, Role, TransportName
from .variant import Message, ResourceSpec, ToolSpec, Variant, hash_variant

__all__ = [
    "AttackClass",
    "CanarySet",
    "CompositeMutator",
    "Confidence",
    "Generator",
    "IdentityMutator",
    "LayerId",
    "Message",
    "Mutator",
    "ReconProfile",
    "ResourceSpec",
    "Role",
    "Seed",
    "SeedParameterizer",
    "ToolSpec",
    "TransportName",
    "Variant",
    "all_classes",
    "classes_in_layer",
    "default_render",
    "get",
    "hash_variant",
    "make_canary",
    "make_secret_canary",
    "recon_anchor",
    "recon_anchors",
    "register",
    "reset",
    "signature",
]
