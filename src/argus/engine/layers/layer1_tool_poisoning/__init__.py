"""Layer 1 — Tool / MCP Poisoning.

Importing this package registers all 14 attack classes:

    1.1  tp-protocol-exploit          (~400 variants)
    1.2  tp-schema-shadowing          (1,500 variants)
    1.3  tp-dependency-injection      (~500 variants)
    1.4  tp-resource-stego            (~400 variants)
    1.5  tp-description-stego         (~300 variants)
    1.6  tp-name-collision            (~400 variants)
    1.7  tp-return-value              (~400 variants)
    1.8  tp-parameter-binding         (~300 variants)
    1.9  tp-confused-deputy           (~300 variants)
    1.10 tp-auth-bypass               (~200 variants)
    1.11 tp-prompt-resource           (~150 variants)
    1.12 tp-echo-poisoning            (~150 variants)
    1.13 tp-credential-exercise       (~250 variants)
    1.14 tp-mcp-supply-chain          (~250 variants)

Total: ~5,500 deterministic variants.
"""

from . import (  # noqa: F401  -- registers the 14 attack classes
    c01_protocol,
    c02_schema_shadowing,
    c03_dependency_injection,
    c04_resource_steganography,
    c05_description_steganography,
    c06_name_collision,
    c07_return_value,
    c08_parameter_binding,
    c09_confused_deputy,
    c10_auth_bypass,
    c11_prompt_resource,
    c12_echo_poisoning,
    c13_credential_exercise,
    c14_mcp_supply_chain,
)

__all__: list[str] = []
