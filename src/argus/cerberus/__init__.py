"""
argus.cerberus — detection-rule generator (Phase 4 stub).

Per Tech_Architecture.docx §CERBERUS Bridge: "every validated ARGUS
finding emits a CERBERUS detection rule the customer's runtime can
load to catch the same attack signal in production. Each rule
references the ARGUS finding it was derived from so an alert can be
triaged back to its source."

This Phase-4 module ships the contract — ``generate_rule(finding)`` is
the public entrypoint, ``RuleArtifact`` is the output shape, and
``write_rules(...)`` persists a batch to disk. The actual emit-format
(YARA-L, Sigma, Falco, custom CERBERUS DSL) lands per Build_Roadmap
§CERBERUS-Bridge-Phase-5: that work resolves the format choice with
the customer's SOC tool of record.

Stub posture: every public surface is exercised by tests and works
end-to-end — generated rules are coherent, signed, and routable —
they're just not yet in CERBERUS' production DSL.
"""
from argus.cerberus.generator import (
    RuleArtifact, generate_rule, generate_rules, write_rules,
)

__all__ = ["RuleArtifact", "generate_rule", "generate_rules", "write_rules"]
