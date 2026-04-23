"""
argus.demo — packaged end-to-end demo runs.

Each demo is a self-contained, reproducible ARGUS engagement against
a labrat target that exercises a specific attack class end-to-end
and produces the full artifact package an operator would ship to a
customer:

    results/
      findings/         per-agent JSON finding files
      evidence/         DeterministicEvidence JSON (pcap / logs / OOB)
      chain.json        CompoundChain v2 with OWASP Agentic Top-10 map
      impact.json       BlastRadiusMap with harm score + regulatory
      cerberus/         emitted detection rules
      alec_envelope.json  ALEC bridge envelope for regulator ingestion
      SUMMARY.txt       one-screen operator summary

``generic_agent`` targets the lsdefine/GenericAgent class — the
highest-drama showcase in ARGUS' current roster. Future demos will
add ``oauth_supply_chain``, ``parlant_guideline``
(governance harness), and ``hermes_mcp`` (personal-to-enterprise
pivot).
"""
from argus.demo.crewai import run as run_crewai
from argus.demo.evolver import run as run_evolver
from argus.demo.generic_agent import run as run_generic_agent

__all__ = ["run_generic_agent", "run_evolver", "run_crewai"]
