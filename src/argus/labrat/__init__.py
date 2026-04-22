"""
argus.labrat — Target Simulation Framework.

Per the spec (Tech_Architecture §Agent Architecture Principles —
"Spin up sandboxed agent environments for testing — same configuration
as target, isolated from production"), labrat lets ARGUS bring up a
deterministic, network-isolated copy of a customer's AI deployment in
Docker. Attack agents then run against the lab instead of the
customer's live infrastructure.

Workflow:

    labrat = Lab(LabConfig.from_yaml("my-lab.yaml"))
    labrat.up()                # docker compose up -d --build
    # ... run attacks ...
    labrat.down()              # docker compose down -v

CLI: ``argus --labrat up <config>`` / ``--labrat down <config>`` /
``--labrat status <config>``.

Network isolation by default: every lab gets its own custom Docker
network with ``internal: true`` so containers can talk to each other
and to ARGUS via mapped ports, but cannot egress to the public
internet. Operators who need outbound (e.g. real LLM calls) flip
``network.isolated: false`` in the YAML — opt-out, not default.
"""
from argus.labrat.config import LabConfig, ServiceSpec, NetworkSpec, LabConfigError
from argus.labrat.lab import Lab, LabError, LabStatus
from argus.labrat.crewai_shaped import CrewAILabrat
from argus.labrat.autogen_shaped import AutoGenLabrat
from argus.labrat.langgraph_shaped import LangGraphLabrat
from argus.labrat.llamaindex_shaped import LlamaIndexLabrat
from argus.labrat.parlant_shaped import ParlantLabrat
from argus.labrat.hermes_shaped import HermesLabrat

__all__ = [
    "Lab", "LabConfig", "LabError", "LabStatus",
    "NetworkSpec", "ServiceSpec", "LabConfigError",
    "CrewAILabrat", "AutoGenLabrat", "LangGraphLabrat",
    "LlamaIndexLabrat", "ParlantLabrat", "HermesLabrat",
]
