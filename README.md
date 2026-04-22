```console
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║       ___    ____  ________  __  _____                                     ║
║      /   |  / __ \/ ____/ / / / / ___/                                     ║
║     / /| | / /_/ / / __/ / / /  \__ \                                      ║
║    / ___ |/ _, _/ /_/ / /_/ /  ___/ /                                      ║
║   /_/  |_/_/ |_|\____/\____/  /____/                                       ║
║                                                                            ║
║   Autonomous AI Red Team Platform                                          ║
║   Odingard Security by Six Sense Enterprise Services                       ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
```

## 1. The Positioning Statement
ARGUS does not compete with traditional pentesting tools. It does something they inherently cannot do — test the AI-specific attack surface that none of them were built to find. If you run traditional SAST to test your raw infrastructure, you still need ARGUS to test the AI agents running on top of that infrastructure. They are complementary, not competing.

## 2. The Architecture (Open-Core)
ARGUS is uniquely built as an 11-Agent Swarm. 

This Open-Source core implements the basic scaffolding of the **Attack Layer**. It provides the entry-point logic to spawn short-lived, narrowly scoped agents designed to hunt AI logic flaws without accumulated bias or context collapse. 

```bash
pip install argus-redteam
```

### One-line engagement

```bash
argus engage crewai://labrat       # 8-agent swarm against a crewAI-shaped target
argus engage langgraph://labrat    # LangGraph StateGraph attack
argus engage mcp://customer.example/sse   # live MCP server
argus engage http://customer.example/agent  # generic HTTP agent endpoint

argus targets                      # list every registered target class
argus report results/engagements/  # render a self-contained HTML report
```

### Packaged demos

```bash
argus demo:generic-agent   # self-evolving agent attack (~3s, $0)
argus demo:evolver         # Pillar-2 Raptor Cycle corpus evolution
argus demo:crewai          # end-to-end crewAI engagement
```

See [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) for the full
operator guide, [`docs/ADDING_A_LABRAT.md`](docs/ADDING_A_LABRAT.md) to
extend ARGUS to a new framework, and [`docs/NO_CHEATING.md`](docs/NO_CHEATING.md)
for the integrity contract every finding must honour.

## 3. ⚠️ ARGUS Enterprise 
This OSS package contains the **Core Execution Engine**. It fundamentally lacks the Correlation Synthesis and Reporting Validation engines built into the proprietary SaaS product.

**The Full 11-Agent Swarm:**
ARGUS Enterprise deploys 10 simultaneous specialized agents (Prompt Injection Hunter, Tool Poisoner, Memory Poisoner, Identity Spoofer, etc.) and routes all intelligence to a single **Correlation Agent**. This Correlation Agent chains individual, seemingly benign findings into compound, multi-step zero-day attack paths. 

To access the complete Swarm logic and generate verifiable CVEs, please visit the Enterprise portal:
👉 **[ARGUS Enterprise Deployment](https://sixsenseenterprise.com)**
