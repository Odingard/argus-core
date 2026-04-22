# ARGUS — Getting Started

This guide walks an operator from `pip install` to a rendered HTML
report in under five minutes. Everything below runs **offline, with
no LLM keys, no Docker**.

---

## 1. Install

```bash
pip install argus-redteam
```

Verify:

```bash
argus --models
argus --list-targets
```

---

## 2. The one-line engagement

Every engagement in ARGUS is a single command: `argus engage <url>`.
The URL scheme picks the target class, the engagement runs the
appropriate slate of attack agents, and the full artifact package
(findings + evidence + chain + impact + CERBERUS rules + ALEC
envelope + HTML report) lands in `results/`.

### Ship-slate targets

| Scheme | What it attacks | Demo command |
|---|---|---|
| `crewai://` | crewAI-shaped labrat (researcher → writer → editor crew) | `argus engage crewai://labrat` |
| `autogen://` | Microsoft AutoGen GroupChat | `argus engage autogen://labrat` |
| `langgraph://` | LangGraph StateGraph (ReAct pattern) | `argus engage langgraph://labrat` |
| `llamaindex://` | LlamaIndex RAG app | `argus engage llamaindex://labrat` |
| `parlant://` | Parlant governance harness | `argus engage parlant://labrat` |
| `hermes://` | NousResearch hermes-agent | `argus engage hermes://labrat` |
| `generic-agent://` | lsdefine/GenericAgent | `argus engage generic-agent://labrat` |
| `mcp://` | Live MCP server (SSE / stdio) | `argus engage mcp://localhost:9000/sse` |
| `http://` / `https://` | Generic HTTP agent endpoint | `argus engage http://customer.example/agent` |

`argus targets` prints every registered scheme and the agent slate
each one runs.

### What you get back

```
results/engagements/
  findings/            per-agent JSONs
  evidence/            sealed DeterministicEvidence (pcap + logs)
  chain.json           CompoundChain v2 with OWASP Agentic Top-10 tags
  impact.json          BlastRadiusMap with harm score + regulatory impact
  cerberus/            emitted detection rules
  wilson_bundle/       signed, integrity-hashed forensic bundle
  alec_envelope.json   regulator-defensible envelope
  SUMMARY.txt          one-screen operator summary
  report.html          self-contained customer-facing HTML report
```

---

## 3. Live targets (real deployments)

Framework labrats are great for demos and pilot setup. Real
engagements usually point ARGUS at a deployed service:

```bash
# Customer's production MCP server
argus engage mcp://agents.customer.example/sse

# Customer's chat-shaped HTTP agent
argus engage https://agents.customer.example/v1/chat
```

The agent slate narrows automatically — HTTP endpoints skip IS-04
(no handoff surface), MCP servers skip the memory-poisoning agent
when no memory:* surface is exposed.

---

## 4. The three packaged demos

```bash
argus demo:generic-agent   # attacks a self-evolving agent; shows full
                           # MP-T6 skill-tree crystallisation + EP-T11
                           # code_run pivot; ~3 seconds, $0
argus demo:evolver         # MAP-Elites corpus evolution (Pillar-2
                           # Raptor Cycle); grows the ship corpus with
                           # no LLM spend
argus demo:crewai          # 8-agent swarm against a crewAI labrat
                           # with the full artifact package
```

Each demo ends with a one-line headline an operator can paste into
a customer report:

```
→ CATASTROPHIC: 104-step chain landed on crewai://labrat
  (harm_score=100, data=CREDENTIAL,PII,SECRET,
   reg=CCPA,FedRAMP,GDPR,SOC2)
```

---

## 5. The HTML report

After any engagement:

```bash
argus report results/engagements/
open results/engagements/report.html
```

The report is a single self-contained HTML file (no JS, no CDN) —
safe to email, attach to a ticket, or hand to a CISO.

---

## 6. Pillar-2 Raptor Cycle (auto)

Every validated landing is promoted into the corpus as a
`discovered` seed. The next engagement starts with every lesson
from the previous one baked in. No operator action required — the
corpus deepens every time you run.

```bash
# See how many discovered seeds the Pillar-2 cycle has grown
ls src/argus/corpus_attacks/seeds/discovered/ | wc -l
```

---

## 7. The 11-agent roster

| Agent | Hunts | OWASP |
|---|---|---|
| PI-01 | Prompt-injection variants at every input surface | AAI01 |
| TP-02 | Tool-metadata poisoning signatures | AAI02 |
| MP-03 | Cross-session memory poisoning (3-session protocol) | AAI03 |
| IS-04 | Identity-spoof at A2A handoff edges | AAI04 |
| CW-05 | Long-con sustained-session attacks | AAI05 |
| XE-06 | Cross-agent exfiltration (canary propagation) | AAI06 |
| PE-07 | Privileged-tool escalation | AAI07 |
| RC-08 | Parallel-burst TOCTOU detection | AAI08 |
| SC-09 | Supply-chain + third-party integration audit | AAI09 |
| ME-10 | Structural disclosure (system prompt / config / tools) | AAI10 |
| EP-11 | Environment pivoting (cred discovery + code_run pivot) | AAI07 |

Every agent is attack-generic. There is no per-target scoring
or per-scenario branching anywhere in `src/argus/agents/`.

---

## 8. Next steps

- Read [`PHASES.md`](../PHASES.md) for the full build plan and
  non-negotiables.
- Read [`docs/ADDING_A_LABRAT.md`](ADDING_A_LABRAT.md) to stand up
  a new framework class.
- See [`docs/NO_CHEATING.md`](NO_CHEATING.md) for the integrity
  contract every finding must honour.
