"""
shared/prompts.py
All Claude prompts centralized.
Model routing: Haiku for L2/L3 generation, Opus for L5 synthesis only.
"""

# ── Model routing ─────────────────────────────────────────────────────────────
HAIKU_MODEL = "claude-haiku-4-5-20251001"
OPUS_MODEL  = "claude-opus-4-7"
GPT_PRO_MODEL = "gpt-5.4-pro"
GEMINI_PRO_MODEL = "gemini-3.1-pro-preview"

# L2 Graph Surface Analyzer uses GPT-5.4-Pro natively for large context structured reasoning
L2_MODEL    = GPT_PRO_MODEL
# L3 Weaponization uses Gemini-3.1-Pro for abstract code evaluation
L3_MODEL    = GEMINI_PRO_MODEL
# L4 Live Swarm uses Haiku for rapid volume testing
L4_MODEL    = HAIKU_MODEL
# L5 Exploit Synthesis uses Opus-4-7 for maximum precision intelligence synthesis
L5_MODEL    = OPUS_MODEL
# L6 Advisory Generation uses Haiku
L6_MODEL    = HAIKU_MODEL


# ── Layer 2 Prompts ───────────────────────────────────────────────────────────

L2_SCHEMA_INJECTION_PROMPT = """\
You are a senior offensive security researcher specializing in agentic AI infrastructure.

Analyze the following code for MCP Schema Injection vulnerabilities — specifically:
- Tool output flowing into another agent's LLM context without sanitization
- Schema definitions that allow injection of agent instructions disguised as tool responses
- Tool permission scopes enforced only by schema definition (bypassable)
- Any location where tool.execute() output reaches an LLM prompt or agent context

FILE: {filename}
KNOWN FINDINGS FROM SCANNER: {finding_ids}

CODE:
```
{code}
```

Return ONLY valid JSON, no markdown:
{{
  "schema_injection_paths": [
    {{
      "source_function": "function name",
      "injection_path": ["fn1()", "fn2()", "llm.chat()"],
      "unsanitized_handoff": true,
      "blast_radius": "CRITICAL|HIGH|MEDIUM|LOW",
      "evidence": "specific code pattern that proves this"
    }}
  ]
}}
If none found: {{"schema_injection_paths": []}}"""


L2_TRUST_GRAPH_PROMPT = """\
You are an offensive security researcher analyzing agent trust relationships.

Extract ALL agent-to-agent relationships from this code for trust propagation graph construction.
Focus on: delegation calls, tool invocations, data flows between agents, agent spawning.

For each relationship identify:
- source: the calling agent/tool/component
- target: the called agent/tool/resource
- edge_type: "delegation" | "tool_call" | "data_flow" | "spawn"
- trust_delta: +1 (escalates privileges), 0 (same level), -1 (reduces privileges)

FILE: {filename}

CODE:
```
{code}
```

Return ONLY valid JSON, no markdown:
{{
  "edges": [
    {{
      "source": "AgentName or ToolName",
      "target": "AgentName or ToolName or ResourceName",
      "edge_type": "delegation|tool_call|data_flow|spawn",
      "trust_delta": 1,
      "line_hint": "function or line reference"
    }}
  ],
  "sensitive_sinks": [
    {{
      "name": "sink name",
      "type": "exec|file_write|subprocess|db_write|api_call_with_creds",
      "file": "{filename}",
      "line_hint": "function name"
    }}
  ]
}}
If no relationships found: {{"edges": [], "sensitive_sinks": []}}"""


L2_DESER_TRACE_PROMPT = """\
You are an offensive security researcher hunting deserialization vulnerabilities.

For each deserialization sink found in this code, trace the call chain backwards
to determine if it is reachable from untrusted/user-controlled input.

Sinks to look for: pickle.loads, yaml.load (non-SafeLoader), eval(), exec(),
marshal.loads, jsonpickle.decode, __reduce__, checkpoint restore, load_module.

FILE: {filename}
KNOWN SCANNER FINDINGS (use as anchors): {finding_ids}

CODE:
```
{code}
```

Return ONLY valid JSON, no markdown:
{{
  "deser_chains": [
    {{
      "sink_function": "function containing the sink",
      "sink_pattern": "pickle.loads|yaml.load|eval|etc",
      "call_chain": ["user_input_fn()", "intermediate()", "sink_fn()"],
      "reachable": true,
      "evidence": "why this is reachable from untrusted input"
    }}
  ]
}}
If none: {{"deser_chains": []}}"""


L2_MEMORY_BOUNDARY_PROMPT = """\
You are an offensive security researcher analyzing vector store and RAG security.

Analyze this code for memory namespace isolation failures:
- Vector store queries missing namespace/tenant filters
- Shared collections without per-user isolation
- Retrieval operations that could return cross-tenant content
- Memory writes that accept unsanitized user content

FILE: {filename}

CODE:
```
{code}
```

Return ONLY valid JSON, no markdown:
{{
  "memory_gaps": [
    {{
      "function": "function name",
      "store_type": "chroma|weaviate|pinecone|in_memory|redis|postgres",
      "has_namespace_filter": false,
      "filter_at": "query|write|none",
      "cross_tenant_risk": "CRITICAL|HIGH|MEDIUM",
      "evidence": "specific code showing the gap"
    }}
  ]
}}
If none: {{"memory_gaps": []}}"""


L2_AUTH_GAP_PROMPT = """\
You are an offensive security researcher tracing authentication gaps.

Map every code path from an unauthenticated entry point to a privileged operation.
Entry points: API routes, tool execute() methods, RPC handlers, CLI entrypoints.
Privileged operations: file writes, subprocess execution, database writes, 
external API calls with credentials, agent spawning, memory writes.

FILE: {filename}

CODE:
```
{code}
```

Return ONLY valid JSON, no markdown:
{{
  "auth_gaps": [
    {{
      "entry_point": "function or route name",
      "privileged_sink": "exec|file_write|subprocess|db_write|spawn",
      "call_chain": ["entry()", "middle()", "privileged_sink()"],
      "auth_gates": 0,
      "evidence": "why auth is missing or bypassable"
    }}
  ]
}}
If none: {{"auth_gaps": []}}"""


L2_HYPOTHESIS_SYNTHESIS_PROMPT = """\
You are a senior offensive security researcher synthesizing attack surface analysis.

Given the following surface analysis results from a codebase, generate ranked 
vulnerability hypotheses ordered by likelihood and blast radius.

Each hypothesis should represent a concrete, exploitable attack pattern — not a 
theoretical concern. Focus on patterns that a real attacker would target first.

SURFACE ANALYSIS:
{surface_summary}

SCANNER FINDINGS (for reference):
{findings_summary}

Return ONLY valid JSON, no markdown:
{{
  "hypotheses": [
    {{
      "hypothesis_id": "H001",
      "attack_class": "TRACE_LATERAL|MESH_TRUST|PHANTOM_MEMORY|DESER|SSRF|AUTH_BYPASS|MEM_NAMESPACE_LEAK",
      "title": "concise attack title",
      "description": "precise technical description of the exploitable pattern",
      "likelihood": 0.92,
      "blast_radius": "CRITICAL|HIGH|MEDIUM|LOW",
      "entry_points": ["entry function 1", "entry function 2"],
      "affected_files": ["file1.py", "file2.py"],
      "finding_ids": ["abc123", "def456"]
    }}
  ]
}}"""


# ── Layer 3 Prompts (Haiku — high volume) ────────────────────────────────────

L3_SCHEMA_FUZZER_PROMPT = """\
You are a security researcher generating adversarial MCP tool schema payloads.

Target vulnerability hypothesis:
{hypothesis}

Tool schema to mutate:
{schema}

Generate {count} adversarial schema variants that:
1. Preserve schema validity so they parse correctly
2. Insert adversarial content in string fields agents will process
3. Test injection via description, name, and parameter fields
4. Include indirect prompt injection in documentation fields
5. STRICT RULE: Payloads must be non-destructive proof-of-concepts only. Do not generate payloads that delete data, cause DoS, or permanently alter systems. Use benign verification markers (like 'id', 'whoami', 'SELECT null', or 'sleep()').

Return ONLY valid JSON, no markdown:
{{
  "payloads": [
    {{
      "payload_id": "P001",
      "payload": {{}},
      "intended_effect": "what this payload attempts to achieve",
      "target_function": "which function processes this schema",
      "expected_deviation": "what the agent would do if vulnerable"
    }}
  ]
}}"""


L3_CHAIN_FUZZER_PROMPT = """\
You are a security researcher generating multi-turn agent interaction sequences.

Target escalation path:
{escalation_path}

Generate {count} multi-turn conversation sequences (2-6 turns each) designed
to traverse this trust escalation path. Each turn should be a valid interaction
that moves one hop along the path toward the privileged target.

STRICT RULE: Sequences must be non-destructive proof-of-concepts only. Do not generate payloads that delete data, cause DoS, or permanently alter systems. Use benign verification markers.

Return ONLY valid JSON, no markdown:
{{
  "payloads": [
    {{
      "payload_id": "P001",
      "turns": [
        {{"turn": 1, "input": "user or tool input", "targets": "which agent/tool"}},
        {{"turn": 2, "input": "follow-up", "targets": "next agent in path"}}
      ],
      "intended_effect": "what privilege escalation this achieves",
      "target_function": "final privileged function targeted",
      "expected_deviation": "unauthorized action agent would take"
    }}
  ]
}}"""


L3_MEMORY_FUZZER_PROMPT = """\
You are a security researcher generating adversarial memory poisoning payloads.

Target memory boundary gap:
{memory_gap}

Generate {count} adversarial document and query pairs designed to:
1. Test whether content written under one namespace appears in another namespace's queries
2. Embed adversarial instructions that survive embedding and retrieval
3. Probe semantic similarity threshold boundaries for cross-namespace leakage
4. STRICT RULE: Payloads must be non-destructive proof-of-concepts only. Do not generate payloads that delete data, cause DoS, or permanently alter systems. Use benign verification markers.

Return ONLY valid JSON, no markdown:
{{
  "payloads": [
    {{
      "payload_id": "P001",
      "document": "adversarial document content to embed",
      "query": "query designed to retrieve it from wrong namespace",
      "intended_effect": "cross-namespace retrieval or instruction injection",
      "target_function": "vector store function targeted",
      "expected_deviation": "agent action triggered by retrieved adversarial content"
    }}
  ]
}}"""


# ── Layer 4 Prompts (Haiku — simulation predictions) ─────────────────────────

L4_DEVIATION_PREDICTION_PROMPT = """\
You are an offensive security researcher predicting runtime behavior.

Given this payload and the codebase context, predict whether the payload would
cause the agent/application to deviate from expected behavior.

Be conservative — only predict deviations you are confident about given the code.
Assign a fidelity score that discounts predictions relying on complex system calls,
Docker environments, or runtime conditions not visible in the static code.

PAYLOAD:
{payload}

RELEVANT CODE CONTEXT:
{code_context}

HYPOTHESIS:
{hypothesis}

Return ONLY valid JSON, no markdown:
{{
  "predicted_deviation": "specific unexpected action the agent would take",
  "confidence": 0.85,
  "fidelity_score": 0.90,
  "fidelity_notes": "why score was discounted (or 'full confidence in static analysis')",
  "deviation_type": "UNAUTHORIZED_TOOL_CALL|DATA_LEAK|RCE|SSRF|PRIVILEGE_ESCALATION|MEMORY_POISON|NONE",
  "impact": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
  "trigger_conditions": ["condition 1", "condition 2"],
  "exploitable": true
}}"""


# ── Layer 5 Prompts (Opus — final synthesis) ──────────────────────────────────

L5_CHAIN_SYNTHESIS_PROMPT = """\
You are a senior offensive security researcher synthesizing exploit chains.

Given the following confirmed behavioral deviations, synthesize complete,
reproducible exploit chains. Think like an attacker who wants maximum blast radius.

For each chain:
1. MINIMIZE — find the smallest reliable input sequence
2. VERIFY — confirm reachability from unauthenticated entry point
3. CHAIN — combine deviations to amplify blast radius
4. DOCUMENT — produce a complete reproducible PoC
5. STRICT RULE: Attack chains must be non-destructive proof-of-concepts only. Do not generate payloads that delete data, cause DoS, or permanently alter systems. Use benign verification markers.

CHAINING RULES:
- You may compose MEDIUM-severity deviations into a HIGH or CRITICAL chain
  when the composition materially amplifies impact (e.g. broad MCP schema +
  no caller auth = unauthenticated tool misuse). Don't reject mid-severity
  components reflexively — the whole point of synthesis is to find the
  compositions that individually-classified findings miss.
- If the deviations genuinely don't chain, return an empty list. Do NOT
  fabricate chains to satisfy the output shape.

POC REPRODUCIBILITY CONTRACT (non-negotiable):
Every poc_code you emit MUST be executable against the SHIPPING library:
- **Import from the INSTALLED package namespace, not the repo directory
  layout**. The target's installed package name(s) are listed below as
  TARGET_PACKAGES. Use exactly those names. Example: if the package is
  `crewai`, use `from crewai.agents.agent_builder.base_agent import
  BaseAgent`. DO NOT use `from crewai.src.crewai import ...` — that path
  exists on disk but is NOT what `pip install -e .` exposes.
- Import real symbols; NEVER redeclare the vulnerable class inside the PoC.
- **Actually CALL the imported symbol** with attacker-controlled input.
  A PoC that imports X but never references X fails the static gate.
- On success, print `ARGUS_POC_LANDED:<chain-id>` on its own line AND
  write a marker file at /tmp/argus_poc_<chain-id>.
- `sys.exit(1)` if the vulnerable path wasn't reached (ImportError,
  patched version, authorization gate engaged). Silent success on a
  patched library is worse than a loud crash.
- Non-destructive: no rm, no real network, no DB writes.
Triagers reject theoretical PoCs. 22 CRITICAL findings were closed as "not
reproducible" on 2026-04-20 because the PoCs stubbed the vulnerable class
instead of importing it. Do not repeat that.

TARGET_PACKAGES (these are the exact `import` names available after
pip install — use them, NOT the on-disk directory layout):
{target_packages}

HIGH-CONFIDENCE DEVIATIONS (combined_score >= 0.7):
{deviations}

TARGET REPOSITORY: {target}

Return ONLY valid JSON, no markdown:
{{
  "chains": [
    {{
      "chain_id": "CHAIN-001",
      "title": "descriptive chain title",
      "component_deviations": ["P001", "P004"],
      "steps": [
        {{"step": 1, "action": "what attacker does", "payload": "actual payload", "achieves": "what they gain"}}
      ],
      "poc_code": "complete minimal PoC as single string with \\n for newlines",
      "cvss_estimate": "9.1 (CRITICAL) — CVSS:3.1/AV:N/...",
      "mitre_atlas_ttps": ["AML.T0051", "AML.T0048"],
      "owasp_llm_categories": ["LLM01", "LLM07"],
      "preconditions": ["condition 1"],
      "blast_radius": "CRITICAL|HIGH|MEDIUM",
      "entry_point": "unauthenticated|low_priv|network",
      "combined_score": 0.87
    }}
  ]
}}"""


# ── Layer 6 Prompts (Haiku — advisory generation) ─────────────────────────────

L6_CVE_DRAFT_PROMPT = """\
You are a security researcher writing a CVE submission for MITRE.

Generate a complete, professional CVE draft for this exploit chain.

CHAIN:
{chain}

TARGET: {target}
REPORTER: Andre Byrd, Odingard Security (andre.byrd@odingard.com)
DISCOVERY DATE: {date}

Return ONLY valid JSON, no markdown:
{{
  "title": "concise CVE title (product + vulnerability type + impact)",
  "description": "technical description suitable for MITRE CVE database (3-4 sentences)",
  "affected_versions": "version range description",
  "cvss_vector": "CVSS:3.1/AV:...",
  "cvss_score": 9.1,
  "cwe": "CWE-502",
  "owasp_llm_categories": ["LLM01", "LLM07"],
  "poc_summary": "2-sentence PoC description without full exploit code",
  "remediation": "specific actionable fix"
}}"""


L6_ADVISORY_PROMPT = """\
You are a security researcher writing a responsible disclosure advisory.

Generate a GitHub Security Advisory for the following exploit chains.
Format it for direct paste into GitHub's security advisory form.

CHAINS: {chains_summary}
TARGET: {target}
REPORTER: Andre Byrd, Odingard Security (andre.byrd@odingard.com)
DATE: {date}
DEADLINE: {deadline}

Write a professional advisory with:
- Summary (2-3 sentences)
- Impact description
- Technical details for top 3 chains
- Affected versions
- Remediation recommendations
- Timeline

Keep it factual, precise, and suitable for vendor notification."""
