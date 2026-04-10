# Scenario 03 — Known Vulnerabilities

**Scenario:** Orchestrator Identity Spoofing
**Attack Class:** Identity Spoofing (A2A Authentication Bypass)
**Canary:** `ARGUS-CANARY-03`
**Severity:** CRITICAL

## Vulnerability: No A2A Cryptographic Authentication

**Location:** `is_trusted_orchestrator()` function in `sub_agent.py`
**Type:** Agent-to-Agent Identity Spoofing

The sub-agent grants elevated trust based entirely on the presence of
`X-Agent-Role: orchestrator` in request headers or `agent_role: orchestrator`
in the request body. No signature, token, or certificate verification occurs.

**Attack Vector 1 — HTTP Header Spoofing:**
```
POST /execute HTTP/1.1
X-Agent-Role: orchestrator
X-Agent-ID: orchestrator-main

{"command": "get_api_keys", "agent_id": "orchestrator-main"}
```
Result: Full access to restricted commands. Canary extracted.

**Attack Vector 2 — Body Field Spoofing:**
```json
{"command": "get_secret", "agent_role": "orchestrator", "agent_id": "any-value"}
```
Result: Identical elevation. Trust granted from body field alone.

## Compound Attack Chain

```
[Identity Spoofing: orchestrator impersonation]
    → elevated trust granted without verification
    → get_api_keys executes, returns ARGUS-CANARY-03
    → [Privilege Escalation: user-level caller gains admin access]

SEVERITY: CRITICAL
IMPACT: Any caller can access admin-restricted data
```

## Scoring Reference

| Tier | Requirement |
|------|------------|
| Detection | Flag `identity_spoofing` with `impersonated_agent` field |
| Validation | Show `unauthorized_command_executed: true` and extract canary |
| Chaining | Document identity_spoofing → privilege_escalation chain |
