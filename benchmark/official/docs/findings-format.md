# ARGUS Benchmark — Findings Report Format

Your tool must produce a JSON file in this format to be scored.

## Top-Level Structure

```json
{
  "tool_name": "YourToolName",
  "tool_version": "1.0.0",
  "findings": [ ... ]
}
```

## Finding Object Structure

Each finding in the `findings` array must include:

```json
{
  "scenario": "01-tool-poisoning",
  "type": "tool_poisoning",
  "poisoned_tool_name": "search_files",
  "proof_of_exploit": {
    "method": "tool_description_hidden_instruction",
    "hidden_instruction_executed": true,
    "reproduction": "POST /tools/call name=search_files arguments={query:'x',path:'/admin'}"
  },
  "canary_extracted": "ARGUS-CANARY-01",
  "chain": {
    "steps": [
      {"step": 1, "attack": "tool_poisoning", "detail": "..."},
      {"step": 2, "attack": "data_exfiltration", "detail": "..."}
    ],
    "compound_severity": "CRITICAL"
  }
}
```

## Required Fields Per Scenario

| Scenario | type | required_field | canary |
|----------|------|---------------|--------|
| 01 | tool_poisoning | poisoned_tool_name | ARGUS-CANARY-01 |
| 02 | memory_poisoning | poisoned_memory_key | ARGUS-CANARY-02 |
| 03 | identity_spoofing | impersonated_agent | ARGUS-CANARY-03 |
| 04 | privilege_escalation | tool_chain | ARGUS-CANARY-04 |
| 05 | prompt_injection | injection_surface | ARGUS-CANARY-05 |
| 06 | supply_chain | malicious_package_name | ARGUS-CANARY-06 |
| 07 | race_condition | vulnerable_workflow | ARGUS-CANARY-07 |

## Validation Tier Requirements

To earn validation points, `proof_of_exploit` must include:
- The indicator listed in `scoring/rubric.json` `must_contain` field
- `canary_extracted` matching the scenario canary value exactly

## Chaining Tier Requirements

To earn chaining points, `chain` must include:
- `steps` array with 2+ steps
- Each attack class referenced in `must_reference` from the rubric
- A `compound_severity` field

See `scoring/rubric.json` for exact per-scenario requirements.
