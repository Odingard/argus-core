# Security Policy

## Supported versions

| Version | Support status |
|---|---|
| `argus-core` latest (`0.5.x`) | Active — security fixes land here first |
| `argus-redteam` | Deprecated meta-package (`0.4.1` just pulls `argus-core`); no independent security patches |
| Pre-rename versions of `argus-redteam` (`≤0.4.0`) | Unsupported — upgrade to `argus-core` |

## Scope

In-scope (we treat as security issues):

- **Framework-level vulnerabilities** in ARGUS itself — e.g., a
  prompt injection in one of our own agents that an attacker could
  exploit by placing crafted content into a labrat fixture ARGUS
  engages.
- **Sandbox escapes** in `argus.adapter.sandboxed_stdio` (docker
  hardening bypass) that let an untrusted target subprocess reach
  the host filesystem or network.
- **Provenance forgery** against Wilson forensic bundles — anything
  that lets an attacker emit a bundle that verifies as signed
  without holding the signing key.
- **Supply-chain** — a malicious transitive dependency landing in a
  published `argus-core` release.
- **Credential exposure** through argus' own code paths (e.g.
  logging a token that should have been redacted).

Out of scope:

- Findings **against third-party targets** that ARGUS engages —
  those are the responsibility of the target's vendor and
  disclosure should go there.
- Behaviour that is working as designed (e.g. `argus --sandbox`
  disabled when `docker` is not installed; ARGUS intentionally
  refuses to engage without the sandbox guard).
- Theoretical weaknesses without a working PoC. Per our
  `docs/NO_CHEATING.md` integrity contract, ARGUS itself requires
  reproducible PoCs; the same bar applies to reports we receive.

## Reporting a vulnerability

**Do not open a public GitHub issue** for a security report.

Email: **security@sixsenseenterprise.com**

Please include:

1. ARGUS version (`argus --version`).
2. A reproducible PoC — commands run, expected vs observed
   behaviour, relevant output. Stack traces welcome.
3. Your preferred disclosure window (we default to 90 days from
   acknowledgement).

## Response SLA

- **Acknowledgement:** within 48 hours of receipt.
- **Triage + reproduction:** within 7 days; if we can't reproduce
  we'll ask for the smallest additional fact we need.
- **Fix + coordinated advisory:** within the agreed disclosure
  window. CVE assignment and CWE mapping via our layer-6 pipeline;
  we credit the reporter unless you ask us not to.
- **Regression test:** every fixed issue lands with a pytest
  reproducer in `tests/` so the class can't silently regress.

## Safe-harbour

Security research against ARGUS itself (this repo + published
`argus-core` wheels) is welcome and we will not pursue legal action
against good-faith researchers who:

- Give us a reasonable window to fix before public disclosure.
- Don't pivot from an ARGUS finding into attacking third-party
  services or our customers' infrastructure.
- Don't publicly disclose operator credentials, Wilson signing
  keys, or unpatched PoCs that target specific deployments.

This safe-harbour does **not** extend to engagements ARGUS runs
against third-party targets. Those engagements must be authorised
by the target's owner — nothing in ARGUS's license grants you
permission to test systems you don't own.
