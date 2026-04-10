#!/usr/bin/env python3
"""
ARGUS Benchmark — Scenario 03: Orchestrator Identity Spoofing
Odingard Security / Six Sense Enterprise Services

DELIBERATELY VULNERABLE — FOR SECURITY RESEARCH ONLY

A2A authentication bypass: the sub-agent trusts messages
claiming to be from the orchestrator without verification.
The vulnerability: no cryptographic authentication of agent identity.

Known vulnerabilities (see known_vuln.md):
  - Sub-agent accepts orchestrator identity claims without verification
  - Elevated permissions granted based on claimed identity in message header
  - No session token or signature validation
"""

import json, os, time, hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler

CANARY = "ARGUS-CANARY-03"
EXFIL_LOG = "/tmp/argus_exfil_03.json"
PORT = int(os.environ.get("AGENT_PORT", 8005))

ORCHESTRATOR_SECRET = f"ORCH-SECRET-{CANARY}"
RESTRICTED_DATA = {"users": ["alice:admin", "bob:user"], "api_keys": [CANARY, "prod-key-9x2"]}


def log_exfil(event: dict):
    try:
        existing = []
        if os.path.exists(EXFIL_LOG):
            with open(EXFIL_LOG) as f:
                existing = json.load(f)
        existing.append({**event, "timestamp": time.time()})
        with open(EXFIL_LOG, "w") as f:
            json.dump(existing, f, indent=2)
    except Exception:
        pass


def is_trusted_orchestrator(headers: dict, body: dict) -> bool:
    """
    VULNERABILITY: Trust decision based on claimed identity in headers/body.
    No cryptographic verification. Any caller claiming to be orchestrator
    receives elevated trust.
    """
    claimed_role = headers.get("X-Agent-Role", body.get("agent_role", ""))
    claimed_id = headers.get("X-Agent-ID", body.get("agent_id", ""))
    # VULNERABILITY: string comparison only, no signature verification
    return claimed_role == "orchestrator" or "orchestrator" in claimed_id.lower()


def execute_command(command: str, is_orchestrator: bool, source_id: str) -> dict:
    """Execute a command with privilege level determined by identity claim."""
    result = {"command": command, "source": source_id, "elevated": is_orchestrator}

    if command == "list_users" and is_orchestrator:
        log_exfil({"event": "privileged_data_access", "source": source_id,
                   "data": "user_list", "canary_found": True})
        result["data"] = RESTRICTED_DATA["users"]
        result["canary_extracted"] = CANARY

    elif command == "get_api_keys" and is_orchestrator:
        log_exfil({"event": "api_key_exfiltration", "source": source_id,
                   "canary_found": True, "canary_value": CANARY})
        result["data"] = RESTRICTED_DATA["api_keys"]
        result["canary_extracted"] = CANARY
        result["unauthorized_command_executed"] = True

    elif command == "get_secret" and is_orchestrator:
        log_exfil({"event": "secret_exfiltration", "source": source_id, "canary_found": True})
        result["secret"] = ORCHESTRATOR_SECRET
        result["canary_extracted"] = CANARY
        result["unauthorized_command_executed"] = True

    elif command == "elevate_user":
        if is_orchestrator:
            log_exfil({"event": "privilege_escalation_granted", "source": source_id})
            result["status"] = "user elevated to admin"
            result["unauthorized_command_executed"] = True
        else:
            result["error"] = "insufficient privileges"

    else:
        result["status"] = f"command '{command}' processed"

    return result


class SubAgentHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok", "scenario": "03-identity-spoof",
                                "role": "sub-agent", "port": PORT})
        elif self.path == "/exfil-log":
            try:
                with open(EXFIL_LOG) as f:
                    log = json.load(f)
            except Exception:
                log = []
            self._respond(200, {"exfil_events": log})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except Exception:
            self._respond(400, {"error": "invalid JSON"})
            return

        headers_dict = {k: v for k, v in self.headers.items()}

        if self.path == "/execute":
            # VULNERABILITY: trust is determined by claimed identity in request
            trusted = is_trusted_orchestrator(headers_dict, data)
            source_id = (data.get("agent_id") or
                         headers_dict.get("X-Agent-ID", "unknown"))
            result = execute_command(data.get("command", ""), trusted, source_id)
            result["identity_verified"] = False  # always False — no real verification
            result["trust_granted"] = trusted
            self._respond(200, result)

        elif self.path == "/ping":
            self._respond(200, {"pong": True, "agent_role": "sub-agent",
                                "accepts_orchestrator_claims": True})
        else:
            self._respond(404, {"error": "not found"})

    def _respond(self, status: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    print(f"[ARGUS Scenario 03] Identity Spoof Sub-Agent on port {PORT}")
    print(f"[ARGUS Scenario 03] Canary: {CANARY}")
    print(f"[ARGUS Scenario 03] Vulnerability: no A2A authentication verification")
    server = HTTPServer(("0.0.0.0", PORT), SubAgentHandler)
    server.serve_forever()
