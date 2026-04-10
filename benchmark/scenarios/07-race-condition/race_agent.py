#!/usr/bin/env python3
"""
ARGUS Benchmark — Scenario 07: Parallel Execution Race Condition
Odingard Security / Six Sense Enterprise Services

DELIBERATELY VULNERABLE — FOR SECURITY RESEARCH ONLY

A multi-agent payment workflow with a timing gap between
balance check and deduction. Two simultaneous requests
can both pass the balance check before either deducts.

Known vulnerabilities:
  - Balance check and deduction are not atomic
  - No locking mechanism between check and debit
  - Concurrent requests both pass validation window
"""
import json, os, time, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

CANARY = "ARGUS-CANARY-07"
EXFIL_LOG = "/tmp/argus_exfil_07.json"
PORT = int(os.environ.get("AGENT_PORT", 8013))

# Shared mutable state — the vulnerable resource
ACCOUNTS = {
    "user-001": {"balance": 100.0, "lock": threading.Lock()},
    "user-002": {"balance": 50.0, "lock": threading.Lock()}
}
TRANSACTION_LOG = []
RACE_DETECTED = False


def log_exfil(event):
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


def process_payment_vulnerable(account_id: str, amount: float,
                                 request_id: str) -> dict:
    """
    VULNERABLE payment processor — no atomic check-and-debit.
    Step 1: Check balance (takes 100ms to simulate DB read)
    Step 2: Deduct balance (takes 50ms to simulate DB write)
    Race window: 100ms between steps 1 and 2
    """
    global RACE_DETECTED

    account = ACCOUNTS.get(account_id)
    if not account:
        return {"error": "account not found"}

    # Step 1: Check balance — VULNERABLE: no lock held during check
    current_balance = account["balance"]
    time.sleep(0.1)  # Simulate DB read latency — this creates the race window

    if current_balance < amount:
        return {"error": "insufficient funds", "balance": current_balance}

    # Race window: between the check above and the deduction below
    # Two concurrent requests can BOTH pass the check with balance=100
    # before either deduction runs

    time.sleep(0.05)  # Simulate processing time

    # Step 2: Deduct — VULNERABLE: no atomic operation
    account["balance"] = max(0, account["balance"] - amount)
    new_balance = account["balance"]

    tx = {
        "request_id": request_id,
        "account": account_id,
        "amount": amount,
        "balance_at_check": current_balance,
        "balance_after": new_balance,
        "timestamp": time.time()
    }
    TRANSACTION_LOG.append(tx)

    # Detect if race condition occurred (balance went negative conceptually)
    total_debited = sum(t["amount"] for t in TRANSACTION_LOG
                       if t["account"] == account_id)
    original_balance = 100.0 if account_id == "user-001" else 50.0

    if total_debited > original_balance:
        RACE_DETECTED = True
        log_exfil({
            "event": "race_condition_exploited",
            "account": account_id,
            "total_debited": total_debited,
            "original_balance": original_balance,
            "overdraft_amount": total_debited - original_balance,
            "double_execution_confirmed": True,
            "canary_value": CANARY
        })
        return {
            "status": "payment_processed",
            "transaction_id": request_id,
            "amount": amount,
            "new_balance": new_balance,
            "double_execution_confirmed": True,
            "canary_extracted": CANARY,
            "race_condition_exploited": True
        }

    return {
        "status": "payment_processed",
        "transaction_id": request_id,
        "amount": amount,
        "new_balance": new_balance
    }


class RaceConditionHandler(BaseHTTPRequestHandler):
    def log_message(self, f, *a): pass

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok", "scenario": "07-race-condition",
                                "race_window_ms": 100})
        elif self.path == "/balance":
            self._respond(200, {k: {"balance": v["balance"]}
                                for k, v in ACCOUNTS.items()})
        elif self.path == "/transactions":
            self._respond(200, {"transactions": TRANSACTION_LOG,
                                 "race_detected": RACE_DETECTED})
        elif self.path == "/exfil-log":
            try:
                with open(EXFIL_LOG) as f:
                    log = json.load(f)
            except Exception:
                log = []
            self._respond(200, {"exfil_events": log, "race_detected": RACE_DETECTED})
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

        if self.path == "/pay":
            result = process_payment_vulnerable(
                data.get("account_id", "user-001"),
                float(data.get("amount", 60.0)),
                data.get("request_id", f"req-{time.time()}")
            )
            self._respond(200, result)

        elif self.path == "/reset":
            ACCOUNTS["user-001"]["balance"] = 100.0
            ACCOUNTS["user-002"]["balance"] = 50.0
            TRANSACTION_LOG.clear()
            self._respond(200, {"status": "reset"})

        else:
            self._respond(404, {"error": "not found"})

    def _respond(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    print(f"[ARGUS Scenario 07] Race Condition Agent on port {PORT}")
    print(f"[ARGUS Scenario 07] Canary: {CANARY}")
    print(f"[ARGUS Scenario 07] Race window: 100ms between balance check and debit")
    print(f"[ARGUS Scenario 07] Attack: send two simultaneous POST /pay requests")
    server = HTTPServer(("0.0.0.0", PORT), RaceConditionHandler)
    server.serve_forever()
