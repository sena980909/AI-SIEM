"""
AI SIEM E2E Attack Simulator
=============================
Mock hacker + QA engineer test script.
Sends 4 attack scenarios and verifies detection pipeline.

Scenarios:
  1. Brute Force       - 10 rapid login failures from same IP
  2. SQL Injection     - 8 SQLi payloads targeting various endpoints
  3. Privilege Escalation - 6 unauthorized admin access attempts
  4. Anomaly Traffic   - Unusual User-Agent, bulk odd-hour requests

Usage:
  pip install requests
  python test_attack_simulator.py
"""

import json
import time
import requests

INGESTION_URL = "http://localhost:8081/api/logs"
DETECTION_URL = "http://localhost:8082/api/detection/events"
DASHBOARD_URL = "http://localhost:8083/api/dashboard/summary"
ALERTS_URL = "http://localhost:8083/api/alerts"

# ─── Scenario 1: Brute Force ────────────────────────────────────────
BRUTE_FORCE_LOGS = []
BRUTE_FORCE_IP = "10.99.99.1"
for i in range(10):
    BRUTE_FORCE_LOGS.append({
        "source": "auth-service",
        "logLevel": "WARN",
        "message": f"Failed login attempt for user admin (attempt {i+1})",
        "sourceIp": BRUTE_FORCE_IP,
        "userId": "admin",
        "endpoint": "/api/auth/login",
        "method": "POST",
        "statusCode": 401,
    })

# ─── Scenario 2: SQL Injection ──────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "' UNION SELECT username, password FROM users --",
    "1; EXEC xp_cmdshell('net user hacker P@ss /add')",
    "' AND 1=1 UNION SELECT NULL, table_name FROM information_schema.tables --",
    "admin'--",
    "' WAITFOR DELAY '0:0:10' --",
    "1' OR '1'='1' /*",
]
SQLI_LOGS = []
SQLI_IPS = ["203.0.113.66", "198.51.100.77"]
for i, payload in enumerate(SQLI_PAYLOADS):
    SQLI_LOGS.append({
        "source": "web-server",
        "logLevel": "ERROR",
        "message": f"SQL error in query parameter: {payload}",
        "sourceIp": SQLI_IPS[i % 2],
        "endpoint": f"/api/users?id={payload}",
        "method": "GET",
        "statusCode": 500,
    })

# ─── Scenario 3: Privilege Escalation ───────────────────────────────
PRIV_ESC_LOGS = []
PRIV_ESC_PATHS = [
    "/admin/settings", "/admin/users", "/admin/logs",
    "/admin/config", "/admin/backup", "/admin/export",
]
PRIV_ESC_USERS = ["eve", "unknown_intruder", "bob"]
for i, path in enumerate(PRIV_ESC_PATHS):
    PRIV_ESC_LOGS.append({
        "source": "api-gateway",
        "logLevel": "WARN",
        "message": f"Unauthorized access attempt to admin endpoint {path}",
        "sourceIp": "45.33.32.200",
        "userId": PRIV_ESC_USERS[i % 3],
        "endpoint": path,
        "method": "GET" if i % 2 == 0 else "POST",
        "statusCode": 401 if i % 2 == 0 else 403,
    })

# ─── Scenario 4: Anomaly Traffic (unusual patterns) ─────────────────
ANOMALY_LOGS = []
# Unusual User-Agent strings in messages
ANOMALY_MESSAGES = [
    "Request with unusual User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1) scanning /etc/passwd",
    "Bulk API calls detected from single IP - 500 requests in 10 seconds",
    "Request at 03:22 AM from IP not seen before, accessing sensitive endpoint",
    "User-Agent: python-requests/2.28.0 automated scraping detected on /api/users/export",
    "Abnormal request pattern: sequential ID enumeration /api/users/1 through /api/users/9999",
    "Request with User-Agent: sqlmap/1.6 - automated SQL injection tool detected",
    "Unusual HTTP method TRACE attempted on /api/admin/debug",
    "Massive data exfiltration: 50MB response to single GET /api/reports/all from unknown IP",
]
for i, msg in enumerate(ANOMALY_MESSAGES):
    ANOMALY_LOGS.append({
        "source": "api-gateway",
        "logLevel": "WARN" if i % 2 == 0 else "ERROR",
        "message": msg,
        "sourceIp": f"172.16.{50 + i}.{100 + i}",
        "endpoint": "/api/users/export" if "export" in msg else "/api/admin/debug" if "TRACE" in msg else "/api/reports/all",
        "method": "GET",
        "statusCode": 200 if i < 4 else 403,
    })


def send_scenario(name: str, logs: list[dict]) -> int:
    """Send all logs for a scenario and return success count."""
    print(f"\n{'='*60}")
    print(f"  SCENARIO: {name}")
    print(f"  Sending {len(logs)} logs...")
    print(f"{'='*60}")

    success = 0
    for i, log in enumerate(logs):
        try:
            resp = requests.post(INGESTION_URL, json=log, timeout=5)
            if resp.status_code in (200, 201):
                success += 1
                status = resp.json().get("status", "?")
                print(f"  [{i+1}/{len(logs)}] OK - {log.get('message', '')[:60]}...")
            else:
                print(f"  [{i+1}/{len(logs)}] FAIL ({resp.status_code})")
        except Exception as e:
            print(f"  [{i+1}/{len(logs)}] ERROR: {e}")
        time.sleep(0.2)

    print(f"\n  Result: {success}/{len(logs)} sent successfully")
    return success


def verify_results():
    """Check detection service and dashboard for results."""
    print(f"\n{'='*60}")
    print(f"  VERIFICATION")
    print(f"{'='*60}")

    # 1. Detection Events
    print("\n--- Detection Events ---")
    try:
        resp = requests.get(DETECTION_URL, timeout=10)
        events = resp.json()
        print(f"  Total events: {len(events)}")

        # Count by type
        by_type = {}
        by_severity = {}
        for ev in events:
            t = ev.get("event_type", "unknown")
            s = ev.get("severity", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
            by_severity[s] = by_severity.get(s, 0) + 1

        print(f"\n  By Type:")
        for t, c in sorted(by_type.items()):
            print(f"    {t}: {c}")
        print(f"\n  By Severity:")
        for s, c in sorted(by_severity.items()):
            print(f"    {s}: {c}")

    except Exception as e:
        print(f"  ERROR: {e}")

    # 2. Dashboard Summary
    print("\n--- Dashboard Summary ---")
    try:
        resp = requests.get(DASHBOARD_URL, timeout=10)
        summary = resp.json()
        print(f"  Period: {summary.get('period_hours', '?')}h")
        print(f"  Total Events: {summary.get('total_events', '?')}")
        print(f"  By Type: {json.dumps(summary.get('events_by_type', {}), indent=4)}")
        print(f"  By Severity: {json.dumps(summary.get('events_by_severity', {}), indent=4)}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # 3. Alerts
    print("\n--- Alerts ---")
    try:
        resp = requests.get(ALERTS_URL, timeout=10)
        alerts = resp.json()
        print(f"  Total alerts: {len(alerts)}")
        # Show last 5 alerts
        for a in alerts[-5:]:
            print(f"    [{a.get('id', '?')}] {a.get('channel', '?')} - {a.get('message', '')[:80]}...")
    except Exception as e:
        print(f"  ERROR: {e}")


def main():
    print("\n" + "=" * 60)
    print("  AI SIEM - E2E Attack Simulator")
    print("  Mock Hacker + QA Engineer Test")
    print("=" * 60)

    total_sent = 0

    # Run all 4 scenarios
    total_sent += send_scenario("1. BRUTE FORCE ATTACK", BRUTE_FORCE_LOGS)
    time.sleep(1)

    total_sent += send_scenario("2. SQL INJECTION ATTACK", SQLI_LOGS)
    time.sleep(1)

    total_sent += send_scenario("3. PRIVILEGE ESCALATION", PRIV_ESC_LOGS)
    time.sleep(1)

    total_sent += send_scenario("4. ANOMALY TRAFFIC", ANOMALY_LOGS)

    print(f"\n{'='*60}")
    print(f"  All scenarios complete. Total logs sent: {total_sent}")
    print(f"  Waiting 35 seconds for detection + alert processing...")
    print(f"{'='*60}")

    # Wait for detection (stream consumer) + alert cycle (30s)
    for i in range(35, 0, -5):
        print(f"  ... {i}s remaining")
        time.sleep(5)

    # Verify results
    verify_results()

    print(f"\n{'='*60}")
    print(f"  E2E Test Complete!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
