"""
AI SIEM Log Simulator
=====================
Generates realistic security log traffic for testing the SIEM pipeline.

Scenarios:
  1. Normal traffic    - regular user activity
  2. Brute Force       - rapid login failures from same IP
  3. SQL Injection     - malicious query patterns
  4. Privilege Escalation - unauthorized admin access
  5. Mixed attack      - combination of above

Usage:
  python log_simulator.py --scenario all --count 50
  python log_simulator.py --scenario brute_force --count 10
  python log_simulator.py --scenario mixed --duration 60
"""

import argparse
import json
import random
import time
import urllib.request

INGESTION_URL = "http://localhost:8081/api/logs"

# --- Realistic data pools ---
NORMAL_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40", "192.168.1.50"]
ATTACKER_IPS = ["10.0.0.200", "203.0.113.42", "198.51.100.7", "45.33.32.156"]
USERS = ["alice", "bob", "charlie", "david", "eve", "admin", "root"]
NORMAL_ENDPOINTS = [
    "/api/users/profile", "/api/products", "/api/orders",
    "/api/dashboard", "/api/settings", "/api/notifications",
    "/api/search", "/api/reports", "/api/files/upload",
]
METHODS = ["GET", "POST", "PUT", "DELETE"]
SOURCES = ["web-server", "app-server", "api-gateway", "auth-service"]


def send_log(log: dict) -> dict | None:
    data = json.dumps(log).encode("utf-8")
    req = urllib.request.Request(
        INGESTION_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  [ERROR] Failed to send log: {e}")
        return None


def gen_normal():
    """Generate a normal traffic log."""
    return {
        "source": random.choice(SOURCES),
        "logLevel": random.choice(["INFO", "INFO", "INFO", "DEBUG"]),
        "message": random.choice([
            "User accessed resource successfully",
            "Page loaded in 234ms",
            "API request completed",
            "Session refreshed",
            "File downloaded successfully",
            "Search query executed",
            "User preferences updated",
        ]),
        "sourceIp": random.choice(NORMAL_IPS),
        "userId": random.choice(USERS[:5]),
        "endpoint": random.choice(NORMAL_ENDPOINTS),
        "method": random.choice(METHODS),
        "statusCode": random.choice([200, 200, 200, 201, 204]),
    }


def gen_brute_force(attacker_ip: str = None, target_user: str = "admin"):
    """Generate a brute force login attempt log."""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    return {
        "source": "auth-service",
        "logLevel": "WARN",
        "message": f"Failed login attempt for user {target_user}",
        "sourceIp": ip,
        "userId": target_user,
        "endpoint": "/api/auth/login",
        "method": "POST",
        "statusCode": 401,
    }


def gen_sql_injection():
    """Generate a SQL injection attempt log."""
    payloads = [
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM users --",
        "1; EXEC xp_cmdshell('net user hacker P@ss /add')",
        "' AND 1=1 UNION SELECT NULL, table_name FROM information_schema.tables --",
        "admin'--",
        "' WAITFOR DELAY '0:0:10' --",
        "1' OR '1'='1' /*",
    ]
    payload = random.choice(payloads)
    return {
        "source": "web-server",
        "logLevel": "ERROR",
        "message": f"SQL error in query parameter: {payload}",
        "sourceIp": random.choice(ATTACKER_IPS),
        "endpoint": f"/api/users?id={payload}",
        "method": "GET",
        "statusCode": 500,
    }


def gen_privilege_escalation():
    """Generate a privilege escalation attempt log."""
    admin_paths = ["/admin/settings", "/admin/users", "/admin/logs", "/admin/config", "/admin/backup"]
    return {
        "source": "api-gateway",
        "logLevel": "WARN",
        "message": "Unauthorized access attempt to admin endpoint",
        "sourceIp": random.choice(ATTACKER_IPS),
        "userId": random.choice(["eve", "bob", "unknown_user"]),
        "endpoint": random.choice(admin_paths),
        "method": random.choice(["GET", "POST", "DELETE"]),
        "statusCode": random.choice([401, 403]),
    }


# --- Scenario runners ---

def scenario_normal(count: int):
    print(f"\n[SCENARIO] Normal Traffic - {count} logs")
    for i in range(count):
        log = gen_normal()
        result = send_log(log)
        if result:
            print(f"  [{i+1}/{count}] Normal: {log['endpoint']} -> {result['status']}")
        time.sleep(0.1)


def scenario_brute_force(count: int):
    ip = random.choice(ATTACKER_IPS)
    print(f"\n[SCENARIO] Brute Force Attack from {ip} - {count} attempts")
    for i in range(count):
        log = gen_brute_force(attacker_ip=ip)
        result = send_log(log)
        if result:
            marker = " *** SHOULD TRIGGER DETECTION" if i >= 4 else ""
            print(f"  [{i+1}/{count}] Login failed from {ip}{marker}")
        time.sleep(0.3)


def scenario_sql_injection(count: int):
    print(f"\n[SCENARIO] SQL Injection Attacks - {count} attempts")
    for i in range(count):
        log = gen_sql_injection()
        result = send_log(log)
        if result:
            print(f"  [{i+1}/{count}] SQLi from {log['sourceIp']} -> {result['status']}")
        time.sleep(0.2)


def scenario_privilege_escalation(count: int):
    print(f"\n[SCENARIO] Privilege Escalation - {count} attempts")
    for i in range(count):
        log = gen_privilege_escalation()
        result = send_log(log)
        if result:
            print(f"  [{i+1}/{count}] {log['userId']} -> {log['endpoint']} ({log['statusCode']})")
        time.sleep(0.2)


def scenario_mixed(count: int):
    """Mixed scenario: 60% normal, 15% brute force, 15% SQLi, 10% priv escalation."""
    print(f"\n[SCENARIO] Mixed Traffic - {count} logs")
    generators = (
        [(gen_normal, "NORMAL")] * 60 +
        [(gen_brute_force, "BRUTE_FORCE")] * 15 +
        [(gen_sql_injection, "SQL_INJECTION")] * 15 +
        [(gen_privilege_escalation, "PRIV_ESCALATION")] * 10
    )
    stats = {"NORMAL": 0, "BRUTE_FORCE": 0, "SQL_INJECTION": 0, "PRIV_ESCALATION": 0}

    for i in range(count):
        gen_func, label = random.choice(generators)
        log = gen_func()
        result = send_log(log)
        stats[label] += 1
        if result:
            severity = "!" if label != "NORMAL" else " "
            print(f"  [{i+1}/{count}]{severity} {label}: {log.get('sourceIp', '?')} -> {result['status']}")
        time.sleep(0.15)

    print(f"\n  --- Mix Stats ---")
    for label, cnt in stats.items():
        print(f"  {label}: {cnt}")


def scenario_all(count: int):
    """Run all scenarios sequentially."""
    per = max(count // 5, 2)
    scenario_normal(per)
    scenario_brute_force(max(per, 7))  # need at least 7 for detection
    scenario_sql_injection(per)
    scenario_privilege_escalation(per)
    scenario_mixed(per)


def main():
    parser = argparse.ArgumentParser(description="AI SIEM Log Simulator")
    parser.add_argument("--scenario", default="all",
                        choices=["normal", "brute_force", "sql_injection", "priv_escalation", "mixed", "all"],
                        help="Attack scenario to simulate")
    parser.add_argument("--count", type=int, default=50, help="Number of logs to generate")
    parser.add_argument("--url", default=INGESTION_URL, help="Ingestion service URL")
    args = parser.parse_args()

    print("=" * 60)
    print("  AI SIEM Log Simulator")
    print(f"  Target: {args.url}")
    print(f"  Scenario: {args.scenario}")
    print(f"  Count: {args.count}")
    print("=" * 60)

    scenarios = {
        "normal": scenario_normal,
        "brute_force": scenario_brute_force,
        "sql_injection": scenario_sql_injection,
        "priv_escalation": scenario_privilege_escalation,
        "mixed": scenario_mixed,
        "all": scenario_all,
    }

    start = time.time()
    scenarios[args.scenario](args.count)
    elapsed = time.time() - start

    print(f"\n{'=' * 60}")
    print(f"  Simulation complete in {elapsed:.1f}s")
    print(f"  Check results:")
    print(f"    Dashboard: http://localhost:8083/api/dashboard/summary")
    print(f"    Events:    http://localhost:8082/api/detection/events")
    print(f"    Alerts:    http://localhost:8083/api/alerts")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
