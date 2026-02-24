import re
import logging
from collections import defaultdict
from datetime import datetime, timedelta

from app.schema.detection import LogMessage, EventType, Severity

logger = logging.getLogger(__name__)

# In-memory store for brute force tracking
_login_failures: dict[str, list[datetime]] = defaultdict(list)

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    r"('\s*(OR|AND)\s+['0-9])",
    r"(UNION\s+SELECT)",
    r"(DROP\s+TABLE)",
    r"(;\s*--)",
    r"(INSERT\s+INTO)",
    r"(DELETE\s+FROM)",
    r"(UPDATE\s+.*\s+SET)",
    r"(xp_cmdshell)",
    r"(EXEC\s*\()",
    r"(WAITFOR\s+DELAY)",
    r"('\s*--)",
]

# Admin endpoints pattern
ADMIN_PATH_PATTERN = r"^/admin(/|$)"


def check_brute_force(log: LogMessage) -> dict | None:
    """Detect brute force login attempts: 5+ failures from same IP in 5 minutes."""
    if "login" not in log.message.lower() or "fail" not in log.message.lower():
        return None

    ip = log.source_ip
    if not ip:
        return None

    now = datetime.utcnow()
    window = timedelta(minutes=5)

    # Add current failure
    _login_failures[ip].append(now)

    # Clean old entries
    _login_failures[ip] = [t for t in _login_failures[ip] if now - t <= window]

    count = len(_login_failures[ip])
    if count >= 5:
        logger.warning(f"Brute force detected: IP={ip}, failures={count}")
        return {
            "event_type": EventType.BRUTE_FORCE,
            "severity": Severity.HIGH,
            "description": f"Brute force attack detected: {count} failed login attempts from {ip} within 5 minutes",
            "confidence": min(count / 10, 1.0),
        }

    return None


def check_sql_injection(log: LogMessage) -> dict | None:
    """Detect SQL injection patterns in log messages."""
    text = log.message + " " + (log.endpoint or "")

    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning(f"SQL injection detected: IP={log.source_ip}, pattern={pattern}")
            return {
                "event_type": EventType.SQL_INJECTION,
                "severity": Severity.CRITICAL,
                "description": f"SQL injection attempt detected from {log.source_ip}: matched pattern '{pattern}'",
                "confidence": 0.95,
            }

    return None


def check_privilege_escalation(log: LogMessage) -> dict | None:
    """Detect non-admin users accessing admin endpoints."""
    if not log.endpoint:
        return None

    if re.search(ADMIN_PATH_PATTERN, log.endpoint, re.IGNORECASE):
        if log.user_id and log.status_code in ("401", "403"):
            logger.warning(f"Privilege escalation attempt: user={log.user_id}, endpoint={log.endpoint}")
            return {
                "event_type": EventType.PRIVILEGE_ESCALATION,
                "severity": Severity.HIGH,
                "description": f"Privilege escalation attempt: user '{log.user_id}' tried to access admin endpoint '{log.endpoint}'",
                "confidence": 0.9,
            }

    return None


def run_all_rules(log: LogMessage) -> list[dict]:
    """Run all detection rules against a log entry."""
    results = []

    checks = [check_brute_force, check_sql_injection, check_privilege_escalation]

    for check in checks:
        result = check(log)
        if result:
            result["log_entry_id"] = log.id
            result["source_ip"] = log.source_ip
            result["detected_by"] = "RULE"
            result["raw_log"] = log.message
            results.append(result)

    return results
