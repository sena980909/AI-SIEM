from pydantic import BaseModel
from datetime import datetime
from enum import Enum


class EventType(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    ANOMALY = "ANOMALY"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectedBy(str, Enum):
    RULE = "RULE"
    AI = "AI"


class EventStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class LogMessage(BaseModel):
    id: str
    timestamp: str
    source: str
    log_level: str = "INFO"
    message: str
    source_ip: str = ""
    user_id: str = ""
    endpoint: str = ""
    method: str = ""
    status_code: str = ""


class SecurityEventResponse(BaseModel):
    id: int
    log_entry_id: str | None
    event_type: EventType
    severity: Severity
    description: str | None
    source_ip: str | None
    detected_by: DetectedBy
    confidence: float
    status: EventStatus
    created_at: datetime | None

    class Config:
        from_attributes = True


class DetectionRuleResponse(BaseModel):
    id: int
    name: str
    description: str | None
    event_type: EventType
    pattern: str
    severity: Severity
    enabled: bool

    class Config:
        from_attributes = True
