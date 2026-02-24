import logging
from sqlalchemy.orm import Session

from app.model.security_event import SecurityEvent

logger = logging.getLogger(__name__)


async def save_security_event(detection: dict, db_session: Session):
    """Save a detected security event to MySQL."""
    event = SecurityEvent(
        log_entry_id=detection.get("log_entry_id"),
        event_type=detection["event_type"],
        severity=detection["severity"],
        description=detection.get("description"),
        source_ip=detection.get("source_ip"),
        detected_by=detection["detected_by"],
        rule_id=detection.get("rule_id"),
        confidence=detection.get("confidence", 0.0),
        status="NEW",
        raw_log=detection.get("raw_log"),
    )

    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    logger.info(f"Saved security event: id={event.id}, type={event.event_type}")
    return event
