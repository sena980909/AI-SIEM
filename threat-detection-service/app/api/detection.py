from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.model.security_event import SecurityEvent, DetectionRule
from app.schema.detection import SecurityEventResponse, DetectionRuleResponse, EventStatus

router = APIRouter(prefix="/api/detection", tags=["Threat Detection"])


@router.get("/events", response_model=list[SecurityEventResponse])
def list_security_events(
    status: Optional[EventStatus] = None,
    event_type: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
):
    """List security events with optional filters."""
    query = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc())

    if status:
        query = query.filter(SecurityEvent.status == status.value)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)

    return query.limit(limit).all()


@router.get("/events/{event_id}", response_model=SecurityEventResponse)
def get_security_event(event_id: int, db: Session = Depends(get_db)):
    """Get a specific security event by ID."""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Security event not found")
    return event


@router.patch("/events/{event_id}/status")
def update_event_status(event_id: int, status: EventStatus, db: Session = Depends(get_db)):
    """Update the status of a security event."""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Security event not found")

    event.status = status.value
    db.commit()
    return {"message": f"Event {event_id} status updated to {status.value}"}


@router.get("/rules", response_model=list[DetectionRuleResponse])
def list_detection_rules(db: Session = Depends(get_db)):
    """List all detection rules."""
    return db.query(DetectionRule).all()
