from sqlalchemy import Column, BigInteger, String, Double, Text, TIMESTAMP, ForeignKey, func
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class DetectionRule(Base):
    __tablename__ = "detection_rule"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    event_type = Column(String(50), nullable=False)
    pattern = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    enabled = Column(String(5), default="1")
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())


class SecurityEvent(Base):
    __tablename__ = "security_event"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    log_entry_id = Column(String(255))
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text)
    source_ip = Column(String(45))
    detected_by = Column(String(20), nullable=False)  # RULE or AI
    rule_id = Column(BigInteger, ForeignKey("detection_rule.id", ondelete="SET NULL"))
    confidence = Column(Double, default=0.0)
    status = Column(String(30), default="NEW")
    raw_log = Column(Text)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
