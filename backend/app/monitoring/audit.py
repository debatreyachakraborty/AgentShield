
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    THREAT_DETECTED = "threat_detected"
    TOOL_ALLOWED = "tool_allowed"
    TOOL_BLOCKED = "tool_blocked"
    MESSAGE_TRACKED = "message_tracked"


class AuditEvent(BaseModel):
    event_id: str = Field(
        default_factory=lambda: str(uuid4())
    )
    session_id: str = Field(min_length=1)
    event_type: AuditEventType
    agent_id: str = Field(min_length=1)
    description: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: dict = Field(default_factory=dict)


class SecurityAuditLogger:
    def __init__(self):
        self.events: list[AuditEvent] = []

    def log_event(
        self,
        session_id: str,
        event_type: AuditEventType,
        agent_id: str,
        description: str,
        metadata: dict | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            session_id=session_id,
            event_type=event_type,
            agent_id=agent_id,
            description=description,
            metadata=metadata or {},
        )

        self.events.append(event)
        return event

    def get_session_events(
        self,
        session_id: str,
    ) -> list[AuditEvent]:
        return [
            event
            for event in self.events
            if event.session_id == session_id
        ]

    def get_events_by_type(
        self,
        event_type: AuditEventType,
    ) -> list[AuditEvent]:
        return [
            event
            for event in self.events
            if event.event_type == event_type
        ]

    def export_events(self) -> list[dict]:
        return [
            event.model_dump(mode="json")
            for event in self.events
        ]
