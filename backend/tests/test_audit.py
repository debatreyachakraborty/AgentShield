
from uuid import UUID

from backend.app.monitoring.audit import (
    AuditEventType,
    SecurityAuditLogger,
)


def test_audit_event_is_recorded():
    logger = SecurityAuditLogger()

    event = logger.log_event(
        session_id="session_001",
        event_type=AuditEventType.THREAT_DETECTED,
        agent_id="analysis_agent",
        description="Suspicious instruction detected",
    )

    UUID(event.event_id)

    assert event.session_id == "session_001"
    assert event.event_type == AuditEventType.THREAT_DETECTED
    assert len(logger.events) == 1


def test_blocked_tool_event():
    logger = SecurityAuditLogger()

    event = logger.log_event(
        session_id="session_001",
        event_type=AuditEventType.TOOL_BLOCKED,
        agent_id="execution_agent",
        description="Unauthorized DELETE_FILE request",
        metadata={"tool": "delete_file"},
    )

    assert event.event_type == AuditEventType.TOOL_BLOCKED
    assert event.metadata["tool"] == "delete_file"


def test_session_event_filtering():
    logger = SecurityAuditLogger()

    logger.log_event(
        "session_001",
        AuditEventType.TOOL_ALLOWED,
        "execution_agent",
        "Authorized action",
    )

    logger.log_event(
        "session_002",
        AuditEventType.TOOL_BLOCKED,
        "execution_agent",
        "Blocked action",
    )

    events = logger.get_session_events("session_001")

    assert len(events) == 1
    assert events[0].session_id == "session_001"


def test_event_type_filtering():
    logger = SecurityAuditLogger()

    logger.log_event(
        "session_001",
        AuditEventType.THREAT_DETECTED,
        "analysis_agent",
        "Threat found",
    )

    logger.log_event(
        "session_001",
        AuditEventType.TOOL_ALLOWED,
        "execution_agent",
        "Tool allowed",
    )

    events = logger.get_events_by_type(
        AuditEventType.THREAT_DETECTED
    )

    assert len(events) == 1
    assert events[0].event_type == AuditEventType.THREAT_DETECTED


def test_audit_export():
    logger = SecurityAuditLogger()

    logger.log_event(
        "session_001",
        AuditEventType.MESSAGE_TRACKED,
        "research_agent",
        "Message recorded",
    )

    exported = logger.export_events()

    assert len(exported) == 1
    assert isinstance(exported[0], dict)
    assert isinstance(exported[0]["timestamp"], str)
    assert exported[0]["event_type"] == "message_tracked"


def test_empty_logger():
    logger = SecurityAuditLogger()

    assert logger.get_session_events("unknown") == []
    assert logger.export_events() == []
