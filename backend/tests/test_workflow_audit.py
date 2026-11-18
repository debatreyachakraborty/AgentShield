
from datetime import datetime

from backend.app.orchestration.workflow import run_workflow


def test_normal_workflow_audit():
    result = run_workflow("Research AI security")

    events = result["audit_events"]
    event_types = [event["event_type"] for event in events]

    assert result["gateway_decision"] == "ALLOW"
    assert len(events) == 4
    assert event_types.count("message_tracked") == 3
    assert "tool_allowed" in event_types
    assert "threat_detected" not in event_types


def test_attack_workflow_audit():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    events = result["audit_events"]
    event_types = [event["event_type"] for event in events]

    assert result["gateway_decision"] == "BLOCK"
    assert len(events) == 4
    assert event_types.count("message_tracked") == 2
    assert "threat_detected" in event_types
    assert "tool_blocked" in event_types
    assert "tool_allowed" not in event_types


def test_audit_session_id_consistency():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    assert all(
        event["session_id"] == result["session_id"]
        for event in result["audit_events"]
    )


def test_audit_records_agent_identities():
    result = run_workflow("Research AI security")

    tracked_events = [
        event
        for event in result["audit_events"]
        if event["event_type"] == "message_tracked"
    ]

    assert [event["agent_id"] for event in tracked_events] == [
        "research_agent",
        "analysis_agent",
        "execution_agent",
    ]


def test_audit_records_gateway_block():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    blocked_events = [
        event
        for event in result["audit_events"]
        if event["event_type"] == "tool_blocked"
    ]

    assert len(blocked_events) == 1

    blocked_event = blocked_events[0]

    assert blocked_event["agent_id"] == "security_gateway"

    assert blocked_event["metadata"]["gateway_decision"] == "BLOCK"
    assert blocked_event["metadata"]["block_source"] == (
        "security_gateway"
    )

    # No tool was requested because execution never started.
    assert blocked_event["metadata"]["requested_tool"] is None


def test_audit_events_have_timestamps():
    result = run_workflow("Research AI security")

    for event in result["audit_events"]:
        assert isinstance(event["timestamp"], str)

        # Verify the timestamp is valid ISO 8601.
        datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )


def test_blocked_workflow_records_gateway_identity():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    tracked_events = [
        event
        for event in result["audit_events"]
        if event["event_type"] == "message_tracked"
    ]

    assert [event["agent_id"] for event in tracked_events] == [
        "research_agent",
        "security_gateway",
    ]


def test_gateway_block_preserves_audit_session():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    blocked_events = [
        event
        for event in result["audit_events"]
        if event["event_type"] == "tool_blocked"
    ]

    assert len(blocked_events) == 1
    assert blocked_events[0]["session_id"] == result["session_id"]
