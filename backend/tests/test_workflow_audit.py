
from backend.app.orchestration.workflow import run_workflow


def test_normal_workflow_audit():
    result = run_workflow("Research AI security")

    events = result["audit_events"]

    assert len(events) == 4

    event_types = [event["event_type"] for event in events]

    assert event_types.count("message_tracked") == 3
    assert "tool_allowed" in event_types
    assert "threat_detected" not in event_types


def test_attack_workflow_audit():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    events = result["audit_events"]

    assert len(events) == 5

    event_types = [event["event_type"] for event in events]

    assert event_types.count("message_tracked") == 3
    assert "threat_detected" in event_types
    assert "tool_blocked" in event_types


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


def test_audit_records_blocked_tool():
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

    assert (
        blocked_events[0]["metadata"]["requested_tool"]
        == "delete_file"
    )


def test_audit_events_have_timestamps():
    result = run_workflow("Research AI security")

    assert all(
        isinstance(event["timestamp"], str)
        for event in result["audit_events"]
    )
