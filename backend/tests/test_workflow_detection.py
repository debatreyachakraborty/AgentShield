
from backend.app.orchestration.workflow import run_workflow


def test_normal_workflow_has_no_threat():
    result = run_workflow("Research AI security")

    assert result["gateway_decision"] == "ALLOW"
    assert result["threat_detected"] is False
    assert result["threat_score"] == 0.0
    assert result["tool_allowed"] is True


def test_attack_workflow_detects_threat():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    assert result["gateway_decision"] == "BLOCK"
    assert result["threat_detected"] is True
    assert result["threat_score"] >= 0.7
    assert result["tool_allowed"] is False


def test_detection_evidence_is_recorded():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    gateway_message = result["messages"][-1]

    assert gateway_message.sender_id == "security_gateway"

    assert gateway_message.metadata["gateway_decision"] == "BLOCK"

    assert gateway_message.metadata["gateway_reason"]

    assert result["threat_detected"] is True
    assert result["threat_score"] > 0.0

    # The gateway must prevent the attack from reaching analysis.
    assert all(
        message.sender_id != "analysis_agent"
        for message in result["messages"]
    )


def test_detection_does_not_replace_permissions():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    assert result["gateway_decision"] == "BLOCK"
    assert result["threat_detected"] is True
    assert result["tool_allowed"] is False

    assert result["final_output"].startswith(
        "BLOCKED BY SECURITY GATEWAY"
    )

    # Execution must never run after a gateway block.
    assert all(
        message.sender_id != "execution_agent"
        for message in result["messages"]
    )


def test_gateway_block_records_threat_event():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    threat_events = [
        event
        for event in result["audit_events"]
        if event["event_type"] == "threat_detected"
    ]

    assert len(threat_events) == 1
    assert threat_events[0]["metadata"]["risk_score"] > 0.0


def test_safe_content_reaches_execution():
    result = run_workflow("Summarize AI security research")

    sender_ids = [
        message.sender_id
        for message in result["messages"]
    ]

    assert result["gateway_decision"] == "ALLOW"
    assert sender_ids == [
        "research_agent",
        "analysis_agent",
        "execution_agent",
    ]

    assert result["tool_allowed"] is True

def test_normal_workflow_records_tool_execution():
    result = run_workflow("Research AI security")

    assert result["tool_allowed"] is True
    assert result["tool_executed"] is True

def test_blocked_attack_records_no_tool_execution():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    assert result["tool_allowed"] is False
    assert result["tool_executed"] is False