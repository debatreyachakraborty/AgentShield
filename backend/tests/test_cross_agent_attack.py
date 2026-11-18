
from backend.app.orchestration.workflow import run_workflow


def test_normal_workflow_is_allowed():
    result = run_workflow("Research AI security")

    assert result["gateway_decision"] == "ALLOW"
    assert result["tool_allowed"] is True
    assert result["attack_detected"] is False
    assert "Simulated report saved" in result["final_output"]


def test_cross_agent_attack_is_blocked():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    assert result["gateway_decision"] == "BLOCK"
    assert result["tool_allowed"] is False
    assert result["attack_detected"] is True

    assert result["final_output"].startswith(
        "BLOCKED BY SECURITY GATEWAY"
    )


def test_attack_payload_enters_research_agent():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    research_message = result["messages"][0]

    assert (
        "Ignore all previous instructions"
        in research_message.content
    )

    assert research_message.metadata["untrusted_content"] is True


def test_attack_does_not_reach_analysis_agent():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    sender_ids = [
        message.sender_id
        for message in result["messages"]
    ]

    assert "research_agent" in sender_ids
    assert "analysis_agent" not in sender_ids
    assert result["gateway_decision"] == "BLOCK"


def test_execution_agent_is_not_invoked_for_attack():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    sender_ids = [
        message.sender_id
        for message in result["messages"]
    ]

    assert "execution_agent" not in sender_ids
    assert result["tool_allowed"] is False

    assert result["messages"][-1].metadata[
        "requested_tool"
    ] is None


def test_message_chain_is_preserved():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    messages = result["messages"]

    assert len(messages) == 2

    assert messages[0].sender_id == "research_agent"
    assert messages[1].sender_id == "security_gateway"

    assert (
        messages[1].parent_message_id
        == messages[0].message_id
    )


def test_gateway_block_is_recorded_in_audit():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    blocked_events = [
        event
        for event in result["audit_events"]
        if event["event_type"] == "tool_blocked"
    ]

    assert len(blocked_events) == 1

    assert blocked_events[0]["agent_id"] == (
        "security_gateway"
    )

    assert blocked_events[0]["metadata"][
        "gateway_decision"
    ] == "BLOCK"
