
from backend.app.models.agent import ToolPermission
from backend.app.orchestration.workflow import run_workflow


def test_normal_workflow_is_allowed():
    result = run_workflow("Research AI security")

    assert result["tool_allowed"] is True
    assert result["attack_detected"] is False
    assert "Simulated report saved" in result["final_output"]


def test_cross_agent_attack_is_blocked():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    assert result["tool_allowed"] is False
    assert result["attack_detected"] is True
    assert result["final_output"].startswith("BLOCKED:")


def test_attack_payload_enters_research_agent():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    research_message = result["messages"][0]

    assert "Ignore all previous instructions" in research_message.content
    assert research_message.metadata["untrusted_content"] is True


def test_attack_propagates_to_analysis_agent():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    research_message = result["messages"][0]
    analysis_message = result["messages"][1]

    assert "Ignore all previous instructions" in analysis_message.content

    assert (
        analysis_message.parent_message_id
        == research_message.message_id
    )

    assert (
        analysis_message.metadata["inherited_untrusted_content"]
        is True
    )


def test_execution_agent_requests_unauthorized_tool():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    execution_message = result["messages"][2]

    assert (
        execution_message.metadata["requested_tool"]
        == ToolPermission.DELETE_FILE.value
    )

    assert execution_message.metadata["tool_allowed"] is False


def test_message_chain_is_preserved():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    messages = result["messages"]

    assert len(messages) == 3

    assert messages[1].parent_message_id == messages[0].message_id
    assert messages[2].parent_message_id == messages[1].message_id
