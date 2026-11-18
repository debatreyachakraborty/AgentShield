
from backend.app.orchestration.workflow import run_workflow


def test_normal_workflow_provenance():
    result = run_workflow("Research AI security")

    chain = result["provenance_chain"]

    assert len(chain) == 3

    assert [record["sender_id"] for record in chain] == [
        "research_agent",
        "analysis_agent",
        "execution_agent",
    ]

    assert result["untrusted_message_count"] == 0


def test_attack_workflow_provenance():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    chain = result["provenance_chain"]

    assert result["gateway_decision"] == "BLOCK"
    assert len(chain) == 2
    assert result["untrusted_message_count"] == 2

    assert [record["sender_id"] for record in chain] == [
        "research_agent",
        "security_gateway",
    ]

    assert all(
        record["is_untrusted"]
        for record in chain
    )


def test_attack_origin_is_research_agent():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    chain = result["provenance_chain"]

    origin_id = chain[0]["message_id"]

    assert chain[0]["sender_id"] == "research_agent"

    assert all(
        record["origin_message_id"] == origin_id
        for record in chain
    )


def test_provenance_parent_chain_is_preserved():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    chain = result["provenance_chain"]

    assert len(chain) == 2

    assert chain[0]["parent_message_id"] is None

    assert (
        chain[1]["parent_message_id"]
        == chain[0]["message_id"]
    )


def test_blocked_message_preserves_research_origin():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    messages = result["messages"]

    assert len(messages) == 2

    research_message = messages[0]
    gateway_message = messages[1]

    assert research_message.sender_id == "research_agent"
    assert gateway_message.sender_id == "security_gateway"

    assert (
        gateway_message.parent_message_id
        == research_message.message_id
    )


def test_untrusted_content_is_not_executed():
    result = run_workflow(
        "Analyze security threats",
        attack_scenario_id="attack_001",
    )

    chain = result["provenance_chain"]

    assert result["gateway_decision"] == "BLOCK"
    assert result["tool_allowed"] is False

    assert all(
        record["sender_id"] != "execution_agent"
        for record in chain
    )
