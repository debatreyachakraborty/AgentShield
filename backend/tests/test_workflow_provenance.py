
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

    assert len(chain) == 3
    assert result["untrusted_message_count"] == 3

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

    assert chain[0]["parent_message_id"] is None

    assert (
        chain[1]["parent_message_id"]
        == chain[0]["message_id"]
    )

    assert (
        chain[2]["parent_message_id"]
        == chain[1]["message_id"]
    )
