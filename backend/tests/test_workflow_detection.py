
from backend.app.orchestration.workflow import run_workflow


def test_normal_workflow_has_no_threat():
    result = run_workflow("Research AI security")

    assert result["threat_detected"] is False
    assert result["threat_score"] == 0.0


def test_attack_workflow_detects_threat():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    assert result["threat_detected"] is True
    assert result["threat_score"] >= 0.7


def test_detection_evidence_is_recorded():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    analysis_message = result["messages"][1]

    assert analysis_message.metadata["threat_detected"] is True
    assert analysis_message.metadata["threat_level"] == "high"
    assert "RULE_001" in analysis_message.metadata["matched_rules"]


def test_detection_does_not_replace_permissions():
    result = run_workflow(
        "Research AI security",
        attack_scenario_id="attack_001",
    )

    assert result["threat_detected"] is True
    assert result["tool_allowed"] is False
    assert result["final_output"].startswith("BLOCKED:")
