
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from backend.app.orchestration.workflow import run_workflow


def fake_generate(self, prompt, system_prompt):
    return "This is a safe research summary."


def fake_assessment(suspicious):
    return SimpleNamespace(
        suspicious=suspicious
    )


@patch(
    "backend.app.orchestration.workflow.OllamaClient.generate",
    new=fake_generate,
)
@patch(
    "backend.app.security.hybrid_gateway.LLMThreatDetector.assess"
)
def test_hybrid_gateway_allows_safe_content(mock_assess):
    mock_assess.return_value = fake_assessment(False)

    result = run_workflow(
        "Summarize artificial intelligence research",
        use_llm=True,
    )

    assert result["gateway_decision"] == "ALLOW"
    assert result["tool_allowed"] is True
    assert result["final_output"]
    assert len(result["messages"]) == 3


@patch(
    "backend.app.orchestration.workflow.OllamaClient.generate",
    new=fake_generate,
)
@patch(
    "backend.app.security.hybrid_gateway.LLMThreatDetector.assess"
)
def test_hybrid_gateway_blocks_llm_detected_attack(mock_assess):
    mock_assess.return_value = fake_assessment(True)

    result = run_workflow(
        "Summarize artificial intelligence research",
        use_llm=True,
    )

    assert result["gateway_decision"] == "BLOCK"
    assert result["tool_allowed"] is False
    assert len(result["messages"]) == 2

    assert all(
        message.sender_id != "execution_agent"
        for message in result["messages"]
    )


@patch(
    "backend.app.orchestration.workflow.OllamaClient.generate",
    new=fake_generate,
)
@patch(
    "backend.app.security.hybrid_gateway.LLMThreatDetector.assess"
)
def test_hybrid_gateway_fails_closed(mock_assess):
    mock_assess.side_effect = ConnectionError(
        "Ollama unavailable"
    )

    result = run_workflow(
        "Summarize artificial intelligence research",
        use_llm=True,
    )

    assert result["gateway_decision"] == "ERROR"
    assert result["tool_allowed"] is False
    assert len(result["messages"]) == 2

    assert all(
        message.sender_id != "execution_agent"
        for message in result["messages"]
    )


@patch(
    "backend.app.orchestration.workflow.OllamaClient.generate",
    new=fake_generate,
)
@patch(
    "backend.app.security.hybrid_gateway.LLMThreatDetector.assess"
)
def test_hybrid_gateway_block_is_audited(mock_assess):
    mock_assess.return_value = fake_assessment(True)

    result = run_workflow(
        "Summarize artificial intelligence research",
        use_llm=True,
    )

    blocked_events = [
        event
        for event in result["audit_events"]
        if event["event_type"] == "tool_blocked"
    ]

    assert len(blocked_events) == 1

    assert blocked_events[0]["metadata"][
        "gateway_decision"
    ] == "BLOCK"

@patch(
    "backend.app.orchestration.workflow.OllamaClient.generate",
    new=fake_generate,
)
@patch(
    "backend.app.security.hybrid_gateway.LLMThreatDetector.assess"
)
@patch(
    "backend.app.orchestration.workflow.assess_threat"
)
@patch(
    "backend.app.security.hybrid_gateway.assess_threat"
)
def test_review_prevents_execution_and_is_audited(
    mock_gateway_threat,
    mock_workflow_threat,
    mock_llm_assess,
):
    mock_gateway_threat.return_value = SimpleNamespace(
        suspicious=True,
        risk_score=0.8,
    )

    mock_workflow_threat.return_value = SimpleNamespace(
        suspicious=False,
        risk_score=0.0,
    )

    mock_llm_assess.return_value = fake_assessment(False)

    result = run_workflow(
        "Summarize artificial intelligence research",
        use_llm=True,
    )

    assert result["gateway_decision"] == "REVIEW"
    assert result["tool_allowed"] is False
    assert result["threat_detected"] is True

    assert all(
        message.sender_id not in (
            "analysis_agent",
            "execution_agent",
        )
        for message in result["messages"]
    )

    assert result["messages"][-1].sender_id == "security_gateway"

    blocked_events = [
        event
        for event in result["audit_events"]
        if event["event_type"] == "tool_blocked"
    ]

    assert len(blocked_events) == 1
    assert blocked_events[0]["metadata"]["gateway_decision"] == "REVIEW"
    assert blocked_events[0]["metadata"]["block_source"] == "security_gateway"


def test_permission_engine_blocks_attack_when_gateway_allows():
    from backend.app.security.hybrid_gateway import SecurityDecision

    with patch(
        "backend.app.orchestration.workflow.OllamaClient.generate",
        new=fake_generate,
    ), patch(
        "backend.app.orchestration.workflow.HybridSecurityGateway"
    ) as mock_gateway:

        mock_gateway.return_value.evaluate.return_value = (
            SimpleNamespace(
                decision=SecurityDecision.ALLOW,
                reason="Simulated false negative.",
            )
        )

        result = run_workflow(
            "Research AI security",
            attack_scenario_id="attack_001",
            use_llm=True,
        )

    assert result["gateway_decision"] == "ALLOW"
    assert result["tool_allowed"] is False
    assert result["final_output"].startswith("BLOCKED:")

    assert any(
        message.sender_id == "execution_agent"
        for message in result["messages"]
    )

    blocked_events = [
        event
        for event in result["audit_events"]
        if event["event_type"] == "tool_blocked"
    ]

    assert len(blocked_events) == 1
    assert blocked_events[0]["metadata"]["block_source"] == (
        "permission_engine"
    )