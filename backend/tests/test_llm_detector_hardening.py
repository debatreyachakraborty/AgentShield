
import json
from unittest.mock import Mock, patch

import pytest
import requests

from backend.app.security.detection.llm_detector import (
    LLMThreatDetector,
    MAX_CONTENT_LENGTH,
)
from backend.app.security.hybrid_gateway import (
    HybridSecurityGateway,
    SecurityDecision,
)


def mock_ollama_response(content):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "message": {
            "content": content,
        }
    }
    return response


def valid_classifier_output():
    return {
        "suspicious": False,
        "confidence": 0.95,
        "reasoning": "Normal research content.",
        "categories": ["benign"],
    }


@patch("backend.app.security.detection.llm_detector.requests.post")
def test_valid_response_is_accepted(mock_post):
    mock_post.return_value = mock_ollama_response(
        json.dumps(valid_classifier_output())
    )

    result = LLMThreatDetector().assess("Normal research summary.")

    assert result.suspicious is False
    assert result.confidence == 0.95


@patch("backend.app.security.detection.llm_detector.requests.post")
def test_malformed_json_is_rejected(mock_post):
    mock_post.return_value = mock_ollama_response(
        "This is not JSON"
    )

    with pytest.raises(ValueError):
        LLMThreatDetector().assess("Research summary.")


@pytest.mark.parametrize(
    "confidence",
    [
        -0.1,
        1.1,
        True,
        "high",
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
@patch("backend.app.security.detection.llm_detector.requests.post")
def test_invalid_confidence_is_rejected(mock_post, confidence):
    output = valid_classifier_output()
    output["confidence"] = confidence

    mock_post.return_value = mock_ollama_response(
        json.dumps(output)
    )

    with pytest.raises(ValueError):
        LLMThreatDetector().assess("Research summary.")


@patch("backend.app.security.detection.llm_detector.requests.post")
def test_empty_reasoning_is_rejected(mock_post):
    output = valid_classifier_output()
    output["reasoning"] = "   "

    mock_post.return_value = mock_ollama_response(
        json.dumps(output)
    )

    with pytest.raises(ValueError):
        LLMThreatDetector().assess("Research summary.")


@patch("backend.app.security.detection.llm_detector.requests.post")
def test_empty_category_is_rejected(mock_post):
    output = valid_classifier_output()
    output["categories"] = [""]

    mock_post.return_value = mock_ollama_response(
        json.dumps(output)
    )

    with pytest.raises(ValueError):
        LLMThreatDetector().assess("Research summary.")


@patch("backend.app.security.detection.llm_detector.requests.post")
def test_oversized_input_is_rejected(mock_post):
    content = "A" * (MAX_CONTENT_LENGTH + 1)

    with pytest.raises(ValueError):
        LLMThreatDetector().assess(content)

    mock_post.assert_not_called()


@patch("backend.app.security.detection.llm_detector.requests.post")
def test_timeout_causes_gateway_error(mock_post):
    mock_post.side_effect = requests.Timeout(
        "Simulated Ollama timeout"
    )

    gateway = HybridSecurityGateway(
        llm_detector=LLMThreatDetector(timeout=1)
    )

    result = gateway.evaluate("Normal research summary.")

    assert result.decision == SecurityDecision.ERROR
    assert result.llm_detected is None


@patch("backend.app.security.detection.llm_detector.requests.post")
def test_malformed_json_causes_gateway_error(mock_post):
    mock_post.return_value = mock_ollama_response(
        "Invalid JSON"
    )

    gateway = HybridSecurityGateway(
        llm_detector=LLMThreatDetector()
    )

    result = gateway.evaluate("Normal research summary.")

    assert result.decision == SecurityDecision.ERROR
    assert result.llm_detected is None
