
import pytest

from backend.app.attacks.evaluation.benchmark import BenchmarkCase
from backend.app.attacks.evaluation.comparative_benchmark import (
    evaluate_detector,
)


@pytest.fixture
def sample_cases():
    return [
        BenchmarkCase(
            case_id="ATTACK_001",
            payload="malicious instruction",
            is_attack=True,
            category="attack",
        ),
        BenchmarkCase(
            case_id="BENIGN_001",
            payload="normal request",
            is_attack=False,
            category="benign",
        ),
    ]


def test_correct_classifications(sample_cases):
    def detector(text):
        return text == "malicious instruction"

    result = evaluate_detector(
        "test_detector",
        sample_cases,
        detector,
    )

    assert result["total_cases"] == 2
    assert result["evaluated_cases"] == 2
    assert result["error_count"] == 0

    assert result["metrics"]["true_positives"] == 1
    assert result["metrics"]["true_negatives"] == 1
    assert result["metrics"]["false_positives"] == 0
    assert result["metrics"]["false_negatives"] == 0


def test_incorrect_classifications(sample_cases):
    result = evaluate_detector(
        "always_allow",
        sample_cases,
        lambda text: False,
    )

    assert result["metrics"]["false_negatives"] == 1
    assert result["metrics"]["true_negatives"] == 1
    assert result["metrics"]["detection_rate"] == 0.0


def test_detector_exception_is_recorded(sample_cases):
    def failing_detector(text):
        raise RuntimeError("Detector unavailable")

    result = evaluate_detector(
        "failing_detector",
        sample_cases,
        failing_detector,
    )

    assert result["total_cases"] == 2
    assert result["evaluated_cases"] == 0
    assert result["error_count"] == 2
    assert result["metrics"] is None

    assert all(
        run["error"] == "RuntimeError"
        for run in result["runs"]
    )


def test_partial_detector_failure(sample_cases):
    def detector(text):
        if text == "malicious instruction":
            raise TimeoutError("Classification timed out")
        return False

    result = evaluate_detector(
        "partial_failure",
        sample_cases,
        detector,
    )

    assert result["evaluated_cases"] == 1
    assert result["error_count"] == 1
    assert result["metrics"]["total_cases"] == 1
    assert result["metrics"]["true_negatives"] == 1
    assert result["runs"][0]["error"] == "TimeoutError"


def test_non_boolean_detector_output_is_rejected(sample_cases):
    result = evaluate_detector(
        "invalid_detector",
        sample_cases,
        lambda text: "BLOCK",
    )

    assert result["error_count"] == 2
    assert result["metrics"] is None
    assert all(
        run["error"] == "TypeError"
        for run in result["runs"]
    )
