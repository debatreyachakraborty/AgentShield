
import pytest

from backend.app.attacks.evaluation.evaluator import (
    AttackEvaluator,
    EvaluationCase,
)


def test_detection_and_false_positive_rates():
    cases = [
        EvaluationCase("attack_1", True, True),
        EvaluationCase("attack_2", True, True),
        EvaluationCase("attack_3", True, False),
        EvaluationCase("benign_1", False, False),
        EvaluationCase("benign_2", False, True),
    ]

    result = AttackEvaluator().evaluate(cases)

    assert result["total_cases"] == 5
    assert result["attack_cases"] == 3
    assert result["benign_cases"] == 2

    assert result["true_positives"] == 2
    assert result["false_negatives"] == 1
    assert result["false_positives"] == 1
    assert result["true_negatives"] == 1

    assert result["detection_rate"] == pytest.approx(2 / 3)
    assert result["false_positive_rate"] == pytest.approx(0.5)


def test_attack_success_and_prevention_rates():
    cases = [
        EvaluationCase("attack_1", True, True, True, False),
        EvaluationCase("attack_2", True, False, True, True),
        EvaluationCase("attack_3", True, True, False, False),
        EvaluationCase("benign_1", False, False),
    ]

    result = AttackEvaluator().evaluate(cases)

    assert result["attack_attempt_rate"] == pytest.approx(2 / 3)
    assert result["attack_success_rate"] == pytest.approx(1 / 3)
    assert result["prevention_rate"] == pytest.approx(0.5)


def test_empty_dataset_is_rejected():
    with pytest.raises(ValueError, match="At least one"):
        AttackEvaluator().evaluate([])


def test_duplicate_case_ids_are_rejected():
    cases = [
        EvaluationCase("case_1", True, True),
        EvaluationCase("case_1", False, False),
    ]

    with pytest.raises(ValueError, match="unique"):
        AttackEvaluator().evaluate(cases)


def test_success_without_attempt_is_rejected():
    cases = [
        EvaluationCase(
            case_id="attack_1",
            is_attack=True,
            detected=True,
            attempted_unauthorized_action=False,
            unauthorized_action_succeeded=True,
        )
    ]

    with pytest.raises(ValueError, match="without being attempted"):
        AttackEvaluator().evaluate(cases)


def test_no_attack_cases_returns_undefined_attack_metrics():
    cases = [
        EvaluationCase("benign_1", False, False),
        EvaluationCase("benign_2", False, True),
    ]

    result = AttackEvaluator().evaluate(cases)

    assert result["detection_rate"] is None
    assert result["attack_attempt_rate"] is None
    assert result["attack_success_rate"] is None
    assert result["prevention_rate"] is None
    assert result["false_positive_rate"] == pytest.approx(0.5)


def test_no_benign_cases_returns_undefined_false_positive_rate():
    cases = [
        EvaluationCase("attack_1", True, True),
        EvaluationCase("attack_2", True, False),
    ]

    result = AttackEvaluator().evaluate(cases)

    assert result["detection_rate"] == pytest.approx(0.5)
    assert result["false_positive_rate"] is None


def test_no_unauthorized_attempts_returns_undefined_prevention_rate():
    cases = [
        EvaluationCase("attack_1", True, True),
        EvaluationCase("attack_2", True, False),
    ]

    result = AttackEvaluator().evaluate(cases)

    assert result["attack_attempt_rate"] is None
    assert result["attack_success_rate"] is None
    assert result["prevention_rate"] is None

def test_unmeasured_attack_outcomes_are_not_reported_as_zero():
    cases = [
        EvaluationCase(
            case_id="attack_1",
            is_attack=True,
            detected=True,
        ),
        EvaluationCase(
            case_id="attack_2",
            is_attack=True,
            detected=False,
        ),
    ]

    result = AttackEvaluator().evaluate(cases)

    assert result["detection_rate"] == pytest.approx(0.5)

    # No execution outcomes were actually measured.
    assert result["attack_attempt_rate"] is None
    assert result["attack_success_rate"] is None
    assert result["prevention_rate"] is None

def test_observed_zero_attempts_report_zero_rate():
    cases = [
        EvaluationCase(
            case_id="attack_1",
            is_attack=True,
            detected=True,
            attempted_unauthorized_action=False,
            unauthorized_action_succeeded=False,
        ),
        EvaluationCase(
            case_id="attack_2",
            is_attack=True,
            detected=False,
            attempted_unauthorized_action=False,
            unauthorized_action_succeeded=False,
        ),
    ]

    result = AttackEvaluator().evaluate(cases)

    assert result["attack_attempt_rate"] == 0.0
    assert result["attack_success_rate"] == 0.0
    assert result["prevention_rate"] is None

def test_attack_outcome_observation_coverage():
    cases = [
        EvaluationCase(
            case_id="attack_1",
            is_attack=True,
            detected=True,
            attempted_unauthorized_action=True,
            unauthorized_action_succeeded=False,
        ),
        EvaluationCase(
            case_id="attack_2",
            is_attack=True,
            detected=False,
        ),
        EvaluationCase(
            case_id="attack_3",
            is_attack=True,
            detected=True,
            attempted_unauthorized_action=False,
        ),
    ]

    result = AttackEvaluator().evaluate(cases)

    assert result["attack_cases"] == 3
    assert result["observed_attempt_cases"] == 2
    assert result["observed_success_cases"] == 1

    assert result["attempt_observation_coverage"] == pytest.approx(2 / 3)
    assert result["success_observation_coverage"] == pytest.approx(1 / 3)

def test_simulated_attack_outcome_is_evaluated():
    from backend.app.attacks.simulator import (
        simulate_unauthorized_tool_attack,
    )

    simulation = simulate_unauthorized_tool_attack()

    case = EvaluationCase(
        case_id="simulated_unauthorized_deletion",
        is_attack=True,
        detected=simulation.blocked,
        attempted_unauthorized_action=True,
        unauthorized_action_succeeded=simulation.tool_executed,
    )

    result = AttackEvaluator().evaluate([case])

    assert result["attack_attempt_rate"] == 1.0
    assert result["attack_success_rate"] == 0.0
    assert result["prevention_rate"] == 1.0
    assert result["attempt_observation_coverage"] == 1.0
    assert result["success_observation_coverage"] == 1.0