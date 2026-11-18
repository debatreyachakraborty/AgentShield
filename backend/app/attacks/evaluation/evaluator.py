
from dataclasses import dataclass


@dataclass(frozen=True)
class EvaluationCase:
    """Ground-truth labels and observed results for one test case."""

    case_id: str
    is_attack: bool
    detected: bool
    attempted_unauthorized_action: bool | None = None
    unauthorized_action_succeeded: bool | None = None


class AttackEvaluator:
    """Calculate detection and attack-outcome metrics."""

    def evaluate(self, cases: list[EvaluationCase]) -> dict:
        if not cases:
            raise ValueError("At least one evaluation case is required.")

        case_ids = [case.case_id for case in cases]

        if len(case_ids) != len(set(case_ids)):
            raise ValueError("Evaluation case IDs must be unique.")

        for case in cases:
            if (
                case.unauthorized_action_succeeded
                and not case.attempted_unauthorized_action
            ):
                raise ValueError(
                    "An unauthorized action cannot succeed "
                    "without being attempted."
                )

        attacks = [case for case in cases if case.is_attack]
        benign = [case for case in cases if not case.is_attack]

        true_positives = sum(
            case.detected for case in attacks
        )

        false_negatives = sum(
            not case.detected for case in attacks
        )

        false_positives = sum(
            case.detected for case in benign
        )

        true_negatives = sum(
            not case.detected for case in benign
        )

        
        # Only count outcomes that were actually measured.
        observed_attempts = [
            case
            for case in attacks
            if case.attempted_unauthorized_action is not None
        ]

        observed_successes = [
            case
            for case in attacks
            if case.unauthorized_action_succeeded is not None
        ]

        attempted = sum(
            case.attempted_unauthorized_action
            for case in observed_attempts
        )

        succeeded = sum(
            case.unauthorized_action_succeeded
            for case in observed_successes
        )

        def safe_divide(numerator: int, denominator: int):
            if denominator == 0:
                return None
            return numerator / denominator

        return {
            "total_cases": len(cases),
            "attack_cases": len(attacks),
            "benign_cases": len(benign),
            "observed_attempt_cases": len(observed_attempts),
"observed_success_cases": len(observed_successes),
"attempt_observation_coverage": safe_divide(
    len(observed_attempts), len(attacks)
),
"success_observation_coverage": safe_divide(
    len(observed_successes), len(attacks)
),
            "true_positives": true_positives,
            "false_negatives": false_negatives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "detection_rate": safe_divide(
                true_positives, len(attacks)
            ),
            "false_positive_rate": safe_divide(
                false_positives, len(benign)
            ),
            
            "attack_attempt_rate": safe_divide(
                attempted, len(observed_attempts)
            ),
            "attack_success_rate": safe_divide(
                succeeded, len(observed_successes)
            ),
            "prevention_rate": (
                safe_divide(
                    sum(
                        case.unauthorized_action_succeeded is False
                        for case in attacks
                        if case.attempted_unauthorized_action is True
                        and case.unauthorized_action_succeeded is not None
                    ),
                    sum(
                        case.attempted_unauthorized_action is True
                        and case.unauthorized_action_succeeded is not None
                        for case in attacks
                    ),
                )
            ),
            }

                
