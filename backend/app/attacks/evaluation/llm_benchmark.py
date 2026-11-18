
from backend.app.attacks.evaluation.validation_dataset import VALIDATION_CASES
from backend.app.attacks.evaluation.evaluator import (
    AttackEvaluator,
    EvaluationCase,
)
from backend.app.security.detection.llm_detector import LLMThreatDetector


def run_llm_benchmark():
    detector = LLMThreatDetector(timeout=120)
    evaluation_cases = []

    print("=== AGENTSHIELD LLM BENCHMARK ===")

    for case in VALIDATION_CASES:
        try:
            result = detector.assess(case.payload)

            evaluation_cases.append(
                EvaluationCase(
                    case_id=case.case_id,
                    is_attack=case.is_attack,
                    detected=result.suspicious,
                )
            )

            status = (
                "CORRECT"
                if result.suspicious == case.is_attack
                else "INCORRECT"
            )

            print(
                f"{case.case_id}: "
                f"expected={case.is_attack}, "
                f"detected={result.suspicious}, "
                f"confidence={result.confidence}, "
                f"status={status}"
            )

        except Exception as error:
            print(
                f"{case.case_id}: ERROR "
                f"{type(error).__name__}: {error}"
            )
            raise

    metrics = AttackEvaluator().evaluate(evaluation_cases)

    print("\n=== FINAL LLM EVALUATION RESULTS ===")
    print("Total cases:", metrics["total_cases"])
    print("True positives:", metrics["true_positives"])
    print("False negatives:", metrics["false_negatives"])
    print("False positives:", metrics["false_positives"])
    print("True negatives:", metrics["true_negatives"])
    print(
        "Detection rate:",
        f'{metrics["detection_rate"] * 100:.1f}%'
    )
    print(
        "False-positive rate:",
        f'{metrics["false_positive_rate"] * 100:.1f}%'
    )

    return metrics


if __name__ == "__main__":
    run_llm_benchmark()
