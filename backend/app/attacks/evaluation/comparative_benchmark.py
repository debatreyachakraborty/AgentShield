
from dataclasses import dataclass
from time import perf_counter
from typing import Callable

from backend.app.attacks.evaluation.benchmark import BenchmarkCase
from backend.app.attacks.evaluation.evaluator import (
    AttackEvaluator,
    EvaluationCase,
)

@dataclass(frozen=True)
class DetectorRun:
    case_id: str
    detected: bool | None
    latency_ms: float
    error: str | None = None

def evaluate_detector(
    name: str,
    cases: list[BenchmarkCase],
    detector: Callable[[str], bool],
) -> dict:
    """Evaluate a detector on labeled benchmark cases."""

    runs = []
    evaluation_cases = []

    for case in cases:
        start = perf_counter()

        try:
            detected = detector(case.payload)

            if not isinstance(detected, bool):
                raise TypeError("Detector must return a boolean.")

            error = None

        except Exception as exc:
            detected = None
            error = type(exc).__name__

        latency_ms = (perf_counter() - start) * 1000

        runs.append(
            DetectorRun(
                case_id=case.case_id,
                detected=detected,
                latency_ms=round(latency_ms, 3),
                error=error,
            )
        )

        if detected is not None:
            evaluation_cases.append(
                EvaluationCase(
                    case_id=case.case_id,
                    is_attack=case.is_attack,
                    detected=detected,
                )
            )

    metrics = (
        AttackEvaluator().evaluate(evaluation_cases)
        if evaluation_cases
        else None
    )

    return {
        "detector": name,
        "total_cases": len(cases),
        "evaluated_cases": len(evaluation_cases),
        "error_count": len(cases) - len(evaluation_cases),
        "metrics": metrics,
        "runs": [
            {
                "case_id": run.case_id,
                "detected": run.detected,
                "latency_ms": run.latency_ms,
                "error": run.error,
            }
            for run in runs
        ],
    }