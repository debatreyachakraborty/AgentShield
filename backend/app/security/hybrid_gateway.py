
from dataclasses import dataclass
from enum import Enum

from backend.app.security.detection.detector import assess_threat
from backend.app.security.detection.llm_detector import LLMThreatDetector


class SecurityDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    ERROR = "ERROR"


@dataclass(frozen=True)
class GatewayResult:
    decision: SecurityDecision
    reason: str
    rule_detected: bool
    llm_detected: bool | None


class HybridSecurityGateway:
    def __init__(self, llm_detector=None):
        self.llm_detector = (
            llm_detector
            if llm_detector is not None
            else LLMThreatDetector()
        )

    def evaluate(self, content: str) -> GatewayResult:
        if not isinstance(content, str) or not content.strip():
            return GatewayResult(
                decision=SecurityDecision.ERROR,
                reason="Invalid or empty input.",
                rule_detected=False,
                llm_detected=None,
            )

        # Layer 1: Deterministic detection.
        rule_result = assess_threat(content)

        # Layer 2: LLM classification.
        try:
            llm_result = self.llm_detector.assess(content)
            if not isinstance(llm_result.suspicious, bool):
                raise TypeError(
                    "LLM suspicious result must be boolean."
                )
        except Exception:
            # Fail closed if LLM classification fails.
            return GatewayResult(
                decision=SecurityDecision.ERROR,
                reason="LLM security classification failed.",
                rule_detected=rule_result.suspicious,
                llm_detected=None,
            )

        rule_detected = rule_result.suspicious
        llm_detected = llm_result.suspicious

        # Both detectors identify suspicious content.
        if rule_detected and llm_detected:
            return GatewayResult(
                decision=SecurityDecision.BLOCK,
                reason="Both security detectors flagged the content.",
                rule_detected=True,
                llm_detected=True,
            )

        # LLM identifies an attack missed by deterministic rules.
        if llm_detected:
            return GatewayResult(
                decision=SecurityDecision.BLOCK,
                reason="LLM security detector flagged the content.",
                rule_detected=False,
                llm_detected=True,
            )

        # Deterministic detector flags content but LLM disagrees.
        # REVIEW must never authorize execution.
        if rule_detected:
            return GatewayResult(
                decision=SecurityDecision.REVIEW,
                reason="Security detectors disagree; manual review required.",
                rule_detected=True,
                llm_detected=False,
            )

        return GatewayResult(
            decision=SecurityDecision.ALLOW,
            reason="No suspicious instructions detected.",
            rule_detected=False,
            llm_detected=False,
        )
