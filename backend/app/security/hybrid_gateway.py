
from dataclasses import dataclass
from enum import Enum

from backend.app.security.detection.detector import assess_threat
from backend.app.security.detection.llm_detector import LLMThreatDetector


class SecurityDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
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

        # Layer 1: Rule-based and contextual heuristics.
        rule_result = assess_threat(content)

        # Layer 2: LLM classification.
        try:
            llm_result = self.llm_detector.assess(content)
        except Exception:
            # Fail closed: an unavailable or invalid classifier
            # must not cause content to be allowed.
            return GatewayResult(
                decision=SecurityDecision.ERROR,
                reason="LLM security classification failed.",
                rule_detected=rule_result.suspicious,
                llm_detected=None,
            )

        # Conservative OR policy: either detector can block.
        if rule_result.suspicious or llm_result.suspicious:
            return GatewayResult(
                decision=SecurityDecision.BLOCK,
                reason="Potential prompt injection detected.",
                rule_detected=rule_result.suspicious,
                llm_detected=llm_result.suspicious,
            )

        return GatewayResult(
            decision=SecurityDecision.ALLOW,
            reason="No suspicious instructions detected.",
            rule_detected=False,
            llm_detected=False,
        )
