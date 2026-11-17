
import re
from dataclasses import dataclass, field


@dataclass
class ContextDetectionResult:
    suspicious: bool
    risk_score: float
    findings: list[str] = field(default_factory=list)


# These patterns identify suspicious intent indicators.
# They are heuristics, not a trained machine-learning model.

INTENT_PATTERNS = {
    "instruction_redirection": [
        r"\binstructions?\s+(?:above|earlier)\s+are\s+(?:outdated|invalid)",
        r"\bfollow\s+(?:this|these)\s+new\s+(?:directive|instructions?)",
        r"\btreat\s+(?:this|the)\s+document\s+as\s+"
        r"(?:the\s+)?highest.priority\s+instruction",
    ],
    "authority_claim": [
        r"\b(?:developer|administrator|system)\s+mode\b",
        r"\byou\s+are\s+now\s+operating\s+in\b",
    ],
    "sensitive_data_request": [
        r"\breveal\s+(?:your\s+)?hidden\s+(?:configuration|instructions?)",
        r"\bsend\s+(?:the\s+)?contents\s+of\b",
    ],
    "security_bypass": [
        r"\bskip\s+(?:verification|security\s+checks?)\b",
        r"\bsecurity\s+checks?\s+have\s+already\s+been\s+completed\b",
    ],
}


def assess_context(content: str) -> ContextDetectionResult:
    if not isinstance(content, str):
        raise TypeError("content must be a string")

    if not content.strip():
        return ContextDetectionResult(
            suspicious=False,
            risk_score=0.0,
        )

    findings = []

    for category, patterns in INTENT_PATTERNS.items():
        if any(
            re.search(pattern, content, flags=re.IGNORECASE)
            for pattern in patterns
        ):
            findings.append(category)

    # Preliminary heuristic score.
    # It is not a calibrated probability.
    risk_score = min(len(findings) * 0.5, 1.0)

    return ContextDetectionResult(
        suspicious=risk_score >= 0.5,
        risk_score=risk_score,
        findings=findings,
    )
