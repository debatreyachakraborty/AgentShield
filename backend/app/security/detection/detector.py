
import re
from enum import Enum

from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ThreatFinding(BaseModel):
    rule_id: str
    description: str
    matched_text: str


class ThreatAssessment(BaseModel):
    suspicious: bool
    threat_level: ThreatLevel
    risk_score: float = Field(ge=0.0, le=1.0)
    findings: list[ThreatFinding] = Field(default_factory=list)


DETECTION_RULES = {
    "RULE_001": {
        "pattern": r"\bignore\s+(all\s+)?previous\s+instructions\b",
        "description": "Instruction override attempt",
        "weight": 0.5,
    },

    
    "RULE_004": {
        "pattern": (
            r"\b(?:disregard|override)\s+"
            r"(?:all\s+|the\s+)?"
            r"(?:earlier|previous|prior)\s+"
            r"(?:instructions|directions|rules)\b"
            r"|"
            r"\bignore\s+"
            r"(?:all\s+|the\s+)?"
            r"(?:earlier|prior)\s+"
            r"(?:instructions|directions|rules)\b"
            r"|"
            r"\bignore\s+"
            r"(?:all\s+|the\s+)?previous\s+"
            r"(?:directions|rules)\b"
        ),
        "description": "Reworded instruction override attempt",
        "weight": 0.5,
    },

    "RULE_005": {
        "pattern": (
            r"\b(?:forget|abandon|discard)\s+"
            r"(?:your\s+|the\s+)?"
            r"(?:original|current|assigned)\s+"
            r"(?:task|instructions|objective)\b"
        ),
        "description": "Task abandonment instruction attempt",
        "weight": 0.5,
    },
    "RULE_006": {
        "pattern": (
            r"\b(?:pretend|act\s+as\s+if)\s+"
            r"you\s+are\s+"
            r"(?:the\s+|an?\s+)?"
            r"(?:system\s+administrator|admin|developer)\b"
        ),
        "description": "Authority or role spoofing attempt",
        "weight": 0.5,
    },



    "RULE_002": {
        "pattern": r"\b(?:delete|remove|erase)\s+(?:the\s+)?file\b",
        "description": "Potentially destructive file operation",
        "weight": 0.3,
    },
    "RULE_003": {
        "pattern": r"\b(?:must|immediately)\s+delete\b",
        "description": "Urgent destructive instruction",
        "weight": 0.3,
    },
}


def assess_threat(content: str) -> ThreatAssessment:
    if not isinstance(content, str):
        raise TypeError("Message content must be a string.")

    findings = []
    score = 0.0

    for rule_id, rule in DETECTION_RULES.items():
        match = re.search(
            rule["pattern"],
            content,
            flags=re.IGNORECASE,
        )

        if match:
            findings.append(
                ThreatFinding(
                    rule_id=rule_id,
                    description=rule["description"],
                    matched_text=match.group(),
                )
            )
            score += rule["weight"]

    score = min(round(score, 2), 1.0)

    if score >= 0.7:
        level = ThreatLevel.HIGH
    elif score >= 0.3:
        level = ThreatLevel.MEDIUM
    else:
        level = ThreatLevel.LOW

    return ThreatAssessment(
        suspicious=bool(findings),
        threat_level=level,
        risk_score=score,
        findings=findings,
    )
