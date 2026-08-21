from dataclasses import dataclass
from enum import Enum


class RiskSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class RiskAssessment:
    indicator: str
    score: int
    severity: RiskSeverity
    confidence: int
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        normalized_indicator = self.indicator.strip()

        if not normalized_indicator:
            raise ValueError(
                "Risk assessment indicator cannot be empty"
            )

        if type(self.score) is not int:
            raise TypeError(
                "Risk score must be an integer"
            )

        if not 0 <= self.score <= 100:
            raise ValueError(
                "Risk score must be between 0 and 100"
            )

        if type(self.confidence) is not int:
            raise TypeError(
                "Risk confidence must be an integer"
            )

        if not 0 <= self.confidence <= 100:
            raise ValueError(
                "Risk confidence must be between 0 and 100"
            )

        object.__setattr__(
            self,
            "indicator",
            normalized_indicator,
        )
        

def test_risk_assessment_rejects_boolean_score():
    with pytest.raises(
        TypeError,
        match="Risk score must be an integer",
    ):
        RiskAssessment(
            indicator="9.9.9.9",
            score=True,
            severity=RiskSeverity.LOW,
            confidence=90,
            reasons=(),
        )
        

def test_risk_assessment_rejects_boolean_confidence():
    with pytest.raises(
        TypeError,
        match="Risk confidence must be an integer",
    ):
        RiskAssessment(
            indicator="9.9.9.9",
            score=50,
            severity=RiskSeverity.MEDIUM,
            confidence=False,
            reasons=(),
        )