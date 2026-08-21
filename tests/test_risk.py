from dataclasses import FrozenInstanceError

import pytest

from sentinelflow.models.risk import RiskAssessment, RiskSeverity


def test_risk_severity_values():
    assert RiskSeverity.LOW.value == "LOW"
    assert RiskSeverity.MEDIUM.value == "MEDIUM"
    assert RiskSeverity.HIGH.value == "HIGH"
    assert RiskSeverity.CRITICAL.value == "CRITICAL"


def test_risk_assessment_stores_values():
    assessment = RiskAssessment(
        indicator="9.9.9.9",
        score=80,
        severity=RiskSeverity.HIGH,
        confidence=90,
        reasons=(
            "Simulated reason",
        ),
    )

    assert assessment.indicator == "9.9.9.9"
    assert assessment.score == 80
    assert assessment.severity == RiskSeverity.HIGH
    assert assessment.confidence == 90
    assert assessment.reasons == (
        "Simulated reason",
    )


def test_risk_assessment_supports_multiple_reasons():
    assessment = RiskAssessment(
        indicator="9.9.9.9",
        score=80,
        severity=RiskSeverity.HIGH,
        confidence=90,
        reasons=(
            "First reason",
            "Second reason",
        ),
    )

    assert len(assessment.reasons) == 2
    assert assessment.reasons[0] == "First reason"
    assert assessment.reasons[1] == "Second reason"


def test_risk_assessment_supports_no_reasons():
    assessment = RiskAssessment(
        indicator="9.9.9.9",
        score=0,
        severity=RiskSeverity.LOW,
        confidence=0,
        reasons=(),
    )

    assert assessment.reasons == ()


def test_risk_assessment_is_immutable():
    assessment = RiskAssessment(
        indicator="9.9.9.9",
        score=80,
        severity=RiskSeverity.HIGH,
        confidence=90,
        reasons=(),
    )

    with pytest.raises(FrozenInstanceError):
        assessment.score = 100
        

def test_risk_assessment_normalizes_indicator_whitespace():
    assessment = RiskAssessment(
        indicator="   9.9.9.9   ",
        score=80,
        severity=RiskSeverity.HIGH,
        confidence=90,
        reasons=(),
    )

    assert assessment.indicator == "9.9.9.9"
    

def test_risk_assessment_rejects_empty_indicator():
    with pytest.raises(
        ValueError,
        match="Risk assessment indicator cannot be empty",
    ):
        RiskAssessment(
            indicator="",
            score=80,
            severity=RiskSeverity.HIGH,
            confidence=90,
            reasons=(),
        )
        

def test_risk_assessment_rejects_whitespace_indicator():
    with pytest.raises(
        ValueError,
        match="Risk assessment indicator cannot be empty",
    ):
        RiskAssessment(
            indicator="   ",
            score=80,
            severity=RiskSeverity.HIGH,
            confidence=90,
            reasons=(),
        )
        

def test_risk_assessment_accepts_zero_score():
    assessment = RiskAssessment(
        indicator="9.9.9.9",
        score=0,
        severity=RiskSeverity.LOW,
        confidence=90,
        reasons=(),
    )

    assert assessment.score == 0
    
    
def test_risk_assessment_accepts_score_100():
    assessment = RiskAssessment(
        indicator="9.9.9.9",
        score=100,
        severity=RiskSeverity.CRITICAL,
        confidence=90,
        reasons=(),
    )

    assert assessment.score == 100
    

def test_risk_assessment_rejects_negative_score():
    with pytest.raises(
        ValueError,
        match="Risk score must be between 0 and 100",
    ):
        RiskAssessment(
            indicator="9.9.9.9",
            score=-1,
            severity=RiskSeverity.LOW,
            confidence=90,
            reasons=(),
        )
        

def test_risk_assessment_rejects_score_above_100():
    with pytest.raises(
        ValueError,
        match="Risk score must be between 0 and 100",
    ):
        RiskAssessment(
            indicator="9.9.9.9",
            score=101,
            severity=RiskSeverity.CRITICAL,
            confidence=90,
            reasons=(),
        )
        

def test_risk_assessment_rejects_non_integer_score():
    with pytest.raises(
        TypeError,
        match="Risk score must be an integer",
    ):
        RiskAssessment(
            indicator="9.9.9.9",
            score=80.5,
            severity=RiskSeverity.HIGH,
            confidence=90,
            reasons=(),
        )
        

def test_risk_assessment_accepts_zero_confidence():
    assessment = RiskAssessment(
        indicator="9.9.9.9",
        score=50,
        severity=RiskSeverity.MEDIUM,
        confidence=0,
        reasons=(),
    )

    assert assessment.confidence == 0
    
    
def test_risk_assessment_accepts_confidence_100():
    assessment = RiskAssessment(
        indicator="9.9.9.9",
        score=50,
        severity=RiskSeverity.MEDIUM,
        confidence=100,
        reasons=(),
    )

    assert assessment.confidence == 100
    

def test_risk_assessment_rejects_negative_confidence():
    with pytest.raises(
        ValueError,
        match="Risk confidence must be between 0 and 100",
    ):
        RiskAssessment(
            indicator="9.9.9.9",
            score=50,
            severity=RiskSeverity.MEDIUM,
            confidence=-1,
            reasons=(),
        )
        
    
def test_risk_assessment_rejects_confidence_above_100():
    with pytest.raises(
        ValueError,
        match="Risk confidence must be between 0 and 100",
    ):
        RiskAssessment(
            indicator="9.9.9.9",
            score=50,
            severity=RiskSeverity.MEDIUM,
            confidence=101,
            reasons=(),
        )
        

def test_risk_assessment_rejects_non_integer_confidence():
    with pytest.raises(
        TypeError,
        match="Risk confidence must be an integer",
    ):
        RiskAssessment(
            indicator="9.9.9.9",
            score=50,
            severity=RiskSeverity.MEDIUM,
            confidence=90.5,
            reasons=(),
        )
        

