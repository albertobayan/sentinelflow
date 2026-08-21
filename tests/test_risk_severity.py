import pytest

from sentinelflow.models.risk import RiskSeverity
from sentinelflow.risk.severity import severity_from_score


def test_score_0_is_low():
    assert severity_from_score(0) == RiskSeverity.LOW


def test_score_24_is_low():
    assert severity_from_score(24) == RiskSeverity.LOW


def test_score_25_is_medium():
    assert severity_from_score(25) == RiskSeverity.MEDIUM


def test_score_49_is_medium():
    assert severity_from_score(49) == RiskSeverity.MEDIUM


def test_score_50_is_high():
    assert severity_from_score(50) == RiskSeverity.HIGH


def test_score_74_is_high():
    assert severity_from_score(74) == RiskSeverity.HIGH


def test_score_75_is_critical():
    assert severity_from_score(75) == RiskSeverity.CRITICAL


def test_score_100_is_critical():
    assert severity_from_score(100) == RiskSeverity.CRITICAL


def test_severity_rejects_negative_score():
    with pytest.raises(
        ValueError,
        match="Risk score must be between 0 and 100",
    ):
        severity_from_score(-1)


def test_severity_rejects_score_above_100():
    with pytest.raises(
        ValueError,
        match="Risk score must be between 0 and 100",
    ):
        severity_from_score(101)


def test_severity_rejects_float_score():
    with pytest.raises(
        TypeError,
        match="Risk score must be an integer",
    ):
        severity_from_score(50.5)


def test_severity_rejects_string_score():
    with pytest.raises(
        TypeError,
        match="Risk score must be an integer",
    ):
        severity_from_score("50")


def test_severity_rejects_boolean_score():
    with pytest.raises(
        TypeError,
        match="Risk score must be an integer",
    ):
        severity_from_score(True)