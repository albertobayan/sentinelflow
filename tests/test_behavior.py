from dataclasses import FrozenInstanceError

import pytest

from sentinelflow.models.behavior import (
    BehaviorSignal,
    BehaviorSignalType,
)


def test_behavior_signal_type_values():
    assert (
        BehaviorSignalType.REPEATED_AUTH_FAILURES.value
        == "REPEATED_AUTH_FAILURES"
    )

    assert (
        BehaviorSignalType.HIGH_404_RATE.value
        == "HIGH_404_RATE"
    )

    assert (
        BehaviorSignalType.DIRECTORY_SCANNING.value
        == "DIRECTORY_SCANNING"
    )

    assert (
        BehaviorSignalType.SUSPICIOUS_PATH_ACTIVITY.value
        == "SUSPICIOUS_PATH_ACTIVITY"
    )


def test_behavior_signal_stores_values():
    signal = BehaviorSignal(
        source_ip="203.0.113.10",
        signal_type=(
            BehaviorSignalType.REPEATED_AUTH_FAILURES
        ),
        score=60,
        event_count=8,
        reason=(
            "8 authentication-related HTTP failures detected"
        ),
    )

    assert signal.source_ip == "203.0.113.10"
    assert (
        signal.signal_type
        == BehaviorSignalType.REPEATED_AUTH_FAILURES
    )
    assert signal.score == 60
    assert signal.event_count == 8
    assert signal.reason == (
        "8 authentication-related HTTP failures detected"
    )


def test_behavior_signal_normalizes_source_ip():
    signal = BehaviorSignal(
        source_ip="   203.0.113.10   ",
        signal_type=BehaviorSignalType.HIGH_404_RATE,
        score=40,
        event_count=5,
        reason="High number of HTTP 404 responses",
    )

    assert signal.source_ip == "203.0.113.10"


def test_behavior_signal_normalizes_reason():
    signal = BehaviorSignal(
        source_ip="203.0.113.10",
        signal_type=BehaviorSignalType.HIGH_404_RATE,
        score=40,
        event_count=5,
        reason="   High number of HTTP 404 responses   ",
    )

    assert signal.reason == (
        "High number of HTTP 404 responses"
    )


def test_behavior_signal_rejects_empty_source_ip():
    with pytest.raises(
        ValueError,
        match="Behavior signal source IP cannot be empty",
    ):
        BehaviorSignal(
            source_ip="",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=40,
            event_count=5,
            reason="High number of HTTP 404 responses",
        )


def test_behavior_signal_rejects_whitespace_source_ip():
    with pytest.raises(
        ValueError,
        match="Behavior signal source IP cannot be empty",
    ):
        BehaviorSignal(
            source_ip="   ",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=40,
            event_count=5,
            reason="High number of HTTP 404 responses",
        )


def test_behavior_signal_rejects_invalid_signal_type():
    with pytest.raises(
        TypeError,
        match=(
            "Behavior signal type must be "
            "a BehaviorSignalType"
        ),
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type="HIGH_404_RATE",
            score=40,
            event_count=5,
            reason="High number of HTTP 404 responses",
        )


def test_behavior_signal_accepts_minimum_score():
    signal = BehaviorSignal(
        source_ip="203.0.113.10",
        signal_type=BehaviorSignalType.HIGH_404_RATE,
        score=0,
        event_count=5,
        reason="Test reason",
    )

    assert signal.score == 0


def test_behavior_signal_accepts_maximum_score():
    signal = BehaviorSignal(
        source_ip="203.0.113.10",
        signal_type=BehaviorSignalType.DIRECTORY_SCANNING,
        score=100,
        event_count=20,
        reason="Test reason",
    )

    assert signal.score == 100


def test_behavior_signal_rejects_negative_score():
    with pytest.raises(
        ValueError,
        match="Behavior signal score must be between 0 and 100",
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=-1,
            event_count=5,
            reason="Test reason",
        )


def test_behavior_signal_rejects_score_above_100():
    with pytest.raises(
        ValueError,
        match="Behavior signal score must be between 0 and 100",
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=101,
            event_count=5,
            reason="Test reason",
        )


def test_behavior_signal_rejects_float_score():
    with pytest.raises(
        TypeError,
        match="Behavior signal score must be an integer",
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=40.5,
            event_count=5,
            reason="Test reason",
        )


def test_behavior_signal_rejects_boolean_score():
    with pytest.raises(
        TypeError,
        match="Behavior signal score must be an integer",
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=True,
            event_count=5,
            reason="Test reason",
        )


def test_behavior_signal_accepts_single_event():
    signal = BehaviorSignal(
        source_ip="203.0.113.10",
        signal_type=(
            BehaviorSignalType.SUSPICIOUS_PATH_ACTIVITY
        ),
        score=50,
        event_count=1,
        reason="Suspicious path requested",
    )

    assert signal.event_count == 1


def test_behavior_signal_rejects_zero_event_count():
    with pytest.raises(
        ValueError,
        match=(
            "Behavior signal event count "
            "must be greater than 0"
        ),
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=40,
            event_count=0,
            reason="Test reason",
        )


def test_behavior_signal_rejects_negative_event_count():
    with pytest.raises(
        ValueError,
        match=(
            "Behavior signal event count "
            "must be greater than 0"
        ),
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=40,
            event_count=-1,
            reason="Test reason",
        )


def test_behavior_signal_rejects_float_event_count():
    with pytest.raises(
        TypeError,
        match=(
            "Behavior signal event count "
            "must be an integer"
        ),
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=40,
            event_count=5.5,
            reason="Test reason",
        )


def test_behavior_signal_rejects_boolean_event_count():
    with pytest.raises(
        TypeError,
        match=(
            "Behavior signal event count "
            "must be an integer"
        ),
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=40,
            event_count=True,
            reason="Test reason",
        )


def test_behavior_signal_rejects_empty_reason():
    with pytest.raises(
        ValueError,
        match="Behavior signal reason cannot be empty",
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=40,
            event_count=5,
            reason="",
        )


def test_behavior_signal_rejects_whitespace_reason():
    with pytest.raises(
        ValueError,
        match="Behavior signal reason cannot be empty",
    ):
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=BehaviorSignalType.HIGH_404_RATE,
            score=40,
            event_count=5,
            reason="   ",
        )


def test_behavior_signal_is_immutable():
    signal = BehaviorSignal(
        source_ip="203.0.113.10",
        signal_type=BehaviorSignalType.HIGH_404_RATE,
        score=40,
        event_count=5,
        reason="High number of HTTP 404 responses",
    )

    with pytest.raises(FrozenInstanceError):
        signal.score = 80