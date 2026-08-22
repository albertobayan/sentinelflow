import pytest

from sentinelflow.models.behavior import (
    BehaviorSignal,
    BehaviorSignalType,
)
from sentinelflow.risk.behavior import (
    MAX_BEHAVIOR_UPLIFT,
    build_behavior_reasons,
    calculate_behavior_uplift,
    validate_behavior_signals_for_indicator,
)


def create_signal(
    score: int,
    signal_type: BehaviorSignalType = (
        BehaviorSignalType.REPEATED_AUTH_FAILURES
    ),
    source_ip: str = "203.0.113.10",
    event_count: int = 5,
) -> BehaviorSignal:
    return BehaviorSignal(
        source_ip=source_ip,
        signal_type=signal_type,
        score=score,
        event_count=event_count,
        reason="Test behavior signal",
    )


def test_max_behavior_uplift_is_25():
    assert MAX_BEHAVIOR_UPLIFT == 25


def test_no_behavior_signals_produce_zero_uplift():
    assert calculate_behavior_uplift([]) == 0


def test_behavior_score_100_produces_maximum_uplift():
    signals = [
        create_signal(score=100)
    ]

    assert calculate_behavior_uplift(
        signals
    ) == 25


def test_behavior_score_60_produces_15_point_uplift():
    signals = [
        create_signal(score=60)
    ]

    assert calculate_behavior_uplift(
        signals
    ) == 15


def test_behavior_uplift_uses_half_up_rounding():
    signals = [
        create_signal(score=70)
    ]

    assert calculate_behavior_uplift(
        signals
    ) == 18


def test_behavior_uplift_uses_strongest_signal():
    signals = [
        create_signal(
            score=50,
            signal_type=(
                BehaviorSignalType.REPEATED_AUTH_FAILURES
            ),
        ),
        create_signal(
            score=70,
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
        ),
        create_signal(
            score=40,
            signal_type=(
                BehaviorSignalType.HIGH_404_RATE
            ),
        ),
    ]

    assert calculate_behavior_uplift(
        signals
    ) == 18


def test_multiple_signals_are_not_added_together():
    signals = [
        create_signal(
            score=100,
            signal_type=(
                BehaviorSignalType.REPEATED_AUTH_FAILURES
            ),
        ),
        create_signal(
            score=100,
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
        ),
    ]

    assert calculate_behavior_uplift(
        signals
    ) == 25


def test_behavior_signals_can_match_indicator():
    signals = [
        create_signal(
            score=50,
            source_ip="203.0.113.10",
        )
    ]

    validate_behavior_signals_for_indicator(
        "203.0.113.10",
        signals,
    )


def test_behavior_indicator_comparison_normalizes_indicator():
    signals = [
        create_signal(
            score=50,
            source_ip="203.0.113.10",
        )
    ]

    validate_behavior_signals_for_indicator(
        "   203.0.113.10   ",
        signals,
    )


def test_behavior_signal_for_other_indicator_is_rejected():
    signals = [
        create_signal(
            score=50,
            source_ip="203.0.113.20",
        )
    ]

    with pytest.raises(
        ValueError,
        match=(
            "Behavior signals must belong "
            "to the assessed indicator"
        ),
    ):
        validate_behavior_signals_for_indicator(
            "203.0.113.10",
            signals,
        )


def test_behavior_reasons_are_empty_without_signals():
    assert build_behavior_reasons([]) == ()


def test_behavior_reason_contains_signal_information():
    signal = BehaviorSignal(
        source_ip="203.0.113.10",
        signal_type=(
            BehaviorSignalType.DIRECTORY_SCANNING
        ),
        score=70,
        event_count=11,
        reason="11 unique HTTP paths requested",
    )

    reasons = build_behavior_reasons(
        [signal]
    )

    assert reasons == (
        (
            "behavior:DIRECTORY_SCANNING: "
            "score=70, "
            "event_count=11, "
            "reason=11 unique HTTP paths requested"
        ),
    )


def test_all_behavior_signals_are_preserved_in_reasons():
    signals = [
        create_signal(
            score=50,
            signal_type=(
                BehaviorSignalType.REPEATED_AUTH_FAILURES
            ),
        ),
        create_signal(
            score=70,
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
        ),
    ]

    reasons = build_behavior_reasons(
        signals
    )

    assert len(reasons) == 2
    

def test_behavior_signal_comparison_normalizes_signal_source_ip():
    signal = BehaviorSignal(
        source_ip="   203.0.113.10   ",
        signal_type=BehaviorSignalType.HIGH_404_RATE,
        score=40,
        event_count=10,
        reason="10 HTTP 404 responses detected",
    )

    validate_behavior_signals_for_indicator(
        "203.0.113.10",
        [signal],
    )


def test_empty_assessed_indicator_is_rejected():
    signals = [
        create_signal(
            score=50,
            source_ip="203.0.113.10",
        )
    ]

    with pytest.raises(
        ValueError,
        match="Assessed indicator cannot be empty",
    ):
        validate_behavior_signals_for_indicator(
            "   ",
            signals,
        )


def test_behavior_uplift_does_not_exceed_maximum():
    signals = [
        create_signal(
            score=100,
        )
    ]

    uplift = calculate_behavior_uplift(
        signals
    )

    assert uplift <= MAX_BEHAVIOR_UPLIFT