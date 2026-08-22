import pytest

from sentinelflow.behavior.auth_failures import (
    DEFAULT_AUTH_FAILURE_THRESHOLD,
    detect_repeated_auth_failures,
)
from sentinelflow.models.behavior import (
    BehaviorSignalType,
)
from sentinelflow.models.security_event import SecurityEvent


def create_event(
    source_ip: str,
    status_code: int,
    path: str = "/login",
) -> SecurityEvent:
    return SecurityEvent(
        timestamp="22/Aug/2026:12:00:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip=source_ip,
        http_method="GET",
        path=path,
        status_code=status_code,
        user_agent="pytest",
    )


def test_default_auth_failure_threshold():
    assert DEFAULT_AUTH_FAILURE_THRESHOLD == 5


def test_no_signal_when_events_are_empty():
    assert detect_repeated_auth_failures([]) == []


def test_no_signal_below_threshold():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        )
        for _ in range(4)
    ]

    assert detect_repeated_auth_failures(
        events
    ) == []


def test_signal_is_created_at_threshold():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        )
        for _ in range(5)
    ]

    signals = detect_repeated_auth_failures(
        events
    )

    assert len(signals) == 1
    assert signals[0].source_ip == "203.0.113.10"
    assert (
        signals[0].signal_type
        == BehaviorSignalType.REPEATED_AUTH_FAILURES
    )
    assert signals[0].event_count == 5
    assert signals[0].score == 50


def test_401_and_403_are_both_counted():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        ),
        create_event(
            source_ip="203.0.113.10",
            status_code=403,
        ),
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        ),
        create_event(
            source_ip="203.0.113.10",
            status_code=403,
        ),
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        ),
    ]

    signals = detect_repeated_auth_failures(
        events
    )

    assert len(signals) == 1
    assert signals[0].event_count == 5


def test_other_status_codes_are_ignored():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        ),
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        ),
        create_event(
            source_ip="203.0.113.10",
            status_code=200,
        ),
        create_event(
            source_ip="203.0.113.10",
            status_code=404,
        ),
        create_event(
            source_ip="203.0.113.10",
            status_code=500,
        ),
    ]

    assert detect_repeated_auth_failures(
        events
    ) == []


def test_failures_are_grouped_by_source_ip():
    events = [
        *[
            create_event(
                source_ip="203.0.113.10",
                status_code=401,
            )
            for _ in range(5)
        ],
        *[
            create_event(
                source_ip="203.0.113.20",
                status_code=401,
            )
            for _ in range(4)
        ],
    ]

    signals = detect_repeated_auth_failures(
        events
    )

    assert len(signals) == 1
    assert signals[0].source_ip == "203.0.113.10"
    assert signals[0].event_count == 5


def test_multiple_ips_can_generate_signals():
    events = [
        *[
            create_event(
                source_ip="203.0.113.10",
                status_code=401,
            )
            for _ in range(5)
        ],
        *[
            create_event(
                source_ip="203.0.113.20",
                status_code=403,
            )
            for _ in range(6)
        ],
    ]

    signals = detect_repeated_auth_failures(
        events
    )

    assert len(signals) == 2

    signals_by_ip = {
        signal.source_ip: signal
        for signal in signals
    }

    assert signals_by_ip[
        "203.0.113.10"
    ].event_count == 5

    assert signals_by_ip[
        "203.0.113.20"
    ].event_count == 6


def test_signal_score_increases_above_threshold():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        )
        for _ in range(8)
    ]

    signals = detect_repeated_auth_failures(
        events
    )

    assert len(signals) == 1
    assert signals[0].score == 65


def test_signal_score_is_capped_at_100():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        )
        for _ in range(100)
    ]

    signals = detect_repeated_auth_failures(
        events
    )

    assert len(signals) == 1
    assert signals[0].score == 100


def test_signal_reason_contains_event_count():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        )
        for _ in range(7)
    ]

    signals = detect_repeated_auth_failures(
        events
    )

    assert signals[0].reason == (
        "7 authentication-related HTTP failures detected"
    )


def test_custom_threshold_is_supported():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        )
        for _ in range(3)
    ]

    signals = detect_repeated_auth_failures(
        events,
        threshold=3,
    )

    assert len(signals) == 1
    assert signals[0].event_count == 3
    assert signals[0].score == 50


def test_custom_threshold_changes_score_baseline():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
        )
        for _ in range(5)
    ]

    signals = detect_repeated_auth_failures(
        events,
        threshold=3,
    )

    assert signals[0].score == 60


def test_threshold_must_be_integer():
    with pytest.raises(
        TypeError,
        match=(
            "Authentication failure threshold "
            "must be an integer"
        ),
    ):
        detect_repeated_auth_failures(
            [],
            threshold=5.5,
        )


def test_boolean_threshold_is_rejected():
    with pytest.raises(
        TypeError,
        match=(
            "Authentication failure threshold "
            "must be an integer"
        ),
    ):
        detect_repeated_auth_failures(
            [],
            threshold=True,
        )


def test_zero_threshold_is_rejected():
    with pytest.raises(
        ValueError,
        match=(
            "Authentication failure threshold "
            "must be greater than 0"
        ),
    ):
        detect_repeated_auth_failures(
            [],
            threshold=0,
        )


def test_negative_threshold_is_rejected():
    with pytest.raises(
        ValueError,
        match=(
            "Authentication failure threshold "
            "must be greater than 0"
        ),
    ):
        detect_repeated_auth_failures(
            [],
            threshold=-1,
        )


def test_source_ip_whitespace_is_normalized():
    events = [
        create_event(
            source_ip="   203.0.113.10   ",
            status_code=401,
        )
        for _ in range(5)
    ]

    signals = detect_repeated_auth_failures(
        events
    )

    assert len(signals) == 1
    assert signals[0].source_ip == "203.0.113.10"


def test_blank_source_ip_is_ignored():
    events = [
        create_event(
            source_ip="   ",
            status_code=401,
        )
        for _ in range(5)
    ]

    assert detect_repeated_auth_failures(
        events
    ) == []


def test_non_http_event_without_status_is_ignored():
    events = [
        SecurityEvent(
            timestamp="22/Aug/2026:12:00:00 +0200",
            source="test",
            event_type="generic_event",
            source_ip="203.0.113.10",
        )
        for _ in range(10)
    ]

    assert detect_repeated_auth_failures(
        events
    ) == []