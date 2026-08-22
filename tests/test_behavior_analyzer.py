import pytest

from sentinelflow.behavior.analyzer import analyze_behavior
from sentinelflow.models.behavior import BehaviorSignalType
from sentinelflow.models.security_event import SecurityEvent


def create_event(
    source_ip: str,
    status_code: int,
    path: str,
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


def test_analyze_behavior_returns_empty_list_for_no_events():
    assert analyze_behavior([]) == []


def test_analyze_behavior_runs_auth_failure_detector():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
            path="/login",
        )
        for _ in range(5)
    ]

    signals = analyze_behavior(events)

    assert len(signals) == 1
    assert (
        signals[0].signal_type
        == BehaviorSignalType.REPEATED_AUTH_FAILURES
    )


def test_analyze_behavior_runs_high_404_detector():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=404,
            path="/missing",
        )
        for _ in range(10)
    ]

    signals = analyze_behavior(events)

    assert len(signals) == 1
    assert (
        signals[0].signal_type
        == BehaviorSignalType.HIGH_404_RATE
    )


def test_analyze_behavior_runs_directory_scanning_detector():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=200,
            path=f"/resource-{index}",
        )
        for index in range(8)
    ]

    signals = analyze_behavior(events)

    assert len(signals) == 1
    assert (
        signals[0].signal_type
        == BehaviorSignalType.DIRECTORY_SCANNING
    )


def test_same_ip_can_generate_multiple_behavior_signals():
    events = []

    events.extend(
        [
            create_event(
                source_ip="203.0.113.10",
                status_code=401,
                path="/login",
            )
            for _ in range(5)
        ]
    )

    events.extend(
        [
            create_event(
                source_ip="203.0.113.10",
                status_code=404,
                path=f"/missing-{index}",
            )
            for index in range(10)
        ]
    )

    signals = analyze_behavior(events)

    signal_types = {
        signal.signal_type
        for signal in signals
    }

    assert (
        BehaviorSignalType.REPEATED_AUTH_FAILURES
        in signal_types
    )

    assert (
        BehaviorSignalType.HIGH_404_RATE
        in signal_types
    )

    assert (
        BehaviorSignalType.DIRECTORY_SCANNING
        in signal_types
    )

    assert len(signals) == 3


def test_different_ips_keep_independent_behavior_signals():
    events = [
        *[
            create_event(
                source_ip="203.0.113.10",
                status_code=401,
                path="/login",
            )
            for _ in range(5)
        ],
        *[
            create_event(
                source_ip="203.0.113.20",
                status_code=404,
                path="/missing",
            )
            for _ in range(10)
        ],
    ]

    signals = analyze_behavior(events)

    assert len(signals) == 2

    signals_by_ip = {
        signal.source_ip: signal
        for signal in signals
    }

    assert (
        signals_by_ip[
            "203.0.113.10"
        ].signal_type
        == BehaviorSignalType.REPEATED_AUTH_FAILURES
    )

    assert (
        signals_by_ip[
            "203.0.113.20"
        ].signal_type
        == BehaviorSignalType.HIGH_404_RATE
    )


def test_custom_auth_failure_threshold_is_forwarded():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=401,
            path="/login",
        )
        for _ in range(3)
    ]

    signals = analyze_behavior(
        events,
        auth_failure_threshold=3,
    )

    assert len(signals) == 1
    assert (
        signals[0].signal_type
        == BehaviorSignalType.REPEATED_AUTH_FAILURES
    )


def test_custom_high_404_threshold_is_forwarded():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=404,
            path="/missing",
        )
        for _ in range(5)
    ]

    signals = analyze_behavior(
        events,
        high_404_threshold=5,
    )

    assert len(signals) == 1
    assert (
        signals[0].signal_type
        == BehaviorSignalType.HIGH_404_RATE
    )


def test_custom_directory_scan_threshold_is_forwarded():
    events = [
        create_event(
            source_ip="203.0.113.10",
            status_code=200,
            path=f"/resource-{index}",
        )
        for index in range(4)
    ]

    signals = analyze_behavior(
        events,
        directory_scan_threshold=4,
    )

    assert len(signals) == 1
    assert (
        signals[0].signal_type
        == BehaviorSignalType.DIRECTORY_SCANNING
    )


def test_analyzer_does_not_merge_signals_from_same_ip():
    events = [
        *[
            create_event(
                source_ip="203.0.113.10",
                status_code=401,
                path="/login",
            )
            for _ in range(5)
        ],
        *[
            create_event(
                source_ip="203.0.113.10",
                status_code=404,
                path=f"/missing-{index}",
            )
            for index in range(10)
        ],
    ]

    signals = analyze_behavior(events)

    signals_for_ip = [
        signal
        for signal in signals
        if signal.source_ip == "203.0.113.10"
    ]

    assert len(signals_for_ip) == 3
    

def test_invalid_auth_failure_threshold_is_rejected():
    with pytest.raises(
        ValueError,
        match=(
            "Authentication failure threshold "
            "must be greater than 0"
        ),
    ):
        analyze_behavior(
            [],
            auth_failure_threshold=0,
        )


def test_invalid_high_404_threshold_is_rejected():
    with pytest.raises(
        ValueError,
        match="HTTP 404 threshold must be greater than 0",
    ):
        analyze_behavior(
            [],
            high_404_threshold=0,
        )


def test_invalid_directory_scan_threshold_is_rejected():
    with pytest.raises(
        ValueError,
        match=(
            "Directory scanning threshold "
            "must be greater than 0"
        ),
    ):
        analyze_behavior(
            [],
            directory_scan_threshold=0,
        )