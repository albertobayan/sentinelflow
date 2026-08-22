import pytest

from sentinelflow.behavior.directory_scanning import (
    DEFAULT_DIRECTORY_SCAN_THRESHOLD,
    detect_directory_scanning,
)
from sentinelflow.models.behavior import (
    BehaviorSignalType,
)
from sentinelflow.models.security_event import SecurityEvent


def create_event(
    source_ip: str,
    path: str | None,
    status_code: int = 404,
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


def test_default_directory_scan_threshold():
    assert DEFAULT_DIRECTORY_SCAN_THRESHOLD == 8


def test_no_signal_when_events_are_empty():
    assert detect_directory_scanning([]) == []


def test_no_signal_below_unique_path_threshold():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path=f"/resource-{index}",
        )
        for index in range(7)
    ]

    assert detect_directory_scanning(
        events
    ) == []


def test_signal_is_created_at_unique_path_threshold():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path=f"/resource-{index}",
        )
        for index in range(8)
    ]

    signals = detect_directory_scanning(
        events
    )

    assert len(signals) == 1
    assert signals[0].source_ip == "203.0.113.10"
    assert (
        signals[0].signal_type
        == BehaviorSignalType.DIRECTORY_SCANNING
    )
    assert signals[0].event_count == 8
    assert signals[0].score == 55


def test_duplicate_paths_are_counted_once():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path="/admin",
        )
        for _ in range(20)
    ]

    assert detect_directory_scanning(
        events
    ) == []


def test_unique_paths_are_grouped_by_source_ip():
    events = [
        *[
            create_event(
                source_ip="203.0.113.10",
                path=f"/a-{index}",
            )
            for index in range(8)
        ],
        *[
            create_event(
                source_ip="203.0.113.20",
                path=f"/b-{index}",
            )
            for index in range(7)
        ],
    ]

    signals = detect_directory_scanning(
        events
    )

    assert len(signals) == 1
    assert signals[0].source_ip == "203.0.113.10"
    assert signals[0].event_count == 8


def test_multiple_ips_can_generate_directory_scan_signals():
    events = [
        *[
            create_event(
                source_ip="203.0.113.10",
                path=f"/a-{index}",
            )
            for index in range(8)
        ],
        *[
            create_event(
                source_ip="203.0.113.20",
                path=f"/b-{index}",
            )
            for index in range(10)
        ],
    ]

    signals = detect_directory_scanning(
        events
    )

    assert len(signals) == 2

    signals_by_ip = {
        signal.source_ip: signal
        for signal in signals
    }

    assert signals_by_ip[
        "203.0.113.10"
    ].event_count == 8

    assert signals_by_ip[
        "203.0.113.20"
    ].event_count == 10


def test_status_code_does_not_control_path_diversity_detection():
    status_codes = [
        200,
        301,
        401,
        403,
        404,
        500,
        404,
        403,
    ]

    events = [
        create_event(
            source_ip="203.0.113.10",
            path=f"/resource-{index}",
            status_code=status_code,
        )
        for index, status_code in enumerate(
            status_codes
        )
    ]

    signals = detect_directory_scanning(
        events
    )

    assert len(signals) == 1
    assert signals[0].event_count == 8


def test_directory_scan_score_increases_above_threshold():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path=f"/resource-{index}",
        )
        for index in range(12)
    ]

    signals = detect_directory_scanning(
        events
    )

    assert len(signals) == 1
    assert signals[0].score == 75


def test_directory_scan_score_is_capped_at_100():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path=f"/resource-{index}",
        )
        for index in range(100)
    ]

    signals = detect_directory_scanning(
        events
    )

    assert len(signals) == 1
    assert signals[0].score == 100


def test_directory_scan_reason_contains_unique_path_count():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path=f"/resource-{index}",
        )
        for index in range(10)
    ]

    signals = detect_directory_scanning(
        events
    )

    assert signals[0].reason == (
        "10 unique HTTP paths requested"
    )


def test_custom_threshold_is_supported():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path=f"/resource-{index}",
        )
        for index in range(4)
    ]

    signals = detect_directory_scanning(
        events,
        threshold=4,
    )

    assert len(signals) == 1
    assert signals[0].event_count == 4
    assert signals[0].score == 55


def test_custom_threshold_changes_score_baseline():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path=f"/resource-{index}",
        )
        for index in range(7)
    ]

    signals = detect_directory_scanning(
        events,
        threshold=4,
    )

    assert signals[0].score == 70


def test_threshold_must_be_integer():
    with pytest.raises(
        TypeError,
        match=(
            "Directory scanning threshold "
            "must be an integer"
        ),
    ):
        detect_directory_scanning(
            [],
            threshold=8.5,
        )


def test_boolean_threshold_is_rejected():
    with pytest.raises(
        TypeError,
        match=(
            "Directory scanning threshold "
            "must be an integer"
        ),
    ):
        detect_directory_scanning(
            [],
            threshold=True,
        )


def test_zero_threshold_is_rejected():
    with pytest.raises(
        ValueError,
        match=(
            "Directory scanning threshold "
            "must be greater than 0"
        ),
    ):
        detect_directory_scanning(
            [],
            threshold=0,
        )


def test_negative_threshold_is_rejected():
    with pytest.raises(
        ValueError,
        match=(
            "Directory scanning threshold "
            "must be greater than 0"
        ),
    ):
        detect_directory_scanning(
            [],
            threshold=-1,
        )


def test_source_ip_whitespace_is_normalized():
    events = [
        create_event(
            source_ip="   203.0.113.10   ",
            path=f"/resource-{index}",
        )
        for index in range(8)
    ]

    signals = detect_directory_scanning(
        events
    )

    assert len(signals) == 1
    assert signals[0].source_ip == "203.0.113.10"


def test_blank_source_ip_is_ignored():
    events = [
        create_event(
            source_ip="   ",
            path=f"/resource-{index}",
        )
        for index in range(8)
    ]

    assert detect_directory_scanning(
        events
    ) == []


def test_event_without_path_is_ignored():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path=None,
        )
        for _ in range(20)
    ]

    assert detect_directory_scanning(
        events
    ) == []


def test_blank_path_is_ignored():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path="   ",
        )
        for _ in range(20)
    ]

    assert detect_directory_scanning(
        events
    ) == []


def test_path_whitespace_is_normalized_before_deduplication():
    events = [
        create_event(
            source_ip="203.0.113.10",
            path="/admin",
        ),
        create_event(
            source_ip="203.0.113.10",
            path="   /admin   ",
        ),
    ]

    events.extend(
        [
            create_event(
                source_ip="203.0.113.10",
                path=f"/resource-{index}",
            )
            for index in range(6)
        ]
    )

    assert detect_directory_scanning(
        events
    ) == []