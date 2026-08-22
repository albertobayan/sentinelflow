from collections import defaultdict

from sentinelflow.models.behavior import (
    BehaviorSignal,
    BehaviorSignalType,
)
from sentinelflow.models.security_event import SecurityEvent


DEFAULT_HIGH_404_THRESHOLD = 10


def detect_high_404_rate(
    events: list[SecurityEvent],
    threshold: int = DEFAULT_HIGH_404_THRESHOLD,
) -> list[BehaviorSignal]:
    if type(threshold) is not int:
        raise TypeError(
            "HTTP 404 threshold must be an integer"
        )

    if threshold <= 0:
        raise ValueError(
            "HTTP 404 threshold must be greater than 0"
        )

    not_found_by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if event.status_code != 404:
            continue

        source_ip = event.source_ip.strip()

        if not source_ip:
            continue

        not_found_by_ip[source_ip].append(event)

    signals = []

    for source_ip, not_found_events in not_found_by_ip.items():
        event_count = len(not_found_events)

        if event_count < threshold:
            continue

        score = _score_high_404_signal(
            event_count=event_count,
            threshold=threshold,
        )

        signals.append(
            BehaviorSignal(
                source_ip=source_ip,
                signal_type=BehaviorSignalType.HIGH_404_RATE,
                score=score,
                event_count=event_count,
                reason=(
                    f"{event_count} HTTP 404 responses detected"
                ),
            )
        )

    return signals


def _score_high_404_signal(
    event_count: int,
    threshold: int,
) -> int:
    additional_events = (
        event_count - threshold
    )

    score = (
        40
        + additional_events * 4
    )

    return min(
        score,
        100,
    )