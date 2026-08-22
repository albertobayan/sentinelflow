from collections import defaultdict

from sentinelflow.models.behavior import (
    BehaviorSignal,
    BehaviorSignalType,
)
from sentinelflow.models.security_event import SecurityEvent


AUTH_FAILURE_STATUS_CODES = {
    401,
    403,
}

DEFAULT_AUTH_FAILURE_THRESHOLD = 5


def detect_repeated_auth_failures(
    events: list[SecurityEvent],
    threshold: int = DEFAULT_AUTH_FAILURE_THRESHOLD,
) -> list[BehaviorSignal]:
    if type(threshold) is not int:
        raise TypeError(
            "Authentication failure threshold must be an integer"
        )

    if threshold <= 0:
        raise ValueError(
            "Authentication failure threshold must be greater than 0"
        )

    failures_by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if event.status_code not in AUTH_FAILURE_STATUS_CODES:
            continue

        source_ip = event.source_ip.strip()

        if not source_ip:
            continue

        failures_by_ip[source_ip].append(event)

    signals = []

    for source_ip, failed_events in failures_by_ip.items():
        event_count = len(failed_events)

        if event_count < threshold:
            continue

        score = _score_auth_failure_signal(
            event_count=event_count,
            threshold=threshold,
        )

        signals.append(
            BehaviorSignal(
                source_ip=source_ip,
                signal_type=(
                    BehaviorSignalType.REPEATED_AUTH_FAILURES
                ),
                score=score,
                event_count=event_count,
                reason=(
                    f"{event_count} authentication-related "
                    f"HTTP failures detected"
                ),
            )
        )

    return signals


def _score_auth_failure_signal(
    event_count: int,
    threshold: int,
) -> int:
    additional_failures = (
        event_count - threshold
    )

    score = (
        50
        + additional_failures * 5
    )

    return min(
        score,
        100,
    )