from sentinelflow.behavior.auth_failures import (
    DEFAULT_AUTH_FAILURE_THRESHOLD,
    detect_repeated_auth_failures,
)
from sentinelflow.behavior.directory_scanning import (
    DEFAULT_DIRECTORY_SCAN_THRESHOLD,
    detect_directory_scanning,
)
from sentinelflow.behavior.high_404 import (
    DEFAULT_HIGH_404_THRESHOLD,
    detect_high_404_rate,
)
from sentinelflow.models.behavior import BehaviorSignal
from sentinelflow.models.security_event import SecurityEvent


def analyze_behavior(
    events: list[SecurityEvent],
    auth_failure_threshold: int = DEFAULT_AUTH_FAILURE_THRESHOLD,
    high_404_threshold: int = DEFAULT_HIGH_404_THRESHOLD,
    directory_scan_threshold: int = DEFAULT_DIRECTORY_SCAN_THRESHOLD,
) -> list[BehaviorSignal]:
    signals = []

    signals.extend(
        detect_repeated_auth_failures(
            events,
            threshold=auth_failure_threshold,
        )
    )

    signals.extend(
        detect_high_404_rate(
            events,
            threshold=high_404_threshold,
        )
    )

    signals.extend(
        detect_directory_scanning(
            events,
            threshold=directory_scan_threshold,
        )
    )

    return signals