from collections import defaultdict

from sentinelflow.models.behavior import (
    BehaviorSignal,
    BehaviorSignalType,
)
from sentinelflow.models.security_event import SecurityEvent


DEFAULT_DIRECTORY_SCAN_THRESHOLD = 8


def detect_directory_scanning(
    events: list[SecurityEvent],
    threshold: int = DEFAULT_DIRECTORY_SCAN_THRESHOLD,
) -> list[BehaviorSignal]:
    if type(threshold) is not int:
        raise TypeError(
            "Directory scanning threshold must be an integer"
        )

    if threshold <= 0:
        raise ValueError(
            "Directory scanning threshold must be greater than 0"
        )

    paths_by_ip: dict[str, set[str]] = defaultdict(set)

    for event in events:
        source_ip = event.source_ip.strip()

        if not source_ip:
            continue

        if event.path is None:
            continue

        normalized_path = event.path.strip()

        if not normalized_path:
            continue

        paths_by_ip[source_ip].add(
            normalized_path
        )

    signals = []

    for source_ip, unique_paths in paths_by_ip.items():
        path_count = len(unique_paths)

        if path_count < threshold:
            continue

        score = _score_directory_scan_signal(
            path_count=path_count,
            threshold=threshold,
        )

        signals.append(
            BehaviorSignal(
                source_ip=source_ip,
                signal_type=(
                    BehaviorSignalType.DIRECTORY_SCANNING
                ),
                score=score,
                event_count=path_count,
                reason=(
                    f"{path_count} unique HTTP paths "
                    f"requested"
                ),
            )
        )

    return signals


def _score_directory_scan_signal(
    path_count: int,
    threshold: int,
) -> int:
    additional_paths = (
        path_count - threshold
    )

    score = (
        55
        + additional_paths * 5
    )

    return min(
        score,
        100,
    )