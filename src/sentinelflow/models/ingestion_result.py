from dataclasses import dataclass

from sentinelflow.models.security_event import SecurityEvent


@dataclass(frozen=True)
class IngestionResult:
    events: list[SecurityEvent]
    total_lines: int
    valid_lines: int
    invalid_lines: int