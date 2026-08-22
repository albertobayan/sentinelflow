from dataclasses import dataclass
from enum import Enum


class BehaviorSignalType(str, Enum):
    REPEATED_AUTH_FAILURES = "REPEATED_AUTH_FAILURES"
    HIGH_404_RATE = "HIGH_404_RATE"
    DIRECTORY_SCANNING = "DIRECTORY_SCANNING"
    SUSPICIOUS_PATH_ACTIVITY = "SUSPICIOUS_PATH_ACTIVITY"


@dataclass(frozen=True)
class BehaviorSignal:
    source_ip: str
    signal_type: BehaviorSignalType
    score: int
    event_count: int
    reason: str

    def __post_init__(self) -> None:
        normalized_source_ip = self.source_ip.strip()
        normalized_reason = self.reason.strip()

        if not normalized_source_ip:
            raise ValueError(
                "Behavior signal source IP cannot be empty"
            )

        if not isinstance(
            self.signal_type,
            BehaviorSignalType,
        ):
            raise TypeError(
                "Behavior signal type must be a BehaviorSignalType"
            )

        if type(self.score) is not int:
            raise TypeError(
                "Behavior signal score must be an integer"
            )

        if not 0 <= self.score <= 100:
            raise ValueError(
                "Behavior signal score must be between 0 and 100"
            )

        if type(self.event_count) is not int:
            raise TypeError(
                "Behavior signal event count must be an integer"
            )

        if self.event_count <= 0:
            raise ValueError(
                "Behavior signal event count must be greater than 0"
            )

        if not normalized_reason:
            raise ValueError(
                "Behavior signal reason cannot be empty"
            )

        object.__setattr__(
            self,
            "source_ip",
            normalized_source_ip,
        )

        object.__setattr__(
            self,
            "reason",
            normalized_reason,
        )