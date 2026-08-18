from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    source: str
    event_type: str
    source_ip: str

    http_method: str | None = None
    path: str | None = None
    status_code: int | None = None
    user_agent: str | None = None