from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    source: str
    source_ip: str
    http_method: str
    path: str
    status_code: int
    user_agent: str