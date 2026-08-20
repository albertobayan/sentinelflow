from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatIntelResult:
    indicator: str
    provider: str
    malicious: bool
    score: int
    confidence: int