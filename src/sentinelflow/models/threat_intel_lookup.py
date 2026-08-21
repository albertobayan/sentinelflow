from dataclasses import dataclass

from sentinelflow.models.threat_intel import ThreatIntelResult


@dataclass(frozen=True)
class ThreatIntelLookupResult:
    results: list[ThreatIntelResult]
    errors: list[str]

    @property
    def partial(self) -> bool:
        return bool(self.results) and bool(self.errors)

    @property
    def successful(self) -> bool:
        return bool(self.results) and not self.errors