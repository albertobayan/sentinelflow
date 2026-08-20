from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.threat_intel.provider import ThreatIntelProvider


class ThreatIntelService:
    def __init__(
        self,
        providers: list[ThreatIntelProvider],
    ) -> None:
        self.providers = providers

    def lookup(self, indicator: str) -> list[ThreatIntelResult]:
        results = []

        for provider in self.providers:
            result = provider.lookup(indicator)
            results.append(result)

        return results