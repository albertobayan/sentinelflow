from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.threat_intel.provider import ThreatIntelProvider


class LocalThreatIntelProvider(ThreatIntelProvider):
    @property
    def name(self) -> str:
        return "local"

    def lookup(self, indicator: str) -> ThreatIntelResult:
        normalized_indicator = indicator.strip()

        if normalized_indicator == "9.9.9.9":
            return ThreatIntelResult(
                indicator=normalized_indicator,
                provider=self.name,
                malicious=True,
                score=80,
                confidence=90,
            )

        return ThreatIntelResult(
            indicator=normalized_indicator,
            provider=self.name,
            malicious=False,
            score=10,
            confidence=70,
        )