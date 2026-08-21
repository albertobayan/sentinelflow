from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.models.threat_intel_lookup import ThreatIntelLookupResult
from sentinelflow.threat_intel.cache import ThreatIntelCache
from sentinelflow.threat_intel.exceptions import ThreatIntelError
from sentinelflow.threat_intel.provider import ThreatIntelProvider


class ThreatIntelService:
    def __init__(
        self,
        providers: list[ThreatIntelProvider],
        cache: ThreatIntelCache | None = None,
    ) -> None:
        self.providers = providers
        self.cache = cache

    def lookup(
        self,
        indicator: str,
    ) -> list[ThreatIntelResult]:
        lookup_result = self.lookup_with_status(
            indicator
        )

        return lookup_result.results

    def lookup_with_status(
        self,
        indicator: str,
    ) -> ThreatIntelLookupResult:
        normalized_indicator = indicator.strip()

        if not normalized_indicator:
            raise ValueError(
                "Indicator cannot be empty"
            )

        if self.cache is not None:
            cached_result = self.cache.get(
                normalized_indicator
            )

            if cached_result is not None:
                return cached_result

        results = []
        errors = []

        for provider in self.providers:
            try:
                result = provider.lookup(
                    normalized_indicator
                )

            except ThreatIntelError as exc:
                errors.append(
                    f"{provider.name}: {exc}"
                )
                continue

            results.append(result)

        lookup_result = ThreatIntelLookupResult(
            results=results,
            errors=errors,
        )

        if (
            self.cache is not None
            and lookup_result.successful
        ):
            self.cache.set(
                normalized_indicator,
                lookup_result,
            )

        return lookup_result