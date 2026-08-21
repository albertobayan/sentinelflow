import time
from dataclasses import dataclass

from sentinelflow.models.threat_intel_lookup import ThreatIntelLookupResult


@dataclass(frozen=True)
class CacheEntry:
    result: ThreatIntelLookupResult
    created_at: float


class ThreatIntelCache:
    def __init__(
        self,
        ttl_seconds: float = 300.0,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError(
                "Cache TTL must be greater than 0"
            )

        self.ttl_seconds = ttl_seconds
        self._data: dict[str, CacheEntry] = {}

    def _normalize_indicator(self, indicator: str) -> str:
        return indicator.strip()

    def _is_expired(self, entry: CacheEntry) -> bool:
        age = time.monotonic() - entry.created_at

        return age >= self.ttl_seconds

    def get(
        self,
        indicator: str,
    ) -> ThreatIntelLookupResult | None:
        normalized_indicator = self._normalize_indicator(
            indicator
        )

        entry = self._data.get(normalized_indicator)

        if entry is None:
            return None

        if self._is_expired(entry):
            del self._data[normalized_indicator]
            return None

        return entry.result

    def set(
        self,
        indicator: str,
        result: ThreatIntelLookupResult,
    ) -> None:
        normalized_indicator = self._normalize_indicator(
            indicator
        )

        self._data[normalized_indicator] = CacheEntry(
            result=result,
            created_at=time.monotonic(),
        )

    def contains(self, indicator: str) -> bool:
        return self.get(indicator) is not None

    def clear(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)