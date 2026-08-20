from abc import ABC, abstractmethod

from sentinelflow.models.threat_intel import ThreatIntelResult


class ThreatIntelProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def lookup(self, indicator: str) -> ThreatIntelResult:
        raise NotImplementedError