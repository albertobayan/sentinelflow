import pytest

from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.threat_intel.provider import ThreatIntelProvider
from sentinelflow.threat_intel.local_provider import LocalThreatIntelProvider
from sentinelflow.threat_intel.service import ThreatIntelService
from sentinelflow.threat_intel.abuseipdb_provider import AbuseIPDBProvider
from sentinelflow.threat_intel.virustotal_provider import VirusTotalProvider


def test_threat_intel_result():
    result = ThreatIntelResult(
        indicator="9.9.9.9",
        provider="local",
        malicious=True,
        score=80,
        confidence=90,
    )

    assert result.indicator == "9.9.9.9"
    assert result.provider == "local"
    assert result.malicious is True
    assert result.score == 80
    assert result.confidence == 90


def test_threat_intel_result_can_represent_non_malicious_indicator():
    result = ThreatIntelResult(
        indicator="8.8.8.8",
        provider="local",
        malicious=False,
        score=10,
        confidence=80,
    )

    assert result.malicious is False
    assert result.score == 10
    assert result.confidence == 80


def test_threat_intel_result_is_immutable():
    result = ThreatIntelResult(
        indicator="9.9.9.9",
        provider="local",
        malicious=True,
        score=80,
        confidence=90,
    )

    with pytest.raises(AttributeError):
        result.score = 10
        

def test_threat_intel_provider_cannot_be_instantiated():
    with pytest.raises(TypeError):
        ThreatIntelProvider()


class TestProvider(ThreatIntelProvider):
    @property
    def name(self) -> str:
        return "test"

    def lookup(self, indicator: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            provider=self.name,
            malicious=False,
            score=10,
            confidence=80,
        )
        

def test_provider_implementation_returns_threat_intel_result():
    provider = TestProvider()

    result = provider.lookup("9.9.9.9")

    assert provider.name == "test"
    assert result.indicator == "9.9.9.9"
    assert result.provider == "test"
    assert result.malicious is False
    assert result.score == 10
    assert result.confidence == 80
    

def test_local_provider_name():
    provider = LocalThreatIntelProvider()

    assert provider.name == "local"
    

def test_local_provider_returns_malicious_result():
    provider = LocalThreatIntelProvider()

    result = provider.lookup("9.9.9.9")

    assert result.indicator == "9.9.9.9"
    assert result.provider == "local"
    assert result.malicious is True
    assert result.score == 80
    assert result.confidence == 90
    

def test_local_provider_returns_non_malicious_result():
    provider = LocalThreatIntelProvider()

    result = provider.lookup("8.8.8.8")

    assert result.indicator == "8.8.8.8"
    assert result.provider == "local"
    assert result.malicious is False
    assert result.score == 10
    assert result.confidence == 70
    

def test_local_provider_strips_indicator_whitespace():
    provider = LocalThreatIntelProvider()

    result = provider.lookup("   9.9.9.9   ")

    assert result.indicator == "9.9.9.9"
    assert result.malicious is True
    

def test_threat_intel_service_with_single_provider():
    provider = LocalThreatIntelProvider()

    service = ThreatIntelService(
        providers=[provider],
    )

    results = service.lookup("9.9.9.9")

    assert len(results) == 1

    result = results[0]

    assert result.indicator == "9.9.9.9"
    assert result.provider == "local"
    assert result.malicious is True
    assert result.score == 80
    assert result.confidence == 90
    

def test_threat_intel_service_with_no_providers():
    service = ThreatIntelService(
        providers=[],
    )

    results = service.lookup("9.9.9.9")

    assert results == []
    

def test_threat_intel_service_with_multiple_providers():
    local_provider = LocalThreatIntelProvider()
    test_provider = TestProvider()

    service = ThreatIntelService(
        providers=[
            local_provider,
            test_provider,
        ],
    )

    results = service.lookup("9.9.9.9")

    assert len(results) == 2

    assert results[0].provider == "local"
    assert results[1].provider == "test"
    

def test_threat_intel_service_preserves_indicator():
    service = ThreatIntelService(
        providers=[
            LocalThreatIntelProvider(),
            TestProvider(),
        ],
    )

    results = service.lookup("8.8.8.8")

    assert all(
        result.indicator == "8.8.8.8"
        for result in results
    )


def test_threat_intel_service_supports_real_provider_types(monkeypatch):
    virustotal = VirusTotalProvider("test-vt-key")
    abuseipdb = AbuseIPDBProvider("test-abuse-key")

    monkeypatch.setattr(
        virustotal,
        "lookup",
        lambda indicator: ThreatIntelResult(
            indicator=indicator,
            provider="virustotal",
            malicious=True,
            score=25,
            confidence=90,
        ),
    )

    monkeypatch.setattr(
        abuseipdb,
        "lookup",
        lambda indicator: ThreatIntelResult(
            indicator=indicator,
            provider="abuseipdb",
            malicious=True,
            score=80,
            confidence=100,
        ),
    )

    service = ThreatIntelService(
        providers=[
            virustotal,
            abuseipdb,
        ]
    )

    results = service.lookup("9.9.9.9")

    assert len(results) == 2

    assert results[0].provider == "virustotal"
    assert results[0].score == 25

    assert results[1].provider == "abuseipdb"
    assert results[1].score == 80