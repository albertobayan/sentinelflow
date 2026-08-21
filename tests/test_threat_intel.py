import pytest

from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.threat_intel.provider import ThreatIntelProvider
from sentinelflow.threat_intel.local_provider import LocalThreatIntelProvider
from sentinelflow.threat_intel.service import ThreatIntelService
from sentinelflow.threat_intel.abuseipdb_provider import AbuseIPDBProvider
from sentinelflow.threat_intel.virustotal_provider import VirusTotalProvider
from sentinelflow.threat_intel.exceptions import ThreatIntelError
from sentinelflow.threat_intel.cache import ThreatIntelCache


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
    

class FailingProvider(ThreatIntelProvider):
    @property
    def name(self) -> str:
        return "failing"

    def lookup(self, indicator: str) -> ThreatIntelResult:
        raise ThreatIntelError(
            "Simulated provider failure"
        )
        

def test_threat_intel_service_continues_when_provider_fails():
    service = ThreatIntelService(
        providers=[
            FailingProvider(),
            LocalThreatIntelProvider(),
        ]
    )

    results = service.lookup("9.9.9.9")

    assert len(results) == 1
    assert results[0].provider == "local"
    

def test_threat_intel_service_keeps_results_before_provider_failure():
    service = ThreatIntelService(
        providers=[
            LocalThreatIntelProvider(),
            FailingProvider(),
        ]
    )

    results = service.lookup("9.9.9.9")

    assert len(results) == 1
    assert results[0].provider == "local"
    

def test_threat_intel_service_returns_empty_list_when_all_providers_fail():
    service = ThreatIntelService(
        providers=[
            FailingProvider(),
            FailingProvider(),
        ]
    )

    results = service.lookup("9.9.9.9")

    assert results == []
    

class BrokenProvider(ThreatIntelProvider):
    @property
    def name(self) -> str:
        return "broken"

    def lookup(self, indicator: str) -> ThreatIntelResult:
        raise RuntimeError(
            "Unexpected programming error"
        )
        
def test_threat_intel_service_does_not_hide_unexpected_errors():
    service = ThreatIntelService(
        providers=[
            BrokenProvider(),
        ]
    )

    with pytest.raises(
        RuntimeError,
        match="Unexpected programming error",
    ):
        service.lookup("9.9.9.9")


def test_lookup_with_status_returns_successful_result():
    service = ThreatIntelService(
        providers=[
            LocalThreatIntelProvider(),
        ]
    )

    lookup = service.lookup_with_status("9.9.9.9")

    assert len(lookup.results) == 1
    assert lookup.errors == []
    assert lookup.successful is True
    assert lookup.partial is False
    

def test_lookup_with_status_reports_partial_failure():
    service = ThreatIntelService(
        providers=[
            LocalThreatIntelProvider(),
            FailingProvider(),
        ]
    )

    lookup = service.lookup_with_status("9.9.9.9")

    assert len(lookup.results) == 1
    assert lookup.results[0].provider == "local"

    assert len(lookup.errors) == 1
    assert lookup.errors[0] == (
        "failing: Simulated provider failure"
    )

    assert lookup.partial is True
    assert lookup.successful is False
    

def test_lookup_with_status_reports_all_provider_failures():
    service = ThreatIntelService(
        providers=[
            FailingProvider(),
            FailingProvider(),
        ]
    )

    lookup = service.lookup_with_status("9.9.9.9")

    assert lookup.results == []

    assert len(lookup.errors) == 2

    assert lookup.successful is False
    assert lookup.partial is False
    

def test_lookup_with_status_handles_no_providers():
    service = ThreatIntelService(
        providers=[],
    )

    lookup = service.lookup_with_status("9.9.9.9")

    assert lookup.results == []
    assert lookup.errors == []
    assert lookup.successful is False
    assert lookup.partial is False
    

def test_lookup_still_returns_only_results():
    service = ThreatIntelService(
        providers=[
            LocalThreatIntelProvider(),
            FailingProvider(),
        ]
    )

    results = service.lookup("9.9.9.9")

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].provider == "local"
    

class CountingProvider(ThreatIntelProvider):
    def __init__(self) -> None:
        self.calls = 0

    @property
    def name(self) -> str:
        return "counting"

    def lookup(self, indicator: str) -> ThreatIntelResult:
        self.calls += 1

        return ThreatIntelResult(
            indicator=indicator,
            provider=self.name,
            malicious=False,
            score=10,
            confidence=90,
        )
        

def test_threat_intel_service_uses_cached_result():
    provider = CountingProvider()
    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[provider],
        cache=cache,
    )

    first_lookup = service.lookup_with_status(
        "9.9.9.9"
    )

    second_lookup = service.lookup_with_status(
        "9.9.9.9"
    )

    assert first_lookup == second_lookup
    assert provider.calls == 1
    assert len(cache) == 1
    
    
def test_threat_intel_service_without_cache_queries_provider_every_time():
    provider = CountingProvider()

    service = ThreatIntelService(
        providers=[provider],
    )

    service.lookup_with_status("9.9.9.9")
    service.lookup_with_status("9.9.9.9")

    assert provider.calls == 2
    

def test_threat_intel_service_cache_normalizes_indicator_whitespace():
    provider = CountingProvider()
    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[provider],
        cache=cache,
    )

    service.lookup_with_status(
        "   9.9.9.9   "
    )

    service.lookup_with_status(
        "9.9.9.9"
    )

    assert provider.calls == 1
    

def test_lookup_uses_cache():
    provider = CountingProvider()
    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[provider],
        cache=cache,
    )

    first_results = service.lookup(
        "9.9.9.9"
    )

    second_results = service.lookup(
        "9.9.9.9"
    )

    assert first_results == second_results
    assert provider.calls == 1
    

def test_cache_prevents_repeated_multi_provider_lookups():
    first_provider = CountingProvider()
    second_provider = CountingProvider()

    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[
            first_provider,
            second_provider,
        ],
        cache=cache,
    )

    service.lookup_with_status("9.9.9.9")
    service.lookup_with_status("9.9.9.9")

    assert first_provider.calls == 1
    assert second_provider.calls == 1
    

def test_partial_lookup_result_can_be_cached():
    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[
            LocalThreatIntelProvider(),
            FailingProvider(),
        ],
        cache=cache,
    )

    first_lookup = service.lookup_with_status(
        "9.9.9.9"
    )

    second_lookup = service.lookup_with_status(
        "9.9.9.9"
    )

    assert first_lookup == second_lookup
    assert second_lookup.partial is True
    assert len(second_lookup.results) == 1
    assert len(second_lookup.errors) == 1
    

def test_service_populates_empty_cache():
    provider = CountingProvider()
    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[provider],
        cache=cache,
    )

    assert len(cache) == 0

    service.lookup_with_status(
        "9.9.9.9"
    )

    assert len(cache) == 1
    

def test_service_queries_provider_again_after_cache_expiration(
    monkeypatch,
):
    current_time = 100.0

    monkeypatch.setattr(
        "sentinelflow.threat_intel.cache.time.monotonic",
        lambda: current_time,
    )

    provider = CountingProvider()

    cache = ThreatIntelCache(
        ttl_seconds=60,
    )

    service = ThreatIntelService(
        providers=[provider],
        cache=cache,
    )

    service.lookup_with_status(
        "9.9.9.9"
    )

    assert provider.calls == 1

    current_time = 150.0

    service.lookup_with_status(
        "9.9.9.9"
    )

    assert provider.calls == 1

    current_time = 161.0

    service.lookup_with_status(
        "9.9.9.9"
    )

    assert provider.calls == 2
    

class CountingFailingProvider(ThreatIntelProvider):
    def __init__(self) -> None:
        self.calls = 0

    @property
    def name(self) -> str:
        return "counting-failing"

    def lookup(
        self,
        indicator: str,
    ) -> ThreatIntelResult:
        self.calls += 1

        raise ThreatIntelError(
            "Simulated provider failure"
        )
        

def test_partial_lookup_result_is_not_cached():
    successful_provider = CountingProvider()
    failing_provider = CountingFailingProvider()

    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[
            successful_provider,
            failing_provider,
        ],
        cache=cache,
    )

    first_lookup = service.lookup_with_status(
        "9.9.9.9"
    )

    assert first_lookup.partial is True
    assert len(first_lookup.results) == 1
    assert len(first_lookup.errors) == 1

    assert len(cache) == 0

    second_lookup = service.lookup_with_status(
        "9.9.9.9"
    )

    assert second_lookup.partial is True

    assert successful_provider.calls == 2
    assert failing_provider.calls == 2

    assert len(cache) == 0
    

def test_complete_provider_failure_is_not_cached():
    first_provider = CountingFailingProvider()
    second_provider = CountingFailingProvider()

    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[
            first_provider,
            second_provider,
        ],
        cache=cache,
    )

    first_lookup = service.lookup_with_status(
        "9.9.9.9"
    )

    assert first_lookup.results == []
    assert len(first_lookup.errors) == 2

    assert first_lookup.successful is False
    assert first_lookup.partial is False

    assert len(cache) == 0

    service.lookup_with_status(
        "9.9.9.9"
    )

    assert first_provider.calls == 2
    assert second_provider.calls == 2

    assert len(cache) == 0
    

def test_lookup_with_no_providers_is_not_cached():
    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[],
        cache=cache,
    )

    lookup = service.lookup_with_status(
        "9.9.9.9"
    )

    assert lookup.results == []
    assert lookup.errors == []
    assert lookup.successful is False
    assert lookup.partial is False

    assert len(cache) == 0
    

def test_lookup_with_status_rejects_empty_indicator():
    service = ThreatIntelService(
        providers=[
            LocalThreatIntelProvider(),
        ]
    )

    with pytest.raises(
        ValueError,
        match="Indicator cannot be empty",
    ):
        service.lookup_with_status("")
        

def test_lookup_with_status_rejects_whitespace_indicator():
    service = ThreatIntelService(
        providers=[
            LocalThreatIntelProvider(),
        ]
    )

    with pytest.raises(
        ValueError,
        match="Indicator cannot be empty",
    ):
        service.lookup_with_status("   ")
        

def test_lookup_rejects_empty_indicator():
    service = ThreatIntelService(
        providers=[
            LocalThreatIntelProvider(),
        ]
    )

    with pytest.raises(
        ValueError,
        match="Indicator cannot be empty",
    ):
        service.lookup("")
        

def test_empty_indicator_is_not_cached():
    provider = CountingProvider()
    cache = ThreatIntelCache()

    service = ThreatIntelService(
        providers=[provider],
        cache=cache,
    )

    with pytest.raises(
        ValueError,
        match="Indicator cannot be empty",
    ):
        service.lookup_with_status("   ")

    assert provider.calls == 0
    assert len(cache) == 0