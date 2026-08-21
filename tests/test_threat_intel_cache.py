import pytest

from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.models.threat_intel_lookup import ThreatIntelLookupResult
from sentinelflow.threat_intel.cache import ThreatIntelCache


def create_lookup_result() -> ThreatIntelLookupResult:
    result = ThreatIntelResult(
        indicator="9.9.9.9",
        provider="test",
        malicious=True,
        score=80,
        confidence=90,
    )

    return ThreatIntelLookupResult(
        results=[result],
        errors=[],
    )


def test_cache_starts_empty():
    cache = ThreatIntelCache()

    assert len(cache) == 0


def test_cache_returns_none_for_missing_indicator():
    cache = ThreatIntelCache()

    assert cache.get("9.9.9.9") is None


def test_cache_stores_lookup_result():
    cache = ThreatIntelCache()
    lookup_result = create_lookup_result()

    cache.set(
        "9.9.9.9",
        lookup_result,
    )

    assert cache.get("9.9.9.9") == lookup_result


def test_cache_contains_stored_indicator():
    cache = ThreatIntelCache()
    lookup_result = create_lookup_result()

    cache.set(
        "9.9.9.9",
        lookup_result,
    )

    assert cache.contains("9.9.9.9") is True


def test_cache_does_not_contain_missing_indicator():
    cache = ThreatIntelCache()

    assert cache.contains("9.9.9.9") is False


def test_cache_normalizes_indicator_whitespace():
    cache = ThreatIntelCache()
    lookup_result = create_lookup_result()

    cache.set(
        "   9.9.9.9   ",
        lookup_result,
    )

    assert cache.contains("9.9.9.9") is True
    assert cache.get("9.9.9.9") == lookup_result


def test_cache_overwrites_existing_indicator():
    cache = ThreatIntelCache()

    first_result = create_lookup_result()

    second_result = ThreatIntelLookupResult(
        results=[],
        errors=[
            "test: simulated failure",
        ],
    )

    cache.set(
        "9.9.9.9",
        first_result,
    )

    cache.set(
        "9.9.9.9",
        second_result,
    )

    assert cache.get("9.9.9.9") == second_result
    assert len(cache) == 1


def test_cache_clear_removes_all_entries():
    cache = ThreatIntelCache()

    cache.set(
        "9.9.9.9",
        create_lookup_result(),
    )

    cache.clear()

    assert len(cache) == 0
    assert cache.get("9.9.9.9") is None
    

def test_cache_default_ttl():
    cache = ThreatIntelCache()

    assert cache.ttl_seconds == 300.0
    

def test_cache_accepts_custom_ttl():
    cache = ThreatIntelCache(
        ttl_seconds=60,
    )

    assert cache.ttl_seconds == 60
    

def test_cache_rejects_zero_ttl():
    with pytest.raises(
        ValueError,
        match="Cache TTL must be greater than 0",
    ):
        ThreatIntelCache(
            ttl_seconds=0,
        )
        

def test_cache_rejects_negative_ttl():
    with pytest.raises(
        ValueError,
        match="Cache TTL must be greater than 0",
    ):
        ThreatIntelCache(
            ttl_seconds=-1,
        )
        

def test_cache_returns_none_after_entry_expires(monkeypatch):
    current_time = 100.0

    monkeypatch.setattr(
        "sentinelflow.threat_intel.cache.time.monotonic",
        lambda: current_time,
    )

    cache = ThreatIntelCache(
        ttl_seconds=60,
    )

    cache.set(
        "9.9.9.9",
        create_lookup_result(),
    )

    current_time = 161.0

    assert cache.get("9.9.9.9") is None
    

def test_cache_returns_result_before_entry_expires(monkeypatch):
    current_time = 100.0

    monkeypatch.setattr(
        "sentinelflow.threat_intel.cache.time.monotonic",
        lambda: current_time,
    )

    cache = ThreatIntelCache(
        ttl_seconds=60,
    )

    lookup_result = create_lookup_result()

    cache.set(
        "9.9.9.9",
        lookup_result,
    )

    current_time = 159.0

    assert cache.get("9.9.9.9") == lookup_result
    

def test_cache_expires_entry_exactly_at_ttl(monkeypatch):
    current_time = 100.0

    monkeypatch.setattr(
        "sentinelflow.threat_intel.cache.time.monotonic",
        lambda: current_time,
    )

    cache = ThreatIntelCache(
        ttl_seconds=60,
    )

    cache.set(
        "9.9.9.9",
        create_lookup_result(),
    )

    current_time = 160.0

    assert cache.get("9.9.9.9") is None
    

def test_expired_entry_is_removed_from_cache(monkeypatch):
    current_time = 100.0

    monkeypatch.setattr(
        "sentinelflow.threat_intel.cache.time.monotonic",
        lambda: current_time,
    )

    cache = ThreatIntelCache(
        ttl_seconds=60,
    )

    cache.set(
        "9.9.9.9",
        create_lookup_result(),
    )

    assert len(cache) == 1

    current_time = 161.0

    assert cache.get("9.9.9.9") is None
    assert len(cache) == 0
    

def test_cache_contains_returns_false_for_expired_entry(monkeypatch):
    current_time = 100.0

    monkeypatch.setattr(
        "sentinelflow.threat_intel.cache.time.monotonic",
        lambda: current_time,
    )

    cache = ThreatIntelCache(
        ttl_seconds=60,
    )

    cache.set(
        "9.9.9.9",
        create_lookup_result(),
    )

    current_time = 161.0

    assert cache.contains("9.9.9.9") is False
    

