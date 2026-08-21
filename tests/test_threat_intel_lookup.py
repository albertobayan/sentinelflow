from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.models.threat_intel_lookup import ThreatIntelLookupResult


def test_lookup_result_is_successful_with_results_and_no_errors():
    result = ThreatIntelResult(
        indicator="9.9.9.9",
        provider="test",
        malicious=False,
        score=10,
        confidence=90,
    )

    lookup = ThreatIntelLookupResult(
        results=[result],
        errors=[],
    )

    assert lookup.successful is True
    assert lookup.partial is False


def test_lookup_result_is_partial_with_results_and_errors():
    result = ThreatIntelResult(
        indicator="9.9.9.9",
        provider="test",
        malicious=False,
        score=10,
        confidence=90,
    )

    lookup = ThreatIntelLookupResult(
        results=[result],
        errors=[
            "other-provider: simulated failure",
        ],
    )

    assert lookup.successful is False
    assert lookup.partial is True


def test_lookup_result_with_only_errors_is_not_partial():
    lookup = ThreatIntelLookupResult(
        results=[],
        errors=[
            "provider: simulated failure",
        ],
    )

    assert lookup.successful is False
    assert lookup.partial is False


def test_lookup_result_with_no_results_or_errors_is_not_successful():
    lookup = ThreatIntelLookupResult(
        results=[],
        errors=[],
    )

    assert lookup.successful is False
    assert lookup.partial is False