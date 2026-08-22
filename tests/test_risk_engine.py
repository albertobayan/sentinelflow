import pytest

from sentinelflow.models.risk import RiskSeverity
from sentinelflow.models.risk_policy import RiskPolicy
from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.models.threat_intel_lookup import ThreatIntelLookupResult
from sentinelflow.risk.engine import (
    assess_lookup_result,
    assess_risk,
)


def test_assess_risk_builds_complete_assessment():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=True,
            score=30,
            confidence=80,
        ),
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="abuseipdb",
            malicious=True,
            score=70,
            confidence=100,
        ),
    ]

    assessment = assess_risk(results)

    assert assessment.indicator == "9.9.9.9"
    assert assessment.score == 52
    assert assessment.severity == RiskSeverity.HIGH
    assert assessment.confidence == 90
    assert len(assessment.reasons) == 2
    

def test_assess_risk_can_return_low_severity():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=False,
            score=10,
            confidence=90,
        ),
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="abuseipdb",
            malicious=False,
            score=20,
            confidence=100,
        ),
    ]

    assessment = assess_risk(results)

    assert assessment.score == 15
    assert assessment.severity == RiskSeverity.LOW
    assert assessment.confidence == 95
    

def test_assess_risk_can_return_critical_severity():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=True,
            score=80,
            confidence=100,
        ),
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="abuseipdb",
            malicious=True,
            score=90,
            confidence=100,
        ),
    ]

    assessment = assess_risk(results)

    assert assessment.score == 85
    assert assessment.severity == RiskSeverity.CRITICAL
    assert assessment.confidence == 100
    

def test_assess_risk_supports_single_provider():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=True,
            score=60,
            confidence=75,
        )
    ]

    assessment = assess_risk(results)

    assert assessment.score == 60
    assert assessment.severity == RiskSeverity.HIGH
    assert assessment.confidence == 75
    

def test_assess_risk_rejects_empty_results():
    with pytest.raises(
        ValueError,
        match="At least one Threat Intelligence result is required",
    ):
        assess_risk([])
        

def test_assess_risk_rejects_mixed_indicators():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=False,
            score=20,
            confidence=90,
        ),
        ThreatIntelResult(
            indicator="1.1.1.1",
            provider="abuseipdb",
            malicious=True,
            score=80,
            confidence=100,
        ),
    ]

    with pytest.raises(
        ValueError,
        match=(
            "Threat Intelligence results must belong "
            "to the same indicator"
        ),
    ):
        assess_risk(results)
        
        
def test_assess_risk_normalizes_indicator():
    results = [
        ThreatIntelResult(
            indicator="   9.9.9.9   ",
            provider="virustotal",
            malicious=False,
            score=20,
            confidence=90,
        )
    ]

    assessment = assess_risk(results)

    assert assessment.indicator == "9.9.9.9"
    

def test_assess_risk_includes_provider_reasons():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=True,
            score=70,
            confidence=90,
        ),
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="abuseipdb",
            malicious=False,
            score=20,
            confidence=100,
        ),
    ]

    assessment = assess_risk(results)

    assert assessment.reasons == (
        (
            "virustotal: score=70, "
            "confidence=90, "
            "status=malicious"
        ),
        (
            "abuseipdb: score=20, "
            "confidence=100, "
            "status=not malicious"
        ),
    )


def test_assess_lookup_result_handles_complete_lookup():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="virustotal",
                malicious=True,
                score=30,
                confidence=80,
            ),
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="abuseipdb",
                malicious=True,
                score=70,
                confidence=100,
            ),
        ],
        errors=[],
    )

    assessment = assess_lookup_result(
        lookup
    )

    assert assessment.indicator == "9.9.9.9"
    assert assessment.score == 52
    assert assessment.severity == RiskSeverity.HIGH
    assert assessment.confidence == 90
    assert len(assessment.reasons) == 2
    

def test_assess_lookup_result_reduces_confidence_when_partial():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="virustotal",
                malicious=True,
                score=70,
                confidence=90,
            ),
        ],
        errors=[
            "abuseipdb: AbuseIPDB request timed out",
        ],
    )

    assessment = assess_lookup_result(
        lookup
    )

    assert assessment.score == 70
    assert assessment.severity == RiskSeverity.HIGH
    assert assessment.confidence == 45
    

def test_assess_lookup_result_adds_provider_errors_to_reasons():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="virustotal",
                malicious=True,
                score=70,
                confidence=90,
            ),
        ],
        errors=[
            "abuseipdb: AbuseIPDB request timed out",
        ],
    )

    assessment = assess_lookup_result(
        lookup
    )

    assert assessment.reasons == (
        (
            "virustotal: score=70, "
            "confidence=90, "
            "status=malicious"
        ),
        (
            "Threat Intelligence provider error: "
            "abuseipdb: AbuseIPDB request timed out"
        ),
    )
    

def test_partial_lookup_errors_do_not_change_risk_score():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="virustotal",
                malicious=True,
                score=80,
                confidence=100,
            ),
        ],
        errors=[
            "abuseipdb: simulated failure",
        ],
    )

    assessment = assess_lookup_result(
        lookup
    )

    assert assessment.score == 80
    assert assessment.severity == RiskSeverity.CRITICAL
    assert assessment.confidence == 50
    

def test_assess_lookup_result_rejects_complete_failure():
    lookup = ThreatIntelLookupResult(
        results=[],
        errors=[
            "virustotal: simulated failure",
            "abuseipdb: simulated failure",
        ],
    )

    with pytest.raises(
        ValueError,
        match=(
            "Cannot assess risk without "
            "Threat Intelligence results"
        ),
    ):
        assess_lookup_result(lookup)
        
    
def test_assess_lookup_result_rejects_empty_lookup():
    lookup = ThreatIntelLookupResult(
        results=[],
        errors=[],
    )

    with pytest.raises(
        ValueError,
        match=(
            "Cannot assess risk without "
            "Threat Intelligence results"
        ),
    ):
        assess_lookup_result(lookup)
        

def test_assess_risk_uses_provider_weights_from_policy():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=True,
            score=80,
            confidence=90,
        ),
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="abuseipdb",
            malicious=True,
            score=60,
            confidence=100,
        ),
    ]

    policy = RiskPolicy(
        provider_weights={
            "virustotal": 1.2,
            "abuseipdb": 0.8,
        }
    )

    assessment = assess_risk(
        results,
        policy=policy,
    )

    assert assessment.score == 71
    

def test_assess_risk_uses_provider_weights_from_policy():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=True,
            score=80,
            confidence=90,
        ),
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="abuseipdb",
            malicious=True,
            score=60,
            confidence=100,
        ),
    ]

    policy = RiskPolicy(
        provider_weights={
            "virustotal": 1.2,
            "abuseipdb": 0.8,
        }
    )

    assessment = assess_risk(
        results,
        policy=policy,
    )

    assert assessment.score == 71
    

def test_assess_risk_uses_same_policy_for_scoring_and_severity():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=True,
            score=80,
            confidence=90,
        ),
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="abuseipdb",
            malicious=True,
            score=60,
            confidence=100,
        ),
    ]

    policy = RiskPolicy(
        medium_threshold=20,
        high_threshold=40,
        critical_threshold=70,
        provider_weights={
            "virustotal": 1.2,
            "abuseipdb": 0.8,
        },
    )

    assessment = assess_risk(
        results,
        policy=policy,
    )

    assert assessment.score == 71
    assert assessment.severity == RiskSeverity.CRITICAL
    

def test_assess_risk_without_policy_keeps_default_behavior():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=True,
            score=70,
            confidence=100,
        )
    ]

    assessment = assess_risk(
        results
    )

    assert assessment.score == 70
    assert assessment.severity == RiskSeverity.HIGH


def test_assess_lookup_result_uses_custom_policy():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="virustotal",
                malicious=True,
                score=80,
                confidence=90,
            ),
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="abuseipdb",
                malicious=True,
                score=60,
                confidence=100,
            ),
        ],
        errors=[],
    )

    policy = RiskPolicy(
        medium_threshold=20,
        high_threshold=40,
        critical_threshold=70,
        provider_weights={
            "virustotal": 1.2,
            "abuseipdb": 0.8,
        },
    )

    assessment = assess_lookup_result(
        lookup,
        policy=policy,
    )

    assert assessment.score == 71
    assert assessment.severity == RiskSeverity.CRITICAL
    assert assessment.confidence == 95
    

def test_partial_lookup_uses_weighted_provider_coverage():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="virustotal",
                malicious=True,
                score=70,
                confidence=90,
            ),
        ],
        errors=[
            "abuseipdb: simulated failure",
        ],
    )

    policy = RiskPolicy(
        medium_threshold=20,
        high_threshold=40,
        critical_threshold=70,
        provider_weights={
            "virustotal": 2.0,
            "abuseipdb": 1.0,
        },
    )

    assessment = assess_lookup_result(
        lookup,
        policy=policy,
    )

    assert assessment.score == 70
    assert assessment.severity == RiskSeverity.CRITICAL
    assert assessment.confidence == 60
    

def test_partial_lookup_higher_weight_success_gives_more_coverage():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="provider-a",
                malicious=True,
                score=70,
                confidence=90,
            ),
        ],
        errors=[
            "provider-b: simulated failure",
        ],
    )

    policy = RiskPolicy(
        provider_weights={
            "provider-a": 2.0,
            "provider-b": 1.0,
        }
    )

    assessment = assess_lookup_result(
        lookup,
        policy=policy,
    )

    assert assessment.confidence == 60
    

def test_partial_lookup_higher_weight_failure_reduces_coverage_more():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="provider-b",
                malicious=True,
                score=70,
                confidence=90,
            ),
        ],
        errors=[
            "provider-a: simulated failure",
        ],
    )

    policy = RiskPolicy(
        provider_weights={
            "provider-a": 2.0,
            "provider-b": 1.0,
        }
    )

    assessment = assess_lookup_result(
        lookup,
        policy=policy,
    )

    assert assessment.confidence == 30
    

def test_partial_lookup_equal_provider_weights_keep_half_coverage():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="provider-a",
                malicious=False,
                score=20,
                confidence=80,
            ),
        ],
        errors=[
            "provider-b: simulated failure",
        ],
    )

    policy = RiskPolicy(
        provider_weights={
            "provider-a": 1.0,
            "provider-b": 1.0,
        }
    )

    assessment = assess_lookup_result(
        lookup,
        policy=policy,
    )

    assert assessment.confidence == 40
    

def test_partial_lookup_unconfigured_failed_provider_uses_default_weight():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="virustotal",
                malicious=True,
                score=70,
                confidence=90,
            ),
        ],
        errors=[
            "unknown-provider: simulated failure",
        ],
    )

    policy = RiskPolicy(
        provider_weights={
            "virustotal": 2.0,
        }
    )

    assessment = assess_lookup_result(
        lookup,
        policy=policy,
    )

    assert assessment.confidence == 60
    

def test_partial_lookup_provider_weights_are_case_insensitive():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="VirusTotal",
                malicious=True,
                score=70,
                confidence=90,
            ),
        ],
        errors=[
            "ABUSEIPDB: simulated failure",
        ],
    )

    policy = RiskPolicy(
        provider_weights={
            "virustotal": 2.0,
            "abuseipdb": 1.0,
        }
    )

    assessment = assess_lookup_result(
        lookup,
        policy=policy,
    )

    assert assessment.confidence == 60
    

def test_partial_lookup_unknown_error_uses_neutral_failure_weight():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="virustotal",
                malicious=True,
                score=70,
                confidence=90,
            ),
        ],
        errors=[
            "",
        ],
    )

    policy = RiskPolicy(
        provider_weights={
            "virustotal": 2.0,
        }
    )

    assessment = assess_lookup_result(
        lookup,
        policy=policy,
    )

    assert assessment.confidence == 60
    

def test_partial_lookup_coverage_supports_multiple_successful_providers():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="provider-a",
                malicious=True,
                score=80,
                confidence=90,
            ),
            ThreatIntelResult(
                indicator="9.9.9.9",
                provider="provider-b",
                malicious=False,
                score=20,
                confidence=90,
            ),
        ],
        errors=[
            "provider-c: simulated failure",
        ],
    )

    policy = RiskPolicy(
        provider_weights={
            "provider-a": 2.0,
            "provider-b": 1.0,
            "provider-c": 1.0,
        }
    )

    assessment = assess_lookup_result(
        lookup,
        policy=policy,
    )

    assert assessment.confidence == 68