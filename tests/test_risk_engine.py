import pytest

from sentinelflow.models.risk import RiskSeverity
from sentinelflow.models.risk_policy import RiskPolicy
from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.models.threat_intel_lookup import ThreatIntelLookupResult
from sentinelflow.risk.engine import (
    assess_lookup_result,
    assess_risk,
)
from sentinelflow.models.behavior import (
    BehaviorSignal,
    BehaviorSignalType,
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
    

def test_assess_risk_behavior_can_increase_score():
    results = [
        ThreatIntelResult(
            indicator="203.0.113.10",
            provider="virustotal",
            malicious=True,
            score=60,
            confidence=90,
        )
    ]

    signals = [
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
            score=70,
            event_count=11,
            reason="11 unique HTTP paths requested",
        )
    ]

    assessment = assess_risk(
        results,
        behavior_signals=signals,
    )

    assert assessment.score == 78
    

def test_assess_risk_behavior_can_raise_severity():
    results = [
        ThreatIntelResult(
            indicator="203.0.113.10",
            provider="virustotal",
            malicious=True,
            score=60,
            confidence=90,
        )
    ]

    signals = [
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
            score=70,
            event_count=11,
            reason="11 unique HTTP paths requested",
        )
    ]

    assessment = assess_risk(
        results,
        behavior_signals=signals,
    )

    assert assessment.score == 78
    assert assessment.severity == RiskSeverity.CRITICAL
    

def test_assess_risk_uses_strongest_behavior_signal_only_for_uplift():
    results = [
        ThreatIntelResult(
            indicator="203.0.113.10",
            provider="virustotal",
            malicious=True,
            score=50,
            confidence=90,
        )
    ]

    signals = [
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.REPEATED_AUTH_FAILURES
            ),
            score=50,
            event_count=5,
            reason=(
                "5 authentication-related "
                "HTTP failures detected"
            ),
        ),
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.HIGH_404_RATE
            ),
            score=40,
            event_count=10,
            reason="10 HTTP 404 responses detected",
        ),
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
            score=70,
            event_count=11,
            reason="11 unique HTTP paths requested",
        ),
    ]

    assessment = assess_risk(
        results,
        behavior_signals=signals,
    )

    assert assessment.score == 68
    

def test_assess_risk_preserves_all_behavior_reasons():
    results = [
        ThreatIntelResult(
            indicator="203.0.113.10",
            provider="virustotal",
            malicious=False,
            score=20,
            confidence=90,
        )
    ]

    signals = [
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.HIGH_404_RATE
            ),
            score=40,
            event_count=10,
            reason="10 HTTP 404 responses detected",
        ),
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
            score=55,
            event_count=8,
            reason="8 unique HTTP paths requested",
        ),
    ]

    assessment = assess_risk(
        results,
        behavior_signals=signals,
    )

    assert len(assessment.reasons) == 3

    assert (
        "behavior:HIGH_404_RATE:"
        in assessment.reasons[1]
    )

    assert (
        "behavior:DIRECTORY_SCANNING:"
        in assessment.reasons[2]
    )
    

def test_assess_risk_rejects_behavior_from_other_indicator():
    results = [
        ThreatIntelResult(
            indicator="203.0.113.10",
            provider="virustotal",
            malicious=False,
            score=20,
            confidence=90,
        )
    ]

    signals = [
        BehaviorSignal(
            source_ip="203.0.113.20",
            signal_type=(
                BehaviorSignalType.HIGH_404_RATE
            ),
            score=40,
            event_count=10,
            reason="10 HTTP 404 responses detected",
        )
    ]

    with pytest.raises(
        ValueError,
        match=(
            "Behavior signals must belong "
            "to the assessed indicator"
        ),
    ):
        assess_risk(
            results,
            behavior_signals=signals,
        )
        
    
def test_assess_risk_behavior_score_is_capped_at_100():
    results = [
        ThreatIntelResult(
            indicator="203.0.113.10",
            provider="virustotal",
            malicious=True,
            score=90,
            confidence=100,
        )
    ]

    signals = [
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
            score=100,
            event_count=20,
            reason="20 unique HTTP paths requested",
        )
    ]

    assessment = assess_risk(
        results,
        behavior_signals=signals,
    )

    assert assessment.score == 100
    assert assessment.severity == RiskSeverity.CRITICAL
    

def test_assess_risk_without_behavior_keeps_existing_score():
    results = [
        ThreatIntelResult(
            indicator="203.0.113.10",
            provider="virustotal",
            malicious=True,
            score=60,
            confidence=90,
        )
    ]

    assessment = assess_risk(
        results
    )

    assert assessment.score == 60
    assert assessment.severity == RiskSeverity.HIGH
    

def test_assess_lookup_result_supports_behavior_signals():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="203.0.113.10",
                provider="virustotal",
                malicious=True,
                score=60,
                confidence=90,
            ),
        ],
        errors=[],
    )

    signals = [
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
            score=70,
            event_count=11,
            reason="11 unique HTTP paths requested",
        )
    ]

    assessment = assess_lookup_result(
        lookup,
        behavior_signals=signals,
    )

    assert assessment.score == 78
    assert assessment.severity == RiskSeverity.CRITICAL
    assert assessment.confidence == 90
    

def test_partial_lookup_keeps_behavior_score_and_reduces_ti_confidence():
    lookup = ThreatIntelLookupResult(
        results=[
            ThreatIntelResult(
                indicator="203.0.113.10",
                provider="virustotal",
                malicious=True,
                score=60,
                confidence=90,
            ),
        ],
        errors=[
            "abuseipdb: simulated failure",
        ],
    )

    signals = [
        BehaviorSignal(
            source_ip="203.0.113.10",
            signal_type=(
                BehaviorSignalType.DIRECTORY_SCANNING
            ),
            score=70,
            event_count=11,
            reason="11 unique HTTP paths requested",
        )
    ]

    assessment = assess_lookup_result(
        lookup,
        behavior_signals=signals,
    )

    assert assessment.score == 78
    assert assessment.severity == RiskSeverity.CRITICAL
    assert assessment.confidence == 45