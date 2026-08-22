import pytest

from sentinelflow.models.risk_policy import RiskPolicy
from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.risk.scoring import (
    calculate_base_risk_score,
    calculate_risk_confidence,
    calculate_weighted_risk_score,
)


def create_result(
    provider: str,
    score: int,
    confidence: int = 100,
) -> ThreatIntelResult:
    return ThreatIntelResult(
        indicator="9.9.9.9",
        provider=provider,
        malicious=score >= 50,
        score=score,
        confidence=confidence,
    )


def test_base_risk_score_with_single_provider():
    results = [
        create_result(
            provider="virustotal",
            score=80,
        )
    ]

    assert calculate_base_risk_score(results) == 80


def test_base_risk_score_averages_two_providers():
    results = [
        create_result(
            provider="virustotal",
            score=20,
        ),
        create_result(
            provider="abuseipdb",
            score=80,
        ),
    ]

    assert calculate_base_risk_score(results) == 50


def test_base_risk_score_averages_multiple_providers():
    results = [
        create_result(
            provider="provider-a",
            score=10,
        ),
        create_result(
            provider="provider-b",
            score=40,
        ),
        create_result(
            provider="provider-c",
            score=70,
        ),
    ]

    assert calculate_base_risk_score(results) == 40


def test_base_risk_score_handles_all_zero_scores():
    results = [
        create_result(
            provider="virustotal",
            score=0,
        ),
        create_result(
            provider="abuseipdb",
            score=0,
        ),
    ]

    assert calculate_base_risk_score(results) == 0


def test_base_risk_score_handles_all_maximum_scores():
    results = [
        create_result(
            provider="virustotal",
            score=100,
        ),
        create_result(
            provider="abuseipdb",
            score=100,
        ),
    ]

    assert calculate_base_risk_score(results) == 100


def test_base_risk_score_rounds_half_up():
    results = [
        create_result(
            provider="provider-a",
            score=50,
        ),
        create_result(
            provider="provider-b",
            score=51,
        ),
    ]

    assert calculate_base_risk_score(results) == 51


def test_base_risk_score_rounds_down_below_half():
    results = [
        create_result(
            provider="provider-a",
            score=50,
        ),
        create_result(
            provider="provider-b",
            score=50,
        ),
        create_result(
            provider="provider-c",
            score=51,
        ),
    ]

    assert calculate_base_risk_score(results) == 50


def test_base_risk_score_rejects_empty_results():
    with pytest.raises(
        ValueError,
        match="At least one Threat Intelligence result is required",
    ):
        calculate_base_risk_score([])
        

def test_base_risk_score_rejects_mixed_indicators():
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
        calculate_base_risk_score(results)
        
        
def test_base_risk_score_normalizes_indicator_whitespace():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=False,
            score=20,
            confidence=90,
        ),
        ThreatIntelResult(
            indicator="   9.9.9.9   ",
            provider="abuseipdb",
            malicious=True,
            score=80,
            confidence=100,
        ),
    ]

    assert calculate_base_risk_score(results) == 50
    
    
def test_base_risk_score_rejects_negative_provider_score():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="test",
            malicious=False,
            score=-1,
            confidence=90,
        )
    ]

    with pytest.raises(
        ValueError,
        match="Threat Intelligence score must be between 0 and 100",
    ):
        calculate_base_risk_score(results)
        

def test_base_risk_score_rejects_provider_score_above_100():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="test",
            malicious=True,
            score=101,
            confidence=90,
        )
    ]

    with pytest.raises(
        ValueError,
        match="Threat Intelligence score must be between 0 and 100",
    ):
        calculate_base_risk_score(results)
        

def test_base_risk_score_rejects_non_integer_provider_score():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="test",
            malicious=True,
            score=80.5,
            confidence=90,
        )
    ]

    with pytest.raises(
        TypeError,
        match="Threat Intelligence score must be an integer",
    ):
        calculate_base_risk_score(results)
        
        
def test_base_risk_score_rejects_boolean_provider_score():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="test",
            malicious=True,
            score=True,
            confidence=90,
        )
    ]

    with pytest.raises(
        TypeError,
        match="Threat Intelligence score must be an integer",
    ):
        calculate_base_risk_score(results)
        

def test_weighted_risk_score_uses_confidence():
    results = [
        create_result(
            provider="virustotal",
            score=90,
            confidence=10,
        ),
        create_result(
            provider="abuseipdb",
            score=30,
            confidence=100,
        ),
    ]

    assert calculate_weighted_risk_score(results) == 35
    

def test_weighted_risk_score_matches_average_when_confidence_is_equal():
    results = [
        create_result(
            provider="virustotal",
            score=20,
            confidence=100,
        ),
        create_result(
            provider="abuseipdb",
            score=80,
            confidence=100,
        ),
    ]

    assert calculate_weighted_risk_score(results) == 50
    
    
def test_weighted_risk_score_with_single_provider():
    results = [
        create_result(
            provider="virustotal",
            score=80,
            confidence=90,
        ),
    ]

    assert calculate_weighted_risk_score(results) == 80
    

def test_zero_confidence_provider_has_no_weight():
    results = [
        create_result(
            provider="provider-a",
            score=100,
            confidence=0,
        ),
        create_result(
            provider="provider-b",
            score=20,
            confidence=100,
        ),
    ]

    assert calculate_weighted_risk_score(results) == 20
    

def test_weighted_risk_score_falls_back_to_base_when_all_confidence_is_zero():
    results = [
        create_result(
            provider="provider-a",
            score=80,
            confidence=0,
        ),
        create_result(
            provider="provider-b",
            score=20,
            confidence=0,
        ),
    ]

    assert calculate_weighted_risk_score(results) == 50
    

def test_weighted_risk_score_rounds_half_up():
    results = [
        create_result(
            provider="provider-a",
            score=50,
            confidence=1,
        ),
        create_result(
            provider="provider-b",
            score=51,
            confidence=1,
        ),
    ]

    assert calculate_weighted_risk_score(results) == 51
    
    
def test_weighted_risk_score_rejects_empty_results():
    with pytest.raises(
        ValueError,
        match="At least one Threat Intelligence result is required",
    ):
        calculate_weighted_risk_score([])
        

def test_weighted_risk_score_rejects_mixed_indicators():
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
        calculate_weighted_risk_score(results)
        
    
def test_weighted_risk_score_rejects_negative_confidence():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="test",
            malicious=False,
            score=50,
            confidence=-1,
        )
    ]

    with pytest.raises(
        ValueError,
        match=(
            "Threat Intelligence confidence "
            "must be between 0 and 100"
        ),
    ):
        calculate_weighted_risk_score(results)
        
        
def test_weighted_risk_score_rejects_confidence_above_100():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="test",
            malicious=False,
            score=50,
            confidence=101,
        )
    ]

    with pytest.raises(
        ValueError,
        match=(
            "Threat Intelligence confidence "
            "must be between 0 and 100"
        ),
    ):
        calculate_weighted_risk_score(results)
        
        
def test_weighted_risk_score_rejects_non_integer_confidence():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="test",
            malicious=False,
            score=50,
            confidence=90.5,
        )
    ]

    with pytest.raises(
        TypeError,
        match=(
            "Threat Intelligence confidence "
            "must be an integer"
        ),
    ):
        calculate_weighted_risk_score(results)
        
        
def test_weighted_risk_score_rejects_boolean_confidence():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="test",
            malicious=False,
            score=50,
            confidence=True,
        )
    ]

    with pytest.raises(
        TypeError,
        match=(
            "Threat Intelligence confidence "
            "must be an integer"
        ),
    ):
        calculate_weighted_risk_score(results)
        

def test_risk_confidence_with_single_provider():
    results = [
        create_result(
            provider="virustotal",
            score=80,
            confidence=90,
        )
    ]

    assert calculate_risk_confidence(results) == 90
    

def test_risk_confidence_averages_multiple_providers():
    results = [
        create_result(
            provider="virustotal",
            score=20,
            confidence=80,
        ),
        create_result(
            provider="abuseipdb",
            score=80,
            confidence=100,
        ),
    ]

    assert calculate_risk_confidence(results) == 90
    

def test_risk_confidence_handles_zero_confidence():
    results = [
        create_result(
            provider="virustotal",
            score=80,
            confidence=0,
        ),
        create_result(
            provider="abuseipdb",
            score=20,
            confidence=0,
        ),
    ]

    assert calculate_risk_confidence(results) == 0
    

def test_risk_confidence_rounds_half_up():
    results = [
        create_result(
            provider="provider-a",
            score=50,
            confidence=50,
        ),
        create_result(
            provider="provider-b",
            score=50,
            confidence=51,
        ),
    ]

    assert calculate_risk_confidence(results) == 51
    

def test_weighted_risk_score_default_policy_keeps_equal_provider_weights():
    results = [
        create_result(
            provider="virustotal",
            score=20,
            confidence=100,
        ),
        create_result(
            provider="abuseipdb",
            score=80,
            confidence=100,
        ),
    ]

    policy = RiskPolicy()

    assert calculate_weighted_risk_score(
        results,
        policy=policy,
    ) == 50
    

def test_weighted_risk_score_uses_provider_weights():
    results = [
        create_result(
            provider="virustotal",
            score=80,
            confidence=90,
        ),
        create_result(
            provider="abuseipdb",
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

    assert calculate_weighted_risk_score(
        results,
        policy=policy,
    ) == 71
    

def test_higher_provider_weight_increases_provider_influence():
    results = [
        create_result(
            provider="provider-a",
            score=100,
            confidence=100,
        ),
        create_result(
            provider="provider-b",
            score=0,
            confidence=100,
        ),
    ]

    policy = RiskPolicy(
        provider_weights={
            "provider-a": 2.0,
            "provider-b": 1.0,
        }
    )

    assert calculate_weighted_risk_score(
        results,
        policy=policy,
    ) == 67
    

def test_lower_provider_weight_reduces_provider_influence():
    results = [
        create_result(
            provider="provider-a",
            score=100,
            confidence=100,
        ),
        create_result(
            provider="provider-b",
            score=0,
            confidence=100,
        ),
    ]

    policy = RiskPolicy(
        provider_weights={
            "provider-a": 0.5,
            "provider-b": 1.0,
        }
    )

    assert calculate_weighted_risk_score(
        results,
        policy=policy,
    ) == 33
    

def test_unconfigured_provider_uses_default_weight():
    results = [
        create_result(
            provider="unknown-provider",
            score=80,
            confidence=100,
        ),
        create_result(
            provider="abuseipdb",
            score=20,
            confidence=100,
        ),
    ]

    policy = RiskPolicy(
        provider_weights={
            "abuseipdb": 1.0,
        }
    )

    assert calculate_weighted_risk_score(
        results,
        policy=policy,
    ) == 50
    

def test_provider_weight_lookup_is_case_insensitive():
    results = [
        create_result(
            provider="VirusTotal",
            score=100,
            confidence=100,
        ),
        create_result(
            provider="abuseipdb",
            score=0,
            confidence=100,
        ),
    ]

    policy = RiskPolicy(
        provider_weights={
            "virustotal": 2.0,
            "abuseipdb": 1.0,
        }
    )

    assert calculate_weighted_risk_score(
        results,
        policy=policy,
    ) == 67
    

def test_provider_weight_lookup_normalizes_whitespace():
    results = [
        create_result(
            provider="   virustotal   ",
            score=100,
            confidence=100,
        ),
        create_result(
            provider="abuseipdb",
            score=0,
            confidence=100,
        ),
    ]

    policy = RiskPolicy(
        provider_weights={
            "virustotal": 2.0,
            "abuseipdb": 1.0,
        }
    )

    assert calculate_weighted_risk_score(
        results,
        policy=policy,
    ) == 67
    

def test_provider_weight_and_confidence_are_both_applied():
    results = [
        create_result(
            provider="provider-a",
            score=100,
            confidence=10,
        ),
        create_result(
            provider="provider-b",
            score=0,
            confidence=100,
        ),
    ]

    policy = RiskPolicy(
        provider_weights={
            "provider-a": 2.0,
            "provider-b": 1.0,
        }
    )

    assert calculate_weighted_risk_score(
        results,
        policy=policy,
    ) == 17
    

def test_provider_weights_do_not_break_zero_confidence_fallback():
    results = [
        create_result(
            provider="provider-a",
            score=80,
            confidence=0,
        ),
        create_result(
            provider="provider-b",
            score=20,
            confidence=0,
        ),
    ]

    policy = RiskPolicy(
        provider_weights={
            "provider-a": 2.0,
            "provider-b": 0.5,
        }
    )

    assert calculate_weighted_risk_score(
        results,
        policy=policy,
    ) == 50
    

def test_weighted_risk_score_rejects_empty_provider_name():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="   ",
            malicious=False,
            score=20,
            confidence=90,
        )
    ]

    with pytest.raises(
        ValueError,
        match="Provider name cannot be empty",
    ):
        calculate_weighted_risk_score(results)