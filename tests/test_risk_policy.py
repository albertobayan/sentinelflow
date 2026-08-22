import pytest

from sentinelflow.models.risk_policy import RiskPolicy


def test_risk_policy_has_default_thresholds():
    policy = RiskPolicy()

    assert policy.medium_threshold == 25
    assert policy.high_threshold == 50
    assert policy.critical_threshold == 75


def test_risk_policy_starts_with_no_explicit_provider_weights():
    policy = RiskPolicy()

    assert policy.provider_weights == {}


def test_risk_policy_returns_default_provider_weight():
    policy = RiskPolicy()

    assert policy.get_provider_weight(
        "virustotal"
    ) == 1.0


def test_risk_policy_accepts_custom_thresholds():
    policy = RiskPolicy(
        medium_threshold=20,
        high_threshold=45,
        critical_threshold=80,
    )

    assert policy.medium_threshold == 20
    assert policy.high_threshold == 45
    assert policy.critical_threshold == 80


def test_risk_policy_accepts_provider_weights():
    policy = RiskPolicy(
        provider_weights={
            "virustotal": 1.0,
            "abuseipdb": 0.8,
        }
    )

    assert policy.get_provider_weight(
        "virustotal"
    ) == 1.0

    assert policy.get_provider_weight(
        "abuseipdb"
    ) == 0.8


def test_risk_policy_normalizes_provider_names():
    policy = RiskPolicy(
        provider_weights={
            "  VirusTotal  ": 1.2,
        }
    )

    assert policy.provider_weights == {
        "virustotal": 1.2,
    }

    assert policy.get_provider_weight(
        "VIRUSTOTAL"
    ) == 1.2


def test_risk_policy_rejects_empty_provider_name():
    with pytest.raises(
        ValueError,
        match="Provider name cannot be empty",
    ):
        RiskPolicy(
            provider_weights={
                "   ": 1.0,
            }
        )


def test_get_provider_weight_rejects_empty_name():
    policy = RiskPolicy()

    with pytest.raises(
        ValueError,
        match="Provider name cannot be empty",
    ):
        policy.get_provider_weight("   ")


def test_risk_policy_rejects_zero_provider_weight():
    with pytest.raises(
        ValueError,
        match="Provider weight must be greater than 0",
    ):
        RiskPolicy(
            provider_weights={
                "virustotal": 0,
            }
        )


def test_risk_policy_rejects_negative_provider_weight():
    with pytest.raises(
        ValueError,
        match="Provider weight must be greater than 0",
    ):
        RiskPolicy(
            provider_weights={
                "virustotal": -1,
            }
        )


def test_risk_policy_rejects_non_numeric_provider_weight():
    with pytest.raises(
        TypeError,
        match="Provider weight must be a number",
    ):
        RiskPolicy(
            provider_weights={
                "virustotal": "high",
            }
        )


def test_risk_policy_rejects_boolean_provider_weight():
    with pytest.raises(
        TypeError,
        match="Provider weight must be a number",
    ):
        RiskPolicy(
            provider_weights={
                "virustotal": True,
            }
        )


def test_risk_policy_rejects_non_integer_threshold():
    with pytest.raises(
        TypeError,
        match="medium_threshold must be an integer",
    ):
        RiskPolicy(
            medium_threshold=25.5,
        )


def test_risk_policy_rejects_threshold_below_range():
    with pytest.raises(
        ValueError,
        match="medium_threshold must be between 1 and 100",
    ):
        RiskPolicy(
            medium_threshold=0,
        )


def test_risk_policy_rejects_threshold_above_range():
    with pytest.raises(
        ValueError,
        match="critical_threshold must be between 1 and 100",
    ):
        RiskPolicy(
            critical_threshold=101,
        )


def test_risk_policy_rejects_equal_thresholds():
    with pytest.raises(
        ValueError,
        match=(
            "Risk severity thresholds must be "
            "strictly increasing"
        ),
    ):
        RiskPolicy(
            medium_threshold=25,
            high_threshold=25,
            critical_threshold=75,
        )


def test_risk_policy_rejects_out_of_order_thresholds():
    with pytest.raises(
        ValueError,
        match=(
            "Risk severity thresholds must be "
            "strictly increasing"
        ),
    ):
        RiskPolicy(
            medium_threshold=50,
            high_threshold=25,
            critical_threshold=75,
        )
        
    
def test_risk_policy_rejects_nan_provider_weight():
    with pytest.raises(
        ValueError,
        match="Provider weight must be finite",
    ):
        RiskPolicy(
            provider_weights={
                "virustotal": float("nan"),
            }
        )


def test_risk_policy_rejects_positive_infinite_provider_weight():
    with pytest.raises(
        ValueError,
        match="Provider weight must be finite",
    ):
        RiskPolicy(
            provider_weights={
                "virustotal": float("inf"),
            }
        )


def test_risk_policy_rejects_negative_infinite_provider_weight():
    with pytest.raises(
        ValueError,
        match="Provider weight must be finite",
    ):
        RiskPolicy(
            provider_weights={
                "virustotal": float("-inf"),
            }
        )


def test_risk_policy_rejects_duplicate_normalized_provider_names():
    with pytest.raises(
        ValueError,
        match=(
            "Provider names must be unique "
            "after normalization"
        ),
    ):
        RiskPolicy(
            provider_weights={
                "VirusTotal": 1.0,
                " virustotal ": 2.0,
            }
        )