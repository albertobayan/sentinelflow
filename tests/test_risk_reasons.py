from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.risk.reasons import build_risk_reasons


def test_build_risk_reasons_with_single_result():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="virustotal",
            malicious=True,
            score=70,
            confidence=90,
        )
    ]

    reasons = build_risk_reasons(results)

    assert reasons == (
        (
            "virustotal: score=70, "
            "confidence=90, "
            "status=malicious"
        ),
    )


def test_build_risk_reasons_with_multiple_results():
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

    reasons = build_risk_reasons(results)

    assert len(reasons) == 2

    assert reasons[0] == (
        "virustotal: score=70, "
        "confidence=90, "
        "status=malicious"
    )

    assert reasons[1] == (
        "abuseipdb: score=20, "
        "confidence=100, "
        "status=not malicious"
    )


def test_build_risk_reasons_returns_tuple():
    results = [
        ThreatIntelResult(
            indicator="9.9.9.9",
            provider="test",
            malicious=False,
            score=10,
            confidence=50,
        )
    ]

    reasons = build_risk_reasons(results)

    assert isinstance(reasons, tuple)


def test_build_risk_reasons_handles_empty_results():
    reasons = build_risk_reasons([])

    assert reasons == ()