from sentinelflow.behavior.analyzer import analyze_behavior
from sentinelflow.models.behavior import BehaviorSignalType
from sentinelflow.models.risk import RiskSeverity
from sentinelflow.models.security_event import SecurityEvent
from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.risk.engine import assess_risk


def create_event(
    path: str,
    status_code: int,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp="22/Aug/2026:12:00:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="203.0.113.10",
        http_method="GET",
        path=path,
        status_code=status_code,
        user_agent="pytest",
    )


def test_behavior_analyzer_output_can_feed_risk_engine():
    events = [
        create_event(
            path=f"/missing-{index}",
            status_code=404,
        )
        for index in range(10)
    ]

    signals = analyze_behavior(
        events
    )

    results = [
        ThreatIntelResult(
            indicator="203.0.113.10",
            provider="test-provider",
            malicious=True,
            score=60,
            confidence=90,
        )
    ]

    assessment = assess_risk(
        results,
        behavior_signals=signals,
    )

    signal_types = {
        signal.signal_type
        for signal in signals
    }

    assert (
        BehaviorSignalType.HIGH_404_RATE
        in signal_types
    )

    assert (
        BehaviorSignalType.DIRECTORY_SCANNING
        in signal_types
    )

    assert assessment.score == 76
    assert assessment.severity == RiskSeverity.CRITICAL
    assert assessment.confidence == 90


def test_behavior_reasons_reach_final_risk_assessment():
    events = [
        create_event(
            path=f"/missing-{index}",
            status_code=404,
        )
        for index in range(10)
    ]

    signals = analyze_behavior(
        events
    )

    results = [
        ThreatIntelResult(
            indicator="203.0.113.10",
            provider="test-provider",
            malicious=False,
            score=20,
            confidence=90,
        )
    ]

    assessment = assess_risk(
        results,
        behavior_signals=signals,
    )

    behavior_reasons = [
        reason
        for reason in assessment.reasons
        if reason.startswith("behavior:")
    ]

    assert len(behavior_reasons) == 2