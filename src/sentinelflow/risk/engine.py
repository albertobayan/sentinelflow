from sentinelflow.models.behavior import BehaviorSignal
from sentinelflow.models.risk import RiskAssessment
from sentinelflow.models.risk_policy import RiskPolicy
from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.models.threat_intel_lookup import ThreatIntelLookupResult
from sentinelflow.risk.behavior import (
    build_behavior_reasons,
    calculate_behavior_uplift,
    validate_behavior_signals_for_indicator,
)
from sentinelflow.risk.reasons import build_risk_reasons
from sentinelflow.risk.scoring import (
    calculate_risk_confidence,
    calculate_weighted_risk_score,
)
from sentinelflow.risk.severity import severity_from_score


def _extract_provider_name_from_error(
    error: str,
) -> str | None:
    provider_name = error.partition(":")[0].strip()

    if not provider_name:
        return None

    return provider_name


def _calculate_lookup_coverage(
    lookup_result: ThreatIntelLookupResult,
    policy: RiskPolicy,
) -> float:
    successful_weight = sum(
        policy.get_provider_weight(
            result.provider
        )
        for result in lookup_result.results
    )

    failed_weight = 0.0

    for error in lookup_result.errors:
        provider_name = (
            _extract_provider_name_from_error(
                error
            )
        )

        if provider_name is None:
            failed_weight += 1.0
            continue

        failed_weight += (
            policy.get_provider_weight(
                provider_name
            )
        )

    total_weight = (
        successful_weight
        + failed_weight
    )

    if total_weight == 0:
        return 0.0

    return (
        successful_weight
        / total_weight
    )


def assess_risk(
    results: list[ThreatIntelResult],
    policy: RiskPolicy | None = None,
    behavior_signals: list[BehaviorSignal] | None = None,
) -> RiskAssessment:
    active_policy = (
        policy
        if policy is not None
        else RiskPolicy()
    )

    active_behavior_signals = (
        behavior_signals
        if behavior_signals is not None
        else []
    )

    base_risk_score = calculate_weighted_risk_score(
        results,
        policy=active_policy,
    )

    indicator = results[0].indicator.strip()

    validate_behavior_signals_for_indicator(
        indicator,
        active_behavior_signals,
    )

    behavior_uplift = calculate_behavior_uplift(
        active_behavior_signals
    )

    risk_score = min(
        base_risk_score + behavior_uplift,
        100,
    )

    confidence = calculate_risk_confidence(
        results
    )

    severity = severity_from_score(
        risk_score,
        policy=active_policy,
    )

    reasons = (
        build_risk_reasons(results)
        + build_behavior_reasons(
            active_behavior_signals
        )
    )

    return RiskAssessment(
        indicator=indicator,
        score=risk_score,
        severity=severity,
        confidence=confidence,
        reasons=reasons,
    )


def assess_lookup_result(
    lookup_result: ThreatIntelLookupResult,
    policy: RiskPolicy | None = None,
    behavior_signals: list[BehaviorSignal] | None = None,
) -> RiskAssessment:
    if not lookup_result.results:
        raise ValueError(
            "Cannot assess risk without Threat Intelligence results"
        )

    active_policy = (
        policy
        if policy is not None
        else RiskPolicy()
    )

    assessment = assess_risk(
        lookup_result.results,
        policy=active_policy,
        behavior_signals=behavior_signals,
    )

    if not lookup_result.errors:
        return assessment

    coverage = _calculate_lookup_coverage(
        lookup_result,
        active_policy,
    )

    adjusted_confidence = int(
        assessment.confidence * coverage
        + 0.5
    )

    error_reasons = tuple(
        f"Threat Intelligence provider error: {error}"
        for error in lookup_result.errors
    )

    return RiskAssessment(
        indicator=assessment.indicator,
        score=assessment.score,
        severity=assessment.severity,
        confidence=adjusted_confidence,
        reasons=(
            assessment.reasons
            + error_reasons
        ),
    )