from sentinelflow.models.risk import RiskAssessment
from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.models.threat_intel_lookup import ThreatIntelLookupResult
from sentinelflow.risk.reasons import build_risk_reasons
from sentinelflow.risk.scoring import (
    calculate_risk_confidence,
    calculate_weighted_risk_score,
)
from sentinelflow.risk.severity import severity_from_score


def assess_risk(
    results: list[ThreatIntelResult],
) -> RiskAssessment:
    risk_score = calculate_weighted_risk_score(
        results
    )

    confidence = calculate_risk_confidence(
        results
    )

    severity = severity_from_score(
        risk_score
    )

    reasons = build_risk_reasons(
        results
    )

    indicator = results[0].indicator.strip()

    return RiskAssessment(
        indicator=indicator,
        score=risk_score,
        severity=severity,
        confidence=confidence,
        reasons=reasons,
    )


def assess_lookup_result(
    lookup_result: ThreatIntelLookupResult,
) -> RiskAssessment:
    if not lookup_result.results:
        raise ValueError(
            "Cannot assess risk without Threat Intelligence results"
        )

    assessment = assess_risk(
        lookup_result.results
    )

    if not lookup_result.errors:
        return assessment

    total_providers = (
        len(lookup_result.results)
        + len(lookup_result.errors)
    )

    coverage = (
        len(lookup_result.results)
        / total_providers
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