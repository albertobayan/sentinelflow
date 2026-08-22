from sentinelflow.models.risk_policy import RiskPolicy
from sentinelflow.models.threat_intel import ThreatIntelResult


def _validate_results(
    results: list[ThreatIntelResult],
) -> None:
    if not results:
        raise ValueError(
            "At least one Threat Intelligence result is required"
        )

    indicators = {
        result.indicator.strip()
        for result in results
    }

    if len(indicators) != 1:
        raise ValueError(
            "Threat Intelligence results must belong to the same indicator"
        )

    for result in results:
        if type(result.score) is not int:
            raise TypeError(
                "Threat Intelligence score must be an integer"
            )

        if not 0 <= result.score <= 100:
            raise ValueError(
                "Threat Intelligence score must be between 0 and 100"
            )

        if type(result.confidence) is not int:
            raise TypeError(
                "Threat Intelligence confidence must be an integer"
            )

        if not 0 <= result.confidence <= 100:
            raise ValueError(
                "Threat Intelligence confidence must be between 0 and 100"
            )


def _round_half_up(value: float) -> int:
    return int(value + 0.5)


def calculate_base_risk_score(
    results: list[ThreatIntelResult],
) -> int:
    _validate_results(results)

    total_score = sum(
        result.score
        for result in results
    )

    average_score = total_score / len(results)

    return _round_half_up(average_score)


def calculate_weighted_risk_score(
    results: list[ThreatIntelResult],
    policy: RiskPolicy | None = None,
) -> int:
    _validate_results(results)

    active_policy = (
        policy
        if policy is not None
        else RiskPolicy()
    )

    weighted_score_total = 0.0
    total_weight = 0.0

    for result in results:
        provider_weight = (
            active_policy.get_provider_weight(
                result.provider
            )
        )

        effective_weight = (
            result.confidence
            * provider_weight
        )

        weighted_score_total += (
            result.score
            * effective_weight
        )

        total_weight += effective_weight

    if total_weight == 0:
        return calculate_base_risk_score(
            results
        )

    weighted_average = (
        weighted_score_total
        / total_weight
    )

    return _round_half_up(
        weighted_average
    )


def calculate_risk_confidence(
    results: list[ThreatIntelResult],
) -> int:
    _validate_results(results)

    total_confidence = sum(
        result.confidence
        for result in results
    )

    average_confidence = (
        total_confidence / len(results)
    )

    return _round_half_up(
        average_confidence
    )