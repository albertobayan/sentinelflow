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
) -> int:
    _validate_results(results)

    total_confidence = sum(
        result.confidence
        for result in results
    )

    if total_confidence == 0:
        return calculate_base_risk_score(results)

    weighted_score = sum(
        result.score * result.confidence
        for result in results
    )

    weighted_average = (
        weighted_score / total_confidence
    )

    return _round_half_up(weighted_average)


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