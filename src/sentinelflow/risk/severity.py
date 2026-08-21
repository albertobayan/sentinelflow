from sentinelflow.models.risk import RiskSeverity


def severity_from_score(score: int) -> RiskSeverity:
    if type(score) is not int:
        raise TypeError(
            "Risk score must be an integer"
        )

    if not 0 <= score <= 100:
        raise ValueError(
            "Risk score must be between 0 and 100"
        )

    if score >= 75:
        return RiskSeverity.CRITICAL

    if score >= 50:
        return RiskSeverity.HIGH

    if score >= 25:
        return RiskSeverity.MEDIUM

    return RiskSeverity.LOW