from sentinelflow.models.risk import RiskSeverity
from sentinelflow.models.risk_policy import RiskPolicy


def severity_from_score(
    score: int,
    policy: RiskPolicy | None = None,
) -> RiskSeverity:
    if type(score) is not int:
        raise TypeError(
            "Risk score must be an integer"
        )

    if not 0 <= score <= 100:
        raise ValueError(
            "Risk score must be between 0 and 100"
        )

    active_policy = (
        policy
        if policy is not None
        else RiskPolicy()
    )

    if score >= active_policy.critical_threshold:
        return RiskSeverity.CRITICAL

    if score >= active_policy.high_threshold:
        return RiskSeverity.HIGH

    if score >= active_policy.medium_threshold:
        return RiskSeverity.MEDIUM

    return RiskSeverity.LOW