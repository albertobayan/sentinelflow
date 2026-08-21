from sentinelflow.models.threat_intel import ThreatIntelResult


def build_risk_reasons(
    results: list[ThreatIntelResult],
) -> tuple[str, ...]:
    reasons = []

    for result in results:
        status = (
            "malicious"
            if result.malicious
            else "not malicious"
        )

        reasons.append(
            (
                f"{result.provider}: "
                f"score={result.score}, "
                f"confidence={result.confidence}, "
                f"status={status}"
            )
        )

    return tuple(reasons)