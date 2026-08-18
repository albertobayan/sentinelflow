from sentinelflow.detection.ip_allowlist import is_ip_allowlisted
from sentinelflow.detection.ip_classifier import classify_ip


def should_enrich_ip(
    value: str,
    allowlist: set[str] | None = None,
) -> bool:
    classification = classify_ip(value)

    if not classification.is_public:
        return False

    if is_ip_allowlisted(value, allowlist=allowlist):
        return False

    return True