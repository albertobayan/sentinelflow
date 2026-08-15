from urllib.parse import urlparse

from sentinelflow.detection.domain_detector import is_valid_domain
from sentinelflow.detection.ip_detector import detect_ip_type


def is_valid_url(value: str) -> bool:
    parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        return False

    if not parsed.hostname:
        return False

    if detect_ip_type(parsed.hostname) is not None:
        return True

    return is_valid_domain(parsed.hostname)