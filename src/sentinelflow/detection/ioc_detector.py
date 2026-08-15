from sentinelflow.detection.domain_detector import is_valid_domain
from sentinelflow.detection.hash_detector import detect_hash_type
from sentinelflow.detection.ip_detector import detect_ip_type
from sentinelflow.detection.url_detector import is_valid_url
from sentinelflow.models.ioc import IOC, IOCType


def detect_ioc(value: str, source: str = "manual") -> IOC:
    clean_value = value.strip()

    if not clean_value:
        return IOC(
            value=clean_value,
            type=IOCType.INVALID,
            valid=False,
            source=source,
        )

    ip_type = detect_ip_type(clean_value)

    if ip_type is not None:
        return IOC(
            value=clean_value,
            type=ip_type,
            valid=True,
            source=source,
        )

    if is_valid_url(clean_value):
        return IOC(
            value=clean_value,
            type=IOCType.URL,
            valid=True,
            source=source,
        )

    hash_type = detect_hash_type(clean_value)

    if hash_type is not None:
        return IOC(
            value=clean_value,
            type=hash_type,
            valid=True,
            source=source,
        )

    if is_valid_domain(clean_value):
        return IOC(
            value=clean_value,
            type=IOCType.DOMAIN,
            valid=True,
            source=source,
        )

    return IOC(
        value=clean_value,
        type=IOCType.INVALID,
        valid=False,
        source=source,
    )