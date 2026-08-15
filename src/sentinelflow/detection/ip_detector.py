import ipaddress

from sentinelflow.models.ioc import IOCType


def detect_ip_type(value: str) -> IOCType | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None

    if ip.version == 4:
        return IOCType.IPV4

    return IOCType.IPV6