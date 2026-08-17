from sentinelflow.detection.ioc_detector import detect_ioc
from sentinelflow.models.ioc import IOC
from sentinelflow.models.security_event import SecurityEvent


def extract_source_ioc(event: SecurityEvent) -> IOC:
    return detect_ioc(
        event.source_ip,
        source=event.source,
    )