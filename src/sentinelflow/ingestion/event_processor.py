from sentinelflow.detection.ioc_detector import detect_ioc
from sentinelflow.detection.ip_classifier import classify_ip
from sentinelflow.models.ioc import IOC
from sentinelflow.models.ip_classification import IPClassification
from sentinelflow.models.security_event import SecurityEvent
from sentinelflow.detection.ip_allowlist import is_ip_allowlisted
from sentinelflow.detection.ip_policy import should_enrich_ip


def extract_source_ioc(event: SecurityEvent) -> IOC:
    return detect_ioc(event.source_ip, source=event.source)


def classify_source_ip(event: SecurityEvent) -> IPClassification:
    return classify_ip(event.source_ip)


def is_source_ip_allowlisted(
    event: SecurityEvent,
    allowlist: set[str] | None = None,
) -> bool:
    return is_ip_allowlisted(
        event.source_ip,
        allowlist=allowlist,
    )
    

def should_enrich_source_ip(
    event: SecurityEvent,
    allowlist: set[str] | None = None,
) -> bool:
    return should_enrich_ip(
        event.source_ip,
        allowlist=allowlist,
    )