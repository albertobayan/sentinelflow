from sentinelflow.ingestion.event_processor import extract_source_ioc
from sentinelflow.models.ioc import IOCType
from sentinelflow.models.security_event import SecurityEvent


def test_extract_source_ioc():
    event = SecurityEvent(
        timestamp="15/Aug/2026:01:34:21 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="185.123.45.20",
        http_method="GET",
        path="/admin",
        status_code=401,
        user_agent="Mozilla/5.0",
    )

    ioc = extract_source_ioc(event)

    assert ioc.value == "185.123.45.20"
    assert ioc.type == IOCType.IPV4
    assert ioc.valid is True
    assert ioc.source == "nginx"
    
def test_extract_source_ioc_preserves_event_source():
    event = SecurityEvent(
        timestamp="15/Aug/2026:01:34:21 +0200",
        source="test_source",
        event_type="http_request",
        source_ip="8.8.8.8",
        http_method="GET",
        path="/",
        status_code=200,
        user_agent="Mozilla/5.0",
    )

    ioc = extract_source_ioc(event)

    assert ioc.value == "8.8.8.8"
    assert ioc.type == IOCType.IPV4
    assert ioc.valid is True
    assert ioc.source == "test_source"
    
def test_extract_source_ioc_from_non_http_event():
    event = SecurityEvent(
        timestamp="18/Aug/2026:17:00:00 +0200",
        source="windows",
        event_type="authentication",
        source_ip="8.8.8.8",
    )

    ioc = extract_source_ioc(event)

    assert ioc.value == "8.8.8.8"
    assert ioc.valid is True
    assert ioc.source == "windows"