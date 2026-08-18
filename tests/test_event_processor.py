from sentinelflow.ingestion.event_processor import (
    classify_source_ip,
    extract_source_ioc,
    is_source_ip_allowlisted,
    should_enrich_source_ip,
)
from sentinelflow.models.ip_classification import IPCategory
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
    
def test_classify_source_ip_from_event():
    event = SecurityEvent(
        timestamp="18/Aug/2026:22:00:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="8.8.8.8",
    )

    classification = classify_source_ip(event)

    assert classification.value == "8.8.8.8"
    assert classification.category == IPCategory.PUBLIC
    assert classification.is_public is True
    
def test_classify_private_source_ip_from_event():
    event = SecurityEvent(
        timestamp="18/Aug/2026:22:05:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="192.168.1.25",
    )

    classification = classify_source_ip(event)

    assert classification.value == "192.168.1.25"
    assert classification.category == IPCategory.PRIVATE
    assert classification.is_public is False

def test_classify_loopback_source_ip_from_event():
    event = SecurityEvent(
        timestamp="18/Aug/2026:22:10:00 +0200",
        source="windows",
        event_type="authentication",
        source_ip="127.0.0.1",
    )

    classification = classify_source_ip(event)

    assert classification.category == IPCategory.LOOPBACK
    assert classification.is_public is False

def test_event_can_be_processed_as_ioc_and_ip_classification():
    event = SecurityEvent(
        timestamp="18/Aug/2026:22:15:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="8.8.8.8",
    )

    ioc = extract_source_ioc(event)
    classification = classify_source_ip(event)

    assert ioc.value == "8.8.8.8"
    assert ioc.valid is True
    assert classification.category == IPCategory.PUBLIC
    assert classification.is_public is True

def test_source_ip_can_be_allowlisted():
    event = SecurityEvent(
        timestamp="18/Aug/2026:22:30:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="8.8.8.8",
    )

    assert is_source_ip_allowlisted(event) is True
    
def test_source_ip_can_be_not_allowlisted():
    event = SecurityEvent(
        timestamp="18/Aug/2026:22:35:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="9.9.9.9",
    )

    assert is_source_ip_allowlisted(event) is False
    
def test_source_ip_uses_custom_allowlist():
    event = SecurityEvent(
        timestamp="18/Aug/2026:22:40:00 +0200",
        source="windows",
        event_type="authentication",
        source_ip="10.0.0.50",
    )

    allowlist = {
        "10.0.0.50",
    }

    assert (
        is_source_ip_allowlisted(
            event,
            allowlist=allowlist,
        )
        is True
    )
    
def test_public_unknown_source_ip_should_be_enriched():
    event = SecurityEvent(
        timestamp="18/Aug/2026:22:50:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="9.9.9.9",
    )

    assert should_enrich_source_ip(event) is True

def test_private_source_ip_should_not_be_enriched():
    event = SecurityEvent(
        timestamp="18/Aug/2026:22:55:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="192.168.1.20",
    )

    assert should_enrich_source_ip(event) is False
    
def test_allowlisted_source_ip_should_not_be_enriched():
    event = SecurityEvent(
        timestamp="18/Aug/2026:23:00:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="8.8.8.8",
    )

    assert should_enrich_source_ip(event) is False