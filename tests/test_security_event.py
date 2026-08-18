import pytest

from sentinelflow.models.security_event import SecurityEvent


def test_security_event_http_fields():
    event = SecurityEvent(
        timestamp="18/Aug/2026:17:00:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="203.0.113.50",
        http_method="GET",
        path="/admin",
        status_code=401,
        user_agent="Mozilla/5.0",
    )

    assert event.timestamp == "18/Aug/2026:17:00:00 +0200"
    assert event.source == "nginx"
    assert event.event_type == "http_request"
    assert event.source_ip == "203.0.113.50"
    assert event.http_method == "GET"
    assert event.path == "/admin"
    assert event.status_code == 401
    assert event.user_agent == "Mozilla/5.0"


def test_security_event_allows_non_http_event():
    event = SecurityEvent(
        timestamp="18/Aug/2026:17:05:00 +0200",
        source="windows",
        event_type="authentication",
        source_ip="10.0.0.15",
    )

    assert event.source == "windows"
    assert event.event_type == "authentication"
    assert event.source_ip == "10.0.0.15"

    assert event.http_method is None
    assert event.path is None
    assert event.status_code is None
    assert event.user_agent is None


def test_security_event_http_fields_are_optional():
    event = SecurityEvent(
        timestamp="18/Aug/2026:17:10:00 +0200",
        source="firewall",
        event_type="network_connection",
        source_ip="192.0.2.25",
    )

    assert event.http_method is None
    assert event.path is None
    assert event.status_code is None
    assert event.user_agent is None


def test_security_event_is_immutable():
    event = SecurityEvent(
        timestamp="18/Aug/2026:17:15:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="8.8.8.8",
    )

    with pytest.raises(AttributeError):
        event.source_ip = "1.1.1.1"


def test_security_event_preserves_event_type():
    event = SecurityEvent(
        timestamp="18/Aug/2026:17:20:00 +0200",
        source="windows",
        event_type="authentication",
        source_ip="10.0.0.20",
    )

    assert event.event_type == "authentication"