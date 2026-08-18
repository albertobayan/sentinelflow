from sentinelflow.models.security_event import SecurityEvent
from sentinelflow.watch import display_event


def test_display_event(capsys):
    event = SecurityEvent(
        timestamp="17/Aug/2026:18:25:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="203.0.113.99",
        http_method="POST",
        path="/login",
        status_code=403,
        user_agent="curl/8.5.0",
    )

    display_event(event)

    captured = capsys.readouterr()

    assert "New security event" in captured.out
    assert "203.0.113.99" in captured.out
    assert "POST" in captured.out
    assert "/login" in captured.out
    assert "403" in captured.out
    assert "curl/8.5.0" in captured.out
    assert "IPv4" in captured.out
    assert "True" in captured.out
    assert "nginx" in captured.out
    

def test_display_event_detects_source_ioc(capsys):
    event = SecurityEvent(
        timestamp="17/Aug/2026:18:25:00 +0200",
        source="nginx",
        event_type="http_request",
        source_ip="8.8.8.8",
        http_method="GET",
        path="/api/status",
        status_code=200,
        user_agent="Mozilla/5.0",
    )

    display_event(event)

    captured = capsys.readouterr()

    assert "Source IP: 8.8.8.8" in captured.out
    assert "IOC Type: IPv4" in captured.out
    assert "IOC Valid: True" in captured.out
    assert "Source: nginx" in captured.out