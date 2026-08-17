from sentinelflow.ingestion.log_reader import read_nginx_log_file


def test_read_nginx_log_file():
    events = read_nginx_log_file("logs/sample_access.log")

    assert len(events) == 5
    
def test_first_event_from_log_file():
    events = read_nginx_log_file("logs/sample_access.log")

    event = events[0]

    assert event.source_ip == "185.123.45.20"
    assert event.timestamp == "15/Aug/2026:01:34:21 +0200"
    assert event.source == "nginx"
    assert event.http_method == "GET"
    assert event.path == "/admin"
    assert event.status_code == 401
    assert event.user_agent == "Mozilla/5.0"
    
def test_post_event_from_log_file():
    events = read_nginx_log_file("logs/sample_access.log")

    event = events[2]

    assert event.source_ip == "198.51.100.23"
    assert event.http_method == "POST"
    assert event.path == "/login"
    assert event.status_code == 403
    assert event.user_agent == "curl/8.5.0"
    
def test_invalid_lines_are_skipped(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        '185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] '
        '"GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"\n'
        "this is not a valid nginx log\n"
        '203.0.113.50 - - [15/Aug/2026:01:35:10 +0200] '
        '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )

    events = read_nginx_log_file(str(log_file))

    assert len(events) == 2