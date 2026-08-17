from sentinelflow.ingestion.nginx_parser import parse_nginx_log


def test_valid_nginx_log():
    line = (
        '185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] '
        '"GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"'
    )

    event = parse_nginx_log(line)

    assert event is not None
    assert event.source_ip == "185.123.45.20"
    assert event.timestamp == "15/Aug/2026:01:34:21 +0200"
    assert event.source == "nginx"
    assert event.http_method == "GET"
    assert event.path == "/admin"
    assert event.status_code == 401
    assert event.user_agent == "Mozilla/5.0"


def test_post_nginx_log():
    line = (
        '198.51.100.23 - - [15/Aug/2026:01:36:42 +0200] '
        '"POST /login HTTP/1.1" 403 245 "-" "curl/8.5.0"'
    )

    event = parse_nginx_log(line)

    assert event is not None
    assert event.source_ip == "198.51.100.23"
    assert event.http_method == "POST"
    assert event.path == "/login"
    assert event.status_code == 403
    assert event.user_agent == "curl/8.5.0"


def test_nginx_log_with_sensitive_path():
    line = (
        '192.0.2.77 - - [15/Aug/2026:01:37:03 +0200] '
        '"GET /.env HTTP/1.1" 404 150 "-" "python-requests/2.32.0"'
    )

    event = parse_nginx_log(line)

    assert event is not None
    assert event.path == "/.env"
    assert event.status_code == 404
    assert event.user_agent == "python-requests/2.32.0"


def test_status_code_is_integer():
    line = (
        '203.0.113.50 - - [15/Aug/2026:01:35:10 +0200] '
        '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    )

    event = parse_nginx_log(line)

    assert event is not None
    assert event.status_code == 200
    assert isinstance(event.status_code, int)


def test_invalid_nginx_log():
    line = "this is not a valid nginx log"

    event = parse_nginx_log(line)

    assert event is None


def test_empty_nginx_log():
    event = parse_nginx_log("")

    assert event is None


def test_whitespace_nginx_log():
    event = parse_nginx_log("     ")

    assert event is None