import pytest

from sentinelflow.ingestion.log_reader import read_nginx_log_file
from sentinelflow.models.ingestion_result import IngestionResult


def test_read_nginx_log_file():
    result = read_nginx_log_file("logs/sample_access.log")

    assert len(result.events) == 5
    assert result.total_lines == 5
    assert result.valid_lines == 5
    assert result.invalid_lines == 0
  
    
def test_first_event_from_log_file():
    result = read_nginx_log_file("logs/sample_access.log")

    event = result.events[0]

    assert event.source_ip == "185.123.45.20"
    assert event.timestamp == "15/Aug/2026:01:34:21 +0200"
    assert event.source == "nginx"
    assert event.http_method == "GET"
    assert event.path == "/admin"
    assert event.status_code == 401
    assert event.user_agent == "Mozilla/5.0"
  
    
def test_post_event_from_log_file():
    result = read_nginx_log_file("logs/sample_access.log")

    event = result.events[2]

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

    result = read_nginx_log_file(str(log_file))

    assert len(result.events) == 2
    assert result.total_lines == 3
    assert result.valid_lines == 2
    assert result.invalid_lines == 1
    
    
def test_missing_log_file():
    with pytest.raises(
        FileNotFoundError,
        match="Log file not found",
    ):
        read_nginx_log_file("logs/no_existe.log")
     
        
def test_log_path_must_be_file():
    with pytest.raises(
        ValueError,
        match="Path is not a file",
    ):
        read_nginx_log_file("logs")
     
        
def test_empty_log_file(tmp_path):
    log_file = tmp_path / "empty.log"
    log_file.write_text("", encoding="utf-8")

    result = read_nginx_log_file(str(log_file))

    assert result.events == []
    assert result.total_lines == 0
    assert result.valid_lines == 0
    assert result.invalid_lines == 0
    

def test_log_reader_returns_ingestion_result():
    result = read_nginx_log_file("logs/sample_access.log")

    assert isinstance(result, IngestionResult)
    

def test_ingestion_statistics_are_consistent():
    result = read_nginx_log_file("logs/sample_access.log")

    assert result.total_lines == result.valid_lines + result.invalid_lines
    assert result.valid_lines == len(result.events)
    

def test_file_with_only_invalid_lines(tmp_path):
    log_file = tmp_path / "invalid.log"

    log_file.write_text(
        "invalid line one\n"
        "invalid line two\n"
        "this is also invalid\n",
        encoding="utf-8",
    )

    result = read_nginx_log_file(str(log_file))

    assert result.events == []
    assert result.total_lines == 3
    assert result.valid_lines == 0
    assert result.invalid_lines == 3
    

def test_blank_lines_are_counted_as_invalid(tmp_path):
    log_file = tmp_path / "blank_lines.log"

    log_file.write_text(
        "\n"
        "\n"
        "\n",
        encoding="utf-8",
    )

    result = read_nginx_log_file(str(log_file))

    assert result.events == []
    assert result.total_lines == 3
    assert result.valid_lines == 0
    assert result.invalid_lines == 3
    

def test_mixed_valid_invalid_and_blank_lines(tmp_path):
    log_file = tmp_path / "mixed.log"

    log_file.write_text(
        '185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] '
        '"GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"\n'
        "\n"
        "invalid log line\n"
        '198.51.100.23 - - [15/Aug/2026:01:36:42 +0200] '
        '"POST /login HTTP/1.1" 403 245 "-" "curl/8.5.0"\n',
        encoding="utf-8",
    )

    result = read_nginx_log_file(str(log_file))

    assert len(result.events) == 2
    assert result.total_lines == 4
    assert result.valid_lines == 2
    assert result.invalid_lines == 2
    

def test_events_preserve_log_order():
    result = read_nginx_log_file("logs/sample_access.log")

    assert result.events[0].source_ip == "185.123.45.20"
    assert result.events[1].source_ip == "203.0.113.50"
    assert result.events[2].source_ip == "198.51.100.23"
    assert result.events[3].source_ip == "192.0.2.77"
    assert result.events[4].source_ip == "8.8.8.8"
    


