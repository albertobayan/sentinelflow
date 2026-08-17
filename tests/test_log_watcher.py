import pytest

from sentinelflow.ingestion.log_watcher import LogWatcher
from sentinelflow.models.security_event import SecurityEvent


def test_watcher_reads_existing_lines(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "line one\n"
        "line two\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    lines = watcher.read_new_lines()

    assert lines == [
        "line one\n",
        "line two\n",
    ]


def test_watcher_does_not_repeat_lines(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "line one\n"
        "line two\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    first_read = watcher.read_new_lines()
    second_read = watcher.read_new_lines()

    assert len(first_read) == 2
    assert second_read == []


def test_watcher_reads_only_appended_lines(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "line one\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    first_read = watcher.read_new_lines()

    with log_file.open("a", encoding="utf-8") as file:
        file.write("line two\n")

    second_read = watcher.read_new_lines()

    assert first_read == ["line one\n"]
    assert second_read == ["line two\n"]


def test_watcher_missing_file():
    watcher = LogWatcher("logs/no_existe.log")

    with pytest.raises(
        FileNotFoundError,
        match="Log file not found",
    ):
        watcher.read_new_lines()


def test_watcher_path_must_be_file(tmp_path):
    watcher = LogWatcher(str(tmp_path))

    with pytest.raises(
        ValueError,
        match="Path is not a file",
    ):
        watcher.read_new_lines()
        
        
def test_watcher_reads_new_events(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        '185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] '
        '"GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    events = watcher.read_new_events()

    assert len(events) == 1
    assert isinstance(events[0], SecurityEvent)
    assert events[0].source_ip == "185.123.45.20"
    assert events[0].path == "/admin"
    assert events[0].status_code == 401
    

def test_watcher_skips_invalid_new_lines(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        '185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] '
        '"GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"\n'
        "this is not a valid nginx log\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    events = watcher.read_new_events()

    assert len(events) == 1
    assert events[0].source_ip == "185.123.45.20"
    
    
def test_watcher_reads_only_new_events(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        '185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] '
        '"GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    first_events = watcher.read_new_events()

    with log_file.open("a", encoding="utf-8") as file:
        file.write(
            '198.51.100.23 - - [15/Aug/2026:01:36:42 +0200] '
            '"POST /login HTTP/1.1" 403 245 "-" "curl/8.5.0"\n'
        )

    second_events = watcher.read_new_events()

    assert len(first_events) == 1
    assert first_events[0].source_ip == "185.123.45.20"

    assert len(second_events) == 1
    assert second_events[0].source_ip == "198.51.100.23"
    assert second_events[0].http_method == "POST"