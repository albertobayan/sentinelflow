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
    

def test_watcher_rejects_zero_interval(tmp_path):
    log_file = tmp_path / "watch.log"
    log_file.write_text("", encoding="utf-8")

    watcher = LogWatcher(str(log_file))
    generator = watcher.watch(interval=0)

    with pytest.raises(
        ValueError,
        match="Polling interval must be greater than 0",
    ):
        next(generator)
        
    
def test_watcher_rejects_negative_interval(tmp_path):
    log_file = tmp_path / "watch.log"
    log_file.write_text("", encoding="utf-8")

    watcher = LogWatcher(str(log_file))
    generator = watcher.watch(interval=-1)

    with pytest.raises(
        ValueError,
        match="Polling interval must be greater than 0",
    ):
        next(generator)
        

def test_watch_yields_security_event(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        '185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] '
        '"GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))
    generator = watcher.watch(interval=0.01)

    event = next(generator)

    assert isinstance(event, SecurityEvent)
    assert event.source_ip == "185.123.45.20"
    assert event.http_method == "GET"
    assert event.path == "/admin"
    assert event.status_code == 401


def test_watcher_accepts_positive_interval(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        '185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] '
        '"GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))
    generator = watcher.watch(interval=0.01)

    event = next(generator)

    assert event.source_ip == "185.123.45.20"
    

def test_watcher_resets_after_file_truncation(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "line one\n"
        "line two\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    first_read = watcher.read_new_lines()

    log_file.write_text(
        "new line\n",
        encoding="utf-8",
    )

    second_read = watcher.read_new_lines()

    assert first_read == [
        "line one\n",
        "line two\n",
    ]
    assert second_read == ["new line\n"]
    

def test_watcher_does_not_repeat_after_truncation(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "old line one\n"
        "old line two\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    watcher.read_new_lines()

    log_file.write_text(
        "new line\n",
        encoding="utf-8",
    )

    first_read_after_truncation = watcher.read_new_lines()
    second_read_after_truncation = watcher.read_new_lines()

    assert first_read_after_truncation == ["new line\n"]
    assert second_read_after_truncation == []
    
    
def test_watcher_stores_file_id_after_first_read(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "line one\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    assert watcher.file_id is None

    watcher.read_new_lines()

    assert watcher.file_id is not None
    

def test_watcher_keeps_file_id_when_file_is_appended(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "line one\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    watcher.read_new_lines()
    original_file_id = watcher.file_id

    with log_file.open("a", encoding="utf-8") as file:
        file.write("line two\n")

    watcher.read_new_lines()

    assert watcher.file_id == original_file_id
    
    
def test_watcher_reads_new_file_after_rotation(tmp_path):
    log_file = tmp_path / "watch.log"
    rotated_file = tmp_path / "watch.log.1"

    log_file.write_text(
        "old line one\n"
        "old line two\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    first_read = watcher.read_new_lines()

    log_file.rename(rotated_file)

    log_file.write_text(
        "new line one\n",
        encoding="utf-8",
    )

    second_read = watcher.read_new_lines()

    assert first_read == [
        "old line one\n",
        "old line two\n",
    ]
    assert second_read == ["new line one\n"]
    
    
def test_watcher_does_not_repeat_after_rotation(tmp_path):
    log_file = tmp_path / "watch.log"
    rotated_file = tmp_path / "watch.log.1"

    log_file.write_text(
        "old line\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    watcher.read_new_lines()

    log_file.rename(rotated_file)

    log_file.write_text(
        "new line\n",
        encoding="utf-8",
    )

    first_read_after_rotation = watcher.read_new_lines()
    second_read_after_rotation = watcher.read_new_lines()

    assert first_read_after_rotation == ["new line\n"]
    assert second_read_after_rotation == []
    

def test_watcher_position_recovers_after_truncation(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "old line one\n"
        "old line two\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    watcher.read_new_lines()

    old_position = watcher.position

    log_file.write_text(
        "new line\n",
        encoding="utf-8",
    )

    watcher.read_new_lines()

    assert old_position > watcher.position
    assert watcher.position > 0
    

def test_watcher_updates_file_id_after_rotation(tmp_path):
    log_file = tmp_path / "watch.log"
    rotated_file = tmp_path / "watch.log.1"

    log_file.write_text(
        "old line\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    watcher.read_new_lines()
    old_file_id = watcher.file_id

    log_file.rename(rotated_file)

    log_file.write_text(
        "new line\n",
        encoding="utf-8",
    )

    watcher.read_new_lines()

    assert watcher.file_id is not None
    assert watcher.file_id != old_file_id
    

def test_watcher_handles_append_truncate_append_sequence(tmp_path):
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

    log_file.write_text(
        "new base line\n",
        encoding="utf-8",
    )

    third_read = watcher.read_new_lines()

    with log_file.open("a", encoding="utf-8") as file:
        file.write("new appended line\n")

    fourth_read = watcher.read_new_lines()

    assert first_read == ["line one\n"]
    assert second_read == ["line two\n"]
    assert third_read == ["new base line\n"]
    assert fourth_read == ["new appended line\n"]
    

def test_watcher_handles_append_rotation_append_sequence(tmp_path):
    log_file = tmp_path / "watch.log"
    rotated_file = tmp_path / "watch.log.1"

    log_file.write_text(
        "old line one\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    first_read = watcher.read_new_lines()

    with log_file.open("a", encoding="utf-8") as file:
        file.write("old line two\n")

    second_read = watcher.read_new_lines()

    log_file.rename(rotated_file)

    log_file.write_text(
        "new line one\n",
        encoding="utf-8",
    )

    third_read = watcher.read_new_lines()

    with log_file.open("a", encoding="utf-8") as file:
        file.write("new line two\n")

    fourth_read = watcher.read_new_lines()

    assert first_read == ["old line one\n"]
    assert second_read == ["old line two\n"]
    assert third_read == ["new line one\n"]
    assert fourth_read == ["new line two\n"]
    

def test_watcher_position_stays_same_without_new_data(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "line one\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(str(log_file))

    watcher.read_new_lines()
    position_after_first_read = watcher.position

    second_read = watcher.read_new_lines()

    assert second_read == []
    assert watcher.position == position_after_first_read
    

def test_watcher_can_start_at_end(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "old line one\n"
        "old line two\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(
        str(log_file),
        start_at_end=True,
    )

    first_read = watcher.read_new_lines()

    assert first_read == []
    

def test_watcher_start_at_end_reads_only_future_lines(tmp_path):
    log_file = tmp_path / "watch.log"

    log_file.write_text(
        "old line\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(
        str(log_file),
        start_at_end=True,
    )

    assert watcher.read_new_lines() == []

    with log_file.open("a", encoding="utf-8") as file:
        file.write("new line\n")

    new_lines = watcher.read_new_lines()

    assert new_lines == ["new line\n"]
    
    
def test_watcher_starts_from_beginning_by_default(tmp_path):
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
    
    
def test_start_at_end_still_reads_new_file_after_rotation(tmp_path):
    log_file = tmp_path / "watch.log"
    rotated_file = tmp_path / "watch.log.1"

    log_file.write_text(
        "old line\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(
        str(log_file),
        start_at_end=True,
    )

    assert watcher.read_new_lines() == []

    log_file.rename(rotated_file)

    log_file.write_text(
        "new rotated line\n",
        encoding="utf-8",
    )

    lines = watcher.read_new_lines()

    assert lines == ["new rotated line\n"]