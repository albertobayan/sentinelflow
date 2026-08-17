import time
from pathlib import Path

from sentinelflow.ingestion.nginx_parser import parse_nginx_log
from sentinelflow.models.security_event import SecurityEvent


class LogWatcher:
    def __init__(self, file_path: str) -> None:
        self.path = Path(file_path)
        self.position = 0

    def read_new_lines(self) -> list[str]:
        if not self.path.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.path}"
            )

        if not self.path.is_file():
            raise ValueError(
                f"Path is not a file: {self.path}"
            )

        with self.path.open("r", encoding="utf-8") as log_file:
            log_file.seek(self.position)

            lines = log_file.readlines()

            self.position = log_file.tell()

        return lines

    def read_new_events(self) -> list[SecurityEvent]:
        lines = self.read_new_lines()

        events = []

        for line in lines:
            event = parse_nginx_log(line)

            if event is not None:
                events.append(event)

        return events

    def watch(self, interval: float = 1.0):
        if interval <= 0:
            raise ValueError("Polling interval must be greater than 0")

        while True:
            events = self.read_new_events()

            for event in events:
                yield event

            time.sleep(interval)
            
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