import time
from pathlib import Path

from sentinelflow.ingestion.nginx_parser import parse_nginx_log
from sentinelflow.models.security_event import SecurityEvent


class LogWatcher:
    def __init__(
        self,
        file_path: str,
        start_at_end: bool = False,
    ) -> None:
        self.path = Path(file_path)
        self.position = 0
        self.file_id: tuple[int, int] | None = None
        self.start_at_end = start_at_end
        self.initialized = False
        
    def _get_file_id(self) -> tuple[int, int]:
        stat = self.path.stat()

        return stat.st_dev, stat.st_ino
    
    def _refresh_file_state(self) -> None:
        current_file_id = self._get_file_id()
        current_size = self.path.stat().st_size

        if not self.initialized:
            self.file_id = current_file_id

            if self.start_at_end:
                self.position = current_size

            self.initialized = True
            return

        if current_file_id != self.file_id:
            self.position = 0
            self.file_id = current_file_id
            return

        if current_size < self.position:
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

        self._refresh_file_state()

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