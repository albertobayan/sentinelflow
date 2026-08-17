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