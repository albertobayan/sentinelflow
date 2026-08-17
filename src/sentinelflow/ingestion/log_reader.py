from pathlib import Path

from sentinelflow.ingestion.nginx_parser import parse_nginx_log
from sentinelflow.models.security_event import SecurityEvent


def read_nginx_log_file(file_path: str) -> list[SecurityEvent]:
    path = Path(file_path)

    events = []

    with path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            event = parse_nginx_log(line)

            if event is not None:
                events.append(event)

    return events