from pathlib import Path

from sentinelflow.ingestion.nginx_parser import parse_nginx_log
from sentinelflow.models.ingestion_result import IngestionResult


def read_nginx_log_file(file_path: str) -> IngestionResult:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    events = []
    total_lines = 0
    valid_lines = 0
    invalid_lines = 0

    with path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            total_lines += 1

            event = parse_nginx_log(line)

            if event is not None:
                events.append(event)
                valid_lines += 1
            else:
                invalid_lines += 1

    return IngestionResult(
        events=events,
        total_lines=total_lines,
        valid_lines=valid_lines,
        invalid_lines=invalid_lines,
    )