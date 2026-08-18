from sentinelflow.ingestion.event_processor import extract_source_ioc
from sentinelflow.ingestion.log_watcher import LogWatcher
from sentinelflow.models.security_event import SecurityEvent


def display_event(event: SecurityEvent) -> None:
    ioc = extract_source_ioc(event)

    print("\nNew security event")
    print("────────────────────")
    print(f"Timestamp: {event.timestamp}")
    print(f"Source IP: {event.source_ip}")
    print(f"Method: {event.http_method}")
    print(f"Path: {event.path}")
    print(f"Status: {event.status_code}")
    print(f"User-Agent: {event.user_agent}")
    print(f"IOC Type: {ioc.type.value}")
    print(f"IOC Valid: {ioc.valid}")
    print(f"Source: {ioc.source}")
    print("────────────────────")


def main() -> None:
    watcher = LogWatcher(
        "logs/sample_access.log",
        start_at_end=True,
    )

    print("SentinelFlow Log Watcher")
    print("Watching: logs/sample_access.log")
    print("Waiting for new events...")
    print("Press Ctrl+C to stop.\n")

    try:
        for event in watcher.watch():
            display_event(event)
    except KeyboardInterrupt:
        print("\nSentinelFlow watcher stopped.")


if __name__ == "__main__":
    main()