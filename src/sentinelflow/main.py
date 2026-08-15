from sentinelflow.detection.ioc_detector import detect_ioc


def display_ioc(value: str) -> None:
    ioc = detect_ioc(value)

    print("\nIOC analysis")
    print("────────────────────")
    print(f"Value: {ioc.value}")
    print(f"Type: {ioc.type.value}")
    print(f"Valid: {ioc.valid}")
    print(f"Source: {ioc.source}")
    print("────────────────────")


def main() -> None:
    print("SentinelFlow v0.1")
    print("Type 'exit' to quit.")

    while True:
        value = input("\nEnter IOC:\n> ")

        if value.strip().lower() in {"exit", "quit"}:
            print("\nSentinelFlow stopped.")
            break

        display_ioc(value)


if __name__ == "__main__":
    main()