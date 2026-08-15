from sentinelflow.detection.ioc_detector import detect_ioc


def main() -> None:
    print("SentinelFlow v0.1")

    value = input("\nEnter IOC:\n> ")

    ioc = detect_ioc(value)

    print("\nIOC detected")
    print("────────────────────")
    print(f"Value: {ioc.value}")
    print(f"Type: {ioc.type.value}")
    print(f"Valid: {ioc.valid}")
    print("────────────────────")


if __name__ == "__main__":
    main()