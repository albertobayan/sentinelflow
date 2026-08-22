from sentinelflow.models.behavior import BehaviorSignal


MAX_BEHAVIOR_UPLIFT = 25


def calculate_behavior_uplift(
    signals: list[BehaviorSignal],
) -> int:
    if not signals:
        return 0

    strongest_score = max(
        signal.score
        for signal in signals
    )

    uplift = int(
        strongest_score
        * MAX_BEHAVIOR_UPLIFT
        / 100
        + 0.5
    )

    return uplift


def validate_behavior_signals_for_indicator(
    indicator: str,
    signals: list[BehaviorSignal],
) -> None:
    normalized_indicator = indicator.strip()

    if not normalized_indicator:
        raise ValueError(
            "Assessed indicator cannot be empty"
        )

    for signal in signals:
        normalized_source_ip = signal.source_ip.strip()

        if normalized_source_ip != normalized_indicator:
            raise ValueError(
                "Behavior signals must belong to the assessed indicator"
            )


def build_behavior_reasons(
    signals: list[BehaviorSignal],
) -> tuple[str, ...]:
    return tuple(
        (
            f"behavior:{signal.signal_type.value}: "
            f"score={signal.score}, "
            f"event_count={signal.event_count}, "
            f"reason={signal.reason}"
        )
        for signal in signals
    )