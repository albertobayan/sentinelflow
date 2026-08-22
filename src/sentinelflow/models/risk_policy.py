import math
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RiskPolicy:
    medium_threshold: int = 25
    high_threshold: int = 50
    critical_threshold: int = 75

    provider_weights: dict[str, float] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        self._validate_threshold(
            "medium_threshold",
            self.medium_threshold,
        )

        self._validate_threshold(
            "high_threshold",
            self.high_threshold,
        )

        self._validate_threshold(
            "critical_threshold",
            self.critical_threshold,
        )

        if not (
            self.medium_threshold
            < self.high_threshold
            < self.critical_threshold
        ):
            raise ValueError(
                "Risk severity thresholds must be strictly increasing"
            )

        normalized_weights = {}

        for provider, weight in self.provider_weights.items():
            normalized_provider = provider.strip().lower()

            if not normalized_provider:
                raise ValueError(
                    "Provider name cannot be empty"
                )

            if type(weight) not in (int, float):
                raise TypeError(
                    "Provider weight must be a number"
                )

            if isinstance(weight, bool):
                raise TypeError(
                    "Provider weight must be a number"
                )

            if not math.isfinite(weight):
                raise ValueError(
                    "Provider weight must be finite"
                )

            if weight <= 0:
                raise ValueError(
                    "Provider weight must be greater than 0"
                )

            if normalized_provider in normalized_weights:
                raise ValueError(
                    "Provider names must be unique after normalization"
                )

            normalized_weights[normalized_provider] = float(
                weight
            )

        object.__setattr__(
            self,
            "provider_weights",
            normalized_weights,
        )

    @staticmethod
    def _validate_threshold(
        name: str,
        value: int,
    ) -> None:
        if type(value) is not int:
            raise TypeError(
                f"{name} must be an integer"
            )

        if not 1 <= value <= 100:
            raise ValueError(
                f"{name} must be between 1 and 100"
            )

    def get_provider_weight(
        self,
        provider: str,
    ) -> float:
        normalized_provider = provider.strip().lower()

        if not normalized_provider:
            raise ValueError(
                "Provider name cannot be empty"
            )

        return self.provider_weights.get(
            normalized_provider,
            1.0,
        )