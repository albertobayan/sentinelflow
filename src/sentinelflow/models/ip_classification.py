from dataclasses import dataclass
from enum import Enum


class IPCategory(str, Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    RESERVED = "RESERVED"
    MULTICAST = "MULTICAST"
    UNSPECIFIED = "UNSPECIFIED"


@dataclass(frozen=True)
class IPClassification:
    value: str
    category: IPCategory
    is_public: bool