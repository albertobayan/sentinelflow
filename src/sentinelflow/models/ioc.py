from dataclasses import dataclass
from enum import Enum


class IOCType(str, Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    INVALID = "INVALID"


@dataclass(frozen=True)
class IOC:
    value: str
    type: IOCType
    valid: bool
    source: str = "manual"