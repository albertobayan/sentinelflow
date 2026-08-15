import re

from sentinelflow.models.ioc import IOCType


def detect_hash_type(value: str) -> IOCType | None:
    if not re.fullmatch(r"[0-9a-fA-F]+", value):
        return None

    if len(value) == 32:
        return IOCType.MD5

    if len(value) == 40:
        return IOCType.SHA1

    if len(value) == 64:
        return IOCType.SHA256

    return None