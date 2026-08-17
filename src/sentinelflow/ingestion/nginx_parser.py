import re

from sentinelflow.models.security_event import SecurityEvent


NGINX_LOG_PATTERN = re.compile(
    r'^(?P<source_ip>\S+) '
    r'\S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<http_method>[A-Z]+) (?P<path>\S+) HTTP/[0-9.]+" '
    r'(?P<status_code>\d{3}) '
    r'\d+ '
    r'"[^"]*" '
    r'"(?P<user_agent>[^"]*)"$'
)


def parse_nginx_log(line: str) -> SecurityEvent | None:
    match = NGINX_LOG_PATTERN.fullmatch(line.strip())

    if match is None:
        return None

    return SecurityEvent(
        timestamp=match.group("timestamp"),
        source="nginx",
        source_ip=match.group("source_ip"),
        http_method=match.group("http_method"),
        path=match.group("path"),
        status_code=int(match.group("status_code")),
        user_agent=match.group("user_agent"),
    )