import ipaddress


DEFAULT_IP_ALLOWLIST = {
    "8.8.8.8",
    "1.1.1.1",
}


def is_ip_allowlisted(
    value: str,
    allowlist: set[str] | None = None,
) -> bool:
    selected_allowlist = (
        DEFAULT_IP_ALLOWLIST
        if allowlist is None
        else allowlist
    )

    ip = ipaddress.ip_address(value.strip())

    normalized_allowlist = {
        str(ipaddress.ip_address(item.strip()))
        for item in selected_allowlist
    }

    return str(ip) in normalized_allowlist