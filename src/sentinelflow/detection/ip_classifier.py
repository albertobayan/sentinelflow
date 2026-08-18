import ipaddress

from sentinelflow.models.ip_classification import (
    IPCategory,
    IPClassification,
)


def classify_ip(value: str) -> IPClassification:
    ip = ipaddress.ip_address(value.strip())

    if ip.is_unspecified:
        category = IPCategory.UNSPECIFIED

    elif ip.is_loopback:
        category = IPCategory.LOOPBACK

    elif ip.is_link_local:
        category = IPCategory.LINK_LOCAL

    elif ip.is_multicast:
        category = IPCategory.MULTICAST

    elif ip.is_reserved:
        category = IPCategory.RESERVED

    elif ip.is_private:
        category = IPCategory.PRIVATE

    elif ip.is_global:
        category = IPCategory.PUBLIC

    else:
        category = IPCategory.RESERVED

    return IPClassification(
        value=str(ip),
        category=category,
        is_public=category == IPCategory.PUBLIC,
    )