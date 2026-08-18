import pytest

from sentinelflow.detection.ip_allowlist import is_ip_allowlisted


def test_default_allowlisted_ip():
    assert is_ip_allowlisted("8.8.8.8") is True


def test_default_non_allowlisted_ip():
    assert is_ip_allowlisted("9.9.9.9") is False


def test_custom_allowlist_matches_ip():
    allowlist = {
        "192.168.1.10",
        "203.0.113.50",
    }

    assert (
        is_ip_allowlisted(
            "192.168.1.10",
            allowlist=allowlist,
        )
        is True
    )


def test_custom_allowlist_rejects_unknown_ip():
    allowlist = {
        "192.168.1.10",
    }

    assert (
        is_ip_allowlisted(
            "192.168.1.20",
            allowlist=allowlist,
        )
        is False
    )


def test_allowlist_strips_whitespace():
    allowlist = {
        "8.8.8.8",
    }

    assert (
        is_ip_allowlisted(
            "   8.8.8.8   ",
            allowlist=allowlist,
        )
        is True
    )


def test_invalid_ip_raises_value_error():
    with pytest.raises(ValueError):
        is_ip_allowlisted("not-an-ip")


def test_ipv6_allowlist_uses_normalized_address():
    allowlist = {
        "2001:4860:4860::8888",
    }

    assert (
        is_ip_allowlisted(
            "2001:4860:4860:0:0:0:0:8888",
            allowlist=allowlist,
        )
        is True
    )