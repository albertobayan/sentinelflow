import pytest

from sentinelflow.detection.ip_policy import should_enrich_ip


def test_public_unknown_ip_should_be_enriched():
    assert should_enrich_ip("9.9.9.9") is True


def test_public_allowlisted_ip_should_not_be_enriched():
    assert should_enrich_ip("8.8.8.8") is False


def test_private_ip_should_not_be_enriched():
    assert should_enrich_ip("192.168.1.10") is False


def test_loopback_ip_should_not_be_enriched():
    assert should_enrich_ip("127.0.0.1") is False


def test_link_local_ip_should_not_be_enriched():
    assert should_enrich_ip("169.254.1.10") is False


def test_custom_allowlist_prevents_enrichment():
    allowlist = {
        "9.9.9.9",
    }

    assert (
        should_enrich_ip(
            "9.9.9.9",
            allowlist=allowlist,
        )
        is False
    )


def test_invalid_ip_raises_value_error():
    with pytest.raises(ValueError):
        should_enrich_ip("not-an-ip")
        
        
def test_ipv6_loopback_should_not_be_enriched():
    assert should_enrich_ip("::1") is False
    

def test_public_ipv6_should_be_enriched():
    assert should_enrich_ip("2606:4700:4700::1111") is True