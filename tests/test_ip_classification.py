import pytest

from sentinelflow.detection.ip_classifier import classify_ip
from sentinelflow.models.ip_classification import (
    IPCategory,
    IPClassification,
)


def test_public_ip_classification_model():
    classification = IPClassification(
        value="8.8.8.8",
        category=IPCategory.PUBLIC,
        is_public=True,
    )

    assert classification.value == "8.8.8.8"
    assert classification.category == IPCategory.PUBLIC
    assert classification.is_public is True


def test_private_ip_classification_model():
    classification = IPClassification(
        value="192.168.1.50",
        category=IPCategory.PRIVATE,
        is_public=False,
    )

    assert classification.value == "192.168.1.50"
    assert classification.category == IPCategory.PRIVATE
    assert classification.is_public is False
    

def test_classify_public_ip():
    classification = classify_ip("8.8.8.8")

    assert classification.value == "8.8.8.8"
    assert classification.category == IPCategory.PUBLIC
    assert classification.is_public is True
    

def test_classify_private_ip():
    classification = classify_ip("192.168.1.10")

    assert classification.category == IPCategory.PRIVATE
    assert classification.is_public is False
    

def test_classify_loopback_ip():
    classification = classify_ip("127.0.0.1")

    assert classification.category == IPCategory.LOOPBACK
    assert classification.is_public is False
    

def test_classify_link_local_ip():
    classification = classify_ip("169.254.1.10")

    assert classification.category == IPCategory.LINK_LOCAL
    assert classification.is_public is False
    

def test_classify_multicast_ip():
    classification = classify_ip("224.0.0.1")

    assert classification.category == IPCategory.MULTICAST
    assert classification.is_public is False
    

def test_classify_reserved_ip():
    classification = classify_ip("240.0.0.1")

    assert classification.category == IPCategory.RESERVED
    assert classification.is_public is False
    

def test_classify_unspecified_ip():
    classification = classify_ip("0.0.0.0")

    assert classification.category == IPCategory.UNSPECIFIED
    assert classification.is_public is False
    

def test_classify_ip_strips_whitespace():
    classification = classify_ip("   8.8.8.8   ")

    assert classification.value == "8.8.8.8"
    assert classification.category == IPCategory.PUBLIC
    

def test_classify_invalid_ip_raises_value_error():
    with pytest.raises(ValueError):
        classify_ip("not-an-ip")
        
    
def test_classify_ipv6_loopback():
    classification = classify_ip("::1")

    assert classification.category == IPCategory.LOOPBACK
    assert classification.is_public is False
    

def test_classify_ipv6_link_local():
    classification = classify_ip("fe80::1")

    assert classification.category == IPCategory.LINK_LOCAL
    assert classification.is_public is False