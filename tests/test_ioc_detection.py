import pytest

from sentinelflow.detection.ioc_detector import detect_ioc
from sentinelflow.models.ioc import IOCType


def test_valid_ipv4():
    result = detect_ioc("8.8.8.8")

    assert result.type == IOCType.IPV4
    assert result.valid is True


def test_invalid_ipv4():
    result = detect_ioc("999.999.999.999")

    assert result.type == IOCType.INVALID
    assert result.valid is False


def test_valid_ipv6():
    result = detect_ioc("2001:4860:4860::8888")

    assert result.type == IOCType.IPV6
    assert result.valid is True


def test_domain_detection():
    result = detect_ioc("example.com")

    assert result.type == IOCType.DOMAIN
    assert result.valid is True


def test_url_detection():
    result = detect_ioc("https://example.com/login")

    assert result.type == IOCType.URL
    assert result.valid is True


def test_md5_detection():
    result = detect_ioc("44d88612fea8a8f36de82e1278abb02f")

    assert result.type == IOCType.MD5
    assert result.valid is True


def test_sha1_detection():
    result = detect_ioc(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )

    assert result.type == IOCType.SHA1
    assert result.valid is True


def test_sha256_detection():
    result = detect_ioc(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )

    assert result.type == IOCType.SHA256
    assert result.valid is True


def test_invalid_input():
    result = detect_ioc("this is not an IOC")

    assert result.type == IOCType.INVALID
    assert result.valid is False
    
def test_invalid_ipv6():
    result = detect_ioc("2001:db8:::1")

    assert result.type == IOCType.INVALID
    assert result.valid is False
    
def test_subdomain_detection():
    result = detect_ioc("login.security.example.com")

    assert result.type == IOCType.DOMAIN
    assert result.valid is True
    
def test_invalid_domain():
    result = detect_ioc("-invalid-domain.com")

    assert result.type == IOCType.INVALID
    assert result.valid is False
    
def test_http_url_detection():
    result = detect_ioc("http://example.com/test")

    assert result.type == IOCType.URL
    assert result.valid is True
    
def test_url_with_ip_detection():
    result = detect_ioc("http://192.0.2.10/login")

    assert result.type == IOCType.URL
    assert result.valid is True
    
def test_unsupported_url_scheme():
    result = detect_ioc("ftp://example.com/file")

    assert result.type == IOCType.INVALID
    assert result.valid is False
    
def test_invalid_url_without_hostname():
    result = detect_ioc("https://")

    assert result.type == IOCType.INVALID
    assert result.valid is False
    
def test_uppercase_md5_detection():
    result = detect_ioc("44D88612FEA8A8F36DE82E1278ABB02F")

    assert result.type == IOCType.MD5
    assert result.valid is True
    
def test_invalid_hash_length():
    result = detect_ioc("abcdef123456")

    assert result.type == IOCType.INVALID
    assert result.valid is False
    
def test_invalid_hash_characters():
    result = detect_ioc("zzzz8612fea8a8f36de82e1278abb02f")

    assert result.type == IOCType.INVALID
    assert result.valid is False
    
def test_empty_input():
    result = detect_ioc("")

    assert result.type == IOCType.INVALID
    assert result.valid is False
    
def test_whitespace_only_input():
    result = detect_ioc("     ")

    assert result.type == IOCType.INVALID
    assert result.valid is False
    
def test_input_is_stripped():
    result = detect_ioc("   8.8.8.8   ")

    assert result.value == "8.8.8.8"
    assert result.type == IOCType.IPV4
    assert result.valid is True
    
def test_default_source_is_manual():
    result = detect_ioc("8.8.8.8")

    assert result.source == "manual"
    
def test_custom_source():
    result = detect_ioc("8.8.8.8", source="nginx")

    assert result.source == "nginx"
    
@pytest.mark.parametrize(
    "value",
    [
        "",
        "     ",
        "hello world",
        "999.999.999.999",
        "https://",
        "abcdef123456",
    ],
)
def test_invalid_values(value):
    result = detect_ioc(value)

    assert result.type == IOCType.INVALID
    assert result.valid is False