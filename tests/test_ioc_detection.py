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