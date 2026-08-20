import pytest
import requests

from sentinelflow.threat_intel.exceptions import VirusTotalError
from sentinelflow.threat_intel.virustotal_provider import VirusTotalProvider


def test_virustotal_provider_name():
    provider = VirusTotalProvider("test-key")

    assert provider.name == "virustotal"


def test_virustotal_provider_stores_api_key():
    provider = VirusTotalProvider("test-key")

    assert provider.api_key == "test-key"


def test_virustotal_provider_strips_api_key_whitespace():
    provider = VirusTotalProvider("   test-key   ")

    assert provider.api_key == "test-key"


def test_virustotal_provider_rejects_empty_api_key():
    with pytest.raises(
        ValueError,
        match="VirusTotal API key cannot be empty",
    ):
        VirusTotalProvider("")


def test_virustotal_provider_rejects_whitespace_api_key():
    with pytest.raises(
        ValueError,
        match="VirusTotal API key cannot be empty",
    ):
        VirusTotalProvider("   ")


def test_virustotal_provider_base_url():
    assert VirusTotalProvider.BASE_URL == (
        "https://www.virustotal.com/api/v3"
    )


def test_virustotal_provider_sets_api_key_header():
    provider = VirusTotalProvider("test-key")

    assert provider.session.headers["x-apikey"] == "test-key"


def test_virustotal_provider_accepts_json():
    provider = VirusTotalProvider("test-key")

    assert provider.session.headers["Accept"] == "application/json"


def test_get_ip_report(monkeypatch):
    provider = VirusTotalProvider("test-key")

    fake_response_data = {
        "data": {
            "id": "9.9.9.9",
            "type": "ip_address",
        }
    }

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return fake_response_data

    def fake_get(url, timeout):
        assert url == (
            "https://www.virustotal.com/api/v3/"
            "ip_addresses/9.9.9.9"
        )
        assert timeout == 10

        return FakeResponse()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    result = provider.get_ip_report("9.9.9.9")

    assert result == fake_response_data


def test_get_ip_report_strips_ip_whitespace(monkeypatch):
    provider = VirusTotalProvider("test-key")

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {}

    def fake_get(url, timeout):
        assert url.endswith("/ip_addresses/9.9.9.9")

        return FakeResponse()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    provider.get_ip_report("   9.9.9.9   ")


def test_get_ip_report_checks_http_status(monkeypatch):
    provider = VirusTotalProvider("test-key")

    status_checked = False

    class FakeResponse:
        def raise_for_status(self):
            nonlocal status_checked
            status_checked = True

        def json(self):
            return {}

    def fake_get(url, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    provider.get_ip_report("9.9.9.9")

    assert status_checked is True


def test_virustotal_lookup_returns_malicious_result(monkeypatch):
    provider = VirusTotalProvider("test-key")

    fake_report = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 10,
                    "suspicious": 4,
                    "harmless": 60,
                    "undetected": 6,
                    "timeout": 0,
                }
            }
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    result = provider.lookup("9.9.9.9")

    assert result.indicator == "9.9.9.9"
    assert result.provider == "virustotal"
    assert result.malicious is True
    assert result.score == 15
    assert result.confidence == 92


def test_virustotal_lookup_returns_non_malicious_result(monkeypatch):
    provider = VirusTotalProvider("test-key")

    fake_report = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 10,
                    "timeout": 0,
                }
            }
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    result = provider.lookup("8.8.8.8")

    assert result.malicious is False
    assert result.score == 0
    assert result.confidence == 88


def test_virustotal_lookup_handles_zero_analysis_results(monkeypatch):
    provider = VirusTotalProvider("test-key")

    fake_report = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "timeout": 0,
                }
            }
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    result = provider.lookup("9.9.9.9")

    assert result.malicious is False
    assert result.score == 0
    assert result.confidence == 0


def test_virustotal_lookup_strips_indicator_whitespace(monkeypatch):
    provider = VirusTotalProvider("test-key")

    fake_report = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 1,
                    "undetected": 0,
                    "timeout": 0,
                }
            }
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    result = provider.lookup("   8.8.8.8   ")

    assert result.indicator == "8.8.8.8"


def test_get_ip_report_rejects_empty_ip():
    provider = VirusTotalProvider("test-key")

    with pytest.raises(
        ValueError,
        match="IP address cannot be empty",
    ):
        provider.get_ip_report("")


def test_get_ip_report_rejects_whitespace_ip():
    provider = VirusTotalProvider("test-key")

    with pytest.raises(
        ValueError,
        match="IP address cannot be empty",
    ):
        provider.get_ip_report("   ")


def test_get_ip_report_handles_timeout(monkeypatch):
    provider = VirusTotalProvider("test-key")

    def fake_get(url, timeout):
        raise requests.Timeout()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        VirusTotalError,
        match="VirusTotal request timed out",
    ):
        provider.get_ip_report("9.9.9.9")


def test_get_ip_report_handles_connection_error(monkeypatch):
    provider = VirusTotalProvider("test-key")

    def fake_get(url, timeout):
        raise requests.ConnectionError()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        VirusTotalError,
        match="Could not connect to VirusTotal",
    ):
        provider.get_ip_report("9.9.9.9")


def test_get_ip_report_handles_unauthorized(monkeypatch):
    provider = VirusTotalProvider("test-key")

    response = requests.Response()
    response.status_code = 401
    response.url = (
        "https://www.virustotal.com/api/v3/"
        "ip_addresses/9.9.9.9"
    )

    def fake_get(url, timeout):
        return response

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        VirusTotalError,
        match="VirusTotal rejected the API key",
    ):
        provider.get_ip_report("9.9.9.9")


def test_get_ip_report_handles_rate_limit(monkeypatch):
    provider = VirusTotalProvider("test-key")

    response = requests.Response()
    response.status_code = 429
    response.url = (
        "https://www.virustotal.com/api/v3/"
        "ip_addresses/9.9.9.9"
    )

    def fake_get(url, timeout):
        return response

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        VirusTotalError,
        match="VirusTotal rate limit exceeded",
    ):
        provider.get_ip_report("9.9.9.9")


def test_get_ip_report_handles_server_error(monkeypatch):
    provider = VirusTotalProvider("test-key")

    response = requests.Response()
    response.status_code = 500
    response.url = (
        "https://www.virustotal.com/api/v3/"
        "ip_addresses/9.9.9.9"
    )

    def fake_get(url, timeout):
        return response

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        VirusTotalError,
        match="VirusTotal service error",
    ):
        provider.get_ip_report("9.9.9.9")


def test_get_ip_report_handles_invalid_json(monkeypatch):
    provider = VirusTotalProvider("test-key")

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            raise requests.exceptions.JSONDecodeError(
                "Invalid JSON",
                "",
                0,
            )

    def fake_get(url, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        VirusTotalError,
        match="VirusTotal returned invalid JSON",
    ):
        provider.get_ip_report("9.9.9.9")


def test_virustotal_lookup_handles_unexpected_response(monkeypatch):
    provider = VirusTotalProvider("test-key")

    fake_report = {
        "data": {}
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    with pytest.raises(
        VirusTotalError,
        match="VirusTotal response has an unexpected structure",
    ):
        provider.lookup("9.9.9.9")