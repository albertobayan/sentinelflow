import pytest
import requests

from sentinelflow.threat_intel.abuseipdb_provider import AbuseIPDBProvider
from sentinelflow.threat_intel.exceptions import AbuseIPDBError


def test_abuseipdb_provider_name():
    provider = AbuseIPDBProvider("test-key")

    assert provider.name == "abuseipdb"


def test_abuseipdb_provider_stores_api_key():
    provider = AbuseIPDBProvider("test-key")

    assert provider.api_key == "test-key"


def test_abuseipdb_provider_strips_api_key_whitespace():
    provider = AbuseIPDBProvider("   test-key   ")

    assert provider.api_key == "test-key"


def test_abuseipdb_provider_rejects_empty_api_key():
    with pytest.raises(
        ValueError,
        match="AbuseIPDB API key cannot be empty",
    ):
        AbuseIPDBProvider("")


def test_abuseipdb_provider_rejects_whitespace_api_key():
    with pytest.raises(
        ValueError,
        match="AbuseIPDB API key cannot be empty",
    ):
        AbuseIPDBProvider("   ")



def test_abuseipdb_provider_base_url():
    assert AbuseIPDBProvider.BASE_URL == (
        "https://api.abuseipdb.com/api/v2"
    )


def test_abuseipdb_provider_sets_api_key_header():
    provider = AbuseIPDBProvider("test-key")

    assert provider.session.headers["Key"] == "test-key"
    

def test_abuseipdb_provider_accepts_json():
    provider = AbuseIPDBProvider("test-key")

    assert provider.session.headers["Accept"] == "application/json"
    

def test_get_ip_report(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_response_data = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
        }
    }

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return fake_response_data

    def fake_get(url, params, timeout):
        assert url == (
            "https://api.abuseipdb.com/api/v2/check"
        )

        assert params == {
            "ipAddress": "8.8.8.8",
            "maxAgeInDays": 30,
        }

        assert timeout == 10

        return FakeResponse()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    result = provider.get_ip_report("8.8.8.8")

    assert result == fake_response_data


def test_get_ip_report_accepts_custom_max_age(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {}

    def fake_get(url, params, timeout):
        assert params["maxAgeInDays"] == 90

        return FakeResponse()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    provider.get_ip_report(
        "8.8.8.8",
        max_age_in_days=90,
    )


def test_get_ip_report_strips_ip_whitespace(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {}

    def fake_get(url, params, timeout):
        assert params["ipAddress"] == "8.8.8.8"

        return FakeResponse()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    provider.get_ip_report("   8.8.8.8   ")
    

def test_get_ip_report_checks_http_status(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    status_checked = False

    class FakeResponse:
        def raise_for_status(self):
            nonlocal status_checked
            status_checked = True

        def json(self):
            return {}

    def fake_get(url, params, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    provider.get_ip_report("8.8.8.8")

    assert status_checked is True
    

def test_abuseipdb_lookup_returns_malicious_result(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_report = {
        "data": {
            "ipAddress": "9.9.9.9",
            "abuseConfidenceScore": 80,
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    result = provider.lookup("9.9.9.9")

    assert result.indicator == "9.9.9.9"
    assert result.provider == "abuseipdb"
    assert result.malicious is True
    assert result.score == 80
    assert result.confidence == 100
    

def test_abuseipdb_lookup_returns_non_malicious_result(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_report = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 10,
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    result = provider.lookup("8.8.8.8")

    assert result.indicator == "8.8.8.8"
    assert result.provider == "abuseipdb"
    assert result.malicious is False
    assert result.score == 10
    assert result.confidence == 100
    
    
def test_abuseipdb_lookup_marks_score_50_as_malicious(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_report = {
        "data": {
            "ipAddress": "9.9.9.9",
            "abuseConfidenceScore": 50,
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    result = provider.lookup("9.9.9.9")

    assert result.malicious is True
    assert result.score == 50


def test_abuseipdb_lookup_marks_score_49_as_non_malicious(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_report = {
        "data": {
            "ipAddress": "9.9.9.9",
            "abuseConfidenceScore": 49,
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    result = provider.lookup("9.9.9.9")

    assert result.malicious is False
    assert result.score == 49
    

def test_abuseipdb_lookup_handles_zero_score(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_report = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
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
    assert result.confidence == 100
    

def test_abuseipdb_lookup_strips_indicator_whitespace(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_report = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    result = provider.lookup("   8.8.8.8   ")

    assert result.indicator == "8.8.8.8"
    

def test_abuseipdb_lookup_handles_missing_score(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_report = {
        "data": {
            "ipAddress": "8.8.8.8",
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="AbuseIPDB response has an unexpected structure",
    ):
        provider.lookup("8.8.8.8")
        

def test_get_ip_report_rejects_empty_ip():
    provider = AbuseIPDBProvider("test-key")

    with pytest.raises(
        ValueError,
        match="IP address cannot be empty",
    ):
        provider.get_ip_report("")
        

def test_get_ip_report_rejects_whitespace_ip():
    provider = AbuseIPDBProvider("test-key")

    with pytest.raises(
        ValueError,
        match="IP address cannot be empty",
    ):
        provider.get_ip_report("   ")
        

def test_get_ip_report_rejects_zero_max_age():
    provider = AbuseIPDBProvider("test-key")

    with pytest.raises(
        ValueError,
        match="max_age_in_days must be between 1 and 365",
    ):
        provider.get_ip_report(
            "8.8.8.8",
            max_age_in_days=0,
        )
        

def test_get_ip_report_rejects_max_age_over_365():
    provider = AbuseIPDBProvider("test-key")

    with pytest.raises(
        ValueError,
        match="max_age_in_days must be between 1 and 365",
    ):
        provider.get_ip_report(
            "8.8.8.8",
            max_age_in_days=366,
        )
        

def test_get_ip_report_handles_timeout(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    def fake_get(url, params, timeout):
        raise requests.Timeout()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="AbuseIPDB request timed out",
    ):
        provider.get_ip_report("9.9.9.9")
        

def test_get_ip_report_handles_connection_error(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    def fake_get(url, params, timeout):
        raise requests.ConnectionError()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="Could not connect to AbuseIPDB",
    ):
        provider.get_ip_report("9.9.9.9")
        

def test_get_ip_report_handles_unauthorized(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    response = requests.Response()
    response.status_code = 401
    response.url = (
        "https://api.abuseipdb.com/api/v2/check"
    )

    def fake_get(url, params, timeout):
        return response

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="AbuseIPDB rejected the API key",
    ):
        provider.get_ip_report("9.9.9.9")
        

def test_get_ip_report_handles_rate_limit(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    response = requests.Response()
    response.status_code = 429
    response.url = (
        "https://api.abuseipdb.com/api/v2/check"
    )

    def fake_get(url, params, timeout):
        return response

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="AbuseIPDB rate limit exceeded",
    ):
        provider.get_ip_report("9.9.9.9")
        

def test_get_ip_report_handles_invalid_parameters(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    response = requests.Response()
    response.status_code = 422
    response.url = (
        "https://api.abuseipdb.com/api/v2/check"
    )

    def fake_get(url, params, timeout):
        return response

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="AbuseIPDB rejected the request parameters",
    ):
        provider.get_ip_report("9.9.9.9")
        

def test_get_ip_report_handles_server_error(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    response = requests.Response()
    response.status_code = 500
    response.url = (
        "https://api.abuseipdb.com/api/v2/check"
    )

    def fake_get(url, params, timeout):
        return response

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="AbuseIPDB service error",
    ):
        provider.get_ip_report("9.9.9.9")
        

def test_get_ip_report_handles_invalid_json(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            raise requests.exceptions.JSONDecodeError(
                "Invalid JSON",
                "",
                0,
            )

    def fake_get(url, params, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        provider.session,
        "get",
        fake_get,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="AbuseIPDB returned invalid JSON",
    ):
        provider.get_ip_report("9.9.9.9")
        
        
def test_abuseipdb_lookup_rejects_score_above_100(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_report = {
        "data": {
            "abuseConfidenceScore": 101,
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="AbuseIPDB returned an invalid abuse score",
    ):
        provider.lookup("9.9.9.9")
        
        
def test_abuseipdb_lookup_rejects_negative_score(monkeypatch):
    provider = AbuseIPDBProvider("test-key")

    fake_report = {
        "data": {
            "abuseConfidenceScore": -1,
        }
    }

    monkeypatch.setattr(
        provider,
        "get_ip_report",
        lambda indicator: fake_report,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="AbuseIPDB returned an invalid abuse score",
    ):
        provider.lookup("9.9.9.9")