from sentinelflow.config import get_virustotal_api_key


def test_get_virustotal_api_key(monkeypatch):
    monkeypatch.setenv(
        "VIRUSTOTAL_API_KEY",
        "test-api-key",
    )

    assert get_virustotal_api_key() == "test-api-key"


def test_get_virustotal_api_key_returns_none_when_missing(monkeypatch):
    monkeypatch.delenv(
        "VIRUSTOTAL_API_KEY",
        raising=False,
    )

    assert get_virustotal_api_key() is None
    

def test_get_virustotal_api_key_returns_none_when_empty(monkeypatch):
    monkeypatch.setenv(
        "VIRUSTOTAL_API_KEY",
        "",
    )

    assert get_virustotal_api_key() is None