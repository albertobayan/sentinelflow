import requests

from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.threat_intel.exceptions import AbuseIPDBError
from sentinelflow.threat_intel.provider import ThreatIntelProvider


class AbuseIPDBProvider(ThreatIntelProvider):
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str) -> None:
        if not api_key.strip():
            raise ValueError("AbuseIPDB API key cannot be empty")

        self.api_key = api_key.strip()
        self.session = requests.Session()

        self.session.headers.update(
            {
                "Key": self.api_key,
                "Accept": "application/json",
            }
        )

    @property
    def name(self) -> str:
        return "abuseipdb"

    def get_ip_report(
        self,
        ip_address: str,
        max_age_in_days: int = 30,
    ) -> dict:
        normalized_ip = ip_address.strip()

        if not normalized_ip:
            raise ValueError("IP address cannot be empty")

        if not 1 <= max_age_in_days <= 365:
            raise ValueError(
                "max_age_in_days must be between 1 and 365"
            )

        url = f"{self.BASE_URL}/check"

        params = {
            "ipAddress": normalized_ip,
            "maxAgeInDays": max_age_in_days,
        }

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=10,
            )

            response.raise_for_status()

        except requests.Timeout as exc:
            raise AbuseIPDBError(
                "AbuseIPDB request timed out"
            ) from exc

        except requests.ConnectionError as exc:
            raise AbuseIPDBError(
                "Could not connect to AbuseIPDB"
            ) from exc

        except requests.HTTPError as exc:
            status_code = (
                exc.response.status_code
                if exc.response is not None
                else None
            )

            if status_code == 401:
                message = "AbuseIPDB rejected the API key"

            elif status_code == 403:
                message = "AbuseIPDB access forbidden"

            elif status_code == 402:
                message = "AbuseIPDB plan limit exceeded"

            elif status_code == 422:
                message = "AbuseIPDB rejected the request parameters"

            elif status_code == 429:
                message = "AbuseIPDB rate limit exceeded"

            elif status_code is not None and status_code >= 500:
                message = "AbuseIPDB service error"

            else:
                message = "AbuseIPDB HTTP request failed"

            raise AbuseIPDBError(message) from exc

        except requests.RequestException as exc:
            raise AbuseIPDBError(
                "AbuseIPDB request failed"
            ) from exc

        try:
            return response.json()

        except requests.exceptions.JSONDecodeError as exc:
            raise AbuseIPDBError(
                "AbuseIPDB returned invalid JSON"
            ) from exc

    def lookup(self, indicator: str) -> ThreatIntelResult:
        normalized_indicator = indicator.strip()

        report = self.get_ip_report(normalized_indicator)

        try:
            data = report["data"]
            abuse_score = data["abuseConfidenceScore"]

        except (KeyError, TypeError) as exc:
            raise AbuseIPDBError(
                "AbuseIPDB response has an unexpected structure"
            ) from exc

        if not isinstance(abuse_score, int):
            raise AbuseIPDBError(
                "AbuseIPDB returned an invalid abuse score"
            )

        if not 0 <= abuse_score <= 100:
            raise AbuseIPDBError(
                "AbuseIPDB returned an invalid abuse score"
            )

        malicious = abuse_score >= 50

        return ThreatIntelResult(
            indicator=normalized_indicator,
            provider=self.name,
            malicious=malicious,
            score=abuse_score,
            confidence=100,
        )