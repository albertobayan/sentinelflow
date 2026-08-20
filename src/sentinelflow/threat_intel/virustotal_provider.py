import requests

from sentinelflow.models.threat_intel import ThreatIntelResult
from sentinelflow.threat_intel.exceptions import VirusTotalError
from sentinelflow.threat_intel.provider import ThreatIntelProvider


class VirusTotalProvider(ThreatIntelProvider):
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str) -> None:
        if not api_key.strip():
            raise ValueError("VirusTotal API key cannot be empty")

        self.api_key = api_key.strip()
        self.session = requests.Session()

        self.session.headers.update(
            {
                "x-apikey": self.api_key,
                "Accept": "application/json",
            }
        )

    @property
    def name(self) -> str:
        return "virustotal"

    def get_ip_report(self, ip_address: str) -> dict:
        normalized_ip = ip_address.strip()

        if not normalized_ip:
            raise ValueError("IP address cannot be empty")

        url = f"{self.BASE_URL}/ip_addresses/{normalized_ip}"

        try:
            response = self.session.get(
                url,
                timeout=10,
            )

            response.raise_for_status()

        except requests.Timeout as exc:
            raise VirusTotalError(
                "VirusTotal request timed out"
            ) from exc

        except requests.ConnectionError as exc:
            raise VirusTotalError(
                "Could not connect to VirusTotal"
            ) from exc

        except requests.HTTPError as exc:
            status_code = (
                exc.response.status_code
                if exc.response is not None
                else None
            )

            if status_code == 401:
                message = "VirusTotal rejected the API key"

            elif status_code == 403:
                message = "VirusTotal access forbidden"

            elif status_code == 404:
                message = "Indicator not found in VirusTotal"

            elif status_code == 429:
                message = "VirusTotal rate limit exceeded"

            elif status_code is not None and status_code >= 500:
                message = "VirusTotal service error"

            else:
                message = "VirusTotal HTTP request failed"

            raise VirusTotalError(message) from exc

        except requests.RequestException as exc:
            raise VirusTotalError(
                "VirusTotal request failed"
            ) from exc

        try:
            return response.json()

        except requests.exceptions.JSONDecodeError as exc:
            raise VirusTotalError(
                "VirusTotal returned invalid JSON"
            ) from exc

    def lookup(self, indicator: str) -> ThreatIntelResult:
        normalized_indicator = indicator.strip()

        report = self.get_ip_report(normalized_indicator)

        try:
            stats = report["data"]["attributes"]["last_analysis_stats"]

        except (KeyError, TypeError) as exc:
            raise VirusTotalError(
                "VirusTotal response has an unexpected structure"
            ) from exc

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        harmless_count = stats.get("harmless", 0)
        undetected_count = stats.get("undetected", 0)

        total_count = (
            malicious_count
            + suspicious_count
            + harmless_count
            + undetected_count
        )

        malicious = malicious_count > 0

        if total_count == 0:
            score = 0
            confidence = 0

        else:
            score = round(
                (
                    malicious_count
                    + (suspicious_count * 0.5)
                )
                / total_count
                * 100
            )

            confidence = round(
                (
                    malicious_count
                    + suspicious_count
                    + harmless_count
                )
                / total_count
                * 100
            )

        return ThreatIntelResult(
            indicator=normalized_indicator,
            provider=self.name,
            malicious=malicious,
            score=score,
            confidence=confidence,
        )