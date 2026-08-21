class ThreatIntelError(Exception):
    """Base exception for threat intelligence errors."""


class VirusTotalError(ThreatIntelError):
    """Raised when VirusTotal cannot complete a lookup."""


class AbuseIPDBError(ThreatIntelError):
    """Raised when AbuseIPDB cannot complete a lookup."""