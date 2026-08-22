# SentinelFlow

**Automated Threat Detection, Enrichment & Response Platform**

SentinelFlow is a defensive cybersecurity automation project built in Python.

The goal of the project is to simulate a modular SOC/SOAR workflow capable of ingesting security events, detecting indicators of compromise, applying enrichment policies, querying external Threat Intelligence providers, assessing risk, generating alerts and supporting controlled defensive response workflows.

---

## Project Status

🚧 **Under active development**

Current development stage:

**Threat Intelligence Enrichment, Risk Assessment & Configurable Risk Policy**

Currently implemented:

- IOC detection and validation.
- Structured security events.
- Nginx log parsing.
- Log file ingestion.
- Real-time log monitoring.
- IOC extraction from events.
- IP classification.
- IP allowlisting.
- Threat Intelligence enrichment policy.
- Modular Threat Intelligence architecture.
- Local deterministic Threat Intelligence provider.
- VirusTotal API v3 integration.
- AbuseIPDB API v2 integration.
- Multi-provider Threat Intelligence.
- Threat Intelligence normalization.
- Provider-specific error handling.
- External API timeout and connection handling.
- API authentication and rate-limit handling.
- Provider failure isolation.
- Partial Threat Intelligence result preservation.
- Threat Intelligence lookup status tracking.
- In-memory Threat Intelligence caching.
- Configurable cache TTL.
- Time-based cache expiration.
- Safe caching policy for complete enrichment results.
- Automatic provider retries after partial or failed enrichment.
- Normalized Risk Assessment model.
- Risk score and confidence validation.
- Automatic severity classification.
- Multi-provider risk score aggregation.
- Confidence-weighted risk scoring.
- Global risk confidence calculation.
- Explainable Risk Assessment reasons.
- Partial-enrichment confidence adjustment.
- Threat Intelligence lookup to Risk Assessment integration.
- Configurable `RiskPolicy`.
- Configurable severity thresholds.
- Provider-specific risk weights.
- Policy-driven risk scoring.
- Policy-driven severity classification.
- Weighted provider coverage for partial enrichment.
- Risk policy validation and defensive hardening.

---

## Focus

SentinelFlow focuses on:

- Blue Team security.
- SOC automation.
- Threat Intelligence.
- Risk Assessment.
- Detection Engineering.
- Incident Response.
- SOAR workflows.
- Security event normalization.
- Defensive automation.
- Python engineering.
- Modular cybersecurity architecture.

---

## Current Architecture

SentinelFlow is being developed as a modular defensive security pipeline.

```text
Log Source
    ↓
Log Ingestion
    ↓
Parsing
    ↓
SecurityEvent
    ↓
IOC Detection
    ↓
IP Classification
    ↓
Allowlist Check
    ↓
Enrichment Policy
    ↓
ThreatIntelService
    ↓
ThreatIntelCache
    ↓
ThreatIntelProvider
    ↓
External / Local Threat Intelligence
    ↓
ThreatIntelResult
    ↓
ThreatIntelLookupResult
    ↓
RiskPolicy
    ↓
Risk Engine
    ↓
RiskAssessment
    ↓
Future Decision Engine
    ↓
Future Alerting
    ↓
Future Defensive Response
    ↓
Future Audit Trail
```

Each component is designed to have a clearly defined responsibility.

SentinelFlow intentionally avoids placing the entire security workflow inside a single large function.

The architecture separates:

```text
data collection
↓
normalization
↓
enrichment
↓
risk policy
↓
risk interpretation
↓
future decision making
```

---

## IOC Detection Engine

SentinelFlow can detect and validate multiple Indicator of Compromise types.

Currently supported:

- IPv4
- IPv6
- Domain
- URL
- MD5
- SHA1
- SHA256
- Invalid / unsupported input

Example:

```text
Input:
8.8.8.8

Output:
IOC analysis
────────────────────
Value: 8.8.8.8
Type: IPv4
Valid: True
Source: manual
────────────────────
```

Other supported examples:

```text
2001:4860:4860::8888
→ IPv6
```

```text
example.com
→ DOMAIN
```

```text
https://example.com/login
→ URL
```

```text
44d88612fea8a8f36de82e1278abb02f
→ MD5
```

```text
da39a3ee5e6b4b0d3255bfef95601890afd80709
→ SHA1
```

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
→ SHA256
```

Invalid input is also handled:

```text
hello world
→ INVALID
→ Valid: False
```

---

## IOC Model

Indicators are represented using a common immutable model instead of passing raw strings through the application.

Conceptually:

```python
IOC(
    value="8.8.8.8",
    type=IOCType.IPV4,
    valid=True,
    source="manual",
)
```

Current fields:

```text
value
type
valid
source
```

The `source` field allows SentinelFlow to identify where an indicator originated.

Examples:

```text
manual
nginx
apache
api
sysmon
honeypot
```

Not all of these sources are implemented yet.

---

## Security Event Model

Parsed security activity is normalized into a common `SecurityEvent` model.

Current common fields include:

```text
timestamp
source
event_type
source_ip
```

HTTP events can additionally contain:

```text
http_method
path
status_code
user_agent
```

Conceptual example:

```python
SecurityEvent(
    timestamp="15/Aug/2026:01:34:21 +0200",
    source="nginx",
    event_type="http_request",
    source_ip="185.123.45.20",
    http_method="GET",
    path="/admin",
    status_code=401,
    user_agent="Mozilla/5.0",
)
```

The model is designed so future sources can reuse the same common event structure without requiring every event to be HTTP-based.

---

## Nginx Log Parsing

SentinelFlow currently supports parsing Nginx access log entries.

Example input:

```text
185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] "GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"
```

The parser converts the raw log line into a structured `SecurityEvent`.

Conceptually:

```text
Raw Nginx Line
      ↓
Regex Parser
      ↓
SecurityEvent
```

Malformed or unsupported lines are rejected instead of producing incomplete events.

---

## Log File Ingestion

SentinelFlow can read complete Nginx log files and generate structured ingestion statistics.

The ingestion result contains:

```text
events
total_lines
valid_lines
invalid_lines
```

Conceptual flow:

```text
sample_access.log
      ↓
read_nginx_log_file()
      ↓
Nginx parser
      ↓
SecurityEvent list
      +
Ingestion statistics
```

The ingestion layer handles:

- valid log lines;
- invalid log lines;
- missing files;
- paths that are not files;
- empty log files.

---

## Real-Time Log Monitoring

SentinelFlow includes a `LogWatcher` capable of incrementally reading appended log data.

The watcher tracks its current position and avoids processing the same line repeatedly.

Current behavior includes:

- reading existing lines;
- detecting newly appended lines;
- maintaining file position;
- parsing new events;
- filtering invalid lines;
- polling continuously;
- configurable polling intervals;
- historical reading mode;
- real-time `start_at_end` mode;
- file truncation recovery;
- basic log rotation recovery;
- file identity tracking.

Conceptually:

```text
Nginx Log
    ↓
LogWatcher
    ↓
New lines only
    ↓
Nginx parser
    ↓
SecurityEvent
```

---

## Event Processing

Security events can be connected to the IOC Detection Engine.

Example flow:

```text
SecurityEvent
      ↓
source_ip
      ↓
detect_ioc()
      ↓
IOC
```

The IOC preserves the source of the original event.

For example:

```text
SecurityEvent source = nginx
        ↓
IOC source = nginx
```

Event processing also connects security events with IP classification, allowlisting and Threat Intelligence enrichment.

---

## IP Classification

SentinelFlow classifies IP addresses before deciding whether external enrichment is appropriate.

Current categories include:

```text
PUBLIC
PRIVATE
LOOPBACK
LINK_LOCAL
RESERVED
MULTICAST
UNSPECIFIED
```

Conceptually:

```text
IP
 ↓
classify_ip()
 ↓
IPClassification
 ├── value
 ├── category
 └── is_public
```

This allows SentinelFlow to distinguish public Internet addresses from addresses that should normally remain inside the local processing pipeline.

---

## IP Allowlist

SentinelFlow supports an IP allowlist.

The allowlist is part of the enrichment decision and is not intended to represent a universal list of trusted infrastructure.

Current default entries are laboratory policy examples.

A match in the allowlist means:

```text
Do not send this IP to the external Threat Intelligence enrichment pipeline.
```

It does **not** mean:

```text
This IP is guaranteed to be safe.
```

Custom allowlists can also be supplied during processing.

---

## Enrichment Policy

SentinelFlow decides whether an IP should be sent to external Threat Intelligence providers before performing enrichment.

Current policy:

```text
IP
 ↓
Classification
 ↓
Public?
 ├── No  → Do not enrich
 └── Yes
       ↓
    Allowlisted?
       ├── Yes → Do not enrich
       └── No  → Enrich
```

Therefore:

```text
PUBLIC + not allowlisted
→ enrichment enabled
```

while:

```text
PRIVATE
LOOPBACK
LINK_LOCAL
RESERVED
MULTICAST
UNSPECIFIED
```

are not sent to external providers.

This reduces unnecessary external requests and prevents local/internal addressing from being sent outside the system.

---

## Threat Intelligence Architecture

SentinelFlow includes a modular Threat Intelligence layer designed to support multiple providers without coupling the core application to a specific external service.

The current implementation includes:

- `ThreatIntelResult`
- `ThreatIntelLookupResult`
- `ThreatIntelProvider`
- `LocalThreatIntelProvider`
- `VirusTotalProvider`
- `AbuseIPDBProvider`
- `ThreatIntelService`
- `ThreatIntelCache`
- `CacheEntry`
- `ThreatIntelError`
- `VirusTotalError`
- `AbuseIPDBError`
- integration with the IP enrichment policy

Architecture:

```text
                            ThreatIntelService
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                    ▼                             ▼
            ThreatIntelCache              ThreatIntelProvider
                                                  │
                              ┌───────────────────┼───────────────────┐
                              │                   │                   │
                              ▼                   ▼                   ▼
                            Local             VirusTotal          AbuseIPDB
                           Provider             Provider            Provider
                              │                   │                   │
                              ▼                   ▼                   ▼
                      ThreatIntelResult   ThreatIntelResult   ThreatIntelResult
                              │                   │                   │
                              └───────────────────┼───────────────────┘
                                                  ↓
                                      ThreatIntelLookupResult
```

Every provider normalizes external data into the same internal structure.

---

## ThreatIntelResult

Threat Intelligence data returned by an individual provider is represented using a normalized immutable model.

Conceptually:

```python
ThreatIntelResult(
    indicator="9.9.9.9",
    provider="virustotal",
    malicious=True,
    score=15,
    confidence=92,
)
```

Current fields:

```text
indicator
provider
malicious
score
confidence
```

Provider-level scores are normalized signals.

They are not themselves the final SentinelFlow Risk Score.

---

## ThreatIntelLookupResult

Multi-provider enrichment is represented through a higher-level lookup result.

Conceptually:

```python
ThreatIntelLookupResult(
    results=[
        ThreatIntelResult(...),
    ],
    errors=[
        "abuseipdb: AbuseIPDB request timed out",
    ],
)
```

Current fields:

```text
results
errors
```

Lookup state is exposed through:

```text
successful
partial
```

Complete success:

```text
results != []
errors == []

→ successful = True
→ partial = False
```

Partial lookup:

```text
results != []
errors != []

→ successful = False
→ partial = True
```

Complete failure:

```text
results == []
errors != []

→ successful = False
→ partial = False
```

This prevents failed Threat Intelligence from being confused with a valid low-risk result.

---

## Local Threat Intelligence Provider

SentinelFlow contains a deterministic local provider used for development and testing.

The local provider:

- requires no Internet connection;
- requires no API key;
- returns deterministic results;
- allows the enrichment pipeline to be tested safely;
- implements the same provider interface as external services.

Example development rule:

```text
9.9.9.9
→ malicious = True
→ score = 80
→ confidence = 90
```

These values are simulated development data and do not represent real-world reputation information about the address.

---

## ThreatIntelService

`ThreatIntelService` coordinates one or multiple Threat Intelligence providers.

A standard lookup:

```python
service.lookup(indicator)
```

returns:

```text
list[ThreatIntelResult]
```

A status-aware lookup:

```python
service.lookup_with_status(indicator)
```

returns:

```text
ThreatIntelLookupResult
```

The service can also use an optional `ThreatIntelCache`.

Controlled `ThreatIntelError` provider failures are isolated so another provider can still return usable evidence.

Unexpected programming exceptions are intentionally allowed to propagate rather than being silently hidden.

---

## Threat Intelligence Cache

SentinelFlow includes an in-memory Threat Intelligence cache.

The cache reduces:

- duplicate API requests;
- API quota consumption;
- enrichment latency;
- unnecessary external dependencies;
- exposure to provider rate limits.

Default development TTL:

```text
300 seconds
```

Expired entries are removed when accessed.

SentinelFlow uses:

```python
time.monotonic()
```

for TTL calculations.

Only complete successful enrichment results are cached.

```text
complete success
→ cache

partial result
→ do not cache

complete failure
→ do not cache
```

This allows temporary provider failures to be retried instead of preserving them in the cache.

---

## VirusTotal Integration

SentinelFlow supports IP reputation enrichment through the **VirusTotal API v3**.

The provider currently:

- authenticates using an API key;
- uses a reusable HTTP session;
- queries IP address reports;
- reads `last_analysis_stats`;
- normalizes responses into `ThreatIntelResult`;
- uses request timeouts;
- handles connection failures;
- handles HTTP failures;
- handles rate limits;
- handles invalid JSON;
- validates unexpected response structures.

Current VirusTotal normalized score and confidence values are SentinelFlow-specific metrics and are not official VirusTotal risk probabilities.

---

## AbuseIPDB Integration

SentinelFlow supports IP reputation enrichment through the **AbuseIPDB API v2**.

The provider currently:

- authenticates using an API key;
- queries the `/check` endpoint;
- supports `maxAgeInDays`;
- reads `abuseConfidenceScore`;
- validates returned scores;
- normalizes responses into `ThreatIntelResult`;
- uses request timeouts;
- handles connection failures;
- handles authentication failures;
- handles rate limits;
- handles invalid JSON;
- validates unexpected response structures.

Current SentinelFlow provider policy uses:

```text
score < 50
→ malicious = False

score >= 50
→ malicious = True
```

This is an internal normalization rule rather than an official statement by AbuseIPDB.

---

## Threat Intelligence Exception Hierarchy

Current exception structure:

```text
ThreatIntelError
      │
      ├── VirusTotalError
      │
      └── AbuseIPDBError
```

This keeps external HTTP-library errors out of the higher-level application architecture.

---

# Risk Assessment Engine

SentinelFlow includes a dedicated Risk Assessment layer separated from Threat Intelligence collection.

Threat Intelligence answers:

```text
What evidence did each provider return?
```

The Risk Engine answers:

```text
How should SentinelFlow interpret that evidence?
```

Architecture:

```text
ThreatIntelLookupResult
        ↓
RiskPolicy
        ↓
Risk Engine
        │
        ├── score aggregation
        ├── provider trust weighting
        ├── evidence confidence
        ├── provider coverage
        ├── severity classification
        └── explainable reasons
        ↓
RiskAssessment
```

---

## RiskAssessment Model

Risk results are represented through the immutable:

```text
RiskAssessment
```

Current fields:

```text
indicator
score
severity
confidence
reasons
```

Conceptually:

```python
RiskAssessment(
    indicator="9.9.9.9",
    score=71,
    severity=RiskSeverity.HIGH,
    confidence=95,
    reasons=(
        "virustotal: score=80, confidence=90, status=malicious",
        "abuseipdb: score=60, confidence=100, status=malicious",
    ),
)
```

The model validates:

```text
indicator
→ non-empty
→ normalized

score
→ integer
→ 0–100

confidence
→ integer
→ 0–100
```

---

## Risk Severity

Current severity levels:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Default policy:

```text
0–24
→ LOW

25–49
→ MEDIUM

50–74
→ HIGH

75–100
→ CRITICAL
```

These thresholds are internal SentinelFlow policy rather than provider-native classifications.

They are now configurable through `RiskPolicy`.

---

# RiskPolicy

SentinelFlow represents Risk Engine configuration using the immutable `RiskPolicy` model.

Conceptually:

```python
RiskPolicy(
    medium_threshold=25,
    high_threshold=50,
    critical_threshold=75,
    provider_weights={
        "virustotal": 1.0,
        "abuseipdb": 1.0,
    },
)
```

A `RiskPolicy` controls:

```text
severity thresholds
+
provider trust weights
```

Default thresholds are:

```text
medium   = 25
high     = 50
critical = 75
```

Providers without an explicitly configured weight use:

```text
1.0
```

as a neutral default.

---

## RiskPolicy Validation

Risk policies are validated during construction.

Severity thresholds must:

```text
be integers
be between 1 and 100
be strictly increasing
```

Therefore:

```text
medium < high < critical
```

must always be true.

Provider names:

```text
are stripped
are converted to lowercase
cannot be empty
must remain unique after normalization
```

Provider weights:

```text
must be numeric
cannot be boolean
must be finite
must be greater than 0
```

Therefore values such as:

```text
0
-1
NaN
+infinity
-infinity
```

are rejected.

---

## Configurable Severity Policy

`severity_from_score()` can receive a `RiskPolicy`.

Default:

```python
severity_from_score(70)
```

uses:

```text
25 / 50 / 75
```

and therefore returns:

```text
HIGH
```

A custom policy:

```python
RiskPolicy(
    medium_threshold=20,
    high_threshold=40,
    critical_threshold=70,
)
```

can interpret the same:

```text
score = 70
```

as:

```text
CRITICAL
```

This allows severity interpretation to change without modifying Risk Engine source code.

---

## Base Risk Score

SentinelFlow retains a simple arithmetic score aggregation function.

Example:

```text
Provider A score = 20
Provider B score = 80

base score = 50
```

This is retained as a development reference and as a fallback when all provider confidence values are zero.

---

## Confidence-Weighted Risk Score

The Risk Engine weights provider scores using normalized provider confidence.

Conceptually:

```text
Σ(score × confidence)
─────────────────────
    Σ(confidence)
```

This prevents a provider result with low confidence from influencing the final score as strongly as a high-confidence result.

---

## Provider Trust Weighting

`RiskPolicy` can additionally assign a relative trust weight to each provider.

The current Risk Score formula becomes:

```text
Σ(score × confidence × provider_weight)
───────────────────────────────────────
Σ(confidence × provider_weight)
```

Example:

```text
VirusTotal
score      = 80
confidence = 90
weight     = 1.2

AbuseIPDB
score      = 60
confidence = 100
weight     = 0.8
```

The resulting SentinelFlow Risk Score is approximately:

```text
71
```

The provider's original normalized score is never changed.

Provider weighting affects only its influence inside SentinelFlow's aggregation policy.

Example weights in tests are development examples and do not represent claims that one real-world provider is objectively more trustworthy than another.

---

## Global Risk Confidence

Risk Score and Risk Confidence are separate concepts.

The current global evidence confidence is calculated from available provider confidence values.

Example:

```text
VirusTotal confidence = 80
AbuseIPDB confidence  = 100

Global confidence = 90
```

A system can therefore produce:

```text
Risk Score = 80
Confidence = 30
```

This means:

```text
the available evidence suggests high risk
but the evidence coverage or confidence is limited
```

It does not mean the Risk Score itself should automatically be reduced.

---

## Partial Enrichment Policy

SentinelFlow supports Risk Assessment when at least one valid Threat Intelligence result exists.

A partial lookup:

```text
Provider A ✅
Provider B ❌
```

can still produce:

```text
Risk Score
Severity
Confidence
Reasons
```

However, Risk Confidence is reduced according to evidence coverage.

A complete failure:

```text
Provider A ❌
Provider B ❌
```

does not produce:

```text
Risk Score = 0
Severity = LOW
```

Instead, SentinelFlow rejects Risk Assessment because no usable Threat Intelligence evidence exists.

Unknown is intentionally not treated as safe.

---

## Weighted Provider Coverage

Provider coverage during partial enrichment also uses `RiskPolicy` weights.

Conceptually:

```text
Σ successful provider weights
───────────────────────────────
Σ all attempted provider weights
```

Example:

```text
Provider A
weight = 2.0
success

Provider B
weight = 1.0
failure
```

Coverage:

```text
2 / 3
≈ 66.7%
```

If available evidence confidence is:

```text
90
```

the final confidence becomes:

```text
90 × 2/3
= 60
```

The opposite case:

```text
Provider A
weight = 2.0
failure

Provider B
weight = 1.0
success
```

produces:

```text
coverage = 1/3

90 × 1/3
= 30
```

Therefore failure of a provider assigned greater importance by the current policy reduces final Risk Confidence more strongly.

---

## Explainable Risk Reasons

Risk Assessments include human-readable reasons derived from provider evidence.

Example:

```text
virustotal: score=70, confidence=90, status=malicious
```

A provider failure can also be preserved:

```text
Threat Intelligence provider error:
abuseipdb: AbuseIPDB request timed out
```

This allows analysts to understand both:

```text
why the Risk Score was produced
```

and:

```text
why confidence may have been reduced
```

Provider failure metadata is currently represented as strings and will be made more structured in a future development stage.

---

## Complete Risk Assessment Flow

The implemented pipeline is now:

```text
SecurityEvent
    ↓
source_ip
    ↓
IOC Detection
    ↓
IP Classification
    ↓
Allowlist
    ↓
Enrichment Policy
    ↓
ThreatIntelService
    ↓
ThreatIntelCache
    ↓
┌──────────────────────────┐
│ Threat Intelligence      │
│ Providers                │
├────────────┬─────────────┤
│ VirusTotal │ AbuseIPDB   │
└─────┬──────┴──────┬──────┘
      ↓             ↓
ThreatIntelResult objects
      ↓
ThreatIntelLookupResult
      ↓
RiskPolicy
      │
      ├── severity thresholds
      └── provider weights
      ↓
Risk Engine
      │
      ├── normalized evidence validation
      ├── confidence weighting
      ├── provider trust weighting
      ├── provider coverage
      ├── severity classification
      └── explainable reasons
      ↓
RiskAssessment
      ↓
Future Decision Engine
```

Future components will consume `RiskAssessment` rather than depending directly on external provider APIs.

---

## API Key Configuration

External provider credentials are loaded from environment variables using `python-dotenv`.

Create a local:

```text
.env
```

with:

```text
VIRUSTOTAL_API_KEY=your_real_api_key
ABUSEIPDB_API_KEY=your_real_api_key
```

The `.env` file must remain local and is excluded from Git.

Never commit real API credentials.

A safe template is provided through:

```text
.env.example
```

Example:

```text
VIRUSTOTAL_API_KEY=your_api_key_here
ABUSEIPDB_API_KEY=your_api_key_here
```

Secrets are never intended to be embedded directly inside source code.

---

## Dependencies

Current runtime dependencies include:

```text
python-dotenv
requests
```

Development dependencies include:

```text
pytest
```

They are declared through `pyproject.toml`.

Install SentinelFlow in editable mode:

```bash
pip install -e .
```

---

## Usage

Activate the virtual environment on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Run the interactive IOC analyzer:

```powershell
python -m sentinelflow.main
```

Run the real-time log watcher:

```powershell
python -m sentinelflow.watch
```

The watcher starts in real-time mode and waits for new events appended to:

```text
logs/sample_access.log
```

Stop the watcher with:

```text
Ctrl+C
```

---

## Project Structure

Current structure:

```text
sentinelflow/
│
├── logs/
│   └── sample_access.log
│
├── src/
│   └── sentinelflow/
│       │
│       ├── __init__.py
│       ├── config.py
│       ├── main.py
│       ├── watch.py
│       │
│       ├── detection/
│       │   ├── __init__.py
│       │   ├── domain_detector.py
│       │   ├── hash_detector.py
│       │   ├── ioc_detector.py
│       │   ├── ip_allowlist.py
│       │   ├── ip_classifier.py
│       │   ├── ip_detector.py
│       │   ├── ip_policy.py
│       │   └── url_detector.py
│       │
│       ├── ingestion/
│       │   ├── __init__.py
│       │   ├── event_processor.py
│       │   ├── log_reader.py
│       │   ├── log_watcher.py
│       │   └── nginx_parser.py
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── ingestion_result.py
│       │   ├── ioc.py
│       │   ├── ip_classification.py
│       │   ├── risk.py
│       │   ├── risk_policy.py
│       │   ├── security_event.py
│       │   ├── threat_intel.py
│       │   └── threat_intel_lookup.py
│       │
│       ├── risk/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   ├── reasons.py
│       │   ├── scoring.py
│       │   └── severity.py
│       │
│       └── threat_intel/
│           ├── __init__.py
│           ├── abuseipdb_provider.py
│           ├── cache.py
│           ├── exceptions.py
│           ├── local_provider.py
│           ├── provider.py
│           ├── service.py
│           └── virustotal_provider.py
│
├── tests/
│   ├── test_abuseipdb_provider.py
│   ├── test_config.py
│   ├── test_event_processor.py
│   ├── test_ioc_detection.py
│   ├── test_ip_allowlist.py
│   ├── test_ip_classification.py
│   ├── test_ip_policy.py
│   ├── test_log_reader.py
│   ├── test_log_watcher.py
│   ├── test_nginx_parser.py
│   ├── test_risk.py
│   ├── test_risk_engine.py
│   ├── test_risk_policy.py
│   ├── test_risk_reasons.py
│   ├── test_risk_scoring.py
│   ├── test_risk_severity.py
│   ├── test_security_event.py
│   ├── test_threat_intel.py
│   ├── test_threat_intel_cache.py
│   ├── test_threat_intel_lookup.py
│   ├── test_virustotal_provider.py
│   └── test_watch.py
│
├── .env.example
├── .gitignore
├── pyproject.toml
└── README.md
```

The repository structure is intentionally created progressively.

Future directories are not added until functionality requires them.

---

## Testing

SentinelFlow uses `pytest` for automated testing.

Run the complete test suite:

```powershell
pytest -v
```

For the current Windows environment when pytest cache/temp permissions are problematic:

```powershell
pytest -v --basetemp=.\tmp -p no:cacheprovider
```

Run Threat Intelligence tests:

```powershell
pytest tests/test_threat_intel.py -v -p no:cacheprovider
```

Run Threat Intelligence cache tests:

```powershell
pytest tests/test_threat_intel_cache.py -v -p no:cacheprovider
```

Run provider tests:

```powershell
pytest tests/test_virustotal_provider.py -v -p no:cacheprovider
pytest tests/test_abuseipdb_provider.py -v -p no:cacheprovider
```

Run Risk Assessment model tests:

```powershell
pytest tests/test_risk.py -v -p no:cacheprovider
```

Run RiskPolicy tests:

```powershell
pytest tests/test_risk_policy.py -v -p no:cacheprovider
```

Run severity tests:

```powershell
pytest tests/test_risk_severity.py -v -p no:cacheprovider
```

Run scoring tests:

```powershell
pytest tests/test_risk_scoring.py -v -p no:cacheprovider
```

Run reason-generation tests:

```powershell
pytest tests/test_risk_reasons.py -v -p no:cacheprovider
```

Run Risk Engine tests:

```powershell
pytest tests/test_risk_engine.py -v -p no:cacheprovider
```

Run the complete Risk suite:

```powershell
pytest tests/test_risk.py tests/test_risk_policy.py tests/test_risk_severity.py tests/test_risk_scoring.py tests/test_risk_reasons.py tests/test_risk_engine.py -v -p no:cacheprovider
```

Tests currently cover areas including:

- IOC type detection;
- IOC validation;
- source attribution;
- Nginx parsing;
- malformed log rejection;
- full-file ingestion;
- ingestion statistics;
- real-time incremental log monitoring;
- duplicate prevention;
- truncation recovery;
- log rotation recovery;
- IP classification;
- special-address categories;
- IP allowlisting;
- enrichment decisions;
- Threat Intelligence normalization;
- provider abstraction;
- VirusTotal integration;
- AbuseIPDB integration;
- provider HTTP failure handling;
- authentication failures;
- rate limits;
- invalid JSON;
- unexpected provider responses;
- provider failure isolation;
- partial Threat Intelligence results;
- complete enrichment failure;
- unexpected exception propagation;
- in-memory Threat Intelligence caching;
- cache hits;
- cache misses;
- configurable TTL;
- expiration;
- provider retries;
- RiskAssessment validation;
- RiskAssessment immutability;
- severity classification boundaries;
- configurable severity thresholds;
- RiskPolicy validation;
- provider-name normalization;
- neutral provider weights;
- provider-specific weights;
- invalid provider weights;
- NaN provider weights;
- infinite provider weights;
- duplicate normalized provider names;
- base score aggregation;
- confidence-weighted scoring;
- provider-weighted scoring;
- deterministic half-up rounding;
- score and confidence validation;
- empty provider-name rejection;
- global Risk Confidence;
- Risk Assessment reason generation;
- full lookup Risk Assessment;
- partial lookup Risk Assessment;
- complete-failure Risk Assessment rejection;
- policy-driven scoring;
- policy-driven severity;
- provider-weighted lookup coverage;
- higher-weight provider success;
- higher-weight provider failure;
- neutral weight fallback for unknown providers;
- partial-evidence confidence adjustment;
- provider errors preserved as Risk Assessment reasons.

New functionality is expected to receive automated test coverage before development advances to the next stage.

---

## Development Philosophy

SentinelFlow is developed incrementally:

```text
Build
  ↓
Understand
  ↓
Test
  ↓
Document
  ↓
Commit
  ↓
Next Feature
```

The project avoids creating unused infrastructure or prematurely adding technologies that are not yet required.

The goal is to build a system where individual components can be understood, tested, replaced and extended independently.

---

## Development Progress

### Foundation

Implemented:

- Python package structure;
- virtual environment;
- Git and GitHub repository;
- `.gitignore`;
- `pyproject.toml`;
- editable installation;
- pytest environment.

### IOC Detection

Implemented:

- immutable IOC model;
- IPv4;
- IPv6;
- domains;
- URLs;
- MD5;
- SHA1;
- SHA256;
- invalid IOC handling;
- normalization;
- source attribution;
- CLI.

### Log Ingestion

Implemented:

- `SecurityEvent`;
- Nginx parser;
- full-file reading;
- ingestion statistics;
- incremental log reading;
- real-time watcher;
- append detection;
- duplicate prevention;
- truncation recovery;
- basic log rotation recovery.

### Event Processing

Implemented:

- event IOC extraction;
- IP classification;
- allowlisting;
- enrichment decision policy;
- Threat Intelligence enrichment.

### Threat Intelligence

Implemented:

- `ThreatIntelResult`;
- `ThreatIntelLookupResult`;
- `ThreatIntelProvider`;
- deterministic local provider;
- `ThreatIntelService`;
- VirusTotal API v3 provider;
- AbuseIPDB API v2 provider;
- normalized provider data;
- Threat Intelligence exception hierarchy;
- controlled provider failure isolation;
- partial-result preservation;
- lookup status;
- in-memory cache;
- configurable TTL;
- monotonic expiration;
- success-only cache policy;
- provider retry behavior.

### Risk Assessment

Implemented:

- `RiskAssessment`;
- `RiskSeverity`;
- validated scores;
- validated confidence;
- automatic severity classification;
- base multi-provider score;
- confidence-weighted scoring;
- global confidence calculation;
- explainable reasons;
- complete lookup assessment;
- partial lookup assessment;
- full-failure protection;
- provider-error reasons.

### Risk Policy

Implemented:

- `RiskPolicy`;
- configurable severity thresholds;
- strict threshold validation;
- provider-specific trust weights;
- default neutral provider weight;
- provider name normalization;
- provider-weight validation;
- finite-number validation;
- duplicate normalized-provider protection;
- policy-driven severity;
- policy-driven Risk Score;
- shared policy across Risk Engine components;
- weighted provider coverage;
- partial-evidence confidence adjustment.

---

## Roadmap

Planned development areas include:

### Threat Intelligence

- domain enrichment;
- URL enrichment;
- hash enrichment;
- additional Threat Intelligence providers;
- provider-specific caching strategies;
- structured provider failure metadata;
- configurable external provider settings.

### Risk Assessment

- richer provider trust models;
- configurable policy loading;
- event-context risk signals;
- behavioral risk signals;
- asset criticality;
- historical risk signals;
- richer evidence explanations.

### Detection Engineering

- brute-force detection;
- directory scanning detection;
- suspicious HTTP request patterns;
- repeated-source behavioral analysis;
- configurable detection rules;
- MITRE ATT&CK mapping.

### Persistence

- SQLite storage;
- IOC history;
- event history;
- enrichment history;
- Risk Assessment history;
- alert history;
- audit trail.

### Alerting

- normalized alert model;
- Risk Assessment to alert conversion;
- alert deduplication;
- configurable alert thresholds;
- notification integrations.

### Defensive Response

- response engine;
- safe default behavior;
- dry-run execution;
- temporary blocking;
- automatic unblocking;
- explicit authorization;
- human approval workflows.

### API

- FastAPI;
- event endpoints;
- IOC endpoints;
- Risk Assessment endpoints;
- alert endpoints;
- health endpoints;
- response-control endpoints.

### Infrastructure

- Docker;
- Docker Compose;
- CI/CD;
- GitHub Actions;
- improved structured logging;
- monitoring;
- production-style documentation.

Additional technologies will only be introduced when their corresponding stage requires them.

---

## Security Philosophy

SentinelFlow is designed as a defensive security project.

The project prioritizes:

- safe defaults;
- explicit authorization;
- modular processing;
- validation before action;
- controlled external enrichment;
- protection of credentials;
- auditability;
- explainable risk decisions;
- human oversight;
- dry-run execution before active remediation.

A failed Threat Intelligence request is not treated as evidence that an indicator is safe.

A high Risk Score does not automatically imply an active response.

Risk Assessment and future response logic are deliberately separated.

Future defensive actions will require explicit policy and authorization.

---

## Current Limitations

SentinelFlow is still under active development.

Current limitations include:

- Nginx is currently the primary implemented log source.
- Threat Intelligence enrichment currently focuses on IP addresses.
- The local provider contains simulated development data.
- VirusTotal and AbuseIPDB are the current external providers.
- Threat Intelligence caching is process-local and in-memory.
- Cached data is lost after process restart.
- Cache entries currently represent complete aggregated lookups rather than independent provider caches.
- Partial and failed lookups are intentionally not cached.
- Provider failure information is currently represented as strings.
- Partial-lookup provider identification currently depends on the `provider: message` error convention.
- Provider weights are currently configured directly through `RiskPolicy`.
- Default provider weights are neutral rather than evidence-based.
- Example custom provider weights used in tests are development examples rather than objective provider reliability claims.
- Global evidence confidence currently uses the arithmetic mean of successful provider confidence values.
- Provider trust weights affect Risk Score and partial-lookup coverage, but do not directly modify provider-reported confidence.
- Risk scoring currently relies on Threat Intelligence evidence rather than event behavior.
- Asset criticality is not yet included in Risk Assessment.
- Historical evidence is not yet included in Risk Assessment.
- SentinelFlow Risk Scores and confidence values are internal metrics, not statistical probabilities.
- No persistent database exists yet.
- No production alerting layer exists yet.
- No active defensive response is performed yet.
- No public API or dashboard exists yet.

These limitations are intentional development boundaries rather than hidden capabilities.

---

## Disclaimer

SentinelFlow is intended exclusively for:

- defensive security research;
- SOC training;
- cybersecurity laboratories;
- owned infrastructure;
- explicitly authorized systems.

It is not intended for unauthorized access, offensive operations or activity against systems without permission.

Any future automated response functionality will be designed for controlled defensive use only.