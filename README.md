# SentinelFlow

**Automated Threat Detection, Enrichment & Response Platform**

SentinelFlow is a defensive cybersecurity automation project built in Python.

The goal of the project is to simulate a modular SOC/SOAR workflow capable of ingesting security events, detecting indicators of compromise, analyzing local behavior, enriching indicators through Threat Intelligence, assessing risk, generating alerts and supporting controlled defensive response workflows.

---

## Project Status

🚧 **Under active development**

Current development stage:

**Threat Intelligence, Behavioral Detection & Risk Assessment**

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
- Partial Threat Intelligence result preservation.
- Threat Intelligence lookup status tracking.
- In-memory Threat Intelligence caching.
- Configurable cache TTL.
- Safe caching policy for complete enrichment results.
- Risk Assessment model.
- Configurable `RiskPolicy`.
- Configurable severity thresholds.
- Provider-specific trust weights.
- Confidence-weighted risk scoring.
- Provider-weighted risk scoring.
- Weighted provider coverage.
- Explainable Risk Assessment reasons.
- Behavioral evidence model.
- Repeated authentication-failure detection.
- High HTTP 404 detection.
- HTTP path-diversity detection.
- Directory-scanning signal generation.
- Multi-detector behavioral analysis.
- Behavioral evidence integration with Risk Assessment.
- Conservative behavioral Risk Score uplift.
- Behavioral explanation preservation.

---

## Focus

SentinelFlow focuses on:

- Blue Team security.
- SOC automation.
- Detection Engineering.
- Threat Intelligence.
- Behavioral detection.
- Risk Assessment.
- Incident Response.
- SOAR workflows.
- Security event normalization.
- Defensive automation.
- Python engineering.
- Modular cybersecurity architecture.

---

## Architecture

SentinelFlow is being developed as a modular defensive security pipeline.

```text
Log Source
    ↓
Log Ingestion
    ↓
Parsing
    ↓
SecurityEvent
    │
    ├──────────────────────────────┐
    │                              │
    ↓                              ↓
IOC Detection               Behavior Analyzer
    │                              │
    ↓                   ┌──────────┼──────────┐
IP Classification       │          │          │
    │                    ↓          ↓          ↓
Allowlist            Auth Fail   High 404   Paths
    │                    │          │          │
Enrichment Policy       └──────────┼──────────┘
    │                              ↓
ThreatIntelService             BehaviorSignal[]
    │                              │
ThreatIntelCache                  │
    │                              │
ThreatIntelProvider               │
    │                              │
    ↓                              │
ThreatIntelResult                 │
    ↓                              │
ThreatIntelLookupResult           │
    └──────────────┬───────────────┘
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

The architecture separates:

```text
collection
↓
normalization
↓
detection
↓
enrichment
↓
risk interpretation
↓
future decision making
```

---

# IOC Detection

SentinelFlow detects and validates multiple Indicator of Compromise types.

Supported:

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
8.8.8.8
→ IPv4
→ Valid
```

Invalid input is also handled:

```text
hello world
→ INVALID
→ Valid: False
```

---

## IOC Model

Indicators are represented using an immutable model.

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

The `source` field identifies where an indicator originated.

---

# SecurityEvent

Parsed activity is normalized into a common `SecurityEvent` model.

Common fields:

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

Conceptually:

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

---

# Nginx Log Parsing

SentinelFlow supports parsing Nginx access-log entries.

Example:

```text
185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] "GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"
```

Conceptual flow:

```text
Raw Nginx line
      ↓
Parser
      ↓
SecurityEvent
```

Malformed or unsupported lines are rejected.

---

# Log File Ingestion

SentinelFlow can read Nginx log files and return structured ingestion data.

Current ingestion statistics include:

```text
events
total_lines
valid_lines
invalid_lines
```

The ingestion layer handles:

- valid lines;
- invalid lines;
- missing files;
- non-file paths;
- empty files.

---

# Real-Time Log Monitoring

`LogWatcher` incrementally reads appended log data.

Current functionality includes:

- reading new lines;
- tracking file position;
- avoiding duplicate processing;
- parsing appended events;
- configurable polling;
- historical mode;
- `start_at_end` mode;
- truncation recovery;
- basic rotation recovery;
- file identity tracking.

---

# Event Processing

Security events can be connected to IOC Detection and Threat Intelligence enrichment.

Conceptually:

```text
SecurityEvent
      ↓
source_ip
      ↓
IOC
      ↓
classification
      ↓
enrichment decision
```

---

# IP Classification

Current categories:

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

---

# IP Allowlist

SentinelFlow supports an IP allowlist as part of the enrichment policy.

A match means:

```text
Do not send this IP to external Threat Intelligence providers.
```

It does not mean that an IP is guaranteed to be safe.

Default entries are development/laboratory policy examples.

---

# Enrichment Policy

Current IP enrichment policy:

```text
IP
 ↓
Classification
 ↓
Public?
 ├── No  → do not externally enrich
 └── Yes
       ↓
    Allowlisted?
       ├── Yes → do not externally enrich
       └── No  → enrich
```

This reduces unnecessary external requests and prevents local addressing from being sent outside the system.

---

# Threat Intelligence

SentinelFlow includes a modular Threat Intelligence layer.

Current components include:

- `ThreatIntelResult`
- `ThreatIntelLookupResult`
- `ThreatIntelProvider`
- `LocalThreatIntelProvider`
- `VirusTotalProvider`
- `AbuseIPDBProvider`
- `ThreatIntelService`
- `ThreatIntelCache`
- provider-specific exceptions

Architecture:

```text
ThreatIntelService
       │
       ├── cache
       │
       └── providers
             │
       ┌─────┼──────────────┐
       ↓     ↓              ↓
     Local VirusTotal   AbuseIPDB
       │     │              │
       └─────┼──────────────┘
             ↓
      ThreatIntelResult[]
             ↓
    ThreatIntelLookupResult
```

---

## ThreatIntelResult

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

Provider scores are normalized evidence, not the final SentinelFlow Risk Score.

---

## ThreatIntelLookupResult

Multi-provider results are represented through:

```python
ThreatIntelLookupResult(
    results=[...],
    errors=[...],
)
```

Complete success:

```text
results != []
errors == []
```

Partial lookup:

```text
results != []
errors != []
```

Complete failure:

```text
results == []
errors != []
```

Failed enrichment is never interpreted as evidence of safety.

---

## Local Threat Intelligence Provider

A deterministic local provider is available for development and testing.

Example development behavior:

```text
9.9.9.9
→ malicious = True
→ score = 80
→ confidence = 90
```

These values are simulated test data and do not represent a real-world reputation judgment.

---

## VirusTotal

SentinelFlow supports IP reputation enrichment through VirusTotal API v3.

Current handling includes:

- API authentication;
- reusable HTTP session;
- request timeout;
- connection errors;
- HTTP errors;
- rate limits;
- invalid JSON;
- unexpected response structures;
- normalized `ThreatIntelResult`.

SentinelFlow score/confidence normalization is internal and is not an official VirusTotal probability.

---

## AbuseIPDB

SentinelFlow supports IP reputation enrichment through AbuseIPDB API v2.

Current handling includes:

- authentication;
- `/check` lookups;
- `maxAgeInDays`;
- `abuseConfidenceScore`;
- score validation;
- HTTP failure handling;
- rate-limit handling;
- invalid JSON handling;
- normalized `ThreatIntelResult`.

Current SentinelFlow provider policy uses:

```text
score < 50
→ malicious = False

score >= 50
→ malicious = True
```

This is an internal normalization rule.

---

# Threat Intelligence Cache

SentinelFlow includes an in-memory cache.

Default development TTL:

```text
300 seconds
```

Only complete successful lookups are cached.

```text
complete success
→ cache

partial
→ do not cache

failure
→ do not cache
```

This avoids storing incomplete enrichment as if it were final evidence.

---

# Risk Assessment

SentinelFlow includes a Risk Assessment layer separated from Threat Intelligence providers.

Threat Intelligence answers:

```text
What did the external sources report?
```

Behavioral Detection answers:

```text
What did SentinelFlow observe locally?
```

The Risk Engine answers:

```text
How should these signals influence the current assessment?
```

---

## RiskAssessment

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
    indicator="203.0.113.10",
    score=76,
    severity=RiskSeverity.CRITICAL,
    confidence=90,
    reasons=(...),
)
```

The model validates:

```text
indicator
score
confidence
```

and is immutable.

---

# RiskSeverity

Current severity levels:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Default thresholds:

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

These thresholds are SentinelFlow policy.

---

# RiskPolicy

`RiskPolicy` controls:

```text
severity thresholds
provider trust weights
```

Default:

```python
RiskPolicy(
    medium_threshold=25,
    high_threshold=50,
    critical_threshold=75,
)
```

Providers without an explicit weight use:

```text
1.0
```

Provider names are normalized.

Provider weights must:

```text
be numeric
be finite
be > 0
```

Thresholds must:

```text
be integers
be between 1 and 100
be strictly increasing
```

---

# Risk Scoring

Base score:

```text
arithmetic mean
```

Confidence-weighted scoring:

```text
Σ(score × confidence)
─────────────────────
Σ(confidence)
```

Provider-weighted scoring:

```text
Σ(score × confidence × provider_weight)
───────────────────────────────────────
Σ(confidence × provider_weight)
```

Provider weights affect aggregation rather than changing the original provider result.

---

# Partial Enrichment Confidence

Partial Threat Intelligence lookups reduce final Risk Confidence.

Provider coverage uses RiskPolicy weights:

```text
Σ successful provider weights
───────────────────────────────
Σ attempted provider weights
```

A higher-weight provider failure therefore reduces evidence coverage more strongly.

Risk Score is not automatically reduced because one provider failed.

This keeps:

```text
risk level
```

separate from:

```text
evidence confidence
```

---

# Behavioral Detection

SentinelFlow now includes local behavioral detection based on `SecurityEvent` collections.

The behavioral layer asks:

```text
What is this source actually doing in the observed logs?
```

instead of relying exclusively on external reputation.

Current architecture:

```text
SecurityEvent[]
      ↓
Behavior Analyzer
      │
      ├── repeated auth failures
      ├── high HTTP 404 count
      └── HTTP path diversity
      ↓
BehaviorSignal[]
```

---

## BehaviorSignal

Behavioral detections use the immutable `BehaviorSignal` model.

Current fields:

```text
source_ip
signal_type
score
event_count
reason
```

Example:

```python
BehaviorSignal(
    source_ip="203.0.113.10",
    signal_type=BehaviorSignalType.DIRECTORY_SCANNING,
    score=70,
    event_count=11,
    reason="11 unique HTTP paths requested",
)
```

Behavior score is a normalized detector signal.

It is not itself the final SentinelFlow Risk Score.

---

## BehaviorSignalType

Current signal types:

```text
REPEATED_AUTH_FAILURES
HIGH_404_RATE
DIRECTORY_SCANNING
SUSPICIOUS_PATH_ACTIVITY
```

`SUSPICIOUS_PATH_ACTIVITY` is currently represented in the model but does not yet have an implemented detector.

---

# Repeated Authentication Failures

The first behavioral detector analyzes repeated:

```text
HTTP 401
HTTP 403
```

per source IP.

Default threshold:

```text
5
```

Default scoring policy:

```text
threshold reached
→ 50

each additional failure
→ +5

maximum
→ 100
```

Example:

```text
8 authentication-related failures
→ score 65
```

The threshold and score are development policy values, not universal attack definitions.

---

# High HTTP 404 Detection

SentinelFlow detects large numbers of:

```text
HTTP 404
```

per source IP.

Default threshold:

```text
10
```

Default scoring:

```text
threshold reached
→ 40

each additional 404
→ +4

maximum
→ 100
```

This is currently a count within the supplied event collection rather than a true time-based rate.

---

# Directory Scanning / Path Diversity

SentinelFlow measures the number of unique HTTP paths requested by each source IP.

Example:

```text
/admin
/wp-admin
/.env
/phpmyadmin
/config
/backup
/server-status
/login
```

Default threshold:

```text
8 unique paths
```

Default score:

```text
threshold reached
→ 55

each additional unique path
→ +5

maximum
→ 100
```

Repeated requests to the same path do not increase path diversity.

For example:

```text
/favicon.ico
/favicon.ico
/favicon.ico
```

represents:

```text
1 unique path
```

not three.

HTTP status code does not currently control path-diversity detection.

---

# Behavior Analyzer

Individual detectors are orchestrated through:

```python
analyze_behavior(events)
```

The analyzer currently executes:

```text
Repeated Auth Failure detector
High 404 detector
Directory Scanning detector
```

and returns a single:

```text
list[BehaviorSignal]
```

A single IP can produce multiple independent signals.

The analyzer does not:

```text
calculate Risk Score
merge signals
decide incidents
perform response
```

Its responsibility is detection orchestration only.

---

# Behavior + Risk Integration

Behavioral evidence can now be passed to the Risk Engine.

Conceptually:

```python
assessment = assess_risk(
    threat_intel_results,
    behavior_signals=signals,
)
```

Behavior is currently treated as contextual risk uplift.

---

## Behavioral Uplift

SentinelFlow uses a deliberately conservative first integration policy.

Maximum behavioral uplift:

```text
25 Risk Score points
```

Formula:

```text
strongest behavior score
×
25 / 100
```

Example:

```text
Behavior score = 70

70 × 25 / 100
= 17.5
→ 18
```

If Threat Intelligence Risk Score is:

```text
60
```

the combined score becomes:

```text
60 + 18
= 78
```

The final score is capped at:

```text
100
```

---

## Strongest-Signal Aggregation

Behavioral scores are not blindly added together.

Example:

```text
Repeated auth failures = 50
High 404              = 40
Directory scanning    = 70
```

SentinelFlow does not calculate:

```text
50 + 40 + 70
```

because several signals may derive from overlapping events.

Instead:

```text
strongest signal = 70
```

is used for numerical uplift.

All signals remain available as explanatory reasons.

This reduces accidental double counting.

---

## Behavior Reasons

Behavioral detections are preserved in the final Risk Assessment.

Example:

```text
behavior:DIRECTORY_SCANNING:
score=70,
event_count=11,
reason=11 unique HTTP paths requested
```

This means a final assessment can explain evidence from:

```text
Threat Intelligence
+
local observed behavior
```

---

# Combined Risk Flow

The current implemented assessment flow is:

```text
SecurityEvent[]
      │
      ├───────────────────────────┐
      │                           │
      ↓                           ↓
IOC / Enrichment           Behavior Analyzer
      │                           │
      ↓                           ↓
ThreatIntelLookupResult     BehaviorSignal[]
      │                           │
      └─────────────┬─────────────┘
                    ↓
               Risk Engine
                    │
       ┌────────────┼────────────┐
       │            │            │
       ↓            ↓            ↓
 TI Risk Score   Behavior      Reasons
                 Uplift
       │            │            │
       └────────────┼────────────┘
                    ↓
              RiskAssessment
```

---

# Confidence Semantics

Current Risk Confidence is still primarily derived from Threat Intelligence evidence.

Behavioral signals currently:

```text
can increase Risk Score
can increase severity
can add reasons
```

but do not directly change:

```text
Risk Confidence
```

This is intentional.

Provider confidence and local detector confidence do not yet share a common semantic model.

---

# Behavior-Only Limitation

The current Risk Engine still requires at least one usable Threat Intelligence result.

Therefore:

```text
behavior signals exist
+
no Threat Intelligence results
```

does not yet produce a `RiskAssessment`.

Behavior-only assessment will require a separate policy for:

```text
base score
confidence
coverage
severity
```

and is intentionally deferred.

---

# Explainability

A final Risk Assessment can contain reasons such as:

```text
test-provider: score=60, confidence=90, status=malicious
```

plus:

```text
behavior:HIGH_404_RATE:
score=40,
event_count=10,
reason=10 HTTP 404 responses detected
```

plus:

```text
behavior:DIRECTORY_SCANNING:
score=65,
event_count=10,
reason=10 unique HTTP paths requested
```

The project prioritizes explainable evidence rather than opaque scores.

---

# API Keys

External API credentials are loaded from environment variables.

Local file:

```text
.env
```

Example:

```text
VIRUSTOTAL_API_KEY=your_real_api_key
ABUSEIPDB_API_KEY=your_real_api_key
```

`.env` must never be committed.

Safe template:

```text
.env.example
```

Example content:

```text
VIRUSTOTAL_API_KEY=your_api_key_here
ABUSEIPDB_API_KEY=your_api_key_here
```

---

# Dependencies

Runtime:

```text
python-dotenv
requests
```

Development:

```text
pytest
```

Install editable package:

```powershell
pip install -e .
```

---

# Usage

Activate the environment:

```powershell
.venv\Scripts\Activate.ps1
```

Run IOC analyzer:

```powershell
python -m sentinelflow.main
```

Run real-time log watcher:

```powershell
python -m sentinelflow.watch
```

Stop with:

```text
Ctrl+C
```

---

# Project Structure

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
│       ├── behavior/
│       │   ├── __init__.py
│       │   ├── analyzer.py
│       │   ├── auth_failures.py
│       │   ├── directory_scanning.py
│       │   └── high_404.py
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
│       │   ├── behavior.py
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
│       │   ├── behavior.py
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
│   ├── test_auth_failures.py
│   ├── test_behavior.py
│   ├── test_behavior_analyzer.py
│   ├── test_behavior_risk_integration.py
│   ├── test_config.py
│   ├── test_directory_scanning.py
│   ├── test_event_processor.py
│   ├── test_high_404.py
│   ├── test_ioc_detection.py
│   ├── test_ip_allowlist.py
│   ├── test_ip_classification.py
│   ├── test_ip_policy.py
│   ├── test_log_reader.py
│   ├── test_log_watcher.py
│   ├── test_nginx_parser.py
│   ├── test_risk.py
│   ├── test_risk_behavior.py
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

---

# Testing

Run everything:

```powershell
pytest -v
```

For the current Windows environment:

```powershell
pytest -v --basetemp=.\tmp -p no:cacheprovider
```

Behavior model:

```powershell
pytest tests/test_behavior.py -v -p no:cacheprovider
```

Repeated authentication failures:

```powershell
pytest tests/test_auth_failures.py -v -p no:cacheprovider
```

High 404:

```powershell
pytest tests/test_high_404.py -v -p no:cacheprovider
```

Directory scanning:

```powershell
pytest tests/test_directory_scanning.py -v -p no:cacheprovider
```

Behavior analyzer:

```powershell
pytest tests/test_behavior_analyzer.py -v -p no:cacheprovider
```

Behavior/Risk integration:

```powershell
pytest tests/test_behavior_risk_integration.py -v -p no:cacheprovider
```

Risk behavioral utilities:

```powershell
pytest tests/test_risk_behavior.py -v -p no:cacheprovider
```

Risk Engine:

```powershell
pytest tests/test_risk_engine.py -v -p no:cacheprovider
```

Current test coverage includes:

- IOC validation;
- log parsing;
- log ingestion;
- real-time monitoring;
- IP classification;
- allowlisting;
- enrichment policy;
- Threat Intelligence providers;
- HTTP error handling;
- partial provider failure;
- caching;
- cache expiration;
- RiskPolicy;
- provider trust weighting;
- Risk Severity;
- Risk Score aggregation;
- partial-evidence coverage;
- BehaviorSignal validation;
- repeated authentication failures;
- high HTTP 404 counts;
- HTTP path diversity;
- per-IP behavioral grouping;
- detector thresholds;
- detector scoring;
- multi-detector orchestration;
- behavioral Risk Score uplift;
- strongest-signal aggregation;
- behavioral reason preservation;
- cross-indicator protection;
- Behavior Analyzer to Risk Engine integration.

New functionality is expected to receive automated tests before development proceeds.

---

# Development Philosophy

SentinelFlow follows:

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

The project intentionally avoids introducing technologies before they are needed.

---

# Development Progress

## Foundation

Implemented:

- Python project structure;
- virtual environment;
- Git/GitHub;
- `.gitignore`;
- `pyproject.toml`;
- editable install;
- pytest.

## IOC Detection

Implemented:

- IOC model;
- IPv4;
- IPv6;
- Domain;
- URL;
- MD5;
- SHA1;
- SHA256;
- invalid handling;
- normalization;
- source attribution.

## Ingestion

Implemented:

- `SecurityEvent`;
- Nginx parser;
- file reading;
- ingestion statistics;
- incremental reading;
- real-time watcher;
- truncation recovery;
- rotation recovery.

## Threat Intelligence

Implemented:

- provider interface;
- local provider;
- VirusTotal;
- AbuseIPDB;
- normalized results;
- lookup status;
- failure isolation;
- cache;
- TTL;
- success-only caching.

## Risk Assessment

Implemented:

- `RiskAssessment`;
- `RiskSeverity`;
- `RiskPolicy`;
- configurable thresholds;
- provider trust weighting;
- weighted risk score;
- global TI confidence;
- weighted provider coverage;
- partial lookup handling;
- explainable reasons.

## Behavioral Detection

Implemented:

- `BehaviorSignal`;
- `BehaviorSignalType`;
- repeated authentication failure detector;
- high 404 detector;
- directory scanning/path-diversity detector;
- per-IP aggregation;
- configurable thresholds;
- signal scoring;
- Behavior Analyzer;
- multi-detector orchestration.

## Behavior + Risk

Implemented:

- behavioral uplift;
- maximum uplift of 25;
- strongest-signal numerical aggregation;
- final score cap at 100;
- behavioral reasons;
- cross-indicator validation;
- Threat Intelligence + local behavior Risk Assessment.

---

# Roadmap

## Behavioral Detection

Planned:

- time windows;
- event-rate calculation;
- suspicious path detector;
- User-Agent context;
- repeated source activity over time;
- behavior confidence;
- configurable behavior policy;
- MITRE ATT&CK mapping.

## Threat Intelligence

Planned:

- domains;
- URLs;
- hashes;
- additional providers;
- structured provider errors;
- richer provider configuration.

## Risk Assessment

Planned:

- behavior-only assessments;
- richer behavior weighting;
- configurable behavioral uplift;
- asset criticality;
- historical evidence;
- richer confidence model;
- event-context scoring.

## Persistence

Planned:

- SQLite;
- event history;
- IOC history;
- Threat Intelligence history;
- behavioral history;
- Risk Assessment history;
- alert history;
- audit trail.

## Alerting

Planned:

- alert model;
- Risk Assessment to alert conversion;
- thresholds;
- deduplication;
- notification channels.

## Defensive Response

Planned:

- response engine;
- dry-run;
- temporary blocking;
- automatic unblock;
- explicit authorization;
- human approval.

## API

Planned:

- FastAPI;
- IOC endpoints;
- event endpoints;
- risk endpoints;
- alert endpoints;
- health endpoints.

## Infrastructure

Planned:

- Docker;
- Docker Compose;
- GitHub Actions;
- CI;
- structured logging;
- monitoring;
- deployment documentation.

---

# Security Philosophy

SentinelFlow is defensive by design.

The project prioritizes:

- safe defaults;
- validation;
- explainability;
- controlled external enrichment;
- credential protection;
- separation of detection and response;
- auditability;
- human oversight.

Important principles:

```text
Unknown Threat Intelligence
≠ safe
```

```text
High Risk Score
≠ automatic blocking
```

```text
BehaviorSignal
≠ confirmed attack
```

Signals contribute evidence.

Future decision and response layers will determine what action, if any, is appropriate.

---

# Current Limitations

SentinelFlow is still under active development.

Current limitations include:

- Nginx is the main implemented log source.
- Threat Intelligence currently focuses mainly on IPs.
- Behavioral detection currently operates on supplied event collections rather than explicit time windows.
- `HIGH_404_RATE` is currently a count rather than a strict temporal rate.
- Authentication failures treat 401 and 403 equally.
- Directory scanning currently uses unique path count without User-Agent or crawler context.
- `SUSPICIOUS_PATH_ACTIVITY` does not yet have a detector.
- Behavioral thresholds are currently configured directly through detector function parameters.
- No dedicated `BehaviorPolicy` exists yet.
- Behavioral scoring values are internal development policy.
- Behavioral signals do not currently have their own confidence field.
- Behavioral evidence can only increase the Risk Score.
- Only the strongest behavior signal affects numerical uplift.
- Maximum behavior uplift is currently fixed at 25.
- Behavioral uplift is not yet part of `RiskPolicy`.
- Risk Confidence is still primarily based on Threat Intelligence.
- Behavior-only Risk Assessment is not currently supported.
- Threat Intelligence provider errors are represented as strings.
- Partial lookup coverage depends on the current `provider: message` convention.
- Threat Intelligence cache is in-memory.
- No persistent database exists.
- No alerting subsystem exists.
- No automated defensive response exists.
- No API exists.
- No dashboard exists.

These are explicit development boundaries rather than hidden capabilities.

---

# Disclaimer

SentinelFlow is intended exclusively for:

- defensive security research;
- SOC training;
- cybersecurity laboratories;
- owned infrastructure;
- explicitly authorized systems.

It is not intended for unauthorized access or offensive activity against systems without permission.

Future response features will be designed for controlled defensive use only.