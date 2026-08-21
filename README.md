# SentinelFlow

**Automated Threat Detection, Enrichment & Response Platform**

SentinelFlow is a defensive cybersecurity automation project built in Python.

The goal of the project is to simulate a modular SOC/SOAR workflow capable of ingesting security events, detecting indicators of compromise, applying enrichment policies, querying external threat intelligence providers, assessing risk, generating alerts and supporting controlled defensive response workflows.

---

## Project Status

🚧 **Under active development**

Current development stage:

**Log Ingestion, Event Normalization & Multi-Provider Threat Intelligence Enrichment**

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

---

## Focus

SentinelFlow focuses on:

- Blue Team security.
- SOC automation.
- Threat Intelligence.
- Detection Engineering.
- Incident Response.
- SOAR workflows.
- Security event normalization.
- Defensive automation.
- Python engineering.
- Modular cybersecurity architecture.

---

## Current Architecture

SentinelFlow is being developed as a modular pipeline.

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
ThreatIntelProvider
    ↓
External / Local Threat Intelligence
    ↓
ThreatIntelResult
    ↓
Future Risk Assessment
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
- `ThreatIntelProvider`
- `LocalThreatIntelProvider`
- `ThreatIntelService`
- `VirusTotalProvider`
- `AbuseIPDBProvider`
- `ThreatIntelError`
- `VirusTotalError`
- `AbuseIPDBError`
- integration with the IP enrichment policy

Architecture:

```text
                         ThreatIntelProvider
                                │
              ┌─────────────────┼──────────────────┐
              │                 │                  │
            Local          VirusTotal          AbuseIPDB
           Provider         Provider            Provider
              │                 │                  │
              ▼                 ▼                  ▼
       ThreatIntelResult ThreatIntelResult ThreatIntelResult
              │                 │                  │
              └─────────────────┼──────────────────┘
                                ↓
                       ThreatIntelService
```

The rest of SentinelFlow does not need to understand each provider's native response format.

Every provider normalizes its data into the same internal model.

---

## ThreatIntelResult

Threat Intelligence data is represented using a normalized immutable model.

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

This allows multiple Threat Intelligence providers to produce a consistent result even when their original APIs use completely different response formats.

---

## Local Threat Intelligence Provider

SentinelFlow contains a deterministic local provider used for development and testing.

The local provider:

- requires no Internet connection;
- requires no API key;
- returns deterministic results;
- allows the complete enrichment pipeline to be tested safely;
- implements the same `ThreatIntelProvider` interface as external providers.

Example development rule:

```text
9.9.9.9
→ malicious = True
→ score = 80
→ confidence = 90
```

These values are **simulated development data**.

They do not represent real-world reputation information about the address.

---

## ThreatIntelService

`ThreatIntelService` coordinates one or multiple Threat Intelligence providers.

Conceptually:

```python
service = ThreatIntelService(
    providers=[
        provider_a,
        provider_b,
    ]
)
```

A lookup can then be performed through:

```python
service.lookup(indicator)
```

The service returns:

```text
list[ThreatIntelResult]
```

Architecture:

```text
Indicator
    ↓
ThreatIntelService
    │
    ├── Provider A
    │      ↓
    │   Result A
    │
    ├── Provider B
    │      ↓
    │   Result B
    │
    └── Provider C
           ↓
        Result C
```

Provider aggregation and final risk decisions are intentionally separate responsibilities.

---

## Threat Intelligence Enrichment Flow

The event processing pipeline can make an enrichment decision and invoke Threat Intelligence only when appropriate.

```text
SecurityEvent
      ↓
source_ip
      ↓
IP Classification
      ↓
Allowlist
      ↓
Enrichment Policy
      ↓
┌─────────────────────────────┐
│ should_enrich = False       │
│ → no external lookup        │
│                             │
│ should_enrich = True        │
│ → ThreatIntelService        │
└─────────────────────────────┘
               ↓
        ThreatIntelProvider
               ↓
        ThreatIntelResult
```

This means Threat Intelligence providers are not queried blindly for every address received by SentinelFlow.

---

## VirusTotal Integration

SentinelFlow supports external IP reputation enrichment through the **VirusTotal API v3**.

The integration is implemented through the modular Threat Intelligence architecture, allowing VirusTotal to operate as a `ThreatIntelProvider` without coupling the rest of the application directly to the external API.

### Current VirusTotal Flow

```text
SecurityEvent
    ↓
Source IP
    ↓
IP Classification
    ↓
Allowlist Check
    ↓
Enrichment Policy
    ↓
ThreatIntelService
    ↓
VirusTotalProvider
    ↓
VirusTotal API v3
    ↓
last_analysis_stats
    ↓
SentinelFlow normalization
    ↓
ThreatIntelResult
```

### VirusTotal Provider

The `VirusTotalProvider` currently:

- authenticates using a VirusTotal API key;
- uses the VirusTotal API v3;
- queries IP address reports;
- uses a reusable `requests.Session`;
- sends the `x-apikey` authentication header;
- requests JSON responses;
- uses HTTP request timeouts;
- reads VirusTotal `last_analysis_stats`;
- normalizes VirusTotal data into `ThreatIntelResult`;
- handles malformed or unexpected responses;
- converts external API failures into SentinelFlow-specific exceptions.

---

## VirusTotal Normalization

VirusTotal provides analysis statistics such as:

```text
malicious
suspicious
harmless
undetected
timeout
```

SentinelFlow converts those external statistics into its internal fields:

```text
malicious
score
confidence
```

The current normalization rules are internal SentinelFlow rules.

### Malicious Flag

Currently:

```text
one or more malicious detections
→ malicious = True
```

Otherwise:

```text
malicious = False
```

### Score

The current internal score gives:

```text
malicious detection → full weight
suspicious detection → half weight
```

Conceptually:

```text
score =
(
    malicious
    + suspicious × 0.5
)
/
total considered engines
× 100
```

### Confidence

Current confidence represents the proportion of considered engines that produced an explicit classification rather than remaining undetected.

If no useful analysis results are available:

```text
score = 0
confidence = 0
```

A score of zero does **not** automatically mean that an indicator is safe.

### Important

The SentinelFlow `score` and `confidence` values are:

```text
SentinelFlow-specific normalization metrics
```

They must **not** be interpreted as:

- probabilities of maliciousness;
- official VirusTotal risk scores;
- guarantees that an indicator is safe or malicious.

A dedicated risk engine will be implemented later in the project.

---

## VirusTotal Error Handling

The VirusTotal integration includes defensive error handling for external failures.

Current cases include:

```text
Timeout
→ VirusTotalError("VirusTotal request timed out")

Connection failure
→ VirusTotalError("Could not connect to VirusTotal")

HTTP 401
→ VirusTotalError("VirusTotal rejected the API key")

HTTP 403
→ VirusTotalError("VirusTotal access forbidden")

HTTP 404
→ VirusTotalError("Indicator not found in VirusTotal")

HTTP 429
→ VirusTotalError("VirusTotal rate limit exceeded")

HTTP 5xx
→ VirusTotalError("VirusTotal service error")

Other request failures
→ VirusTotalError("VirusTotal request failed")

Invalid JSON
→ VirusTotalError("VirusTotal returned invalid JSON")

Unexpected API structure
→ VirusTotalError(
    "VirusTotal response has an unexpected structure"
)
```

This prevents low-level HTTP implementation details from leaking throughout the rest of the application.

---

## AbuseIPDB Integration

SentinelFlow also supports external IP reputation enrichment through the **AbuseIPDB API v2**.

The provider follows the same Threat Intelligence abstraction used by VirusTotal.

### Current AbuseIPDB Flow

```text
SecurityEvent
    ↓
Source IP
    ↓
IP Classification
    ↓
Allowlist Check
    ↓
Enrichment Policy
    ↓
ThreatIntelService
    ↓
AbuseIPDBProvider
    ↓
AbuseIPDB API v2
    ↓
/check
    ↓
abuseConfidenceScore
    ↓
SentinelFlow normalization
    ↓
ThreatIntelResult
```

### AbuseIPDB Provider

The `AbuseIPDBProvider` currently:

- authenticates using an AbuseIPDB API key;
- uses the AbuseIPDB API v2;
- queries the `/check` endpoint;
- uses a reusable `requests.Session`;
- sends the API key through the `Key` HTTP header;
- requests JSON responses;
- uses HTTP request timeouts;
- supports configurable `maxAgeInDays`;
- validates the allowed age range;
- reads `abuseConfidenceScore`;
- validates returned abuse scores;
- normalizes AbuseIPDB data into `ThreatIntelResult`;
- handles malformed and unexpected responses;
- converts API failures into SentinelFlow-specific exceptions.

---

## AbuseIPDB Normalization

AbuseIPDB returns an:

```text
abuseConfidenceScore
```

in the range:

```text
0 ───────────────────────── 100
```

SentinelFlow currently maps that value directly into its internal score:

```text
AbuseIPDB abuseConfidenceScore
              ↓
      SentinelFlow score
```

For example:

```text
abuseConfidenceScore = 80
→ score = 80
```

### Malicious Flag

Current SentinelFlow policy:

```text
score < 50
→ malicious = False

score >= 50
→ malicious = True
```

This threshold is a **SentinelFlow-specific normalization policy**.

It should not be interpreted as an official AbuseIPDB statement that every IP address with a score of 50 or greater is definitively malicious.

### Confidence

Current normalized AbuseIPDB results use:

```text
confidence = 100
```

when a valid score has been successfully retrieved and processed.

This represents successful interpretation of the external score.

It does **not** represent absolute certainty that the indicator is malicious or safe.

This model is expected to become more sophisticated when the dedicated risk and confidence engine is introduced.

---

## AbuseIPDB Error Handling

The AbuseIPDB integration includes defensive error handling.

Current cases include:

```text
Timeout
→ AbuseIPDBError("AbuseIPDB request timed out")

Connection failure
→ AbuseIPDBError("Could not connect to AbuseIPDB")

HTTP 401
→ AbuseIPDBError("AbuseIPDB rejected the API key")

HTTP 402
→ AbuseIPDBError("AbuseIPDB plan limit exceeded")

HTTP 403
→ AbuseIPDBError("AbuseIPDB access forbidden")

HTTP 422
→ AbuseIPDBError(
    "AbuseIPDB rejected the request parameters"
)

HTTP 429
→ AbuseIPDBError("AbuseIPDB rate limit exceeded")

HTTP 5xx
→ AbuseIPDBError("AbuseIPDB service error")

Other request failures
→ AbuseIPDBError("AbuseIPDB request failed")

Invalid JSON
→ AbuseIPDBError("AbuseIPDB returned invalid JSON")

Unexpected API structure
→ AbuseIPDBError(
    "AbuseIPDB response has an unexpected structure"
)

Invalid abuse score
→ AbuseIPDBError(
    "AbuseIPDB returned an invalid abuse score"
)
```

AbuseIPDB-specific exceptions inherit from the common Threat Intelligence exception hierarchy.

---

## Threat Intelligence Exception Hierarchy

SentinelFlow does not expose raw external-library errors throughout the whole application.

Current exception structure:

```text
ThreatIntelError
      │
      ├── VirusTotalError
      │
      └── AbuseIPDBError
```

This provides a common abstraction for external Threat Intelligence failures while still allowing provider-specific handling when necessary.

---

## Multi-Provider Threat Intelligence

SentinelFlow can now operate with multiple Threat Intelligence providers through the same service.

Current providers:

```text
LocalThreatIntelProvider
VirusTotalProvider
AbuseIPDBProvider
```

Conceptually:

```text
Indicator
    ↓
ThreatIntelService
    │
    ├── VirusTotalProvider
    │       ↓
    │   VirusTotal API
    │       ↓
    │   ThreatIntelResult
    │
    └── AbuseIPDBProvider
            ↓
        AbuseIPDB API
            ↓
        ThreatIntelResult
```

Both external services use completely different APIs and reputation models.

However, the rest of SentinelFlow receives a consistent structure:

```text
ThreatIntelResult
├── indicator
├── provider
├── malicious
├── score
└── confidence
```

This is one of the main architectural goals of the project:

```text
Provider-specific API format
            ↓
Provider normalization
            ↓
Common SentinelFlow model
```

Provider aggregation and final security risk decisions remain separate responsibilities.

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

Configuration flow:

```text
.env
 ↓
config.py
 │
 ├── VIRUSTOTAL_API_KEY
 │        ↓
 │   VirusTotalProvider
 │
 └── ABUSEIPDB_API_KEY
          ↓
     AbuseIPDBProvider
```

Secrets are never intended to be embedded directly inside Python source code.

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

## Example Log Watcher Flow

```text
New line appended to log
        ↓
LogWatcher
        ↓
Nginx Parser
        ↓
SecurityEvent
        ↓
IOC extraction
        ↓
Structured output
```

Example event output:

```text
New security event
────────────────────
Timestamp: ...
Source IP: ...
Method: GET
Path: /admin
Status: 401
User-Agent: Mozilla/5.0
IOC Type: IPv4
IOC Valid: True
Source: nginx
────────────────────
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
│       │   ├── security_event.py
│       │   └── threat_intel.py
│       │
│       └── threat_intel/
│           ├── __init__.py
│           ├── abuseipdb_provider.py
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
│   ├── test_security_event.py
│   ├── test_threat_intel.py
│   ├── test_virustotal_provider.py
│   └── test_watch.py
│
├── .env.example
├── .gitignore
├── pyproject.toml
└── README.md
```

The repository structure is intentionally created progressively.

Future directories are not added until the functionality actually requires them.

---

## Testing

SentinelFlow uses `pytest` for automated testing.

Run the complete test suite:

```powershell
pytest -v
```

If pytest cache/temp permissions are problematic in the current Windows environment, the suite can be executed with:

```powershell
pytest -v --basetemp=.\tmp -p no:cacheprovider
```

Run only IOC tests:

```powershell
pytest tests/test_ioc_detection.py -v -p no:cacheprovider
```

Run only Threat Intelligence tests:

```powershell
pytest tests/test_threat_intel.py -v -p no:cacheprovider
```

Run only VirusTotal tests:

```powershell
pytest tests/test_virustotal_provider.py -v -p no:cacheprovider
```

Run only AbuseIPDB tests:

```powershell
pytest tests/test_abuseipdb_provider.py -v -p no:cacheprovider
```

Run configuration tests:

```powershell
pytest tests/test_config.py -v -p no:cacheprovider
```

Filter tests:

```powershell
pytest -k ipv4 -v -p no:cacheprovider
```

Tests currently cover areas including:

- IPv4 detection;
- IPv6 detection;
- domain detection;
- URL detection;
- MD5 detection;
- SHA1 detection;
- SHA256 detection;
- malformed IOC handling;
- whitespace normalization;
- IOC source tracking;
- structured security events;
- HTTP and non-HTTP event representation;
- Nginx parsing;
- invalid Nginx lines;
- log file ingestion;
- ingestion statistics;
- missing files;
- invalid file paths;
- incremental log reading;
- duplicate prevention;
- new event parsing;
- invalid event filtering;
- polling interval validation;
- continuous event yielding;
- file truncation recovery;
- basic log rotation recovery;
- file identity tracking;
- watcher position tracking;
- append/truncate sequences;
- append/rotation sequences;
- historical watcher mode;
- real-time `start_at_end` mode;
- IOC extraction from events;
- IP classification;
- public/private IP classification;
- special IP categories;
- IP allowlisting;
- custom allowlists;
- enrichment policy;
- event-level enrichment decisions;
- normalized Threat Intelligence results;
- immutable Threat Intelligence results;
- abstract Threat Intelligence provider contract;
- local Threat Intelligence provider;
- multi-provider Threat Intelligence service;
- environment-variable configuration;
- VirusTotal API key configuration;
- AbuseIPDB API key configuration;
- VirusTotal provider configuration;
- VirusTotal HTTP session configuration;
- VirusTotal authentication headers;
- VirusTotal IP report requests;
- VirusTotal request URL generation;
- VirusTotal request timeouts;
- VirusTotal response normalization;
- VirusTotal malicious and non-malicious result handling;
- VirusTotal zero-analysis handling;
- VirusTotal HTTP error handling;
- VirusTotal authentication failures;
- VirusTotal rate-limit failures;
- VirusTotal server errors;
- VirusTotal connection failures;
- VirusTotal malformed JSON;
- VirusTotal unexpected response structures;
- AbuseIPDB provider configuration;
- AbuseIPDB HTTP session configuration;
- AbuseIPDB authentication headers;
- AbuseIPDB `/check` endpoint;
- AbuseIPDB `maxAgeInDays`;
- AbuseIPDB response normalization;
- AbuseIPDB malicious threshold behavior;
- AbuseIPDB abuse score validation;
- AbuseIPDB timeout handling;
- AbuseIPDB connection failures;
- AbuseIPDB authentication failures;
- AbuseIPDB plan-limit failures;
- AbuseIPDB rate-limit failures;
- AbuseIPDB parameter validation failures;
- AbuseIPDB server errors;
- AbuseIPDB malformed JSON;
- AbuseIPDB unexpected response structures;
- multi-provider behavior using VirusTotal and AbuseIPDB provider types.

The project follows the principle that new functionality must be covered by automated tests before development moves on to the next stage.

---

## Development Philosophy

SentinelFlow is developed incrementally using the following workflow:

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

Each feature is introduced only after the previous stage is working and verified.

The project avoids creating unused infrastructure or prematurely introducing technologies that are not yet required.

The goal is not simply to produce a large repository.

The goal is to build a system where each component can be understood, tested, replaced and extended independently.

---

## Development Progress

### Foundation

Implemented:

- Python project structure.
- Virtual environment.
- Git repository.
- GitHub repository.
- `.gitignore`.
- `pyproject.toml`.
- editable Python package.
- pytest testing environment.

### IOC Detection

Implemented:

- common IOC model;
- IOC types;
- IPv4 detection;
- IPv6 detection;
- domain detection;
- URL detection;
- MD5 detection;
- SHA1 detection;
- SHA256 detection;
- invalid input detection;
- input normalization;
- source attribution;
- interactive CLI.

### Log Ingestion

Implemented:

- `SecurityEvent`;
- Nginx parser;
- sample Nginx log;
- full-file ingestion;
- ingestion statistics;
- incremental log reading;
- real-time log watcher;
- append detection;
- duplicate prevention;
- truncation recovery;
- basic log rotation recovery;
- watcher CLI.

### Event Processing

Implemented:

- source IOC extraction;
- IP classification;
- IP allowlist;
- enrichment decision policy;
- event-level Threat Intelligence enrichment.

### Threat Intelligence

Implemented:

- normalized `ThreatIntelResult`;
- abstract `ThreatIntelProvider`;
- deterministic local provider;
- multi-provider `ThreatIntelService`;
- common Threat Intelligence exception hierarchy;
- VirusTotal provider;
- VirusTotal API v3 IP lookup;
- VirusTotal response normalization;
- VirusTotal timeout handling;
- VirusTotal HTTP error handling;
- VirusTotal rate-limit handling;
- VirusTotal authentication error handling;
- VirusTotal connection error handling;
- VirusTotal JSON validation;
- VirusTotal unexpected response handling;
- AbuseIPDB provider;
- AbuseIPDB API v2 `/check` integration;
- AbuseIPDB response normalization;
- AbuseIPDB abuse score validation;
- AbuseIPDB timeout handling;
- AbuseIPDB HTTP error handling;
- AbuseIPDB authentication error handling;
- AbuseIPDB rate-limit handling;
- AbuseIPDB request validation;
- AbuseIPDB JSON validation;
- AbuseIPDB unexpected response handling;
- multi-provider Threat Intelligence compatibility.

---

## Roadmap

Planned development areas include:

### Threat Intelligence Hardening

- provider failure isolation;
- partial results when one provider fails;
- enrichment caching;
- cache expiration;
- reduced duplicate API requests;
- additional IOC enrichment;
- additional Threat Intelligence providers.

### Risk Assessment

- multi-provider signal aggregation;
- risk scoring;
- confidence scoring;
- severity classification;
- provider weighting;
- explainable scoring decisions.

### Detection Engineering

- brute-force detection;
- directory scanning detection;
- suspicious request patterns;
- repeated-source behavioral analysis;
- MITRE ATT&CK mapping;
- configurable detection rules.

### Persistence

- SQLite storage;
- IOC history;
- event history;
- enrichment history;
- alert history;
- audit trail.

### Alerting

- normalized alert model;
- alert deduplication;
- configurable severity thresholds;
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
- alert endpoints;
- health endpoints;
- response-control endpoints.

### Infrastructure

- Docker;
- Docker Compose;
- CI/CD;
- GitHub Actions;
- improved logging;
- monitoring;
- production-style documentation.

Additional technologies will only be introduced when the corresponding stage of the project requires them.

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
- human oversight;
- dry-run execution before active remediation.

External API keys are never intended to be stored directly in source code or committed to the repository.

Future active-response capabilities will be designed so that detection and enrichment do not automatically imply remediation.

---

## Current Limitations

SentinelFlow is still under active development.

Current limitations include:

- Nginx is currently the primary implemented log source.
- Threat Intelligence enrichment currently focuses on IP addresses.
- The local Threat Intelligence provider contains simulated development data.
- VirusTotal and AbuseIPDB are the current external providers.
- Provider failures are not yet isolated at the `ThreatIntelService` level.
- A failing provider can still interrupt a multi-provider lookup.
- External enrichment results are not cached yet.
- SentinelFlow-specific score and confidence values are not probabilities.
- Provider scores are not yet combined into a final risk score.
- No final multi-provider risk engine exists yet.
- No behavioral detection engine exists yet.
- No persistent database exists yet.
- No production alerting system exists yet.
- No active defensive response is currently performed.
- No public API or dashboard exists yet.

These capabilities are planned as later stages rather than being prematurely added to the project.

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