# SentinelFlow

**Automated Threat Detection, Enrichment & Response Platform**

SentinelFlow is a defensive cybersecurity automation project built in Python.

The goal of the project is to simulate a modular SOC/SOAR workflow capable of ingesting security events, detecting indicators of compromise, applying enrichment policies, querying external Threat Intelligence providers, assessing risk, generating alerts and supporting controlled defensive response workflows.

---

## Project Status

🚧 **Under active development**

Current development stage:

**Threat Intelligence Enrichment & Risk Assessment**

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
- Risk score validation.
- Confidence validation.
- Automatic severity classification.
- Multi-provider risk score aggregation.
- Confidence-weighted risk scoring.
- Global risk confidence calculation.
- Explainable risk reasons.
- Partial-enrichment confidence adjustment.
- Threat Intelligence lookup to Risk Assessment integration.

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

The rest of SentinelFlow does not need to understand each provider's native response format.

Every provider normalizes its data into the same internal result model.

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

This allows multiple Threat Intelligence providers to produce a consistent result even when their original APIs use completely different response formats.

---

## ThreatIntelLookupResult

Multi-provider enrichment is represented through a higher-level lookup result.

While `ThreatIntelResult` represents the result returned by a single provider, `ThreatIntelLookupResult` represents the state of the complete Threat Intelligence lookup.

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

It also exposes lookup state through:

```text
successful
partial
```

A successful lookup contains at least one result and no provider errors:

```text
results != []
errors == []

→ successful = True
→ partial = False
```

A partial lookup contains usable Threat Intelligence results but also one or more provider failures:

```text
results != []
errors != []

→ successful = False
→ partial = True
```

A complete provider failure contains no results:

```text
results == []
errors != []

→ successful = False
→ partial = False
```

A lookup with no configured providers also has no results:

```text
results == []
errors == []

→ successful = False
→ partial = False
```

This distinction allows SentinelFlow to differentiate between:

```text
A provider returned a legitimate low-risk result
```

and:

```text
Threat Intelligence could not be obtained
```

These situations are intentionally not treated as equivalent.

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

A standard lookup can be performed through:

```python
service.lookup(indicator)
```

and returns:

```text
list[ThreatIntelResult]
```

For callers that also need provider failure information and lookup completeness, SentinelFlow exposes:

```python
service.lookup_with_status(indicator)
```

which returns:

```text
ThreatIntelLookupResult
```

The service also accepts an optional `ThreatIntelCache`:

```python
service = ThreatIntelService(
    providers=[
        provider_a,
        provider_b,
    ],
    cache=cache,
)
```

Conceptually:

```text
Indicator
    ↓
ThreatIntelService
    ↓
Cache lookup
    ↓
┌─────────────────────────────┐
│ Cached result available?    │
├──────────────┬──────────────┤
│ Yes          │ No           │
│ ↓            │ ↓            │
│ Return       │ Providers    │
│              │ ↓            │
│              │ Results      │
└──────────────┴──────────────┘
```

Provider aggregation and final security risk decisions remain separate responsibilities.

---

## Provider Failure Isolation

Threat Intelligence providers are isolated from each other at the service layer.

A controlled failure from one provider does not prevent SentinelFlow from using results returned by other providers.

For example:

```text
VirusTotal
→ success

AbuseIPDB
→ timeout
```

can produce:

```text
results:
    VirusTotal result

errors:
    abuseipdb: AbuseIPDB request timed out
```

Instead of failing the entire enrichment operation.

Controlled provider failures derived from:

```text
ThreatIntelError
```

are isolated.

The current hierarchy includes:

```text
ThreatIntelError
      │
      ├── VirusTotalError
      │
      └── AbuseIPDBError
```

Unexpected programming errors are intentionally **not** silently suppressed.

For example:

```text
RuntimeError
TypeError
unexpected internal software bug
```

continue to propagate.

This prevents the enrichment layer from hiding defects in SentinelFlow itself.

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
        ThreatIntelCache
               ↓
        ThreatIntelProvider
               ↓
        ThreatIntelResult
               ↓
     ThreatIntelLookupResult
```

This means Threat Intelligence providers are not queried blindly for every address received by SentinelFlow.

---

## Threat Intelligence Cache

SentinelFlow includes an in-memory cache for Threat Intelligence enrichment results.

The cache reduces:

- duplicate external API requests;
- API quota consumption;
- enrichment latency;
- unnecessary dependency on external services;
- exposure to provider rate limits.

Conceptually:

```text
Indicator
    ↓
ThreatIntelService
    ↓
Cache lookup
    │
    ├── HIT
    │     ↓
    │   return cached result
    │
    └── MISS
          ↓
       providers
          ↓
       enrichment
          ↓
    successful?
       │
       ├── Yes → cache
       └── No  → do not cache
          ↓
        return
```

### Cache Entries

Cached data is stored as:

```text
indicator
    ↓
CacheEntry
├── ThreatIntelLookupResult
└── created_at
```

The cache currently exists only in memory.

This means cached data is intentionally lost when the SentinelFlow process stops.

No Redis, database-backed cache or external caching infrastructure is currently required.

### Indicator Normalization

Indicators are normalized with surrounding whitespace removed before cache access.

Therefore:

```text
"9.9.9.9"
```

and:

```text
"   9.9.9.9   "
```

use the same cache key.

Empty or whitespace-only indicators are rejected by the service before providers or cache storage are used.

---

## Cache TTL

Cache entries use a configurable time-to-live.

Default development TTL:

```text
300 seconds
```

Equivalent to:

```text
5 minutes
```

Custom values can be supplied:

```python
ThreatIntelCache(
    ttl_seconds=60,
)
```

Invalid TTL values are rejected.

For example:

```text
TTL <= 0
→ ValueError
```

SentinelFlow uses:

```python
time.monotonic()
```

for cache-age calculations.

This avoids depending on the system wall clock, which can change because of:

- clock synchronization;
- manual clock changes;
- NTP corrections;
- daylight-saving adjustments.

An entry is considered expired when:

```text
entry age >= TTL
```

Expired entries are removed when accessed.

---

## Cache Policy

SentinelFlow intentionally caches only complete successful enrichment results.

### Complete Success

```text
results != []
errors == []

→ successful = True
→ CACHE
```

### Partial Enrichment

```text
results != []
errors != []

→ partial = True
→ DO NOT CACHE
```

### Complete Provider Failure

```text
results == []
errors != []

→ DO NOT CACHE
```

### No Providers

```text
results == []
errors == []

→ DO NOT CACHE
```

This prevents temporary provider failures, timeouts, authentication problems or rate limits from being artificially extended by the local cache.

A subsequent lookup can retry the providers immediately after a partial or failed enrichment.

---

## Cache Expiration & Retry Behavior

When a valid cached result exists:

```text
lookup
→ cache hit
→ external providers are not queried
```

When the entry expires:

```text
lookup
→ cache entry expired
→ cache entry removed
→ providers queried again
→ new result generated
```

Partial and failed lookups are not cached, so the next lookup naturally retries the external providers.

This prevents temporary external outages from becoming locally persistent failures.

---

## Score Zero vs Provider Failure

A valid Threat Intelligence result with:

```text
score = 0
```

is not considered a provider failure.

For example:

```text
AbuseIPDB
→ valid HTTP response
→ abuseConfidenceScore = 0
```

represents valid external data.

This is fundamentally different from:

```text
AbuseIPDB
→ timeout
```

where no Threat Intelligence result was obtained.

Therefore SentinelFlow distinguishes:

```text
Provider answered and returned a low score
```

from:

```text
Provider could not be queried successfully
```

If all configured providers answer successfully, a complete lookup can be cached even when the returned scores are zero.

---

## VirusTotal Integration

SentinelFlow supports external IP reputation enrichment through the **VirusTotal API v3**.

The integration is implemented through the modular Threat Intelligence architecture, allowing VirusTotal to operate as a `ThreatIntelProvider` without coupling the rest of the application directly to the external API.

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

SentinelFlow converts relevant external statistics into:

```text
malicious
score
confidence
```

The current normalization rules are internal SentinelFlow rules.

### Malicious Flag

```text
one or more malicious detections
→ malicious = True
```

Otherwise:

```text
malicious = False
```

### Score

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

The provider-level score is not the final SentinelFlow Risk Score.

---

## AbuseIPDB Integration

SentinelFlow also supports external IP reputation enrichment through the **AbuseIPDB API v2**.

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

SentinelFlow currently maps that value into its normalized provider score.

Current provider-level malicious policy:

```text
score < 50
→ malicious = False

score >= 50
→ malicious = True
```

This threshold is a **SentinelFlow-specific normalization policy**.

Current normalized AbuseIPDB results use:

```text
confidence = 100
```

when a valid score is successfully retrieved and processed.

This does **not** represent absolute certainty that the indicator is malicious or safe.

The provider-level score is later processed independently by the Risk Engine.

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

Current providers:

```text
LocalThreatIntelProvider
VirusTotalProvider
AbuseIPDBProvider
```

Individual provider results use:

```text
ThreatIntelResult
├── indicator
├── provider
├── malicious
├── score
└── confidence
```

The complete multi-provider lookup uses:

```text
ThreatIntelLookupResult
├── results
├── errors
├── successful
└── partial
```

This allows the rest of the system to process provider-independent data.

---

# Risk Assessment Engine

SentinelFlow includes a dedicated Risk Assessment layer separated from Threat Intelligence collection.

Threat Intelligence answers:

```text
What does each external provider report?
```

The Risk Engine answers:

```text
How should SentinelFlow interpret the combined evidence?
```

Architecture:

```text
ThreatIntelLookupResult
        ↓
available ThreatIntelResult objects
        ↓
Risk Engine
        │
        ├── score aggregation
        ├── confidence weighting
        ├── global confidence
        ├── severity classification
        └── explainable reasons
        ↓
RiskAssessment
```

This separation prevents provider-specific logic from directly controlling future alerting or defensive actions.

---

## RiskAssessment Model

Risk evaluations are represented through the immutable:

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
    score=52,
    severity=RiskSeverity.HIGH,
    confidence=90,
    reasons=(
        "virustotal: score=30, confidence=80, status=malicious",
        "abuseipdb: score=70, confidence=100, status=malicious",
    ),
)
```

The model validates:

```text
indicator
→ non-empty

score
→ integer
→ 0–100

confidence
→ integer
→ 0–100
```

The model is immutable after construction.

---

## Risk Severity

Current severities are:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Current SentinelFlow policy:

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

These thresholds are internal SentinelFlow policy.

They are not official VirusTotal or AbuseIPDB severity classifications.

Severity is generated automatically from the final SentinelFlow Risk Score rather than being manually chosen by callers.

---

## Base Risk Score

SentinelFlow can calculate a basic multi-provider score using the arithmetic mean of available normalized provider scores.

Example:

```text
VirusTotal score = 20
AbuseIPDB score  = 80
```

Base score:

```text
(20 + 80) / 2
= 50
```

The base calculation is retained as a simple fallback and development reference.

---

## Confidence-Weighted Risk Score

The main current Risk Engine calculation weights provider scores according to provider confidence.

Conceptually:

```text
Σ(score × confidence)
─────────────────────
    Σ(confidence)
```

Example:

```text
VirusTotal
score = 90
confidence = 10

AbuseIPDB
score = 30
confidence = 100
```

Simple average:

```text
60
```

Confidence-weighted result:

```text
35
```

This prevents a low-confidence score from having the same influence as a high-confidence score.

When all available provider confidence values are zero, SentinelFlow falls back to the unweighted base risk score instead of treating risk as zero.

---

## Global Risk Confidence

SentinelFlow separately calculates confidence in the overall Risk Assessment.

For complete enrichment, current global confidence is the arithmetic mean of available provider confidence values.

Example:

```text
VirusTotal confidence = 80
AbuseIPDB confidence  = 100

Global confidence = 90
```

Risk score and risk confidence represent different concepts.

A high Risk Score with low confidence is possible.

For example:

```text
Risk Score = 80
Confidence = 20
```

means that available evidence suggests elevated risk, but the evidence quality or coverage is weak.

---

## Partial Enrichment Risk Policy

SentinelFlow can generate a Risk Assessment from a partial Threat Intelligence lookup when at least one valid provider result exists.

Example:

```text
VirusTotal ✅
AbuseIPDB ❌
```

The available provider result is still used to calculate:

```text
risk score
severity
```

However, global confidence is reduced according to provider coverage.

Conceptually:

```text
adjusted confidence =
available-result confidence
×
successful providers / total attempted providers
```

Example:

```text
VirusTotal confidence = 90

1 provider succeeded
1 provider failed

coverage = 1 / 2

adjusted confidence =
90 × 0.5
= 45
```

Therefore a partial lookup can produce:

```text
Risk Score: 70
Severity: HIGH
Confidence: 45
```

rather than falsely presenting the assessment as fully supported.

---

## Complete Threat Intelligence Failure

SentinelFlow does not create a Risk Assessment when there are no valid Threat Intelligence results.

For example:

```text
VirusTotal ❌
AbuseIPDB ❌
```

does **not** become:

```text
Risk Score = 0
Severity = LOW
```

Instead, risk assessment is rejected because no evidence is available.

This protects the system from treating:

```text
unknown
```

as:

```text
safe
```

---

## Explainable Risk Reasons

Risk Assessments include human-readable reasons derived from provider signals.

Example:

```text
virustotal: score=70, confidence=90, status=malicious
```

Another provider may produce:

```text
abuseipdb: score=20, confidence=100, status=not malicious
```

If a provider fails during a partial lookup, the failure is also preserved:

```text
Threat Intelligence provider error:
abuseipdb: AbuseIPDB request timed out
```

This makes Risk Assessment explainable rather than returning only an opaque numerical score.

Future detection and behavioral signals can be added to the same explanation layer.

---

## Risk Assessment Flow

The complete implemented flow is now:

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
┌──────────────────────┐
│ Threat Intel Providers│
├──────────┬───────────┤
│VirusTotal│ AbuseIPDB │
└─────┬────┴─────┬─────┘
      ↓          ↓
ThreatIntelResult
      ↓
ThreatIntelLookupResult
      ↓
Risk Engine
      │
      ├── weighted score
      ├── confidence
      ├── severity
      ├── partial coverage
      └── reasons
      ↓
RiskAssessment
```

Future decision, alerting and response layers will consume the normalized `RiskAssessment` rather than depending directly on provider-specific data.

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
│       │   ├── risk.py
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

Future directories are not added until the functionality actually requires them.

---

## Testing

SentinelFlow uses `pytest` for automated testing.

Run the complete test suite:

```powershell
pytest -v
```

If pytest cache/temp permissions are problematic in the current Windows environment:

```powershell
pytest -v --basetemp=.\tmp -p no:cacheprovider
```

Run IOC tests:

```powershell
pytest tests/test_ioc_detection.py -v -p no:cacheprovider
```

Run Threat Intelligence service tests:

```powershell
pytest tests/test_threat_intel.py -v -p no:cacheprovider
```

Run Threat Intelligence lookup tests:

```powershell
pytest tests/test_threat_intel_lookup.py -v -p no:cacheprovider
```

Run Threat Intelligence cache tests:

```powershell
pytest tests/test_threat_intel_cache.py -v -p no:cacheprovider
```

Run VirusTotal tests:

```powershell
pytest tests/test_virustotal_provider.py -v -p no:cacheprovider
```

Run AbuseIPDB tests:

```powershell
pytest tests/test_abuseipdb_provider.py -v -p no:cacheprovider
```

Run Risk Assessment model tests:

```powershell
pytest tests/test_risk.py -v -p no:cacheprovider
```

Run Risk Severity tests:

```powershell
pytest tests/test_risk_severity.py -v -p no:cacheprovider
```

Run Risk Scoring tests:

```powershell
pytest tests/test_risk_scoring.py -v -p no:cacheprovider
```

Run Risk Reasons tests:

```powershell
pytest tests/test_risk_reasons.py -v -p no:cacheprovider
```

Run Risk Engine tests:

```powershell
pytest tests/test_risk_engine.py -v -p no:cacheprovider
```

Run all Risk tests:

```powershell
pytest tests/test_risk.py tests/test_risk_severity.py tests/test_risk_scoring.py tests/test_risk_reasons.py tests/test_risk_engine.py -v -p no:cacheprovider
```

Tests currently cover areas including:

- IOC detection and validation;
- IPv4 and IPv6 detection;
- domains, URLs and cryptographic hashes;
- IOC normalization and source tracking;
- structured security events;
- Nginx log parsing;
- full log ingestion;
- ingestion statistics;
- malformed log handling;
- real-time log monitoring;
- incremental reading;
- duplicate prevention;
- truncation recovery;
- basic rotation recovery;
- event-level IOC extraction;
- IP classification;
- special IP categories;
- IP allowlisting;
- enrichment policy;
- Threat Intelligence models;
- provider abstraction;
- local deterministic provider;
- VirusTotal integration;
- AbuseIPDB integration;
- HTTP timeout handling;
- connection failures;
- authentication errors;
- rate limits;
- malformed JSON;
- unexpected API structures;
- provider failure isolation;
- partial Threat Intelligence results;
- complete provider failures;
- unexpected exception propagation;
- lookup status tracking;
- in-memory Threat Intelligence caching;
- cache hits and misses;
- configurable TTL;
- cache expiration;
- cache normalization;
- duplicate provider request prevention;
- cache retry behavior;
- successful-result caching;
- partial-result cache prevention;
- failed-result cache prevention;
- RiskAssessment construction;
- RiskAssessment immutability;
- risk score validation;
- confidence validation;
- indicator normalization;
- LOW severity boundaries;
- MEDIUM severity boundaries;
- HIGH severity boundaries;
- CRITICAL severity boundaries;
- base multi-provider scoring;
- deterministic half-up rounding;
- mixed-indicator rejection;
- invalid provider score rejection;
- confidence-weighted scoring;
- zero-confidence handling;
- weighted-score fallback behavior;
- global confidence calculation;
- explainable risk reasons;
- complete Risk Assessment generation;
- single-provider Risk Assessment;
- multi-provider Risk Assessment;
- ThreatIntelLookupResult integration;
- partial-enrichment Risk Assessment;
- confidence reduction for incomplete provider coverage;
- provider-error preservation in Risk Assessment reasons;
- rejection of Risk Assessment without usable Threat Intelligence.

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

- Python project structure;
- virtual environment;
- Git repository;
- GitHub repository;
- `.gitignore`;
- `pyproject.toml`;
- editable Python package;
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
- multi-provider `ThreatIntelLookupResult`;
- abstract `ThreatIntelProvider`;
- deterministic local provider;
- multi-provider `ThreatIntelService`;
- common Threat Intelligence exception hierarchy;
- VirusTotal API v3 integration;
- AbuseIPDB API v2 integration;
- provider response normalization;
- timeout handling;
- HTTP error handling;
- rate-limit handling;
- authentication handling;
- connection-error handling;
- malformed JSON handling;
- unexpected response handling;
- provider failure isolation;
- partial-result preservation;
- provider-error preservation;
- complete/partial lookup-state tracking;
- unexpected exception propagation;
- indicator validation;
- in-memory Threat Intelligence caching;
- configurable cache TTL;
- monotonic expiration tracking;
- cache integration with `ThreatIntelService`;
- cache hit and miss handling;
- duplicate provider lookup reduction;
- complete-result caching;
- partial-result cache prevention;
- failed-result cache prevention;
- retry behavior after partial or failed enrichment;
- provider re-query after cache expiration.

### Risk Assessment

Implemented:

- `RiskAssessment`;
- `RiskSeverity`;
- immutable risk results;
- score validation;
- confidence validation;
- indicator normalization;
- automatic severity classification;
- LOW / MEDIUM / HIGH / CRITICAL policy;
- base multi-provider score aggregation;
- confidence-weighted risk scoring;
- deterministic half-up rounding;
- Threat Intelligence score validation;
- Threat Intelligence confidence validation;
- global Risk Assessment confidence;
- explainable provider-derived reasons;
- automated `RiskAssessment` creation;
- `ThreatIntelLookupResult` integration;
- complete lookup assessment;
- partial lookup assessment;
- provider-coverage confidence adjustment;
- provider error preservation in reasons;
- rejection of assessment when no usable Threat Intelligence exists.

---

## Roadmap

Planned development areas include:

### Threat Intelligence

- additional IOC enrichment;
- domain enrichment;
- URL enrichment;
- hash enrichment;
- provider-specific caching strategies;
- additional Threat Intelligence providers;
- richer provider failure metadata;
- configurable Threat Intelligence settings.

### Risk Assessment

- provider-specific trust weighting;
- configurable severity thresholds;
- configurable scoring policies;
- event-context risk signals;
- behavioral risk signals;
- asset/context awareness;
- richer evidence explanations;
- risk-policy configuration.

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
- Risk Assessment history;
- alert history;
- audit trail.

### Alerting

- normalized alert model;
- alert deduplication;
- configurable severity thresholds;
- Risk Assessment to alert conversion;
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
- explainable risk decisions;
- human oversight;
- dry-run execution before active remediation.

External API keys are never intended to be stored directly in source code or committed to the repository.

A missing or failed Threat Intelligence lookup is not interpreted as evidence that an indicator is safe.

Risk Assessment and future automated response are intentionally separated.

A high Risk Score will not automatically imply remediation.

Future active-response capabilities will require explicit defensive policy and authorization.

---

## Current Limitations

SentinelFlow is still under active development.

Current limitations include:

- Nginx is currently the primary implemented log source.
- Threat Intelligence enrichment currently focuses on IP addresses.
- The local Threat Intelligence provider contains simulated development data.
- VirusTotal and AbuseIPDB are the current external providers.
- Threat Intelligence caching is currently process-local and in-memory.
- Cache entries are stored at the complete lookup level rather than independently per provider.
- Partial Threat Intelligence results are intentionally not cached.
- Failed Threat Intelligence lookups are intentionally not cached.
- Expired cache entries are removed when accessed rather than through a background cleanup process.
- Current risk scoring is based exclusively on normalized Threat Intelligence signals.
- Provider-specific trust weighting is not yet implemented.
- Severity thresholds are currently hard-coded SentinelFlow policy.
- Global confidence is currently based on provider confidence and lookup coverage.
- Partial enrichment confidence assumes each attempted provider represents one unit of coverage.
- Risk reasons currently describe provider-level signals and provider errors.
- Behavioral and event-context signals are not yet included in the final Risk Score.
- Asset criticality is not yet included in Risk Assessment.
- SentinelFlow risk scores and confidence values are internal metrics, not statistical probabilities.
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