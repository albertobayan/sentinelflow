# SentinelFlow

**Automated Threat Detection, Enrichment & Response Platform**

SentinelFlow is a defensive cybersecurity automation project built in Python.

The goal of the project is to simulate a modular SOC/SOAR workflow capable of ingesting security events, detecting indicators of compromise, applying enrichment policies, querying external Threat Intelligence providers, assessing risk, generating alerts and supporting controlled defensive response workflows.

---

## Project Status

🚧 **Under active development**

Current development stage:

**Log Ingestion, Event Normalization & Resilient Multi-Provider Threat Intelligence Enrichment**

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

For example:

```text
VirusTotal → timeout
AbuseIPDB → timeout
```

does not create a cached failure.

A subsequent lookup can therefore retry the providers.

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
ThreatIntelCache
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

SentinelFlow converts relevant external statistics into its internal fields:

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
ThreatIntelCache
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

SentinelFlow can operate with multiple Threat Intelligence providers through the same service.

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
    ↓
ThreatIntelCache
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
             │
             ↓
    ThreatIntelLookupResult
```

Both external services use different APIs and reputation models.

However, the rest of SentinelFlow receives consistent internal structures.

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

This is one of the main architectural goals of the project:

```text
Provider-specific API format
            ↓
Provider normalization
            ↓
Common SentinelFlow models
            ↓
Provider-independent processing
```

Final provider aggregation and risk decisions remain separate responsibilities.

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
│       │   ├── threat_intel.py
│       │   └── threat_intel_lookup.py
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

If pytest cache/temp permissions are problematic in the current Windows environment, the suite can be executed with:

```powershell
pytest -v --basetemp=.\tmp -p no:cacheprovider
```

Run only IOC tests:

```powershell
pytest tests/test_ioc_detection.py -v -p no:cacheprovider
```

Run only Threat Intelligence service tests:

```powershell
pytest tests/test_threat_intel.py -v -p no:cacheprovider
```

Run only Threat Intelligence lookup-result tests:

```powershell
pytest tests/test_threat_intel_lookup.py -v -p no:cacheprovider
```

Run only Threat Intelligence cache tests:

```powershell
pytest tests/test_threat_intel_cache.py -v -p no:cacheprovider
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
- multi-provider behavior using VirusTotal and AbuseIPDB provider types;
- Threat Intelligence provider failure isolation;
- continuation after controlled provider failures;
- preservation of valid results when another provider fails;
- complete provider-failure handling;
- unexpected exception propagation;
- multi-provider lookup status;
- successful lookup detection;
- partial lookup detection;
- empty lookup-state behavior;
- empty indicator validation;
- whitespace-only indicator validation;
- in-memory Threat Intelligence caching;
- cache storage;
- cache retrieval;
- cache overwrites;
- cache clearing;
- indicator cache normalization;
- configurable cache TTL;
- invalid cache TTL rejection;
- cache expiration;
- exact TTL expiration boundary;
- expired-entry removal;
- cache-aware `contains()` behavior;
- cache hits;
- cache misses;
- duplicate provider request reduction;
- multi-provider cache behavior;
- cache expiration followed by provider retry;
- successful-result caching;
- partial-result cache prevention;
- failed-result cache prevention;
- empty-result cache prevention;
- provider retries after partial enrichment;
- provider retries after complete enrichment failure.

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
- multi-provider `ThreatIntelLookupResult`;
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
- multi-provider Threat Intelligence compatibility;
- provider failure isolation;
- partial-result preservation;
- provider-error preservation;
- complete/partial lookup-state tracking;
- unexpected exception propagation;
- empty indicator validation;
- `ThreatIntelCache`;
- in-memory enrichment caching;
- configurable cache TTL;
- monotonic expiration tracking;
- automatic removal of accessed expired entries;
- cache integration with `ThreatIntelService`;
- cache hit and miss handling;
- duplicate provider lookup reduction;
- safe cache policy;
- complete-result caching;
- partial-result cache prevention;
- failed-result cache prevention;
- retry behavior after partial or failed enrichment;
- provider re-query after cache expiration.

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

A missing or failed Threat Intelligence lookup is not automatically interpreted as evidence that an indicator is safe.

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
- SentinelFlow-specific score and confidence values are not probabilities.
- Provider scores are not yet combined into a final risk score.
- No final multi-provider risk engine exists yet.
- No provider weighting system exists yet.
- No final severity classification engine exists yet.
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