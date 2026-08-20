# SentinelFlow

**Automated Threat Detection, Enrichment & Response Platform**

SentinelFlow is a defensive cybersecurity automation project built in Python.

The goal of the project is to simulate a modular SOC/SOAR workflow capable of processing security events, detecting indicators of compromise, enriching them with threat intelligence, assessing their risk, generating alerts and supporting defensive response workflows.

## Project Status

🚧 Under active development.

Current development stage:

**IOC Detection + Nginx Log Ingestion + Real-Time Monitoring + Normalized Security Events**

## Focus

- Blue Team
- SOC Automation
- Threat Intelligence
- Detection Engineering
- Incident Response
- SOAR
- Python

---

## Current Features

### IOC Detection Engine

SentinelFlow currently identifies and validates:

- IPv4
- IPv6
- Domains
- URLs
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

The IOC engine:

- detects IOC types automatically;
- validates supported indicators;
- handles invalid or malformed input;
- preserves the source of the IOC;
- includes automated tests with pytest.

---

## Nginx Log Ingestion

SentinelFlow can parse Nginx access logs and convert valid log entries into structured `SecurityEvent` objects.

Example Nginx event:

```text
185.123.45.20 - - [15/Aug/2026:01:34:21 +0200] "GET /admin HTTP/1.1" 401 532 "-" "Mozilla/5.0"
```

Parsed data includes:

- timestamp;
- source;
- event type;
- source IP;
- HTTP method;
- requested path;
- HTTP status code;
- user agent.

SentinelFlow can also process complete Nginx log files and generate ingestion statistics including:

- total lines;
- valid lines;
- invalid lines;
- parsed security events.

---

## Normalized Security Events

SentinelFlow uses a normalized `SecurityEvent` model to represent security events from different data sources.

Each event contains a set of common fields:

- timestamp;
- source;
- event type;
- source IP.

Source-specific fields can be optional.

For HTTP events, SentinelFlow currently supports:

- HTTP method;
- requested path;
- HTTP status code;
- user agent.

Example HTTP event:

```python
SecurityEvent(
    timestamp="18/Aug/2026:17:00:00 +0200",
    source="nginx",
    event_type="http_request",
    source_ip="203.0.113.50",
    http_method="GET",
    path="/admin",
    status_code=401,
    user_agent="Mozilla/5.0",
)
```

The same model can also represent non-HTTP events:

```python
SecurityEvent(
    timestamp="18/Aug/2026:17:05:00 +0200",
    source="windows",
    event_type="authentication",
    source_ip="10.0.0.15",
)
```

In this case, HTTP-specific fields remain `None`.

This normalization allows SentinelFlow to process different security data sources through a common internal event model.

Current concept:

```text
Nginx
Windows
Firewall
EDR
Other Sources
    │
    ▼
SecurityEvent
    │
    ├── timestamp
    ├── source
    ├── event_type
    ├── source_ip
    │
    └── optional source-specific fields
    │
    ▼
Detection / Enrichment / Risk / Response
```

---

## Real-Time Nginx Log Monitoring

SentinelFlow includes an incremental Nginx log watcher designed for continuous monitoring.

The watcher:

- tracks its current read position;
- processes only newly appended lines;
- avoids processing the same line twice;
- ignores malformed Nginx entries;
- converts valid entries into `SecurityEvent` objects;
- extracts the source IP as an IOC;
- supports configurable polling intervals;
- validates invalid polling intervals;
- detects log truncation;
- detects basic log rotation or replacement;
- tracks file identity;
- supports historical and real-time monitoring modes;
- can be stopped cleanly with `Ctrl+C`.

### Current Pipeline

```text
Nginx access.log
       ↓
LogWatcher
       ↓
Truncation / Rotation Handling
       ↓
Nginx Parser
       ↓
SecurityEvent
       ↓
IOC Detection
       ↓
Structured Console Output
```

---

## Log Truncation Handling

SentinelFlow tracks both the current read position and the size of the monitored log file.

If the log becomes smaller than the last known read position, SentinelFlow assumes that the file has been truncated and resets the position.

Conceptually:

```text
Current position: 1500 bytes
New file size:     200 bytes

200 < 1500
    ↓
Truncation detected
    ↓
position = 0
    ↓
Read current file from the beginning
```

This prevents the watcher from remaining at an invalid position after a log file is cleared or truncated.

---

## Basic Log Rotation Handling

SentinelFlow also tracks the identity of the monitored file.

A typical log rotation may look like:

```text
access.log
    ↓
access.log.1

new access.log
```

When SentinelFlow detects that the file at the monitored path has changed identity, it resets its read position and begins processing the new file.

This allows the watcher to continue operating after basic Nginx log rotation or file replacement.

---

## Historical vs Real-Time Monitoring

`LogWatcher` supports two operating modes.

### Historical Mode

```python
LogWatcher(
    "logs/sample_access.log",
    start_at_end=False,
)
```

This starts from the beginning of the file and processes existing content.

### Real-Time Mode

```python
LogWatcher(
    "logs/sample_access.log",
    start_at_end=True,
)
```

This starts at the end of the existing file.

Historical log entries are ignored and only events appended after SentinelFlow starts are processed.

The SentinelFlow real-time watcher uses this mode by default.

---

## Running the Real-Time Watcher

Run:

```bash
python -m sentinelflow.watch
```

Example startup:

```text
SentinelFlow Log Watcher
Watching: logs/sample_access.log
Waiting for new events...
Press Ctrl+C to stop.
```

Existing log entries are ignored.

When a new Nginx event is appended, SentinelFlow processes it automatically.

Example:

```text
New security event
────────────────────
Timestamp: 18/Aug/2026:16:45:00 +0200
Source IP: 203.0.113.99
Method: POST
Path: /login
Status: 403
User-Agent: curl/8.5.0
IOC Type: IPv4
IOC Valid: True
Source: nginx
────────────────────
```

Stop the watcher with:

```text
Ctrl+C
```

Expected output:

```text
SentinelFlow watcher stopped.
```

---

## IOC CLI

SentinelFlow also provides an interactive CLI for manually analysing indicators of compromise.

Run:

```bash
python -m sentinelflow.main
```

Example:

```text
SentinelFlow v0.1
Type 'exit' to quit.

Enter IOC:
> 8.8.8.8

IOC analysis
────────────────────
Value: 8.8.8.8
Type: IPv4
Valid: True
Source: manual
────────────────────
```

Example invalid input:

```text
Enter IOC:
> hello world

IOC analysis
────────────────────
Value: hello world
Type: INVALID
Valid: False
Source: manual
────────────────────
```

Type:

```text
exit
```

or:

```text
quit
```

to close the CLI.

---

## Project Architecture

Current high-level architecture:

```text
                         SentinelFlow
                              │
               ┌──────────────┴──────────────┐
               │                             │
        Manual IOC Input               Nginx Log
               │                             │
               ▼                             ▼
          IOC Detector                  LogWatcher
                                             │
                                  ┌──────────┴──────────┐
                                  │                     │
                             Truncation              Rotation
                              Handling               Handling
                                  │                     │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                        Nginx Parser
                                             │
                                             ▼
                                       SecurityEvent
                                             │
                                ┌────────────┴────────────┐
                                │                         │
                           Common Fields           Optional HTTP Fields
                                │                         │
                           timestamp                 http_method
                           source                    path
                           event_type                status_code
                           source_ip                 user_agent
                                │                         │
                                └────────────┬────────────┘
                                             │
                                             ▼
                                      Event Processor
                                             │
                                             ▼
                                       IOC Detection
                                             │
                                             ▼
                                      Structured Output
```

SentinelFlow is being developed incrementally toward a larger defensive security automation workflow:

```text
Security Event
      ↓
Ingestion
      ↓
Parsing
      ↓
Normalization
      ↓
IOC Detection
      ↓
Threat Intelligence
      ↓
Risk Assessment
      ↓
Decision Engine
      ↓
Alerting
      ↓
Defensive Response
      ↓
Audit Trail
```

---

## Project Structure

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
│       ├── main.py
│       ├── watch.py
│       │
│       ├── detection/
│       │   ├── __init__.py
│       │   ├── domain_detector.py
│       │   ├── hash_detector.py
│       │   ├── ioc_detector.py
│       │   ├── ip_detector.py
│       │   └── url_detector.py
│       │
│       ├── ingestion/
│       │   ├── __init__.py
│       │   ├── event_processor.py
│       │   ├── log_reader.py
│       │   ├── log_watcher.py
│       │   └── nginx_parser.py
│       │
│       └── models/
│           ├── __init__.py
│           ├── ingestion_result.py
│           ├── ioc.py
│           └── security_event.py
│
├── tests/
│   ├── test_event_processor.py
│   ├── test_ioc_detection.py
│   ├── test_log_reader.py
│   ├── test_log_watcher.py
│   ├── test_nginx_parser.py
│   ├── test_security_event.py
│   └── test_watch.py
│
├── .gitignore
├── pyproject.toml
└── README.md
```

---

## Testing

SentinelFlow uses `pytest` for automated testing.

Run the complete test suite:

```bash
pytest -v
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
- structured event output;
- normalized HTTP security events;
- non-HTTP security events;
- optional HTTP fields;
- event type preservation;
- immutable `SecurityEvent` objects;
- IOC extraction from HTTP and non-HTTP events.

---

## IP Classification and Enrichment Policy

SentinelFlow classifies IP addresses before they are considered for external Threat Intelligence enrichment.

Supported IP categories include:

- `PUBLIC`
- `PRIVATE`
- `LOOPBACK`
- `LINK_LOCAL`
- `RESERVED`
- `MULTICAST`
- `UNSPECIFIED`

Example:

```python
classification = classify_ip("8.8.8.8")

print(classification.category)
print(classification.is_public)
```

Result:

```text
IPCategory.PUBLIC
True
```

Private and special-use addresses are identified separately:

```text
192.168.1.10  → PRIVATE
127.0.0.1     → LOOPBACK
169.254.1.10  → LINK_LOCAL
224.0.0.1     → MULTICAST
240.0.0.1     → RESERVED
0.0.0.0       → UNSPECIFIED
```

### IP Allowlist

SentinelFlow also supports an IP allowlist.

The allowlist represents local policy and known addresses that should not automatically continue to external enrichment.

Being allowlisted does not mean that an IP is universally safe or trusted. It only means that SentinelFlow applies a local policy decision to that address.

Example:

```python
is_ip_allowlisted("8.8.8.8")
```

### Enrichment Policy

SentinelFlow combines IP classification and allowlisting to decide whether an IP should be considered for external Threat Intelligence enrichment.

Current policy:

```text
IP
│
▼
Classification
│
├── NOT PUBLIC
│      ↓
│   Do not enrich
│
└── PUBLIC
       │
       ▼
   Allowlist Check
       │
       ├── Allowlisted
       │      ↓
       │   Do not enrich
       │
       └── Not Allowlisted
              ↓
         Enrichment Candidate
```

Examples:

```text
9.9.9.9
├── Valid IPv4
├── PUBLIC
├── Not allowlisted
└── should_enrich = True
```

```text
192.168.1.20
├── Valid IPv4
├── PRIVATE
└── should_enrich = False
```

```text
8.8.8.8
├── Valid IPv4
├── PUBLIC
├── Allowlisted
└── should_enrich = False
```

A `False` enrichment decision does not mean that an IP is safe. It only means that, according to the current SentinelFlow policy, the address should not be sent to an external Threat Intelligence enrichment stage.

## Threat Intelligence

SentinelFlow includes a modular threat intelligence layer designed to support multiple providers without coupling the core application to a specific external service.

The current implementation includes:

- A common `ThreatIntelProvider` interface.
- A normalized `ThreatIntelResult` model.
- A local threat intelligence provider for deterministic testing.
- A `ThreatIntelService` capable of querying one or multiple providers.
- Integration with the IP enrichment policy.
- Automatic enrichment only for public IP addresses that are not allowlisted.

Current flow:

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
ThreatIntelProvider
    ↓
ThreatIntelResult

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

Each component is designed to remain modular and testable before additional functionality is introduced.

---

## Roadmap

Planned areas of development include:

- additional log source support;
- further event normalization;
- internal/private IP handling;
- allowlists;
- threat intelligence integrations;
- reputation enrichment;
- caching;
- risk scoring;
- confidence scoring;
- severity classification;
- behavioral detections;
- persistence and audit logging;
- alert generation;
- defensive response workflows;
- dry-run response mode;
- human approval workflows;
- API access;
- containerization;
- CI/CD;
- production-style documentation and demonstrations.

---

## Security Philosophy

SentinelFlow is designed as a defensive security project.

Future response capabilities will prioritize:

- controlled actions;
- explicit authorization;
- auditability;
- human oversight;
- safe defaults;
- dry-run execution before active remediation.

---

## Disclaimer

SentinelFlow is intended exclusively for:

- defensive security research;
- SOC training;
- cybersecurity laboratories;
- owned infrastructure;
- explicitly authorized systems.

It is not intended for unauthorized access, offensive operations or activity against systems without permission.