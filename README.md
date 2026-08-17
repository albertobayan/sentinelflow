# SentinelFlow

**Automated Threat Detection, Enrichment & Response Platform**

SentinelFlow is a defensive cybersecurity automation project built in Python.

The goal of the project is to simulate a modular SOC/SOAR workflow capable of processing security events, detecting indicators of compromise, enriching them with threat intelligence, assessing their risk, generating alerts and supporting defensive response workflows.

## Project Status

🚧 Under active development.

Current milestone:

**v0.1 — IOC Detection Engine**

## Focus

- Blue Team
- SOC Automation
- Threat Intelligence
- Detection Engineering
- Incident Response
- SOAR
- Python

## Current status

### v0.1 — IOC Detection Engine

SentinelFlow currently identifies and validates:

- IPv4
- IPv6
- Domains
- URLs
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

The IOC engine includes automated testing with pytest and handles invalid or malformed input.

## Nginx Log Watcher

SentinelFlow can monitor an Nginx access log incrementally and process newly appended events without re-reading previously processed lines.

Run the watcher:

```bash
python -m sentinelflow.watch

Current pipeline:

Nginx Log
    ↓
LogWatcher
    ↓
Nginx Parser
    ↓
SecurityEvent
    ↓
IOC Detection
    ↓
Structured Output

The watcher:

tracks its current position in the log file;
processes only newly appended lines;
ignores malformed Nginx lines;
supports a configurable polling interval;
validates invalid polling intervals;
extracts the source IP as an IOC;
can be stopped cleanly with Ctrl+C.

Example:

New security event
────────────────────
Timestamp: 15/Aug/2026:01:34:21 +0200
Source IP: 185.123.45.20
Method: GET
Path: /admin
Status: 401
User-Agent: Mozilla/5.0
IOC Type: IPv4
IOC Valid: True
Source: nginx
────────────────────

## Usage

Start SentinelFlow:

```bash
python -m sentinelflow.main

Example:

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

Run tests:

pytest

## Disclaimer

SentinelFlow is intended exclusively for defensive security research, SOC training, controlled laboratory environments, owned infrastructure and explicitly authorized systems.