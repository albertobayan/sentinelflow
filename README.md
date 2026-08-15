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

## Usage

Start SentinelFlow:

```bash
python -m sentinelflow.main

## Disclaimer

SentinelFlow is intended exclusively for defensive security research, SOC training, controlled laboratory environments, owned infrastructure and explicitly authorized systems.