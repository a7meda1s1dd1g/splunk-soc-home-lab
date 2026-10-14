# Splunk SOC Home Lab

A hands-on Security Operations Center (SOC) home lab focused on attack simulation, security monitoring, threat detection, and incident investigation using Splunk and virtual machines.

## Overview

This project documents simulated security attacks performed in an isolated lab environment and the subsequent investigations conducted using Splunk. Each case demonstrates a practical SOC workflow, from generating security events to analyzing logs, identifying suspicious activity, and documenting findings.

## Objectives

- Simulate controlled attacks in a virtual lab environment.
- Collect and analyze security logs using Splunk.
- Develop and test SPL queries for threat detection.
- Investigate alerts and correlate relevant events.
- Identify indicators of suspicious activity.
- Document investigation findings and evidence.
- Recommend appropriate defensive and remediation measures.

## Lab Environment

| Component | Details |
|---|---|
| SIEM | Splunk |
| Infrastructure | Virtual machines |
| Attack Simulation | Controlled lab exercises |
| Log Sources | Based on each scenario |
| Investigation | Splunk searches and event analysis |

## Investigation Workflow

1. **Attack Simulation** — Execute a controlled attack scenario against a designated lab target.
2. **Log Collection** — Verify that relevant security events are generated and ingested into Splunk.
3. **Threat Detection** — Search for suspicious activity using SPL queries.
4. **Alert Triage** — Review event details, timestamps, affected systems, and severity.
5. **Investigation** — Correlate available evidence and determine what occurred.
6. **Verdict** — Document whether the activity was malicious, benign, or inconclusive based on the evidence.
7. **Recommendations** — Identify appropriate defensive measures and detection improvements.

## Repository Structure

```text
splunk-soc-home-lab/
├── README.md
├── attack-scenarios/
├── investigations/
│   ├── case-001-brute-force/
│   ├── case-002-suspicious-powershell/
│   └── case-003-network-reconnaissance/
├── screenshots/
├── .gitignore
└── LICENSE
```

## Attack Scenarios

The following scenarios are planned for investigation and documentation.

| Case | Scenario | Status |
|---|---|---|
| 001 | Brute-Force Login Attempt | Planned |
| 002 | Suspicious PowerShell Activity | Planned |
| 003 | Network Reconnaissance | Planned |

Additional scenarios will be added as the lab evolves.

## Case Documentation

Each investigation will include:

- Attack objective and simulation procedure
- Attacker and target lab systems
- Relevant log sources and event details
- Splunk SPL queries
- Investigation steps and supporting evidence
- Findings and verdict
- Recommended defensive measures

## Evidence

Screenshots, queries, and investigation reports will be included to demonstrate the attack simulation and analysis process. Sensitive information and credentials will be removed before publication.

## Disclaimer

All attack simulations are conducted for educational purposes within an authorized, isolated lab environment. Testing against systems without explicit authorization is not permitted.

## Progress

This is an ongoing project. New attack scenarios, detection queries, investigation reports, and defensive improvements will be documented as they are completed.
