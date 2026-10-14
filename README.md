# Splunk SOC Home Lab

A hands-on Security Operations Center (SOC) home lab using Splunk and virtual machines to practice attack simulation, security monitoring, threat detection, threat hunting, and incident investigation.

## Overview

This project documents practical SOC exercises in two environments:

- **Attack Simulation:** Generate controlled security events in a virtual lab and investigate them using Splunk.
- **BOTS v3:** Analyze the Splunk Boss of the SOC Version 3 dataset to practice threat hunting, SPL queries, and security investigations.

The goal is to develop practical skills in SIEM operations, alert triage, log analysis, and evidence-based incident investigation.

## Objectives

- Configure and use Splunk as a Security Information and Event Management (SIEM) platform.
- Collect and analyze security logs from virtual machines.
- Simulate controlled attacks and investigate the resulting events.
- Develop and test SPL queries for threat detection.
- Practice threat hunting using the BOTS v3 dataset.
- Correlate events and document investigation findings.
- Recommend defensive measures and detection improvements.

## Lab Environment

| Component | Details |
|---|---|
| SIEM | Splunk |
| Infrastructure | Virtual machines |
| Attack Simulation | Controlled lab exercises |
| Threat Hunting | BOTS v3 dataset |
| Log Sources | Depends on the scenario |
| Investigation Tools | Splunk Search Processing Language (SPL) |

## SOC Workflow

1. **Attack Simulation** — Generate controlled security events in the lab.
2. **Log Collection** — Verify that relevant telemetry reaches Splunk.
3. **Threat Detection** — Search for suspicious activity using SPL.
4. **Alert Triage** — Review event details, timestamps, affected systems, and severity.
5. **Investigation** — Correlate events and analyze supporting evidence.
6. **Threat Hunting** — Search available datasets for suspicious behavior and related activity.
7. **Reporting** — Document findings, conclusions, and recommended actions.

## Repository Structure

```text
splunk-soc-home-lab/
├── README.md
├── attack-scenarios/
├── investigations/
│   ├── case-001-brute-force/
│   ├── case-002-suspicious-powershell/
│   └── case-003-network-reconnaissance/
├── botsv3/
│   ├── README.md
│   ├── investigations/
│   └── screenshots/
├── screenshots/
├── .gitignore
└── LICENSE
```

## 1. Attack Simulation and Investigation

This section documents controlled attack scenarios performed against authorized lab systems and the subsequent investigations in Splunk.

Planned scenarios include:

| Case | Scenario | Status |
|---|---|---|
| 001 | Brute-Force Login Attempt | Planned |
| 002 | Suspicious PowerShell Activity | Planned |
| 003 | Network Reconnaissance | Planned |

Each case will document the attack objective, simulation procedure, relevant log sources, SPL queries, investigation findings, verdict, and recommended defensive measures.

## 2. BOTS v3 — Boss of the SOC

BOTS v3 is a Splunk security investigation dataset used to practice threat hunting and security analysis.

This section will document investigations using the available dataset, including:

- Exploring security events and data sources.
- Identifying relevant indexes and sourcetypes.
- Developing SPL queries to investigate suspicious activity.
- Correlating events and examining potential indicators of compromise.
- Documenting findings and evidence-based conclusions.

**Official dataset:** [Splunk BOTS v3 on GitHub](https://github.com/splunk/botsv3)

Setup instructions, investigation reports, SPL queries, and selected screenshots will be maintained in the [`botsv3/`](botsv3/) directory.

## Investigation Methodology

Each investigation will include:

- **Overview:** Scenario, objective, and environment.
- **Evidence Collection:** Relevant logs, events, timestamps, and affected systems.
- **Analysis:** SPL queries and investigation steps.
- **Findings:** Observed activity and supporting evidence.
- **Verdict:** Assessment based on the available evidence.
- **Recommendations:** Appropriate detection, containment, or remediation measures.

## Evidence and Documentation

Screenshots and Markdown reports will be included where they help demonstrate the investigation process and results. Sensitive information, credentials, tokens, and unnecessary private network details will be removed or sanitized before publication.

## Disclaimer

This repository is intended for educational purposes and authorized security testing. Attack simulations must be performed only against systems for which authorization has been granted.

BOTS v3 materials remain subject to their original licensing and usage terms.

## Progress

This is an ongoing project. New attack scenarios, detection queries, BOTS v3 investigations, and incident response exercises will be documented as they are completed.
