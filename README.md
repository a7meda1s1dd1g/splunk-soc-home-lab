# Splunk SOC Home Lab — Active Directory Attack Detection

A home lab built to simulate real-world Active Directory attacks and detect them using Splunk. This repo documents the lab setup, each attack scenario executed against the domain, the raw telemetry generated, and the corresponding Splunk detections (SPL queries) mapped to MITRE ATT&CK.

## 🎯 Goal

Practice both offensive techniques (simulating common AD attacks) and defensive detection engineering (building and tuning Splunk searches/dashboards to catch them) — bridging SOC analyst and red team skill sets in one hands-on project.

## 🏗️ Lab Architecture

```
┌───────────────────────────┐
│  Attacker (Kali Linux)    │
│  - Impacket, Mimikatz     │
│  - Responder, BloodHound  │
└─────────────┬─────────────┘
              │ attacks
              ▼
┌───────────────────────────┐          ┌───────────────────────────┐
│  Windows Server            │  logs   │  Splunk Enterprise         │
│  (Domain Controller)       │────────▶│  (SOC server)               │
│  - Active Directory DS     │         │  - Ingests logs             │
│  - Sysmon + Universal      │         │  - Dashboards & detections  │
│    Forwarder                │         │    (SPL)                    │
└─────────────┬─────────────┘          └─────────────▲───────────────┘
              │ domain-joined                          │
              ▼                                        │ logs
┌───────────────────────────┐                          │
│  Windows 10/11 Client      │──────────────────────────┘
│  (Domain-joined victim)    │
│  - Sysmon + Universal      │
│    Forwarder                │
└───────────────────────────┘
```

## 🧱 Lab Components

| Component | Role | Key Tools |
|---|---|---|
| Windows Server 2019/2022 | Domain Controller | Active Directory Domain Services, Sysmon |
| Windows 10/11 | Domain-joined client | Sysmon, Splunk Universal Forwarder |
| Kali Linux | Attacker machine | Impacket, Mimikatz, Responder, BloodHound |
| Splunk Enterprise | SOC / log analysis | Splunk Free/Dev license (500MB/day) |

## 📁 Repository Structure

```
splunk-soc-ad-homelab/
├── README.md
├── lab-setup/
│   ├── 01-network-topology.md
│   ├── 02-domain-controller-setup.md
│   ├── 03-client-setup.md
│   ├── 04-splunk-install-config.md
│   └── 05-sysmon-config.md
├── attacks/
│   ├── 01-kerberoasting/
│   ├── 02-pass-the-hash/
│   ├── 03-asrep-roasting/
│   ├── 04-dcsync/
│   ├── 05-golden-ticket/
│   ├── 06-llmnr-poisoning/
│   └── 07-bloodhound-enum/
├── detections/
│   └── splunk-detection-rules.md
└── dashboards/
    └── soc-overview-dashboard.json
```

Each attack folder follows the same format:
**Objective → Attack Steps → Raw Log Sample → Detection Logic (SPL) → Dashboard/Alert Screenshot → MITRE ATT&CK Mapping**

## 🗺️ Attack Scenarios Covered

| # | Attack | MITRE ATT&CK | Status |
|---|---|---|---|
| 1 | Kerberoasting | T1558.003 | ⬜ Planned |
| 2 | Pass-the-Hash | T1550.002 | ⬜ Planned |
| 3 | AS-REP Roasting | T1558.004 | ⬜ Planned |
| 4 | DCSync Attack | T1003.006 | ⬜ Planned |
| 5 | Golden Ticket | T1558.001 | ⬜ Planned |
| 6 | LLMNR/NBT-NS Poisoning | T1557.001 | ⬜ Planned |
| 7 | BloodHound Enumeration | T1087 / T1482 | ✅ Complete |

## 🛠️ Tech Stack

- **Hypervisor:** VMware Workstation / VirtualBox / Proxmox
- **SIEM:** Splunk Enterprise (Free/Dev license)
- **Telemetry:** Sysmon + Windows Event Logs + Splunk Universal Forwarder
- **Attack Tooling:** Impacket, Mimikatz, Responder, BloodHound, Hashcat

## ⚠️ Disclaimer

All attacks and techniques documented in this repository were performed exclusively in an **isolated, self-owned home lab environment**. Nothing here was run against any system without explicit authorization. This repo is for educational and defensive security research purposes only.

## 🔎 About

- GitHub: [@a7meda1s1dd1g](https://github.com/a7meda1s1dd1g)
- LinkedIn: [Ahmed Alsiddig](https://www.linkedin.com/in/ahmed-alsiddig-6a0801287/)

## 📜 License

This repository is licensed under the [MIT License](./LICENSE).
