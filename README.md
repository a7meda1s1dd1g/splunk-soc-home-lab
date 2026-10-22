# Splunk SOC Home Lab — Active Directory Attack Detection

A home lab built to simulate real-world Active Directory attacks and detect them using Splunk. This repo documents the lab setup, each attack scenario executed against the domain, the raw telemetry generated, and the corresponding Splunk detections (SPL queries) mapped to MITRE ATT&CK.

## 🎯 Goal

Practice both offensive techniques (simulating common AD attacks) and defensive detection engineering (building and tuning Splunk searches/dashboards to catch them) — bridging SOC analyst and red team skill sets in one hands-on project.

## 🏗️ Lab Architecture

```
┌───────────────────────────┐          ┌───────────────────────────┐          ┌───────────────────────────┐
│  Attacker (Kali Linux)    │          │  Windows Server            │          │  Splunk Enterprise         │
│  - Impacket, CrackMapExec │ attacks  │  (Domain Controller)       │ logs to  │  (SOC server)               │
│  - Hydra, Kerbrute        │ ───────▶ │  - Active Directory DS     │ ───────▶ │  - Ingests logs             │
│  - Responder, BloodHound  │          │  - Splunk Universal        │          │  - Dashboards & detections  │
│  - enum4linux             │          │    Forwarder               │          │    (SPL)                    │
└───────────────────────────┘          └───────────────────────────┘          └───────────────────────────┘
```

> **Current lab state:** two-box setup (DC + attacker) forwarding to Splunk. A dedicated
> domain-joined victim client and Sysmon on both endpoints are on the roadmap — see
> [Planned Additions](#-planned-additions) below — but are not yet part of the detections
> documented in this repo.

## 🧱 Lab Components

| Component | Role | Key Tools |
|---|---|---|
| Windows Server | Domain Controller | Active Directory Domain Services, Splunk Universal Forwarder |
| Kali Linux | Attacker machine | Impacket, CrackMapExec, Hydra, Kerbrute, Responder, BloodHound, enum4linux, Mimikatz (planned), Hashcat |
| Splunk Enterprise | SOC / log analysis | Splunk Free/Dev license (500MB/day) |

> All domain names, usernames, and passwords referenced throughout this repo (e.g. `exbugz0d.org`)
> belong to this isolated lab environment and are not real credentials.

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
│   ├── 00-password-bruteforce/
│   ├── 01-kerberoasting/
│   ├── 02-pass-the-hash/
│   ├── 03-asrep-roasting/
│   ├── 04-dcsync/
│   ├── 05-golden-ticket/
│   ├── 06-llmnr-poisoning/
│   ├── 07-bloodhound-enum/
│   ├── 08-ldap-enumeration/
│   └── 09-smb-null-session-enumeration/
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
| 0 | Password Brute Forcing (SMB / RDP / Kerberos) | T1110.001 / T1110.003 | 🟧 In Progress |
| 1 | Kerberoasting | T1558.003 | ⬜ Planned |
| 2 | Pass-the-Hash | T1550.002 | ⬜ Planned |
| 3 | AS-REP Roasting | T1558.004 | ⬜ Planned |
| 4 | DCSync Attack | T1003.006 | ⬜ Planned |
| 5 | Golden Ticket | T1558.001 | ⬜ Planned |
| 6 | LLMNR/NBT-NS Poisoning | T1557.001 | ⬜ Planned |
| 7 | BloodHound Enumeration | T1087.002 / T1482 | ✅ Complete |
| 8 | LDAP Enumeration | T1087.002 / T1482 | ✅ Complete |
| 9 | SMB / Null Session Enumeration | T1135 / T1046 | ✅ Complete |

**Status legend:** ⬜ Planned · 🟧 In Progress (attack run, detection not yet fully verified/matched) · ✅ Complete (attack run + detection verified end-to-end in Splunk)

> Phase 0 is marked In Progress rather than Complete: the initial Splunk success-event screenshot
> pulled for the brute-force attack was later found to reference a different account than the one
> actually cracked — the correctly-matched 4624 event still needs to be captured before this is
> closed out.

## 🔎 Key Findings So Far

- **LDAP and SMB share-access auditing are both off by default** on a fresh Domain Controller.
  `ldapsearch`, `enum4linux`, and BloodHound collection leave no trace in Splunk unless Directory
  Service diagnostics (Event ID 1644 / 2889) and Advanced Audit Policy → Object Access (Event ID
  5140 / 5145) are explicitly enabled first.
- Kerberos-dependent tooling (BloodHound, and later Kerberoasting/AS-REP roasting) silently falls
  back to NTLM if the attacker box's DNS isn't pointed at the DC — easy to miss, worth checking
  early in each new attack.
- Pairing an attacker-side terminal screenshot with the **matching** Splunk event (same source IP,
  account, and timeframe) is far more convincing evidence than showing either one alone — learned
  this the hard way on the brute-force phase, see the note above.

## 🛠️ Tech Stack

- **Hypervisor:** VirtualBox
- **SIEM:** Splunk Enterprise (Free/Dev license)
- **Telemetry:** Windows Event Logs (Security, System, Directory Service) + Splunk Universal Forwarder
- **Attack Tooling:** Impacket, CrackMapExec, Hydra, Kerbrute, Responder, BloodHound, enum4linux, Hashcat

## 📌 Planned Additions

- Sysmon on the Domain Controller (and Sysmon for Linux on the attacker box) for process- and
  LSASS-access-level telemetry — needed for Phases 4–6 (lateral movement, DCSync/Mimikatz,
  persistence), since Sysmon has no visibility into LDAP/SMB protocol content and doesn't replace
  the native auditing used in Phases 0, 7, 8 and 9.
- A dedicated domain-joined Windows 10/11 client as a second attack target, separate from the DC.

## ⚠️ Disclaimer

All attacks and techniques documented in this repository were performed exclusively in an **isolated, self-owned home lab environment**. Nothing here was run against any system without explicit authorization. This repo is for educational and defensive security research purposes only.

## 🔎 About

- GitHub: [@a7meda1s1dd1g](https://github.com/a7meda1s1dd1g)
- LinkedIn: [Ahmed Alsiddig](https://www.linkedin.com/in/ahmed-alsiddig-6a0801287/)

## 📜 License

This repository is licensed under the [MIT License](./LICENSE).
