# Splunk SOC Home Lab — Active Directory Attack Detection

A home lab built to simulate real-world Active Directory attacks and detect them using Splunk. This repo documents the lab setup, each attack phase executed against the domain, the raw telemetry generated, and the corresponding Splunk detections (SPL queries) mapped to MITRE ATT&CK.

## 🎯 Goal

Practice both offensive techniques (simulating common AD attacks) and defensive detection engineering (building and tuning Splunk searches/dashboards to catch them) — bridging SOC analyst and red team skill sets in one hands-on project.

## 🏗️ Lab Architecture

```
┌───────────────────────────┐          ┌───────────────────────────┐          ┌────────────────────────────┐
│  Attacker (Kali Linux)    │          │  Windows Server           │          │  Splunk Enterprise         │
│  - Impacket, CrackMapExec │ attacks  │  (Domain Controller)      │ logs to  │  (SOC server)              │
│  - Hydra, Kerbrute        │ ───────▶ │  - Active Directory DS    │ ───────▶ │  - Ingests logs            │
│  - Responder, BloodHound  │          │  - Splunk Universal       │          │  - Dashboards & detections │
│  - enum4linux             │          │    Forwarder              │          │    (SPL)                   │
└───────────────────────────┘          └───────────────────────────┘          └────────────────────────────┘
```

## 🧱 Lab Components

| Component | Role | Key Tools |
|---|---|---|
| Windows Server | Domain Controller | Active Directory Domain Services, Splunk Universal Forwarder |
| Kali Linux | Attacker machine | Impacket, CrackMapExec, Hydra, Kerbrute, Responder, BloodHound, enum4linux, Hashcat |
| Splunk Enterprise | SOC / log analysis | Splunk Free/Dev license (500MB/day) |

> All domain names, usernames, and passwords referenced throughout this repo (e.g. `exbugz0d.org`)
> belong to this isolated lab environment and are not real credentials.

## 📁 Repository Structure

```
splunk-soc-home-lab/
├── README.md
├── phase1-bruteforce/
│   └── README.md
├── phase2-recon-enumeration/
│   ├── README.md
│   └── screenshots/
├── phase3-credential-access/
├── phase4-lateral-movement/
├── phase5-privilege-escalation/
└── phase6-persistence/
```

Each phase folder follows the same format:
**Objective → Command → Evidence → Detection Setup → Detecting It (SPL) → False Positives**, with MITRE ATT&CK mapped per technique.

## 🗺️ Phases Covered

| # | Phase | Techniques | MITRE ATT&CK | Status |
|---|---|---|---|---|
| 1 | Password Brute Forcing | SMB / RDP / Kerberos brute force | T1110.001 / T1110.003 | 🟧 In Progress |
| 2 | Reconnaissance & Enumeration | LDAP Enumeration, SMB/Null Session Enumeration, BloodHound Collection | T1087.002 / T1482 / T1135 / T1046 | ✅ Complete |
| 3 | Credential Access | Kerberoasting, AS-REP Roasting, Password Spraying | T1558.003 / T1558.004 / T1110.003 | ⬜ Planned |
| 4 | Lateral Movement | Pass-the-Hash, Overpass-the-Hash / Pass-the-Ticket | T1550.002 / T1550.003 | ⬜ Planned |
| 5 | Privilege Escalation & Domain Dominance | DCSync, Golden/Silver Ticket, Delegation Abuse | T1003.006 / T1558.001 / T1558.002 | ⬜ Planned |
| 6 | Persistence | Skeleton Key, AdminSDHolder Abuse, DCShadow | T1556.001 / T1098 / T1207 | ⬜ Planned |

**Status legend:** ⬜ Planned · 🟧 In Progress (attack run, detection not yet fully verified/matched) · ✅ Complete (attack run + detection verified end-to-end in Splunk, writeup done)

> Phase 1 is marked In Progress rather than Complete: the initial Splunk success-event screenshot
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
  early in each new phase.
- Pairing an attacker-side terminal screenshot with the **matching** Splunk event (same source IP,
  account, and timeframe) is far more convincing evidence than showing either one alone — learned
  this the hard way on Phase 1, see the note above.

## 🛠️ Tech Stack

- **Hypervisor:** VirtualBox
- **SIEM:** Splunk Enterprise (Free/Dev license)
- **Telemetry:** Windows Event Logs (Security, System, Directory Service) + Splunk Universal Forwarder
- **Attack Tooling:** Impacket, CrackMapExec, Hydra, Kerbrute, Responder, BloodHound, enum4linux, Hashcat

## 📌 Planned Additions

- Sysmon on the Domain Controller (and Sysmon for Linux on the attacker box) for process- and
  LSASS-access-level telemetry — needed for Phases 4–6, since Sysmon has no visibility into
  LDAP/SMB protocol content and doesn't replace the native auditing used in Phases 1 and 2.

## ⚠️ Disclaimer

All attacks and techniques documented in this repository were performed exclusively in an **isolated, self-owned home lab environment**. Nothing here was run against any system without explicit authorization. This repo is for educational and defensive security research purposes only.

## 🔎 About

- GitHub: [@a7meda1s1dd1g](https://github.com/a7meda1s1dd1g)
- LinkedIn: [Ahmed Alsiddig](https://www.linkedin.com/in/ahmed-alsiddig-6a0801287/)

## 📜 License

This repository is licensed under the [MIT License](./LICENSE).
