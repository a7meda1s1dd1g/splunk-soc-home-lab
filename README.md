# Splunk SOC Home Lab — Active Directory Attack & Detection Engineering

A home lab documenting common Active Directory attack techniques end-to-end: executed from a Kali
attacker box, logged on a Windows Server domain controller, and detected in Splunk. Each phase
pairs the attacker-side evidence with the matching Splunk detection, including the configuration
needed to make Windows actually log the activity — several of these events are **not captured by
default**.

## Lab Architecture

```
 Linux (Kali)                 Windows Server                 Splunk Enterprise
 ───────────────       attacks       ─────────────       logs to      ─────────────
 Attacker box     ───────────────▶   Domain Controller  ───────────▶  SIEM / Detection
 Impacket, CME,                      (AD DS)                          Engineering
 BloodHound,                         Universal Forwarder
 Responder, Kerbrute                 installed
```

| Role | Host | Notes |
|---|---|---|
| Domain Controller | `WIN-11AN9QVN6Q3` | Windows Server, AD DS |
| Attacker | Kali Linux | Impacket, CrackMapExec, BloodHound, Responder, Kerbrute, enum4linux |
| SIEM | Splunk Enterprise | Universal Forwarder on the DC forwards Security, System, Application, and Directory Service logs |

> **Note:** All domain names, usernames, and passwords in this repo (`exbugz0d.org`, `ahmed`,
> `Ahmedalsiddig123`, etc.) belong to an isolated lab environment and are not real credentials.

## Phase Status

| Phase | Technique Area | Status |
|---|---|---|
| 1 | Password Brute Forcing | 🚧 In Progress |
| 2 | [Reconnaissance & Enumeration](./phase2-recon-enumeration/) | ✅ Complete |
| 3 | Credential Access | 📋 Planned |
| 4 | Lateral Movement | 📋 Planned |
| 5 | Privilege Escalation & Domain Dominance | 📋 Planned |
| 6 | Persistence | 📋 Planned |

**Status legend**
- 📋 **Planned** — not started yet
- 🚧 **In Progress** — attack run, but detection not yet fully verified/matched in Splunk, or writeup incomplete
- ✅ **Complete** — attack run, detection verified end-to-end in Splunk, README + screenshots written

## Repo Structure

```
splunk-soc-home-lab/
├── README.md                          (this file)
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
- **Objective** — what the technique does and why it matters
- **Command** — exact commands run from the attacker box
- **Evidence** — attacker-side terminal screenshot
- **Detection Setup** — what Windows/Splunk config was needed, since several of these events are
  not logged by default
- **Detecting It** — the SPL query and matching Splunk screenshot
- **False Positives** — what legitimate activity could look similar

## Key Findings So Far

- **LDAP and SMB share-access auditing are both off by default** on a fresh Domain Controller —
  enumeration via `ldapsearch`, `enum4linux`, or BloodHound leaves no trace in Splunk unless
  Directory Service diagnostics (Event ID 1644/2889) and Advanced Audit Policy (Event ID 5140/5145)
  are explicitly enabled.
- Kerberos-dependent tooling (BloodHound, Kerberoasting) silently falls back to NTLM if the
  attacker box's DNS isn't pointed at the DC — easy to miss, worth checking early.
- Pairing an attacker-side screenshot with the **matching** Splunk event (same source IP, account,
  and timeframe) is far more convincing evidence than either one shown alone — confirmed this the
  hard way in Phase 1, where an initial "success" screenshot turned out to be a different account
  than the one actually cracked.

## Tooling Used

| Category | Tools |
|---|---|
| Enumeration | `ldapsearch`, `enum4linux`, `crackmapexec`, `bloodhound-python` |
| Brute Forcing | CrackMapExec, Hydra, Kerbrute |
| Credential Access | Impacket (`GetUserSPNs`, `GetNPUsers`, `secretsdump`), Responder, hashcat |
| Lateral Movement | Impacket (`psexec`, `wmiexec`), Mimikatz |
| Detection | Splunk Enterprise, Splunk Universal Forwarder, Windows Advanced Audit Policy |

---

*This lab is built for defensive detection engineering practice in an isolated environment.
Educational / authorized-testing use only.*
