# Phase 2 — Reconnaissance & Enumeration

Part of the [Splunk SOC Home Lab](../) series. This phase covers unauthenticated and low-privilege
enumeration of an Active Directory environment, and how to make each technique visible in Splunk
even though most of it is **not logged by Windows out of the box**.

## Contents
- [Environment](#environment)
- [Techniques Covered](#techniques-covered)
- [Quick Reference — Event IDs](#quick-reference--event-ids)
- [1. LDAP Enumeration](#1-ldap-enumeration)
- [2. BloodHound Collection](#2-bloodhound-collection)
- [3. SMB / Null Session Enumeration](#3-smb--null-session-enumeration)
- [Verifying the Detection Pipeline](#verifying-the-detection-pipeline)
- [Lessons Learned](#lessons-learned)

---

## Environment

| Role | Host |
|---|---|
| Domain Controller | `WIN-11AN9QVN6Q3` (Windows Server, AD DS) |
| Attacker | Kali Linux |
| SIEM | Splunk Enterprise + Universal Forwarder on the DC |

## Techniques Covered

| # | Technique | MITRE ATT&CK |
|---|---|---|
| 1 | LDAP Enumeration | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) · [T1482](https://attack.mitre.org/techniques/T1482/) |
| 2 | BloodHound Collection | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) · [T1482](https://attack.mitre.org/techniques/T1482/) |
| 3 | SMB / Null Session Enumeration | [T1135](https://attack.mitre.org/techniques/T1135/) · [T1046](https://attack.mitre.org/techniques/T1046/) |

## Quick Reference — Event IDs

| Event ID | Log | What it shows | Logged by default? |
|---|---|---|---|
| 1644 | Directory Service | LDAP search filter, client IP, query duration | ❌ No |
| 2889 | Directory Service | Unsigned / cleartext LDAP bind + client identity | ❌ No |
| 4624 | Security | Logon Type 3 (network logon) | ✅ Yes |
| 5140 | Security | Network share accessed | ❌ No |
| 5145 | Security | Detailed share permission check | ❌ No |

---

## 1. LDAP Enumeration

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) · [T1482](https://attack.mitre.org/techniques/T1482/)

#### Objective
Dump the full LDAP tree — OUs, Domain Controllers, user objects, trust containers — using no more
than a valid domain credential.

#### Command
```bash
ldapsearch -x -H ldap://<dc-ip> -D "ahmed@<domain>" -w '<password>' \
  -b "DC=<domain-component>,DC=<tld>" "(objectClass=user)"
```

#### Evidence
![Ldapsearch User Dump](screenshots/01-ldapsearch-user-dump.png)

#### Why It Matters
Windows does **not** log LDAP search filters by default. An attacker can run broad queries like
`(objectClass=*)` against the entire directory and leave essentially no trace unless Directory
Service diagnostics are explicitly enabled.

#### Detection Setup *(not on by default)*
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering" /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f
```
```ini
# Universal Forwarder inputs.conf
[WinEventLog://Directory Service]
disabled = 0
```
![Detection Setup Registry](screenshots/07-detection-setup-registry.png)
![Detection Setup Inputs Conf](screenshots/9-detection-setup-inputs-conf.png)

#### Detecting It — Event ID 1644
```spl
index=wineventlog source="Directory Service" EventCode=1644
| table _time, Client_IP, Filter, Duration, Entries_Returned
```
![Splunk 1644 Ldap Filter](screenshots/02-splunk-1644-ldap-filter.png)

#### Bonus Detection — Event ID 2889 (unsigned / cleartext bind)
Catches the client's identity even when the search filter itself looks benign — `ldapsearch` and
`bloodhound-python` frequently don't negotiate LDAP signing, which trips this event.
```spl
index=wineventlog source="WinEventLog:Directory Service" EventCode=2889
| rex field=Message "Client IP address:\s+(?<client_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=Message "Identity.*:\s+(?<user>[^\r\n]+)"
| table _time, host, client_ip, user, Message
```
![Splunk 2889 Ldap Bind](screenshots/06-splunk-2889-ldap-bind.png)

#### False Positives
Legitimate admin tools (ADUC, the PowerShell AD module) generate similar LDAP queries. Baseline
known admin workstations and alert on unusual source hosts or unusually broad/bulk queries rather
than on the presence of LDAP traffic alone.

[⬆ Back to top](#contents)

---

## 2. BloodHound Collection

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) · [T1482](https://attack.mitre.org/techniques/T1482/)

#### Objective
Collect users, groups, GPOs, OUs, containers, and trust relationships for offline attack-path
analysis in the BloodHound GUI.

#### Command
```bash
bloodhound-python -u ahmed -p '<password>' -d <domain> -ns <dc-ip> -c All
```

#### Evidence
![Bloodhound Collection Terminal](screenshots/05-bloodhound-collection-terminal.png)

#### Troubleshooting Note
Hit this warning during collection:
```
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.
Error: [Errno Connection error ... ] [Errno -3] Temporary failure in name resolution
```
Collection still completed successfully, but this points to the attacker box's DNS resolver not
being pointed at the DC (`/etc/resolv.conf`). Kerberos needs working forward/reverse DNS to the DC;
without it, tools silently fall back to NTLM. Worth fixing before later phases that rely on
Kerberos (Kerberoasting, AS-REP roasting) to avoid confusing failures.

#### Detecting It
Same 1644 / 2889 searches above catch BloodHound's LDAP traffic — it is, under the hood, just a
very large volume of LDAP queries from one source in a short window.

[⬆ Back to top](#contents)

---

## 3. SMB / Null Session Enumeration

**MITRE ATT&CK:** [T1135](https://attack.mitre.org/techniques/T1135/) · [T1046](https://attack.mitre.org/techniques/T1046/)

#### Objective
Confirm null sessions are allowed, pull the domain name and SID, NetBIOS service info, and
enumerate shares.

#### Command
```bash
enum4linux -a <dc-ip>
crackmapexec smb <dc-ip> --shares
smbclient -L //<dc-ip>/ -N
```

#### Evidence
![Enum4linux Domain Sid](screenshots/03-enum4linux-domain-sid.png)

#### Why It Matters
`4624` (Logon Type 3) logs by default, but `5140` (share accessed) and `5145` (detailed share
access check) — the events that actually show **which share** was touched — do not, until the
"Audit File Share" / "Audit Detailed File Share" subcategories are turned on.

#### Detection Setup *(not on by default)*
```powershell
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```
![Detection Setup Auditpol](screenshots/08-detection-setup-auditpol.png)

These land in the regular Security log — no extra `inputs.conf` stanza needed if Security is
already forwarded.

#### Detecting It
```spl
index=wineventlog EventCode=5140 OR EventCode=5145
| table _time, Account_Name, Share_Name, Source_Address
```
![Splunk 5140 Anonymous Logon](screenshots/04-splunk-5140-anonymous-logon.png)

In the lab run, this surfaced 29 events of `ANONYMOUS LOGON` repeatedly accessing `\\*\IPC$` from
the attacker's IP — a clean signature of null-session enumeration tooling.

#### Note on SAMR Enumeration
Some `enum4linux`/CrackMapExec modules pull user/group lists over RPC (SAMR) rather than SMB share
access. This has **no dedicated Windows event at all** by default — visibility here is limited to
Sysmon Event ID 3 tying a process to port 445/135, or blocking it outright via "Network access:
Restrict clients allowed to make remote calls to SAM" (which blocks silently, it doesn't log).

#### False Positives
Null sessions are rare in hardened environments, so frequent anonymous logons across many hosts
are a strong indicator — but confirm asset inventory first, since some legacy printers/scanners
still rely on them.

[⬆ Back to top](#contents)

---

## Verifying the Detection Pipeline

Before trusting any of the searches above, confirm the logging changes actually took effect rather
than assuming the command worked:
```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering"
auditpol /get /subcategory:"File Share"
auditpol /get /subcategory:"Detailed File Share"
type "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
```
This closes the loop end-to-end: audit policy enabled on the DC → forwarder configured to collect
it → event actually shows up in Splunk.

---

## Lessons Learned
- LDAP and SMB share-access auditing are both **off by default** on a fresh DC — don't assume
  "Security log forwarded" means full visibility.
- Kerberos-dependent tools need working DNS to the DC, or they silently degrade to NTLM.
- Pairing an attacker-side screenshot with the matching Splunk event (same source IP / account /
  timeframe) is far more convincing in a writeup than either one alone.

[⬆ Back to top](#contents)
