# Sample Event Analysis

**Data:** [sample-security-events.csv](sample-security-events.csv), 284 synthetic Security events from
`CONTOSO` on 2026-10-13, 08:00–18:00 (141 × 4625, 143 × 4624). Generated to resemble real exports; no real
hosts or people.
**Run:** `.\Detect-BruteForce.ps1 -CsvPath .\sample-security-events.csv` with default thresholds
(10-min window, 10 failures per user+IP, 10 distinct users per IP, 30-min success window).
**Output:** [sample-alerts.csv](sample-alerts.csv), 3 alerts.

## What a single event looks like

A 4625 from the targeted attack, as Event Viewer's *Details → XML* shows the `EventData` block:

```xml
<EventData>
  <Data Name="TargetUserName">adm.jsmith</Data>
  <Data Name="TargetDomainName">CONTOSO</Data>
  <Data Name="Status">0xC000006D</Data>      <!-- generic "bad user name or password" -->
  <Data Name="SubStatus">0xC000006A</Data>   <!-- the real reason: wrong password, account exists -->
  <Data Name="LogonType">3</Data>            <!-- network: RDP with NLA pre-auth -->
  <Data Name="LogonProcessName">NtLmSsp</Data>
  <Data Name="AuthenticationPackageName">NTLM</Data>
  <Data Name="WorkstationName">DESKTOP-7Q2LK9</Data>  <!-- attacker's hostname, not one of ours -->
  <Data Name="IpAddress">198.51.100.23</Data>
</EventData>
```

## Grouped view

Failures grouped by source IP and username:

| Source IP | Scope | Users | Failures | Span | SubStatus mix | Then a 4624? |
|---|---|---|---|---|---|---|
| 198.51.100.23 | External | 1 (`adm.jsmith`) | 64 | 13:30:00–13:39:27 | 64 × bad password | **Yes, 13:39:50, types 3 and 10** |
| 203.0.113.45 | External | 28 | 56 (2 each) | 10:05:00–10:12:09 | 20 bad password, 36 no such user | No |
| 10.0.8.15 | Internal | 1 (`svc_backup`) | 18 | 15:00:00–15:14:10 | 5 bad password, 13 locked out | No |
| 10.0.4.22 | Internal | 1 (`mlopez`) | 3 | 09:12:00–09:12:40 | 3 bad password | Yes, 09:13:15 |

## Alert by alert

### 1. HIGH: Brute force with success, `adm.jsmith` from 198.51.100.23

- 64 wrong-password attempts in 9.5 minutes (one every ~9 s): automated, not a person mistyping.
- Target is a privileged admin account, and every failure says the account exists (`0xC000006A`), so
  the attacker had a valid username going in.
- 23 seconds after the last failure, a **type 3 then type 10 logon succeeded** from the same IP: the
  password was guessed and an RDP session was opened on `SRV-RDGW01`.
- No lockout fired. Either the account is exempt from lockout or the threshold is higher than 64.
- Source is external and the workstation name `DESKTOP-7Q2LK9` is not a CONTOSO naming pattern.

**Verdict: true positive, confirmed compromise. Start incident response now** (playbook in
[incident-response.md](incident-response.md), all phases). Highest priority: the session on SRV-RDGW01 is
still potentially live.

### 2. MEDIUM: Password spray from 203.0.113.45

- 28 distinct accounts, exactly 2 attempts each, in two passes 4 minutes apart: classic low-and-slow
  spray designed to stay under per-account lockout.
- 18 of 28 names don't exist (`0xC0000064`: `admin`, `test`, `guest`, `sql`, …), so the attacker is using a
  generic wordlist mixed with real names. The 10 real accounts it hit (8 staff plus `administrator` and
  `helpdesk`) mean someone has partial knowledge of the directory, likely from OSINT or an earlier leak.
- Workstation name `kali` points at an attacker toolkit.
- No 4624 from this IP: **no evidence the spray worked**.

**Verdict: true positive, attempted intrusion, no compromise seen.** Block the IP at the edge, confirm the
10 real accounts have MFA and no successful logons from *any* new IP in the next 24 h (sprays often rotate
IPs), and check whether RDP on SRV-RDGW01 needs to be internet-facing at all.

### 3. LOW: Repeated failures for `svc_backup` from 10.0.8.15

- Steady cadence of one attempt every 50 s, from an internal backup server (`SRV-BKP01`), against one account.
- After 5 bad passwords the account locked (`0xC0000234` from 15:04:10) and the source kept retrying:
  software doesn't react to lockout, people and most attack tools do.
- Only the 15:00 window crossed the threshold (12 failures); the remaining 6 fell in the next window.

**Verdict: benign, operational.** Almost certainly a backup job holding the old password after a
reset. Confirm with whoever owns the backup system, update the stored credential, unlock the account.
Close as *benign true positive* and consider a tuning exception for this IP + account pair. If nobody reset
that password recently, re-open it: a locked service account can also mean someone tried it.

### Not alerted: `mlopez` from 10.0.4.22

Three wrong passwords at the user's own workstation (type 2 console), then a success 35 s later. This is a
typo, well below threshold, and the correct outcome is silence.

## What the sample teaches

1. **The 4624 is what matters.** 141 failures produced one alert that needs immediate action, because only
   one was followed by a success.
2. **SubStatus separates attacker situations.** `0xC0000064` heavy means a name list; `0xC000006A` only
   means the attacker knows the username; `0xC0000234` that keeps coming means software that ignores lockout.
3. **Group both ways.** IP+user alone misses the spray (at most 2 failures per user); IP alone loses the
   per-account detail you need to decide which passwords to reset.
4. **Cadence tells human from machine.** Sub-10-second or perfectly regular intervals are automated.
