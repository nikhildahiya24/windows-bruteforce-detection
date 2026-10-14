# Windows Brute-Force Detection

A detection package for password guessing against Windows hosts, built on Security log events
**4625** (failed logon) and **4624** (successful logon).

| File | What it is |
|---|---|
| [BruteForce-Sentinel.kql](BruteForce-Sentinel.kql) | Microsoft Sentinel scheduled analytics rule, plus three hunting queries for triage |
| [Detect-BruteForce.ps1](Detect-BruteForce.ps1) | Same logic in PowerShell (`Get-WinEvent`) for a single host, an exported `.evtx`, or a CSV |
| [sample-security-events.csv](sample-security-events.csv) | 284 synthetic 4624/4625 events covering four scenarios |
| [sample-alerts.csv](sample-alerts.csv) | What the PowerShell script produced from that sample |
| [sample-event-analysis.md](sample-event-analysis.md) | Walk-through of the sample: what fired, what didn't, and the triage verdict for each |
| [incident-response.md](incident-response.md) | Triage criteria and the response playbook |

## 1. The two events

Both are written to the **Security** log by the machine that *receives* the logon (a DC for domain
authentication, the member server or workstation for local/RDP/SMB logons).

| | 4624 – An account was successfully logged on | 4625 – An account failed to log on |
|---|---|---|
| Audit policy | Logon/Logoff → Audit Logon: **Success** | Logon/Logoff → Audit Logon: **Failure** |
| Key fields | `TargetUserName`, `TargetDomainName`, `LogonType`, `IpAddress`, `WorkstationName`, `TargetLogonId`, `AuthenticationPackageName` | same, plus `Status` and `SubStatus` (why it failed) |
| Use here | Did an attack eventually work? | How many tries, against whom, from where |

**Logon types worth knowing**

| Type | Meaning | Brute-force relevance |
|---|---|---|
| 2 | Interactive (console) | Physical/console or `runas` |
| 3 | Network (SMB, NTLM/Kerberos over the wire, and the NLA pre-auth step of RDP) | Most common type in 4625 floods |
| 4 / 5 | Batch / Service | Scheduled task or service with a stale password, usually benign |
| 7 | Unlock | Someone at the keyboard |
| 8 | NetworkCleartext (IIS basic auth, etc.) | Web-facing password guessing |
| 10 | RemoteInteractive (RDP) | RDP session actually opened |
| 11 | CachedInteractive | Laptop offline from DC |

With Network Level Authentication on, an RDP brute force logs **type 3** failures; a successful RDP
logon then shows a type 3 *and* a type 10 4624 seconds apart.

**4625 SubStatus codes** (the field that tells you the attacker's situation)

| SubStatus | Meaning | Reading |
|---|---|---|
| `0xC000006A` | Wrong password for a real account | Account exists: guessing is live |
| `0xC0000064` | User name does not exist | Attacker is using a generic name list (spray/enumeration) |
| `0xC0000234` | Account locked out | Lockout policy has kicked in |
| `0xC0000072` | Account disabled | Old or decoy account targeted |
| `0xC0000071` / `0xC0000193` | Password / account expired | Usually stale creds, rarely an attack |
| `0xC000006F` / `0xC0000070` | Outside logon hours / workstation not allowed | Policy restriction; correct password may have been used |
| `0xC000015B` | Logon type not granted | Correct password, wrong rights. Treat as a possible valid credential |

## 2. Detection logic

Failures are grouped by **source IP + target username** and by **source IP alone**, inside 10-minute windows.

| Detection | Condition (default) | Base severity |
|---|---|---|
| BruteForce | ≥ 10 failures, one user, one IP, one window | Low internal / Medium external / **High** if the account is privileged |
| PasswordSpray | ≥ 10 distinct users failing from one IP in one window | Medium |
| SuccessAfterFailure | A 4624 for a targeted user from the same IP within 30 min of the last failure | **High**, always |

Ignored: `IpAddress` of `-`, empty, or loopback (local service noise). Thresholds, the privileged-account
pattern and the success window are parameters in both the KQL (`let` statements) and the PowerShell
(`-FailThreshold`, `-SprayUserThreshold`, `-PrivilegedPatterns`, `-SuccessGraceMinutes`).

**Tuning:** run the hunting query *A* in the KQL file over 14 days first. Set `failThreshold` above the
99th percentile of per-user-per-IP failures from internal ranges, and add known-noisy sources (VPN
concentrators, NAT gateways, monitoring) to an exclusion watchlist instead of raising thresholds globally.

## 3. Running it

**PowerShell** (run elevated, or as a member of *Event Log Readers*):

```powershell
# Last 24 h on this machine
.\Detect-BruteForce.ps1 -Hours 24 | Format-List

# A DC or server remotely, results to CSV
.\Detect-BruteForce.ps1 -ComputerName DC01 -Hours 6 -ExportPath .\alerts.csv

# An exported log from an investigation
.\Detect-BruteForce.ps1 -EvtxPath .\DC01-Security.evtx

# The bundled sample
.\Detect-BruteForce.ps1 -CsvPath .\sample-security-events.csv | Format-List
```

Written for Windows PowerShell 5.1 and PowerShell 7 (tested on 7.4 only).

**Event Viewer, by hand:** Security log → *Filter Current Log* → Event IDs `4624,4625`. For a single IP,
use *XML* → *Edit query manually*:

```xml
<QueryList><Query Id="0" Path="Security"><Select Path="Security">
  *[System[(EventID=4625)]] and *[EventData[Data[@Name='IpAddress']='198.51.100.23']]
</Select></Query></QueryList>
```

**Sentinel:** Analytics → Create → Scheduled query rule, paste the rule section of the KQL file, and use the
settings in its header comment. To test against old data, comment out the `where LastFail > ago(runFrequency)`
line and widen `lookback`.

## 4. Verification status

- `Detect-BruteForce.ps1` was run under PowerShell 7.4 against the sample CSV; its output is `sample-alerts.csv`.
  The live `Get-WinEvent` and `.evtx` paths were not exercised (no Windows host available).
- The KQL rule has **not** been run against a Sentinel workspace. Validate it in *Logs* before enabling the rule.
- All sample events are synthetic. IPs are from documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`).
