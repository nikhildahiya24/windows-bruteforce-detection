# Brute-Force Incident Response

## 1. When does an alert need investigation?

Score the alert on these questions. **Any red item means investigate now.** Two or more amber items mean
investigate today. Only green items means it can be handled as a ticket or tuned out.

| Question | 🔴 Investigate now | 🟠 Investigate today | 🟢 Likely benign |
|---|---|---|---|
| Did a 4624 follow from the same IP? | Yes, for a targeted account | Success for the user from a *different* new IP | No success, or the user's own device |
| Which accounts? | Domain/enterprise admins, Tier 0, break-glass, service accounts with high rights | Other real accounts (`0xC000006A`) | Only non-existent names (`0xC0000064`) |
| Where from? | External IP on RDP/SMB/WinRM, or an internal host that never authenticates to this target | VPN pool, partner range, new internal host | The user's assigned workstation, a known app server |
| How fast / regular? | Sub-10 s or perfectly regular, many accounts | Bursts over hours | A handful within a minute, then success (typo) |
| How wide? | > 10 accounts, or many target hosts | 2–10 accounts | One account |
| SubStatus | `0xC000015B`, `0xC000006F`, `0xC0000070` (password was right, logon refused) | `0xC0000072` disabled / decoy account | `0xC0000071`, `0xC0000234` with a regular cadence from a known server |
| Context | Matches threat intel, other alerts on the same host/user | First seen IP for the org | Password change ticket for that account in the last 48 h |

Common benign causes to rule out quickly: a service, scheduled task, mapped drive or mobile device
holding an old password after a reset; a misconfigured monitoring probe; a user with Caps Lock on.

## 2. Playbook

Severity drives how far you go: **Low** stops after Triage. **Medium** goes through Containment.
**High** (any success after failure) runs every phase, starting containment immediately in parallel with scoping.

### Phase 1. Triage (target: within 15 min of the alert)

1. Open the alert and record: source IP(s), target account(s), target host(s), first/last failure, failure
   count, SubStatus mix, and whether `SuccessAfterFailure` is true.
2. Pull the full timeline for the IP (hunting query **B** in the KQL file, or
   `Detect-BruteForce.ps1 -ExportEventsCsv` and filter by `IpAddress`).
3. Enrich the IP: internal asset owner (CMDB/DHCP) or external reputation, geolocation, ASN, whether it
   appears in other alerts.
4. For each targeted real account: is it privileged? Was its password recently changed? Does the owner
   recognise the activity? (Contact via a channel other than the possibly compromised account.)
5. Classify: **benign** (document cause, fix it, tune), **attempted** (no success), or **compromised**
   (any successful logon you can't explain). When in doubt, treat it as compromised.

### Phase 2. Containment

For **attempted** attacks:
- Block the source IP/range at the perimeter firewall or NSG; for spraying, block the ASN if it's a hosting provider.
- Confirm MFA is enforced for every real account targeted; force a password change for any that don't have it.
- If RDP/SMB/WinRM is reachable from the internet, close it or put it behind VPN / RD Gateway with MFA.

For **compromised** accounts, additionally:
- Disable the account (`Disable-ADAccount adm.jsmith`) or, if it can't be disabled, reset the password **twice**.
- Kill the active session on the target host (`query session /server:SRV-RDGW01`, then `logoff <ID> /server:SRV-RDGW01`).
- Revoke cloud tokens if the account syncs to Entra ID (`Revoke-MgUserSignInSession`), and reset any
  secrets the account can read (service credentials, keys in scripts).
- Isolate the target host through EDR if the session ran any commands or the account is privileged.
- For a Domain/Enterprise Admin: treat as domain compromise. Engage the IR lead before acting further, and
  plan a `krbtgt` double reset once scope is known.

### Phase 3. Scoping (compromised only)

Answer: what did the attacker do with the access, and did they move?

- Every logon by the account after the first success, on all hosts: 4624, 4648 (explicit credentials), 4672 (admin privileges assigned).
- Process creation on the target host for that logon session (4688 or Sysmon 1, matching `TargetLogonId`); look for `whoami`, `net group`, `nltest`, `mimikatz`, `procdump`, `rundll32 comsvcs.dll`, PowerShell download cradles.
- Persistence: new accounts (4720), group membership changes (4728/4732/4756), new services (7045), scheduled tasks (4698), Run keys.
- Log tampering: Security log cleared (1102), audit policy changed (4719).
- Lateral movement: 4624 type 3/10 from the target host to others shortly after; RDP/SMB/WinRM out of it.
- Data access: 5140/5145 share access, large outbound transfers in firewall/proxy logs.

Hunting query **C** in the KQL file gives the account's post-logon activity in one view.

### Phase 4. Eradication and recovery

- Remove persistence and attacker accounts found in scoping; re-image hosts where code ran, rather than cleaning.
- Reset credentials for every account that logged on to an affected host during the window (credentials may have been dumped from memory).
- Re-enable the account with a new password and MFA only after scoping is complete and the owner is verified.
- Watch the account and source IPs at heightened sensitivity for 14 days (lower the rule thresholds for them, or add them to a watchlist).

### Phase 5. Lessons learned and hardening

- **Account lockout:** e.g. 10 failures / 15 min (Microsoft baseline). Confirm admins aren't exempt. Note: lockout slows guessing but enables lockout-DoS; pair it with the next items.
- **MFA** on every remote access path (RDP gateway, VPN, OWA, Entra ID).
- **Don't expose RDP/SMB/WinRM** to the internet; use RD Gateway, VPN or Azure Bastion.
- **Tiered admin accounts** that can't log on to internet-facing systems; Protected Users group for admins.
- **Disable NTLM** where possible, and enable Microsoft Entra Password Protection / banned-password lists against spray-friendly passwords.
- Feed the incident's IPs and patterns back into the rule (watchlists) and record the time from first failure to detection and to containment.

## 3. Closing the alert

Record in the ticket: classification (benign / attempted / compromised), root cause, accounts and hosts
affected, actions taken with timestamps, and any tuning change made to the rule. Benign recurring sources
get a scoped exclusion (IP + account), never a blanket threshold increase.
