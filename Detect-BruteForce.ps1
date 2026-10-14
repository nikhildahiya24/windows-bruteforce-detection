<#
.SYNOPSIS
    Detects brute-force and password-spray activity from Windows Security events 4625 (failed logon)
    and 4624 (successful logon), grouped by target username and source IP.

.DESCRIPTION
    Three detections, matching the Sentinel rule in BruteForce-Sentinel.kql:
      BruteForce          >= FailThreshold failures for one user from one IP inside WindowMinutes
      PasswordSpray       >= SprayUserThreshold distinct users failing from one IP inside WindowMinutes
      SuccessAfterFailure a 4624 for a targeted user from the same IP within SuccessGraceMinutes of the
                          last failure (escalates the alert to High)

    Data sources (pick one):
      (default)    live Security log on this machine or -ComputerName   (needs admin / Event Log Readers)
      -EvtxPath    an exported .evtx file
      -CsvPath     a CSV with the columns produced by -ExportEventsCsv (used for the bundled sample)

.EXAMPLE
    .\Detect-BruteForce.ps1 -Hours 24
.EXAMPLE
    .\Detect-BruteForce.ps1 -EvtxPath C:\IR\DC01-Security.evtx -ExportPath C:\IR\alerts.csv
.EXAMPLE
    .\Detect-BruteForce.ps1 -CsvPath .\sample-security-events.csv
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(ParameterSetName = 'Live')] [string]   $ComputerName = $env:COMPUTERNAME,
    [Parameter(ParameterSetName = 'Live')] [int]      $Hours = 24,
    [Parameter(ParameterSetName = 'Evtx', Mandatory)] [string] $EvtxPath,
    [Parameter(ParameterSetName = 'Csv',  Mandatory)] [string] $CsvPath,

    [int]      $WindowMinutes       = 10,
    [int]      $FailThreshold       = 10,
    [int]      $SprayUserThreshold  = 10,
    [int]      $SuccessGraceMinutes = 30,
    # Accounts that make any alert High. Replace with your Tier 0 / admin naming convention.
    [string[]] $PrivilegedPatterns  = @('administrator', 'adm.*', '*admin*'),
    [string]   $ExportPath,
    [string]   $ExportEventsCsv
)

$SubStatusText = @{
    '0xC000006A' = 'Bad password'
    '0xC0000064' = 'User does not exist'
    '0xC0000234' = 'Account locked out'
    '0xC0000072' = 'Account disabled'
    '0xC000006F' = 'Outside allowed hours'
    '0xC0000070' = 'Workstation restriction'
    '0xC0000071' = 'Password expired'
    '0xC0000193' = 'Account expired'
    '0xC0000224' = 'Must change password'
    '0xC0000133' = 'Clock skew (Kerberos)'
    '0xC000015B' = 'Logon type not granted'
}
$IgnoreIps = @('', '-', '::1', '127.0.0.1')

function ConvertFrom-LogonEvent {
    param([System.Diagnostics.Eventing.Reader.EventRecord] $Event)
    $data = @{}
    foreach ($d in ([xml]$Event.ToXml()).Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [pscustomobject]@{
        TimeCreated               = $Event.TimeCreated
        EventID                   = $Event.Id
        Computer                  = $Event.MachineName
        TargetUserName            = $data.TargetUserName
        TargetDomainName          = $data.TargetDomainName
        LogonType                 = [int]$data.LogonType
        Status                    = $data.Status      # 4625 only
        SubStatus                 = $data.SubStatus   # 4625 only
        IpAddress                 = $data.IpAddress
        WorkstationName           = $data.WorkstationName
        LogonProcessName          = $data.LogonProcessName
        AuthenticationPackageName = $data.AuthenticationPackageName
    }
}

# ---- 1. Collect 4624/4625 -------------------------------------------------------------------
switch ($PSCmdlet.ParameterSetName) {
    'Csv' {
        $events = Import-Csv $CsvPath | ForEach-Object {
            $_.TimeCreated = [datetime]$_.TimeCreated; $_.EventID = [int]$_.EventID; $_.LogonType = [int]$_.LogonType; $_
        }
    }
    default {
        $filter = @{ Id = 4624, 4625 }
        if ($EvtxPath) { $filter.Path = $EvtxPath } else { $filter.LogName = 'Security'; $filter.StartTime = (Get-Date).AddHours(-$Hours) }
        $getArgs = @{ FilterHashtable = $filter; ErrorAction = 'SilentlyContinue' }
        if (-not $EvtxPath -and $ComputerName -ne $env:COMPUTERNAME) { $getArgs.ComputerName = $ComputerName }
        $events = Get-WinEvent @getArgs | ForEach-Object { ConvertFrom-LogonEvent $_ }
    }
}
if ($ExportEventsCsv) { $events | Export-Csv $ExportEventsCsv -NoTypeInformation }

$failures  = @($events | Where-Object { $_.EventID -eq 4625 -and $_.IpAddress -notin $IgnoreIps })
# Logon types a human attacker produces: interactive, network, unlock, cleartext, RDP, cached
$successes = @($events | Where-Object { $_.EventID -eq 4624 -and $_.LogonType -in 2, 3, 7, 8, 10, 11 })
Write-Verbose "Loaded $($events.Count) events: $($failures.Count) failures, $($successes.Count) successes"

function Get-UserKey($e) { ('{0}\{1}' -f $e.TargetDomainName, $e.TargetUserName).ToLower() }
function Get-WindowStart([datetime]$t) {
    $t.AddMinutes(-($t.Minute % $WindowMinutes)).AddSeconds(-$t.Second).AddMilliseconds(-$t.Millisecond)
}
foreach ($f in $failures) {
    $f | Add-Member -NotePropertyName UserKey -NotePropertyValue (Get-UserKey $f) -Force
    $f | Add-Member -NotePropertyName Window  -NotePropertyValue (Get-WindowStart $f.TimeCreated) -Force
}

# ---- 2. Group and apply thresholds ----------------------------------------------------------
$candidates = [System.Collections.Generic.List[object]]::new()

# Brute force: one IP, one user, one window
foreach ($g in ($failures | Group-Object IpAddress, UserKey, Window)) {
    if ($g.Count -lt $FailThreshold) { continue }
    $candidates.Add([pscustomobject]@{ DetectionType = 'BruteForce'; IpAddress = $g.Group[0].IpAddress
        Window = $g.Group[0].Window; Events = $g.Group })
}
# Password spray: one IP, many users, one window
foreach ($g in ($failures | Group-Object IpAddress, Window)) {
    $users = @($g.Group.UserKey | Sort-Object -Unique)
    if ($users.Count -lt $SprayUserThreshold) { continue }
    $candidates.Add([pscustomobject]@{ DetectionType = 'PasswordSpray'; IpAddress = $g.Group[0].IpAddress
        Window = $g.Group[0].Window; Events = $g.Group })
}

# Attacks that straddle a window boundary would otherwise raise one alert per window: merge
# back-to-back windows for the same detection, IP and (for brute force) user into one alert.
$merged = [System.Collections.Generic.List[object]]::new()
$candidates | Sort-Object DetectionType, IpAddress, { $_.Events[0].UserKey }, Window | ForEach-Object {
    $key  = '{0}|{1}|{2}' -f $_.DetectionType, $_.IpAddress, $(if ($_.DetectionType -eq 'BruteForce') { $_.Events[0].UserKey })
    $prev = if ($merged.Count) { $merged[-1] }
    if ($prev -and $prev.Key -eq $key -and $_.Window -le $prev.LastWindow.AddMinutes($WindowMinutes)) {
        $prev.Events += $_.Events; $prev.LastWindow = $_.Window
    } else {
        $merged.Add([pscustomobject]@{ Key = $key; DetectionType = $_.DetectionType; IpAddress = $_.IpAddress
            Window = $_.Window; LastWindow = $_.Window; Events = @($_.Events) })
    }
}
$candidates = $merged

# ---- 3. Enrich: success after failure, privilege, failure reasons ---------------------------
$alerts = foreach ($c in $candidates) {
    $ev        = $c.Events | Sort-Object TimeCreated
    $firstFail = $ev[0].TimeCreated
    $lastFail  = $ev[-1].TimeCreated
    $users     = @($ev.UserKey | Sort-Object -Unique)

    $hits = @($successes | Where-Object {
        $_.IpAddress -eq $c.IpAddress -and (Get-UserKey $_) -in $users -and
        $_.TimeCreated -ge $firstFail -and $_.TimeCreated -le $lastFail.AddMinutes($SuccessGraceMinutes)
    } | Sort-Object TimeCreated)

    $privileged = @($users | Where-Object { $u = ($_ -split '\\')[-1]; $PrivilegedPatterns | Where-Object { $u -like $_ } })
    $isPrivateIp = $c.IpAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|fd)'
    $reasons = $ev | Group-Object SubStatus | Sort-Object Count -Descending |
        ForEach-Object { '{0} {1} ({2})' -f $_.Count, $_.Name, $(if ($SubStatusText[$_.Name]) { $SubStatusText[$_.Name] } else { 'other' }) }
    $lockedOut = @($ev | Where-Object SubStatus -eq '0xC0000234').Count -gt 0

    $severity = switch ($true) {
        ($hits.Count -gt 0)          { 'High'; break }
        ($privileged.Count -gt 0 -and $c.DetectionType -eq 'BruteForce') { 'High'; break }
        (-not $isPrivateIp)          { 'Medium'; break }
        ($c.DetectionType -eq 'PasswordSpray') { 'Medium'; break }
        default                      { 'Low' }
    }

    [pscustomobject]@{
        Severity            = $severity
        DetectionType       = if ($hits.Count) { "$($c.DetectionType)+SuccessAfterFailure" } else { $c.DetectionType }
        IpAddress           = $c.IpAddress
        SourceScope         = if ($isPrivateIp) { 'Internal' } else { 'External' }
        FirstFailure        = $firstFail
        LastFailure         = $lastFail
        Failures            = $ev.Count
        DistinctUsers       = $users.Count
        Users               = ($users | Select-Object -First 15) -join ', '
        PrivilegedTargeted  = $privileged -join ', '
        TargetHosts         = (@($ev.Computer | Sort-Object -Unique)) -join ', '
        LogonTypes          = (@($ev.LogonType | Sort-Object -Unique)) -join ','
        FailureReasons      = $reasons -join '; '
        LockoutObserved     = $lockedOut
        SuccessAfterFailure = $hits.Count -gt 0
        SuccessfulUsers     = (@($hits | ForEach-Object { Get-UserKey $_ } | Sort-Object -Unique)) -join ', '
        FirstSuccess        = if ($hits) { $hits[0].TimeCreated } else { $null }
        SuccessLogonTypes   = (@($hits.LogonType | Sort-Object -Unique)) -join ','
    }
}

$order = @{ High = 0; Medium = 1; Low = 2 }
$alerts = @($alerts | Sort-Object { $order[$_.Severity] }, FirstFailure)
if ($ExportPath) { $alerts | Export-Csv $ExportPath -NoTypeInformation }
if (-not $alerts) { Write-Host "No brute-force or spray activity above threshold."; return }
$alerts
