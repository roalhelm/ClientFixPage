<#
.SYNOPSIS
    Read-only health check for a Windows client (Windows Update, Intune/MDM, Entra ID, BitLocker,
    drivers, Company Portal, Defender, Secure Boot, LAPS, firewall, Store, Microsoft 365 Apps, network).

.DESCRIPTION
    Collects the state of a Windows 10/11 client and writes a JSON report.
    The report is meant to be uploaded or pasted into the Client Fix Page, which maps
    each finding ID to a recommended fix script.

    The script changes nothing on the device. It only reads services, registry values,
    scheduled tasks, certificates and status cmdlets, and tests TCP connectivity.

    Run it elevated (as Administrator or SYSTEM) for complete results. Without elevation
    some checks return the status "unknown". The Entra ID Primary Refresh Token can only
    be checked in the context of the signed-in user, not as SYSTEM.

.PARAMETER OutputPath
    Path of the JSON report. Default: ClientHealth-<COMPUTERNAME>.json in the TEMP folder,
    or in the Intune Management Extension log folder in Intune mode.

.PARAMETER IntuneMode
    Runs the script as an Intune Remediation detection script. It is switched on
    automatically when the script runs as SYSTEM, because Intune passes no parameters.
    In Intune mode the script
      - writes the report to C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ClientHealth-<COMPUTERNAME>.json
        (that folder is part of "Collect diagnostics" in the Intune admin center),
      - prints a single summary line (shown in the Intune remediation report),
      - exits 1 when the device has a failed check ("With issues" in Intune), otherwise 0.

.PARAMETER Anonymize
    Replaces the computer name with a short hash and leaves out the user name and the
    tenant ID, so the report can be shared more freely.

.PARAMETER SkipNetwork
    Skips the endpoint connectivity tests.

.PARAMETER SkipUpdateScan
    Skips the Windows Update agent search test (the slowest check).

.PARAMETER SkipComponentStore
    Skips the component store health check.

.PARAMETER CopyToClipboard
    Also copies the JSON report to the clipboard.

.PARAMETER PassThru
    Returns the report object instead of printing the summary only.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Get-ClientHealth.ps1 -CopyToClipboard

.EXAMPLE
    Intune > Devices > Scripts and remediations > Remediations: upload this file as the detection
    script only, run as SYSTEM in 64-bit PowerShell. Read the summary in the device status column
    and collect the JSON with "Collect diagnostics", or from the IME Logs folder.

.NOTES
    Version : 0.3.0
    Requires: Windows PowerShell 5.1 or PowerShell 7
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Anonymize,
    [switch]$SkipNetwork,
    [switch]$SkipUpdateScan,
    [switch]$SkipComponentStore,
    [switch]$CopyToClipboard,
    [switch]$PassThru,
    [switch]$IntuneMode
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptVersion = '0.3.0'
$SchemaVersion = '1.0'

#region Thresholds
$MinFreeSpaceGB         = 20   # SYS.DISK.LOWSPACE
$MaxDaysSinceWuScan     = 7    # WU.SCAN.FAILED
$MaxDaysSinceWuInstall  = 40   # WU.PATCHLEVEL.BEHIND
$MaxDaysSinceMdmSync    = 7    # MDM.SYNC.STALE
$MaxSignatureAgeDays    = 3    # DEF.SIGNATURE.OUTDATED
$MdmCertWarnDays        = 30   # MDM.ENROLLMENT.BROKEN (certificate expiry warning)
$MaxClockSkewSeconds    = 300  # SYS.TIME.SKEW (Kerberos tolerance is 5 minutes)
$MaxUptimeDays          = 14   # SYS.UPTIME.LONG
$PolicyErrorDays        = 3    # MDM.POLICY.ERRORS (look-back)
$MinPolicyErrors        = 10   # MDM.POLICY.ERRORS (error events in that time)
$MaxDaysSinceOfficeUpdateCheck = 14  # APP.M365.UPDATESTUCK
$MaxPlatformAgeMonths   = 4    # DEF.PLATFORM.OUTDATED
$ServicingWarnDays      = 90   # WU.OSVERSION.EOS
# WU.OSVERSION.EOS: last servicing day per build (Home/Pro and Enterprise/Education).
# Source: https://learn.microsoft.com/windows/release-health/. Add new versions here.
$ServicingEnd = @(
    [pscustomobject]@{ Build = 19045; Name = 'Windows 10 22H2'; Pro = '2025-10-14'; Enterprise = '2025-10-14' },
    [pscustomobject]@{ Build = 22000; Name = 'Windows 11 21H2'; Pro = '2023-10-10'; Enterprise = '2024-10-08' },
    [pscustomobject]@{ Build = 22621; Name = 'Windows 11 22H2'; Pro = '2024-10-08'; Enterprise = '2025-10-14' },
    [pscustomobject]@{ Build = 22631; Name = 'Windows 11 23H2'; Pro = '2025-11-11'; Enterprise = '2026-11-10' },
    [pscustomobject]@{ Build = 26100; Name = 'Windows 11 24H2'; Pro = '2026-10-13'; Enterprise = '2027-10-12' },
    [pscustomobject]@{ Build = 26200; Name = 'Windows 11 25H2'; Pro = '2027-10-12'; Enterprise = '2028-10-10' }
)
$NetworkTimeoutMs       = 4000
$Endpoints = @(
    @{ Host = 'login.microsoftonline.com';           Purpose = 'Entra ID sign-in' },
    @{ Host = 'enterpriseregistration.windows.net';  Purpose = 'Entra ID device registration' },
    @{ Host = 'manage.microsoft.com';                Purpose = 'Intune management' },
    @{ Host = 'fe2.update.microsoft.com';            Purpose = 'Windows Update scan' },
    @{ Host = 'dl.delivery.mp.microsoft.com';        Purpose = 'Windows Update download' },
    @{ Host = 'wdcp.microsoft.com';                  Purpose = 'Defender cloud protection' }
)
#endregion

#region Helpers
$script:Checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    # Status values: pass, fail, warn, info, unknown
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][ValidateSet('pass', 'fail', 'warn', 'info', 'unknown')][string]$Status,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail = '',
        $Evidence = $null
    )
    $script:Checks.Add([pscustomobject][ordered]@{
            id       = $Id
            area     = $Area
            status   = $Status
            title    = $Title
            detail   = $Detail
            evidence = $Evidence
        })
}

function Invoke-Check {
    # Runs one check. An unexpected error becomes an "unknown" result instead of stopping the script.
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][scriptblock]$Script
    )
    try {
        & $Script
    }
    catch {
        Add-Check -Id $Id -Area $Area -Status 'unknown' -Title $Title -Detail ("Check could not run: " + $_.Exception.Message)
    }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function Get-ServiceState {
    # Returns $null when the service does not exist.
    param([string]$Name)
    $svc = $null
    try { $svc = Get-Service -Name $Name -ErrorAction Stop } catch { return $null }
    if (-not $svc) { return $null }
    $startType = 'Unknown'
    try { $startType = [string]$svc.StartType } catch { }
    return [pscustomobject]@{ Name = $Name; Status = [string]$svc.Status; StartType = $startType }
}

function Test-IsElevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-IsSystem {
    try {
        return ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
    }
    catch {
        return $false
    }
}

function Test-TcpPort {
    param([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 4000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected) {
            $client.EndConnect($async)
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Test-WinHttpProxyConfigured {
    # Reads the machine-wide WinHTTP proxy setting. Returns $true, $false or $null (unknown).
    try {
        $bytes = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name 'WinHttpSettings'
        if (-not $bytes -or $bytes.Length -lt 12) { return $false }
        # Byte 8 holds the flags: bit 1 (0x02) is set when a proxy server is configured.
        return (($bytes[8] -band 0x02) -ne 0)
    }
    catch {
        return $null
    }
}

function Get-ShortHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        return (-join ($hash[0..3] | ForEach-Object { $_.ToString('x2') }))
    }
    finally {
        $sha.Dispose()
    }
}

function Get-LatestEventTime {
    # Returns the time of the newest matching event, or $null. Never throws.
    param([string]$LogName, [string]$ProviderName, [int[]]$Id)
    try {
        $filter = @{ LogName = $LogName; Id = $Id }
        if ($ProviderName) { $filter.ProviderName = $ProviderName }
        $entry = Get-WinEvent -FilterHashtable $filter -MaxEvents 1 -ErrorAction Stop
        if ($entry) { return $entry.TimeCreated }
    }
    catch { }
    return $null
}

function Get-NewestDate {
    # Returns the newest valid date from a list that may contain $null values.
    param([object[]]$Dates)
    $newest = $null
    foreach ($d in $Dates) {
        if (-not $d) { continue }
        try { $dt = [datetime]$d } catch { continue }
        if ($dt.Year -lt 2000) { continue }
        if (-not $newest -or $dt -gt $newest) { $newest = $dt }
    }
    return $newest
}

function ConvertTo-DaysAgo {
    param($Date)
    if (-not $Date) { return $null }
    try {
        $d = [datetime]$Date
        if ($d.Year -lt 2000) { return $null }
        return [math]::Round(((Get-Date) - $d).TotalDays, 1)
    }
    catch {
        return $null
    }
}
#endregion

$isElevated = Test-IsElevated
$isSystem   = Test-IsSystem
if ($isSystem) { $IntuneMode = $true }

#region Device information
$device = [ordered]@{
    computerName  = $env:COMPUTERNAME
    userName      = $env:USERNAME
    osCaption     = $null
    osVersion     = $null
    build         = $null
    ubr           = $null
    displayVersion = $null
    manufacturer  = $null
    model         = $null
    lastBoot      = $null
    entraJoined   = $null
    domainJoined  = $null
    tenantId      = $null
    coManaged     = $null
}
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $device.osCaption = $os.Caption
    $device.osVersion = $os.Version
    $device.build     = $os.BuildNumber
    $device.lastBoot  = $os.LastBootUpTime.ToString('o')
}
catch { }
try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $device.manufacturer = $cs.Manufacturer
    $device.model        = $cs.Model
}
catch { }
$ntKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$device.ubr            = Get-RegValue -Path $ntKey -Name 'UBR'
$device.displayVersion = Get-RegValue -Path $ntKey -Name 'DisplayVersion'
#endregion

#region Elevation
if ($isElevated) {
    Add-Check -Id 'SYS.ELEVATION' -Area 'system' -Status 'pass' -Title 'Script runs elevated' -Detail 'All checks can run.'
}
else {
    Add-Check -Id 'SYS.ELEVATION' -Area 'system' -Status 'info' -Title 'Script does not run elevated' `
        -Detail 'Some checks return "unknown". Run as Administrator for complete results.'
}
#endregion

#region Patching: services
Invoke-Check -Id 'WU.SERVICE.DISABLED' -Area 'patching' -Title 'Windows Update services' -Script {
    # wuauserv, BITS and UsoSvc are demand-start services: "Stopped" is normal, "Disabled" is not.
    $names = 'wuauserv', 'BITS', 'CryptSvc', 'UsoSvc', 'TrustedInstaller'
    $problems = @()
    $evidence = @()
    foreach ($name in $names) {
        $state = Get-ServiceState -Name $name
        if (-not $state) {
            $problems += "$name missing"
            $evidence += [pscustomobject]@{ Name = $name; Status = 'Missing'; StartType = 'Missing' }
        }
        else {
            $evidence += $state
            if ($state.StartType -eq 'Disabled') { $problems += "$name disabled" }
        }
    }
    if ($problems.Count -gt 0) {
        Add-Check -Id 'WU.SERVICE.DISABLED' -Area 'patching' -Status 'fail' -Title 'Windows Update service disabled or missing' `
            -Detail ($problems -join ', ') -Evidence $evidence
    }
    else {
        Add-Check -Id 'WU.SERVICE.DISABLED' -Area 'patching' -Status 'pass' -Title 'Windows Update services are available' -Evidence $evidence
    }
}
#endregion

#region Patching: scan and install recency
$script:WuResults = $null
try {
    $autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
    $script:WuResults = $autoUpdate.Results
}
catch { }

Invoke-Check -Id 'WU.SCAN.FAILED' -Area 'patching' -Title 'Windows Update scan' -Script {
    # The update agent's own timestamp is not always refreshed on Windows 10/11, where the
    # Update Orchestrator drives scans. The event log is used as a second source and the newer one wins.
    $agentScan = $null
    if ($script:WuResults) { $agentScan = $script:WuResults.LastSearchSuccessDate }
    $eventScan = Get-LatestEventTime -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' -Id 26
    $lastScanDays = ConvertTo-DaysAgo (Get-NewestDate @($agentScan, $eventScan))

    $searchError = $null
    $pendingCount = $null
    if (-not $SkipUpdateScan) {
        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $searcher.Online = $false   # tests the agent and its database without a network scan
            $result = $searcher.Search('IsInstalled=0 and IsHidden=0')
            $pendingCount = $result.Updates.Count
        }
        catch {
            $searchError = $_.Exception.Message
            if ($_.Exception.HResult) { $searchError = ('0x{0:X8} {1}' -f $_.Exception.HResult, $searchError) }
        }
    }
    $evidence = [ordered]@{ daysSinceLastSuccessfulScan = $lastScanDays; daysSinceAgentScan = (ConvertTo-DaysAgo $agentScan); daysSinceScanEvent = (ConvertTo-DaysAgo $eventScan); pendingUpdatesInCache = $pendingCount; searchError = $searchError }

    if ($searchError) {
        Add-Check -Id 'WU.SCAN.FAILED' -Area 'patching' -Status 'fail' -Title 'Windows Update agent does not respond' -Detail $searchError -Evidence $evidence
    }
    elseif ($null -eq $lastScanDays) {
        Add-Check -Id 'WU.SCAN.FAILED' -Area 'patching' -Status 'unknown' -Title 'Last successful update scan unknown' `
            -Detail 'The update agent did not report a last successful scan.' -Evidence $evidence
    }
    elseif ($lastScanDays -gt $MaxDaysSinceWuScan) {
        Add-Check -Id 'WU.SCAN.FAILED' -Area 'patching' -Status 'fail' -Title 'No successful update scan recently' `
            -Detail ("Last successful scan was {0} days ago (limit {1})." -f $lastScanDays, $MaxDaysSinceWuScan) -Evidence $evidence
    }
    else {
        Add-Check -Id 'WU.SCAN.FAILED' -Area 'patching' -Status 'pass' -Title 'Windows Update scan works' `
            -Detail ("Last successful scan {0} days ago." -f $lastScanDays) -Evidence $evidence
    }
}

Invoke-Check -Id 'WU.PATCHLEVEL.BEHIND' -Area 'patching' -Title 'Quality update recency' -Script {
    # Three sources, newest wins: the update agent, the installed hotfix list and the install-success event.
    $agentInstall = $null
    if ($script:WuResults) { $agentInstall = $script:WuResults.LastInstallationSuccessDate }
    $hotfixInstall = $null
    try {
        $hotfix = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hotfix) { $hotfixInstall = $hotfix.InstalledOn }
    }
    catch { }
    $eventInstall = Get-LatestEventTime -LogName 'System' -ProviderName 'Microsoft-Windows-WindowsUpdateClient' -Id 19
    $days = ConvertTo-DaysAgo (Get-NewestDate @($agentInstall, $hotfixInstall, $eventInstall))
    $source = [ordered]@{
        agent   = ConvertTo-DaysAgo $agentInstall
        hotfix  = ConvertTo-DaysAgo $hotfixInstall
        event19 = ConvertTo-DaysAgo $eventInstall
    }
    $evidence = [ordered]@{ daysSinceLastInstall = $days; daysBySource = $source; build = $device.build; ubr = $device.ubr }
    if ($null -eq $days) {
        Add-Check -Id 'WU.PATCHLEVEL.BEHIND' -Area 'patching' -Status 'unknown' -Title 'Last update installation unknown' -Evidence $evidence
    }
    elseif ($days -gt $MaxDaysSinceWuInstall) {
        Add-Check -Id 'WU.PATCHLEVEL.BEHIND' -Area 'patching' -Status 'fail' -Title 'No update installed recently' `
            -Detail ("Last installation was {0} days ago (limit {1})." -f $days, $MaxDaysSinceWuInstall) -Evidence $evidence
    }
    else {
        Add-Check -Id 'WU.PATCHLEVEL.BEHIND' -Area 'patching' -Status 'pass' -Title 'Updates were installed recently' `
            -Detail ("Last installation {0} days ago." -f $days) -Evidence $evidence
    }
}
#endregion

#region Patching: component store
Invoke-Check -Id 'WU.COMPONENTSTORE.CORRUPT' -Area 'patching' -Title 'Component store health' -Script {
    if ($SkipComponentStore) {
        Add-Check -Id 'WU.COMPONENTSTORE.CORRUPT' -Area 'patching' -Status 'unknown' -Title 'Component store check skipped'
        return
    }
    if (-not $isElevated) {
        Add-Check -Id 'WU.COMPONENTSTORE.CORRUPT' -Area 'patching' -Status 'unknown' -Title 'Component store health not checked' -Detail 'Needs elevation.'
        return
    }
    # -CheckHealth only reads the corruption flag that servicing already recorded. It does not scan or repair.
    $image = Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop
    $state = [string]$image.ImageHealthState
    switch ($state) {
        'Healthy' {
            Add-Check -Id 'WU.COMPONENTSTORE.CORRUPT' -Area 'patching' -Status 'pass' -Title 'Component store is healthy' -Evidence @{ imageHealthState = $state }
        }
        'Repairable' {
            Add-Check -Id 'WU.COMPONENTSTORE.CORRUPT' -Area 'patching' -Status 'fail' -Title 'Component store is corrupt but repairable' -Evidence @{ imageHealthState = $state }
        }
        default {
            Add-Check -Id 'WU.COMPONENTSTORE.CORRUPT' -Area 'patching' -Status 'fail' -Title 'Component store is corrupt and not repairable' `
                -Detail 'An in-place upgrade or reinstall is likely needed.' -Evidence @{ imageHealthState = $state }
        }
    }
}
#endregion

#region Patching: policy conflicts
$ccmExec = Get-ServiceState -Name 'CcmExec'
$device.coManaged = [bool]$ccmExec

Invoke-Check -Id 'WU.POLICY.WSUS_LEFTOVER' -Area 'patching' -Title 'Update policy conflicts' -Script {
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $values = [ordered]@{
        WUServer                                    = Get-RegValue -Path $wu -Name 'WUServer'
        UseWUServer                                 = Get-RegValue -Path $au -Name 'UseWUServer'
        NoAutoUpdate                                = Get-RegValue -Path $au -Name 'NoAutoUpdate'
        DoNotConnectToWindowsUpdateInternetLocations = Get-RegValue -Path $wu -Name 'DoNotConnectToWindowsUpdateInternetLocations'
        DisableWindowsUpdateAccess                  = Get-RegValue -Path $wu -Name 'DisableWindowsUpdateAccess'
        DisableDualScan                             = Get-RegValue -Path $wu -Name 'DisableDualScan'
        configMgrClientPresent                      = [bool]$ccmExec
    }
    $problems = @()
    if ($values.UseWUServer -eq 1) { $problems += 'UseWUServer=1 (device scans against WSUS)' }
    if ($values.WUServer) { $problems += "WUServer is set" }
    if ($values.NoAutoUpdate -eq 1) { $problems += 'NoAutoUpdate=1 (automatic updates off)' }
    if ($values.DoNotConnectToWindowsUpdateInternetLocations -eq 1) { $problems += 'DoNotConnectToWindowsUpdateInternetLocations=1' }
    if ($values.DisableWindowsUpdateAccess -eq 1) { $problems += 'DisableWindowsUpdateAccess=1' }

    if ($problems.Count -eq 0) {
        Add-Check -Id 'WU.POLICY.WSUS_LEFTOVER' -Area 'patching' -Status 'pass' -Title 'No conflicting update policies' -Evidence $values
    }
    elseif ($ccmExec) {
        Add-Check -Id 'WU.POLICY.WSUS_LEFTOVER' -Area 'patching' -Status 'warn' -Title 'WSUS or GPO update policies on a co-managed device' `
            -Detail (($problems -join '; ') + '. A Configuration Manager client is installed: these values are expected if the update workload is still on Configuration Manager. Do not remove them without checking the workload.') -Evidence $values
    }
    else {
        Add-Check -Id 'WU.POLICY.WSUS_LEFTOVER' -Area 'patching' -Status 'fail' -Title 'WSUS or GPO update policies conflict with Intune' `
            -Detail ($problems -join '; ') -Evidence $values
    }
}
#endregion

#region Patching: feature update blockers
Invoke-Check -Id 'WU.FEATUREUPDATE.BLOCKED' -Area 'patching' -Title 'Feature update safeguard holds' -Script {
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators'
    if (-not (Test-Path -LiteralPath $base)) {
        Add-Check -Id 'WU.FEATUREUPDATE.BLOCKED' -Area 'patching' -Status 'info' -Title 'No compatibility appraisal data found' `
            -Detail 'The compatibility appraiser has not written results yet.'
        return
    }
    $holds = @()
    foreach ($key in (Get-ChildItem -LiteralPath $base -ErrorAction Stop)) {
        $gate = Get-RegValue -Path $key.PSPath -Name 'GatedBlockId'
        if ($gate -and $gate -ne 'None') {
            $holds += [pscustomobject]@{ target = $key.PSChildName; gatedBlockId = $gate; reason = (Get-RegValue -Path $key.PSPath -Name 'GatedBlockReason') }
        }
    }
    if ($holds.Count -gt 0) {
        Add-Check -Id 'WU.FEATUREUPDATE.BLOCKED' -Area 'patching' -Status 'warn' -Title 'Feature update blocked by a safeguard hold' `
            -Detail (($holds | ForEach-Object { "$($_.target): $($_.gatedBlockId)" }) -join '; ') -Evidence $holds
    }
    else {
        Add-Check -Id 'WU.FEATUREUPDATE.BLOCKED' -Area 'patching' -Status 'pass' -Title 'No safeguard hold'
    }
}
#endregion

#region Patching: pending reboot
Invoke-Check -Id 'WU.REBOOT.PENDING' -Area 'patching' -Title 'Pending reboot' -Script {
    $reasons = @()
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Component Based Servicing' }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
    if (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations') { $reasons += 'Pending file rename operations' }
    # A pending file rename alone is very common and harmless, so it does not count as a finding.
    $blocking = @($reasons | Where-Object { $_ -ne 'Pending file rename operations' })
    $evidence = @{ reasons = $reasons; lastBoot = $device.lastBoot }
    if ($blocking.Count -gt 0) {
        Add-Check -Id 'WU.REBOOT.PENDING' -Area 'patching' -Status 'fail' -Title 'Restart required to finish updates' -Detail ($reasons -join ', ') -Evidence $evidence
    }
    else {
        Add-Check -Id 'WU.REBOOT.PENDING' -Area 'patching' -Status 'pass' -Title 'No restart pending for updates' -Evidence $evidence
    }
}
#endregion

#region System: disk
Invoke-Check -Id 'SYS.DISK.LOWSPACE' -Area 'patching' -Title 'Free disk space' -Script {
    $drive = $env:SystemDrive
    if (-not $drive) { $drive = 'C:' }
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $drive) -ErrorAction Stop
    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
    $evidence = @{ drive = $drive; freeGB = $freeGB; sizeGB = [math]::Round($disk.Size / 1GB, 1) }
    if ($freeGB -lt $MinFreeSpaceGB) {
        Add-Check -Id 'SYS.DISK.LOWSPACE' -Area 'patching' -Status 'fail' -Title 'Low free disk space' `
            -Detail ("{0} GB free on {1} (minimum {2} GB)." -f $freeGB, $drive, $MinFreeSpaceGB) -Evidence $evidence
    }
    else {
        Add-Check -Id 'SYS.DISK.LOWSPACE' -Area 'patching' -Status 'pass' -Title 'Enough free disk space' -Detail ("{0} GB free on {1}." -f $freeGB, $drive) -Evidence $evidence
    }
}

Invoke-Check -Id 'SYS.STORAGE.HARDWARE' -Area 'patching' -Title 'Physical disk health' -Script {
    $disks = @(Get-PhysicalDisk -ErrorAction Stop | Select-Object FriendlyName, MediaType, HealthStatus, @{ n = 'OperationalStatus'; e = { ($_.OperationalStatus -join ',') } })
    $bad = @($disks | Where-Object { $_.HealthStatus -and $_.HealthStatus -notin @('Healthy', 'Unknown') })
    $evidence = $disks | ForEach-Object { [pscustomobject]@{ name = [string]$_.FriendlyName; mediaType = [string]$_.MediaType; health = [string]$_.HealthStatus; operational = [string]$_.OperationalStatus } }
    if ($bad.Count -gt 0) {
        Add-Check -Id 'SYS.STORAGE.HARDWARE' -Area 'patching' -Status 'fail' -Title 'Physical disk reports a problem' `
            -Detail (($bad | ForEach-Object { "$($_.FriendlyName): $($_.HealthStatus)" }) -join '; ') -Evidence $evidence
    }
    else {
        Add-Check -Id 'SYS.STORAGE.HARDWARE' -Area 'patching' -Status 'pass' -Title 'Physical disks are healthy' -Evidence $evidence
    }
}
#endregion

#region Patching: diagnostic data
Invoke-Check -Id 'WU.TELEMETRY.BLOCKED' -Area 'patching' -Title 'Diagnostic data' -Script {
    $gpo = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry'
    $mdm = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System' -Name 'AllowTelemetry'
    $diagTrack = Get-ServiceState -Name 'DiagTrack'
    $evidence = [ordered]@{ allowTelemetryGpo = $gpo; allowTelemetryMdm = $mdm; diagTrack = $diagTrack }
    $problems = @()
    if ($null -ne $gpo -and [int]$gpo -eq 0) { $problems += 'Group Policy sets AllowTelemetry=0' }
    if ($null -ne $mdm -and [int]$mdm -eq 0) { $problems += 'MDM policy sets AllowTelemetry=0' }
    if (-not $diagTrack) { $problems += 'DiagTrack service missing' }
    elseif ($diagTrack.StartType -eq 'Disabled') { $problems += 'DiagTrack service disabled' }
    if ($problems.Count -gt 0) {
        Add-Check -Id 'WU.TELEMETRY.BLOCKED' -Area 'patching' -Status 'warn' -Title 'Diagnostic data is blocked' `
            -Detail (($problems -join '; ') + '. Autopatch and Windows Update reports need at least "Required" diagnostic data.') -Evidence $evidence
    }
    else {
        Add-Check -Id 'WU.TELEMETRY.BLOCKED' -Area 'patching' -Status 'pass' -Title 'Diagnostic data is not blocked' -Evidence $evidence
    }
}
#endregion

#region Network
Invoke-Check -Id 'NET.ENDPOINT.UNREACHABLE' -Area 'network' -Title 'Microsoft endpoints' -Script {
    if ($SkipNetwork) {
        Add-Check -Id 'NET.ENDPOINT.UNREACHABLE' -Area 'network' -Status 'unknown' -Title 'Endpoint test skipped'
        return
    }
    $proxy = Test-WinHttpProxyConfigured
    $results = @()
    foreach ($endpoint in $Endpoints) {
        $dns = $true
        try { [void][System.Net.Dns]::GetHostAddresses($endpoint.Host) } catch { $dns = $false }
        $tcp = $false
        if ($dns) { $tcp = Test-TcpPort -HostName $endpoint.Host -Port 443 -TimeoutMs $NetworkTimeoutMs }
        $results += [pscustomobject]@{ host = $endpoint.Host; purpose = $endpoint.Purpose; dns = $dns; tcp443 = $tcp }
    }
    $failed = @($results | Where-Object { -not $_.tcp443 })
    $evidence = [ordered]@{ winHttpProxyConfigured = $proxy; endpoints = $results }
    if ($failed.Count -eq 0) {
        Add-Check -Id 'NET.ENDPOINT.UNREACHABLE' -Area 'network' -Status 'pass' -Title 'Microsoft endpoints are reachable' -Evidence $evidence
    }
    elseif ($proxy) {
        # A direct TCP test says nothing when traffic has to go through a proxy.
        Add-Check -Id 'NET.ENDPOINT.UNREACHABLE' -Area 'network' -Status 'unknown' -Title 'Direct connection failed, but a proxy is configured' `
            -Detail (('No direct TCP 443 connection to: ' + (($failed | ForEach-Object { $_.host }) -join ', ')) + '. A WinHTTP proxy is configured, so this may be expected.') -Evidence $evidence
    }
    else {
        Add-Check -Id 'NET.ENDPOINT.UNREACHABLE' -Area 'network' -Status 'fail' -Title 'Microsoft endpoints are not reachable' `
            -Detail ('No TCP 443 connection to: ' + (($failed | ForEach-Object { $_.host }) -join ', ')) -Evidence $evidence
    }
}
#endregion

#region Identity: Entra ID join and PRT
$script:Dsreg = @{}
try {
    $dsregExe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
    foreach ($line in (& $dsregExe /status 2>$null)) {
        if ($line -match '^\s*([A-Za-z][A-Za-z0-9 ]*?)\s*:\s*(.+?)\s*$') {
            $script:Dsreg[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
}
catch { }
if ($script:Dsreg.Count -gt 0) {
    $device.entraJoined  = ($script:Dsreg['AzureAdJoined'] -eq 'YES')
    $device.domainJoined = ($script:Dsreg['DomainJoined'] -eq 'YES')
    $device.tenantId     = $script:Dsreg['TenantId']
}

Invoke-Check -Id 'AAD.PRT.MISSING' -Area 'identity' -Title 'Entra ID join and Primary Refresh Token' -Script {
    if ($script:Dsreg.Count -eq 0) {
        Add-Check -Id 'AAD.PRT.MISSING' -Area 'identity' -Status 'unknown' -Title 'Entra ID join state unknown' -Detail 'dsregcmd /status returned no data.'
        return
    }
    $evidence = [ordered]@{
        azureAdJoined = $script:Dsreg['AzureAdJoined']
        domainJoined  = $script:Dsreg['DomainJoined']
        azureAdPrt    = $script:Dsreg['AzureAdPrt']
        deviceAuthStatus = $script:Dsreg['DeviceAuthStatus']
        tpmProtected  = $script:Dsreg['TpmProtected']
    }
    if ($script:Dsreg['AzureAdJoined'] -ne 'YES') {
        Add-Check -Id 'AAD.PRT.MISSING' -Area 'identity' -Status 'fail' -Title 'Device is not joined to Entra ID' -Evidence $evidence
    }
    elseif ($script:Dsreg['DeviceAuthStatus'] -and $script:Dsreg['DeviceAuthStatus'] -ne 'SUCCESS') {
        Add-Check -Id 'AAD.PRT.MISSING' -Area 'identity' -Status 'fail' -Title 'Device authentication against Entra ID fails' `
            -Detail ("DeviceAuthStatus: " + $script:Dsreg['DeviceAuthStatus']) -Evidence $evidence
    }
    elseif ($isSystem -or -not $script:Dsreg.ContainsKey('AzureAdPrt')) {
        Add-Check -Id 'AAD.PRT.MISSING' -Area 'identity' -Status 'info' -Title 'Device is Entra joined; token not checked' `
            -Detail 'The Primary Refresh Token can only be checked in the context of the signed-in user.' -Evidence $evidence
    }
    elseif ($script:Dsreg['AzureAdPrt'] -ne 'YES') {
        Add-Check -Id 'AAD.PRT.MISSING' -Area 'identity' -Status 'fail' -Title 'No Primary Refresh Token for the signed-in user' -Evidence $evidence
    }
    else {
        Add-Check -Id 'AAD.PRT.MISSING' -Area 'identity' -Status 'pass' -Title 'Device is Entra joined and has a Primary Refresh Token' -Evidence $evidence
    }
}
#endregion

#region Identity: hybrid join
Invoke-Check -Id 'AAD.HYBRIDJOIN.PENDING' -Area 'identity' -Title 'Hybrid Entra join' -Script {
    if ($script:Dsreg.Count -eq 0) {
        Add-Check -Id 'AAD.HYBRIDJOIN.PENDING' -Area 'identity' -Status 'unknown' -Title 'Hybrid join state unknown' -Detail 'dsregcmd /status returned no data.'
        return
    }
    if ($script:Dsreg['DomainJoined'] -ne 'YES') {
        Add-Check -Id 'AAD.HYBRIDJOIN.PENDING' -Area 'identity' -Status 'info' -Title 'Not domain joined: hybrid join does not apply'
        return
    }
    if ($script:Dsreg['AzureAdJoined'] -eq 'YES') {
        Add-Check -Id 'AAD.HYBRIDJOIN.PENDING' -Area 'identity' -Status 'pass' -Title 'Device is hybrid Entra joined'
        return
    }

    # Is hybrid join configured? Client-side SCP in the registry, else the SCP object in Active Directory.
    $scpTenant = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD' -Name 'TenantId'
    $scpSource = $null
    $scpError  = $null
    if ($scpTenant) {
        $scpSource = 'registry (client-side SCP)'
    }
    else {
        try {
            $rootDse = [ADSI]'LDAP://RootDSE'
            $configNc = [string]$rootDse.Properties['configurationNamingContext'].Value
            $scp = [ADSI]("LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services," + $configNc)
            foreach ($keyword in @($scp.Properties['keywords'])) {
                if ([string]$keyword -like 'azureADId:*') { $scpTenant = ([string]$keyword).Substring(10); $scpSource = 'Active Directory' }
            }
        }
        catch {
            $scpError = $_.Exception.Message
        }
    }

    $task = $null
    $taskInfo = $null
    try {
        $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Workplace Join\' -TaskName 'Automatic-Device-Join' -ErrorAction Stop
        $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    }
    catch { }
    $taskResult = $null
    if ($taskInfo) { $taskResult = ('0x{0:X8}' -f [uint32]$taskInfo.LastTaskResult) }

    $evidence = [ordered]@{
        scpFound           = [bool]$scpTenant
        scpSource          = $scpSource
        scpLookupError     = $scpError
        joinTaskState      = $(if ($task) { [string]$task.State } else { 'missing' })
        joinTaskLastResult = $taskResult
        joinTaskLastRun    = $(if ($taskInfo -and $taskInfo.LastRunTime -and $taskInfo.LastRunTime.Year -gt 2000) { $taskInfo.LastRunTime.ToString('o') } else { $null })
        errorPhase         = $script:Dsreg['Error Phase']
        clientErrorCode    = $script:Dsreg['Client ErrorCode']
        serverErrorCode    = $script:Dsreg['Server ErrorCode']
        serverMessage      = $script:Dsreg['Server Message']
    }

    if (-not $scpTenant -and -not $scpError) {
        Add-Check -Id 'AAD.HYBRIDJOIN.PENDING' -Area 'identity' -Status 'info' -Title 'Domain joined without hybrid join configuration' `
            -Detail 'No service connection point (SCP) for Entra hybrid join found. Ignore this if the device is not meant to be hybrid joined.' -Evidence $evidence
    }
    elseif (-not $scpTenant) {
        Add-Check -Id 'AAD.HYBRIDJOIN.PENDING' -Area 'identity' -Status 'warn' -Title 'Domain joined but not hybrid joined' `
            -Detail ('The SCP could not be read from Active Directory: ' + $scpError) -Evidence $evidence
    }
    else {
        $reason = @()
        if (-not $task) { $reason += 'the Automatic-Device-Join task is missing' }
        elseif ([string]$task.State -eq 'Disabled') { $reason += 'the Automatic-Device-Join task is disabled' }
        if ($evidence.clientErrorCode -or $evidence.serverErrorCode) { $reason += ('last attempt: client error {0}, server error {1}' -f $evidence.clientErrorCode, $evidence.serverErrorCode) }
        elseif ($taskResult -and $taskResult -ne '0x00000000') { $reason += ('join task result ' + $taskResult) }
        if ($reason.Count -eq 0) { $reason += 'the computer object may not be synced to Entra ID yet' }
        Add-Check -Id 'AAD.HYBRIDJOIN.PENDING' -Area 'identity' -Status 'fail' -Title 'Hybrid Entra join has not completed' `
            -Detail (($reason -join '; ') + '.') -Evidence $evidence
    }
}
#endregion

#region Identity: Entra joined and registered (dual state)
Invoke-Check -Id 'AAD.DUALSTATE' -Area 'identity' -Title 'Entra joined and registered' -Script {
    if ($script:Dsreg.Count -eq 0 -or $script:Dsreg['AzureAdJoined'] -ne 'YES') {
        Add-Check -Id 'AAD.DUALSTATE' -Area 'identity' -Status 'info' -Title 'Dual state not checked: device is not Entra joined'
        return
    }
    if ($isSystem -or -not $script:Dsreg.ContainsKey('WorkplaceJoined')) {
        Add-Check -Id 'AAD.DUALSTATE' -Area 'identity' -Status 'info' -Title 'Dual state not checked' `
            -Detail 'Entra registration is per user and can only be checked in the context of the signed-in user.'
        return
    }
    $evidence = [ordered]@{ azureAdJoined = $script:Dsreg['AzureAdJoined']; domainJoined = $script:Dsreg['DomainJoined']; workplaceJoined = $script:Dsreg['WorkplaceJoined'] }
    if ($script:Dsreg['WorkplaceJoined'] -eq 'YES') {
        Add-Check -Id 'AAD.DUALSTATE' -Area 'identity' -Status 'warn' -Title 'Device is Entra joined and also Entra registered' `
            -Detail 'A work account was added as "Entra registered" on top of the join. This can break Conditional Access, SSO and Intune enrollment.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'AAD.DUALSTATE' -Area 'identity' -Status 'pass' -Title 'No additional Entra registration' -Evidence $evidence
    }
}
#endregion

#region Identity: clock
function Get-ServerTimeUtc {
    # Reads the Date header of an HTTPS response. Returns $null when there is no answer.
    param([string]$Url, [int]$TimeoutMs = 8000)
    $response = $null
    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = 'HEAD'
        $request.Timeout = $TimeoutMs
        $request.AllowAutoRedirect = $false
        try { $response = $request.GetResponse() }
        catch [System.Net.WebException] { $response = $_.Exception.Response }
        if (-not $response) { return $null }
        $header = $response.Headers['Date']
        if (-not $header) { return $null }
        $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
        return [datetime]::Parse($header, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
    }
    catch {
        return $null
    }
    finally {
        if ($response) { $response.Close() }
    }
}

Invoke-Check -Id 'SYS.TIME.SKEW' -Area 'identity' -Title 'System clock' -Script {
    $w32 = Get-ServiceState -Name 'W32Time'
    $skew = $null
    if (-not $SkipNetwork) {
        $serverUtc = Get-ServerTimeUtc -Url 'https://login.microsoftonline.com/'
        if ($serverUtc) { $skew = [math]::Round(([datetime]::UtcNow - $serverUtc).TotalSeconds, 0) }
    }
    $evidence = [ordered]@{ skewSeconds = $skew; w32time = $w32; reference = 'Date header of login.microsoftonline.com' }
    if ($null -ne $skew -and [math]::Abs($skew) -gt $MaxClockSkewSeconds) {
        Add-Check -Id 'SYS.TIME.SKEW' -Area 'identity' -Status 'fail' -Title 'System clock is wrong' `
            -Detail ("The clock is {0} seconds off. Kerberos, Entra sign-in and certificates fail above 5 minutes." -f $skew) -Evidence $evidence
    }
    elseif (-not $w32 -or $w32.StartType -eq 'Disabled') {
        Add-Check -Id 'SYS.TIME.SKEW' -Area 'identity' -Status 'warn' -Title 'Windows Time service is disabled or missing' `
            -Detail 'The clock is not kept in sync and will drift.' -Evidence $evidence
    }
    elseif ($null -eq $skew) {
        Add-Check -Id 'SYS.TIME.SKEW' -Area 'identity' -Status 'unknown' -Title 'Clock offset not measured' `
            -Detail 'No answer from login.microsoftonline.com (or -SkipNetwork was used).' -Evidence $evidence
    }
    else {
        Add-Check -Id 'SYS.TIME.SKEW' -Area 'identity' -Status 'pass' -Title 'System clock is in sync' `
            -Detail ("Offset {0} seconds." -f $skew) -Evidence $evidence
    }
}
#endregion

#region Intune: enrollment
# Common auto-enrollment error codes (event 76 in the DeviceManagement-Enterprise-Diagnostics-Provider/Admin log).
$EnrollmentErrorHints = @{
    '0x80180018' = 'The user has no Intune license, or it is not active yet.'
    '0x8018002B' = 'The UPN uses an unverified or non-routable domain, or the user is outside the MDM user scope.'
    '0x80180014' = 'Blocked by an enrollment restriction (platform or personal devices).'
    '0x8018000A' = 'The device is already enrolled (another user or leftover enrollment entries).'
    '0x80192EE7' = 'Name resolution failed: check DNS and proxy (see NET.ENDPOINT.UNREACHABLE).'
    '0x80072EE7' = 'Name resolution failed: check DNS and proxy (see NET.ENDPOINT.UNREACHABLE).'
    '0x80192EE2' = 'Connection timed out: check proxy and firewall (see NET.ENDPOINT.UNREACHABLE).'
    '0x80072EE2' = 'Connection timed out: check proxy and firewall (see NET.ENDPOINT.UNREACHABLE).'
}

function Add-EnrollmentMissingCheck {
    # Called when no Intune enrollment exists: works out why auto-enrollment did not happen.
    $mdmUrl = $null
    if ($script:Dsreg.Count -gt 0) { $mdmUrl = $script:Dsreg['MdmUrl'] }
    $autoEnrollGpo = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -Name 'AutoEnrollMDM'
    $autoEnrollTask = $null
    try {
        $autoEnrollTask = Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\' -ErrorAction Stop |
            Where-Object { $_.TaskName -like '*automatically enrolling in MDM*' } | Select-Object -First 1
    }
    catch { }

    $lastError = $null
    $lastErrorTime = $null
    try {
        $entry = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'; Id = 76; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 1 -ErrorAction Stop
        if ($entry) {
            $lastErrorTime = $entry.TimeCreated.ToString('o')
            if ($entry.Message -match '0x[0-9A-Fa-f]{8}') { $lastError = '0x' + $Matches[0].Substring(2).ToUpper() }
        }
    }
    catch { }
    $hint = $null
    if ($lastError -and $EnrollmentErrorHints.ContainsKey($lastError)) { $hint = $EnrollmentErrorHints[$lastError] }

    $entraJoined = ($script:Dsreg.Count -gt 0 -and $script:Dsreg['AzureAdJoined'] -eq 'YES')
    $domainJoined = ($script:Dsreg.Count -gt 0 -and $script:Dsreg['DomainJoined'] -eq 'YES')
    $evidence = [ordered]@{
        entraJoined         = $entraJoined
        domainJoined        = $domainJoined
        mdmUrl              = $mdmUrl
        autoEnrollGpo       = $autoEnrollGpo
        autoEnrollTaskFound = [bool]$autoEnrollTask
        lastEnrollError     = $lastError
        lastEnrollErrorTime = $lastErrorTime
        hint                = $hint
    }

    if (-not $entraJoined) {
        $cause = 'The device is not Entra joined, so automatic enrollment cannot start. Fix the join first (AAD.PRT.MISSING or AAD.HYBRIDJOIN.PENDING).'
    }
    elseif (-not $mdmUrl) {
        $cause = 'The Entra join has no MDM URL: the user is outside the MDM user scope, or automatic Intune enrollment is not configured in Entra ID.'
    }
    elseif ($domainJoined -and $autoEnrollGpo -ne 1) {
        $cause = 'Hybrid joined, but the GPO "Enable automatic MDM enrollment using default Azure AD credentials" is not applied.'
    }
    elseif ($lastError) {
        $cause = 'Last automatic enrollment attempt failed with ' + $lastError + '.'
        if ($hint) { $cause += ' ' + $hint }
    }
    else {
        $cause = 'No failed enrollment attempt logged in the last 30 days. Automatic enrollment may not have been triggered yet.'
    }
    Add-Check -Id 'MDM.ENROLLMENT.MISSING' -Area 'intune' -Status 'fail' -Title 'Device is not enrolled in Intune' -Detail $cause -Evidence $evidence
}

$script:MdmEnrollmentIds = @()
Invoke-Check -Id 'MDM.ENROLLMENT.BROKEN' -Area 'intune' -Title 'MDM enrollment' -Script {
    $enrollments = @()
    $base = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (Test-Path -LiteralPath $base) {
        foreach ($key in (Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $provider = Get-RegValue -Path $key.PSPath -Name 'ProviderID'
            if ($provider -eq 'MS DM Server') {
                $enrollments += [pscustomobject]@{
                    id              = $key.PSChildName
                    enrollmentState = Get-RegValue -Path $key.PSPath -Name 'EnrollmentState'
                    enrollmentType  = Get-RegValue -Path $key.PSPath -Name 'EnrollmentType'
                }
            }
        }
    }
    $script:MdmEnrollmentIds = @($enrollments | ForEach-Object { $_.id })

    $cert = $null
    $certDaysLeft = $null
    try {
        $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop |
            Where-Object { $_.Issuer -like '*Microsoft Intune MDM Device CA*' } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
        if ($cert) { $certDaysLeft = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0) }
    }
    catch { }

    $evidence = [ordered]@{
        enrollmentCount  = $enrollments.Count
        enrollments      = @($enrollments | ForEach-Object { [pscustomobject]@{ enrollmentState = $_.enrollmentState; enrollmentType = $_.enrollmentType } })
        mdmCertFound     = [bool]$cert
        mdmCertDaysLeft  = $certDaysLeft
    }

    if ($enrollments.Count -eq 0) {
        Add-EnrollmentMissingCheck
        Add-Check -Id 'MDM.ENROLLMENT.BROKEN' -Area 'intune' -Status 'info' -Title 'Enrollment health not checked: device is not enrolled (see MDM.ENROLLMENT.MISSING)'
    }
    elseif (-not $cert) {
        Add-Check -Id 'MDM.ENROLLMENT.BROKEN' -Area 'intune' -Status 'fail' -Title 'Intune MDM device certificate is missing' -Evidence $evidence
    }
    elseif ($certDaysLeft -lt 0) {
        Add-Check -Id 'MDM.ENROLLMENT.BROKEN' -Area 'intune' -Status 'fail' -Title 'Intune MDM device certificate has expired' `
            -Detail ("Expired {0} days ago." -f [math]::Abs($certDaysLeft)) -Evidence $evidence
    }
    elseif ($enrollments.Count -gt 1) {
        Add-Check -Id 'MDM.ENROLLMENT.BROKEN' -Area 'intune' -Status 'warn' -Title 'More than one Intune enrollment found' `
            -Detail 'Orphaned enrollment entries can block policy sync.' -Evidence $evidence
    }
    elseif ($certDaysLeft -lt $MdmCertWarnDays) {
        Add-Check -Id 'MDM.ENROLLMENT.BROKEN' -Area 'intune' -Status 'warn' -Title 'Intune MDM device certificate expires soon' `
            -Detail ("{0} days left. It normally renews automatically." -f $certDaysLeft) -Evidence $evidence
    }
    else {
        Add-Check -Id 'MDM.ENROLLMENT.BROKEN' -Area 'intune' -Status 'pass' -Title 'Device is enrolled in Intune' -Evidence $evidence
    }
}
#endregion

#region Intune: sync
Invoke-Check -Id 'MDM.SYNC.STALE' -Area 'intune' -Title 'Intune sync' -Script {
    if ($script:MdmEnrollmentIds.Count -eq 0) {
        Add-Check -Id 'MDM.SYNC.STALE' -Area 'intune' -Status 'unknown' -Title 'Intune sync not checked' -Detail 'No Intune enrollment found.'
        return
    }
    $tasks = @()
    foreach ($id in $script:MdmEnrollmentIds) {
        $tasks += @(Get-ScheduledTask -TaskPath ("\Microsoft\Windows\EnterpriseMgmt\{0}\" -f $id) -ErrorAction SilentlyContinue)
    }
    $push = Get-ServiceState -Name 'dmwappushservice'
    if ($tasks.Count -eq 0) {
        Add-Check -Id 'MDM.SYNC.STALE' -Area 'intune' -Status 'fail' -Title 'Intune sync tasks are missing' `
            -Detail 'No scheduled tasks under \Microsoft\Windows\EnterpriseMgmt for this enrollment.' -Evidence @{ taskCount = 0; dmwappushservice = $push }
        return
    }
    $disabled = @($tasks | Where-Object { [string]$_.State -eq 'Disabled' })
    $lastRun = $null
    foreach ($task in $tasks) {
        $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 2000) {
            if (-not $lastRun -or $info.LastRunTime -gt $lastRun) { $lastRun = $info.LastRunTime }
        }
    }
    $days = ConvertTo-DaysAgo $lastRun
    $evidence = [ordered]@{ taskCount = $tasks.Count; disabledTasks = $disabled.Count; daysSinceLastSyncTaskRun = $days; dmwappushservice = $push }
    if ($null -eq $days) {
        Add-Check -Id 'MDM.SYNC.STALE' -Area 'intune' -Status 'fail' -Title 'Intune sync tasks have never run' -Evidence $evidence
    }
    elseif ($days -gt $MaxDaysSinceMdmSync) {
        Add-Check -Id 'MDM.SYNC.STALE' -Area 'intune' -Status 'fail' -Title 'No Intune sync recently' `
            -Detail ("Last sync task run was {0} days ago (limit {1})." -f $days, $MaxDaysSinceMdmSync) -Evidence $evidence
    }
    elseif ($push -and $push.StartType -eq 'Disabled') {
        Add-Check -Id 'MDM.SYNC.STALE' -Area 'intune' -Status 'warn' -Title 'dmwappushservice is disabled' `
            -Detail 'Sync on demand from the Intune portal will not reach the device.' -Evidence $evidence
    }
    elseif ($disabled.Count -eq $tasks.Count) {
        Add-Check -Id 'MDM.SYNC.STALE' -Area 'intune' -Status 'fail' -Title 'All Intune sync tasks are disabled' -Evidence $evidence
    }
    else {
        Add-Check -Id 'MDM.SYNC.STALE' -Area 'intune' -Status 'pass' -Title 'Intune sync runs' `
            -Detail ("Last sync task run {0} days ago." -f $days) -Evidence $evidence
    }
}
#endregion

#region Intune: management extension
Invoke-Check -Id 'MDM.IME.NOTRUNNING' -Area 'intune' -Title 'Intune Management Extension' -Script {
    $ime = Get-ServiceState -Name 'IntuneManagementExtension'
    if (-not $ime) {
        # The agent is only installed once a script, remediation or Win32 app is assigned.
        Add-Check -Id 'MDM.IME.NOTRUNNING' -Area 'intune' -Status 'warn' -Title 'Intune Management Extension is not installed' `
            -Detail 'It is installed automatically when a script, remediation or Win32 app is assigned. Without it none of these run.'
    }
    elseif ($ime.StartType -eq 'Disabled' -or $ime.Status -ne 'Running') {
        Add-Check -Id 'MDM.IME.NOTRUNNING' -Area 'intune' -Status 'fail' -Title 'Intune Management Extension is not running' `
            -Detail ("Status {0}, start type {1}." -f $ime.Status, $ime.StartType) -Evidence $ime
    }
    else {
        Add-Check -Id 'MDM.IME.NOTRUNNING' -Area 'intune' -Status 'pass' -Title 'Intune Management Extension is running' -Evidence $ime
    }
}
#endregion

#region Intune: Company Portal
Invoke-Check -Id 'CP.APP.MISSING' -Area 'intune' -Title 'Company Portal app' -Script {
    $packages = $null
    if ($isElevated) { $packages = @(Get-AppxPackage -AllUsers -Name 'Microsoft.CompanyPortal' -ErrorAction Stop) }
    else { $packages = @(Get-AppxPackage -Name 'Microsoft.CompanyPortal' -ErrorAction Stop) }
    $pkg = $packages | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $pkg) {
        Add-Check -Id 'CP.APP.MISSING' -Area 'intune' -Status 'warn' -Title 'Company Portal is not installed' `
            -Detail 'Users cannot install available apps or check compliance without it.'
        Add-Check -Id 'CP.APP.BROKEN' -Area 'intune' -Status 'info' -Title 'Company Portal state not checked: app not installed'
        return
    }
    $evidence = [ordered]@{ version = [string]$pkg.Version; status = [string]$pkg.Status; allUsers = $isElevated }
    Add-Check -Id 'CP.APP.MISSING' -Area 'intune' -Status 'pass' -Title 'Company Portal is installed' -Detail ('Version ' + $pkg.Version) -Evidence $evidence
    if ([string]$pkg.Status -ne 'Ok') {
        Add-Check -Id 'CP.APP.BROKEN' -Area 'intune' -Status 'fail' -Title 'Company Portal app package is damaged' `
            -Detail ('Package status: ' + $pkg.Status) -Evidence $evidence
    }
    else {
        Add-Check -Id 'CP.APP.BROKEN' -Area 'intune' -Status 'pass' -Title 'Company Portal app package is OK' -Evidence $evidence
    }
}
#endregion

#region BitLocker and TPM
$script:Bl = $null
$script:BlError = $null
if (-not $isElevated) {
    $script:BlError = 'Needs elevation.'
}
else {
    try { $script:Bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop }
    catch { $script:BlError = $_.Exception.Message }
}
# Event Viewer shows this channel as BitLocker-API > Management. Resolve the name on the device
# so a different channel name on some builds does not silently hide the events.
$BitLockerLog = 'Microsoft-Windows-BitLocker/BitLocker Management'
try {
    $found = @(Get-WinEvent -ListLog 'Microsoft-Windows-BitLocker*' -ErrorAction Stop | Where-Object { $_.LogName -like '*Management' })
    if ($found.Count -gt 0) { $BitLockerLog = $found[0].LogName }
}
catch { }

function Get-RecoveryKeyBackupTimes {
    # Newest backup success (845) for one of the given recovery password protector IDs, and newest
    # backup failure (846) for the OS drive. Events of other volumes or removed protectors are ignored.
    param([string[]]$ProtectorIds)
    $result = @{ ok = $null; fail = $null }
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = $BitLockerLog; Id = 845, 846 } -MaxEvents 200 -ErrorAction Stop) } catch { }
    foreach ($entry in $events) {
        $message = [string]$entry.Message
        if ($entry.Id -eq 845 -and -not $result.ok) {
            foreach ($id in $ProtectorIds) { if ($id -and $message -like ('*' + $id.Trim('{}') + '*')) { $result.ok = $entry.TimeCreated } }
        }
        elseif ($entry.Id -eq 846 -and -not $result.fail -and $message -like ('*' + $env:SystemDrive + '*')) {
            $result.fail = $entry.TimeCreated
        }
    }
    return $result
}

function Get-BitLockerProtectorTypes {
    # The comma keeps an empty or one-element array an array when it is returned.
    if (-not $script:Bl) { return , @() }
    return , @($script:Bl.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
}

Invoke-Check -Id 'BL.OSVOLUME.NOTENCRYPTED' -Area 'bitlocker' -Title 'BitLocker on the OS drive' -Script {
    if (-not $script:Bl) {
        Add-Check -Id 'BL.OSVOLUME.NOTENCRYPTED' -Area 'bitlocker' -Status 'unknown' -Title 'BitLocker state unknown' -Detail $script:BlError
        return
    }
    $policy = (Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker' -Name 'RequireDeviceEncryption') -eq 1 -or
              (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE')
    $lastError = $null
    try {
        $entry = Get-WinEvent -FilterHashtable @{ LogName = $BitLockerLog; Level = 2; StartTime = (Get-Date).AddDays(-14) } -MaxEvents 1 -ErrorAction Stop
        if ($entry) {
            $message = [string]$entry.Message
            if ($message.Length -gt 300) { $message = $message.Substring(0, 300) + '...' }
            $lastError = [ordered]@{ id = $entry.Id; time = $entry.TimeCreated.ToString('o'); message = $message }
        }
    }
    catch { }
    $status = [string]$script:Bl.VolumeStatus
    $protectors = Get-BitLockerProtectorTypes
    $evidence = [ordered]@{
        mountPoint           = $env:SystemDrive
        volumeStatus         = $status
        protectionStatus     = [string]$script:Bl.ProtectionStatus
        encryptionPercentage = $script:Bl.EncryptionPercentage
        encryptionMethod     = [string]$script:Bl.EncryptionMethod
        keyProtectors        = $protectors
        policyAssigned       = $policy
        lastBitLockerError   = $lastError
    }
    $errorText = ''
    if ($lastError) { $errorText = (' Last BitLocker error (event {0}): {1}' -f $lastError.id, $lastError.message) }
    if ($status -eq 'EncryptionInProgress') {
        Add-Check -Id 'BL.OSVOLUME.NOTENCRYPTED' -Area 'bitlocker' -Status 'info' -Title 'OS drive encryption in progress' `
            -Detail ('{0}% encrypted.' -f $script:Bl.EncryptionPercentage) -Evidence $evidence
    }
    elseif ($status -ne 'FullyEncrypted') {
        $detail = 'Volume status: ' + $status + '.'
        if (-not $policy) { $detail += ' No BitLocker policy found on the device.' }
        Add-Check -Id 'BL.OSVOLUME.NOTENCRYPTED' -Area 'bitlocker' -Status 'fail' -Title 'OS drive is not encrypted' -Detail ($detail + $errorText) -Evidence $evidence
    }
    elseif ($protectors.Count -eq 0) {
        Add-Check -Id 'BL.OSVOLUME.NOTENCRYPTED' -Area 'bitlocker' -Status 'fail' -Title 'OS drive is encrypted but not protected' `
            -Detail ('BitLocker waits for activation: no key protector exists, so the key is stored in the clear.' + $errorText) -Evidence $evidence
    }
    else {
        Add-Check -Id 'BL.OSVOLUME.NOTENCRYPTED' -Area 'bitlocker' -Status 'pass' -Title 'OS drive is encrypted' -Evidence $evidence
    }
}

Invoke-Check -Id 'BL.PROTECTION.SUSPENDED' -Area 'bitlocker' -Title 'BitLocker protection' -Script {
    if (-not $script:Bl) {
        Add-Check -Id 'BL.PROTECTION.SUSPENDED' -Area 'bitlocker' -Status 'unknown' -Title 'BitLocker protection state unknown' -Detail $script:BlError
        return
    }
    $protectors = Get-BitLockerProtectorTypes
    if ([string]$script:Bl.VolumeStatus -ne 'FullyEncrypted' -or $protectors.Count -eq 0) {
        Add-Check -Id 'BL.PROTECTION.SUSPENDED' -Area 'bitlocker' -Status 'info' -Title 'Not checked: OS drive is not protected yet (see BL.OSVOLUME.NOTENCRYPTED)'
        return
    }
    if ([string]$script:Bl.ProtectionStatus -eq 'On') {
        Add-Check -Id 'BL.PROTECTION.SUSPENDED' -Area 'bitlocker' -Status 'pass' -Title 'BitLocker protection is on'
        return
    }
    $suspendCount = $null
    try {
        $volume = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName 'Win32_EncryptableVolume' `
            -Filter ("DriveLetter='{0}'" -f $env:SystemDrive) -ErrorAction Stop
        $suspendCount = (Invoke-CimMethod -InputObject $volume -MethodName 'GetSuspendCount' -ErrorAction Stop).SuspendCount
    }
    catch { }
    $evidence = [ordered]@{ protectionStatus = [string]$script:Bl.ProtectionStatus; suspendCount = $suspendCount; keyProtectors = $protectors }
    if ($suspendCount -gt 0) {
        Add-Check -Id 'BL.PROTECTION.SUSPENDED' -Area 'bitlocker' -Status 'warn' -Title 'BitLocker protection is paused' `
            -Detail ("It resumes by itself after {0} more restart(s), typically after a firmware or BIOS update." -f $suspendCount) -Evidence $evidence
    }
    else {
        Add-Check -Id 'BL.PROTECTION.SUSPENDED' -Area 'bitlocker' -Status 'fail' -Title 'BitLocker protection is suspended' `
            -Detail 'The drive is encrypted, but the key is stored in the clear until protection is resumed.' -Evidence $evidence
    }
}

Invoke-Check -Id 'BL.RECOVERYKEY.NOTESCROWED' -Area 'bitlocker' -Title 'BitLocker recovery key backup' -Script {
    if (-not $script:Bl) {
        Add-Check -Id 'BL.RECOVERYKEY.NOTESCROWED' -Area 'bitlocker' -Status 'unknown' -Title 'Recovery key state unknown' -Detail $script:BlError
        return
    }
    $protectors = Get-BitLockerProtectorTypes
    if ([string]$script:Bl.VolumeStatus -eq 'FullyDecrypted') {
        Add-Check -Id 'BL.RECOVERYKEY.NOTESCROWED' -Area 'bitlocker' -Status 'info' -Title 'Not checked: OS drive is not encrypted'
        return
    }
    if ($device.entraJoined -ne $true) {
        Add-Check -Id 'BL.RECOVERYKEY.NOTESCROWED' -Area 'bitlocker' -Status 'info' -Title 'Not checked: device is not Entra joined' `
            -Detail 'Key backup to Active Directory is not checked.'
        return
    }
    $recoveryIds = @($script:Bl.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq 'RecoveryPassword' } | ForEach-Object { [string]$_.KeyProtectorId })
    $backup = Get-RecoveryKeyBackupTimes -ProtectorIds $recoveryIds
    $lastOk = $backup.ok
    $lastFail = $backup.fail
    $recoveryCount = $recoveryIds.Count
    $evidence = [ordered]@{
        recoveryPasswordProtectors = $recoveryCount
        lastBackupSuccess = $(if ($lastOk) { $lastOk.ToString('o') } else { $null })
        lastBackupFailure = $(if ($lastFail) { $lastFail.ToString('o') } else { $null })
    }
    if ($recoveryCount -eq 0) {
        Add-Check -Id 'BL.RECOVERYKEY.NOTESCROWED' -Area 'bitlocker' -Status 'fail' -Title 'No BitLocker recovery password exists' `
            -Detail 'Without a recovery password there is no key to back up, and a locked device cannot be recovered.' -Evidence $evidence
    }
    elseif ($lastFail -and (-not $lastOk -or $lastFail -gt $lastOk)) {
        Add-Check -Id 'BL.RECOVERYKEY.NOTESCROWED' -Area 'bitlocker' -Status 'fail' -Title 'Recovery key backup to Entra ID failed' `
            -Detail 'The newest backup event is a failure (event 846).' -Evidence $evidence
    }
    elseif (-not $lastOk) {
        Add-Check -Id 'BL.RECOVERYKEY.NOTESCROWED' -Area 'bitlocker' -Status 'warn' -Title 'Recovery key backup to Entra ID not confirmed' `
            -Detail 'No success event 845 for the current recovery password in the BitLocker Management log (the log may have rolled over). Check the key in the Intune admin center.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'BL.RECOVERYKEY.NOTESCROWED' -Area 'bitlocker' -Status 'pass' -Title 'Recovery key is backed up to Entra ID' -Evidence $evidence
    }
}

Invoke-Check -Id 'BL.WINRE.DISABLED' -Area 'bitlocker' -Title 'Windows Recovery Environment' -Script {
    if (-not $isElevated) {
        Add-Check -Id 'BL.WINRE.DISABLED' -Area 'bitlocker' -Status 'unknown' -Title 'WinRE state not checked' -Detail 'Needs elevation.'
        return
    }
    # reagentc /info shows the WinRE location as \\?\GLOBALROOT\device\... only while WinRE is enabled.
    # That path is language independent; the labels around it are localized.
    $reagentOk = $false
    $location = $null
    $output = & (Join-Path $env:SystemRoot 'System32\reagentc.exe') /info 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        $reagentOk = $true
        if ($output -match '(\\\\\?\\GLOBALROOT\\device\\\S+)') { $location = $Matches[1] }
    }
    $state = $null
    if (-not $reagentOk) {
        # Fallback only: ReAgent.xml InstallState is 1 while enabled.
        try {
            [xml]$xml = Get-Content -LiteralPath (Join-Path $env:SystemRoot 'System32\Recovery\ReAgent.xml') -Raw -ErrorAction Stop
            $state = [string]$xml.WindowsRE.InstallState.state
        }
        catch { }
    }
    $evidence = [ordered]@{ source = $(if ($reagentOk) { 'reagentc /info' } else { 'ReAgent.xml' }); winreLocation = $location; installState = $state }
    if ($location -or $state -eq '1') {
        Add-Check -Id 'BL.WINRE.DISABLED' -Area 'bitlocker' -Status 'pass' -Title 'WinRE is enabled' -Evidence $evidence
    }
    elseif ($reagentOk) {
        Add-Check -Id 'BL.WINRE.DISABLED' -Area 'bitlocker' -Status 'fail' -Title 'WinRE is disabled' `
            -Detail 'Silent BitLocker encryption, Autopilot reset and remote wipe need the Windows Recovery Environment.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'BL.WINRE.DISABLED' -Area 'bitlocker' -Status 'unknown' -Title 'WinRE state could not be read' `
            -Detail 'reagentc /info failed. Run it by hand to see the state.' -Evidence $evidence
    }
}

Invoke-Check -Id 'BL.TPM.NOTREADY' -Area 'bitlocker' -Title 'TPM' -Script {
    if (-not $isElevated) {
        Add-Check -Id 'BL.TPM.NOTREADY' -Area 'bitlocker' -Status 'unknown' -Title 'TPM state not checked' -Detail 'Needs elevation.'
        return
    }
    $tpm = Get-Tpm -ErrorAction Stop
    $spec = $null
    try { $spec = [string](Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName 'Win32_Tpm' -ErrorAction Stop).SpecVersion } catch { }
    $evidence = [ordered]@{
        present      = $tpm.TpmPresent
        ready        = $tpm.TpmReady
        enabled      = $tpm.TpmEnabled
        activated    = $tpm.TpmActivated
        manufacturer = $tpm.ManufacturerIdTxt
        firmware     = $tpm.ManufacturerVersion
        specVersion  = $spec
    }
    if (-not $tpm.TpmPresent) {
        Add-Check -Id 'BL.TPM.NOTREADY' -Area 'bitlocker' -Status 'fail' -Title 'No TPM found' `
            -Detail 'The TPM is missing or disabled in the firmware (BIOS/UEFI).' -Evidence $evidence
    }
    elseif (-not $tpm.TpmReady) {
        Add-Check -Id 'BL.TPM.NOTREADY' -Area 'bitlocker' -Status 'fail' -Title 'TPM is not ready' `
            -Detail 'BitLocker, Windows Hello and the Entra device key cannot use it.' -Evidence $evidence
    }
    elseif ($spec -and $spec -notlike '2.0*') {
        Add-Check -Id 'BL.TPM.NOTREADY' -Area 'bitlocker' -Status 'warn' -Title 'TPM 1.2 only' `
            -Detail 'Windows 11 and Autopilot pre-provisioning need TPM 2.0.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'BL.TPM.NOTREADY' -Area 'bitlocker' -Status 'pass' -Title 'TPM is ready' -Evidence $evidence
    }
}
#endregion

#region Drivers
$PnpProblemText = @{
    1 = 'not configured correctly'; 3 = 'driver may be corrupt'; 10 = 'cannot start'; 12 = 'not enough free resources'
    14 = 'restart required'; 18 = 'drivers must be reinstalled'; 19 = 'registry configuration damaged'
    24 = 'not present or not working'; 28 = 'no driver installed'; 31 = 'not working properly'; 32 = 'driver disabled'
    37 = 'driver failed to initialize'; 39 = 'driver missing or corrupt'; 41 = 'driver loaded but device not found'
    43 = 'device reported a problem'; 48 = 'driver blocked'; 52 = 'driver signature cannot be verified'
}
Invoke-Check -Id 'DRV.DEVICE.ERROR' -Area 'drivers' -Title 'Device drivers' -Script {
    # 22 = disabled on purpose, 45 = device not connected: not driver problems.
    $bad = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -ErrorAction Stop |
        Where-Object { $_.ConfigManagerErrorCode -notin @(22, 45) })
    $devices = @($bad | Select-Object -First 15 | ForEach-Object {
            $code = [int]$_.ConfigManagerErrorCode
            [pscustomobject][ordered]@{
                name       = $_.Name
                class      = $_.PNPClass
                errorCode  = $code
                problem    = $(if ($PnpProblemText.ContainsKey($code)) { $PnpProblemText[$code] } else { 'see Device Manager' })
                hardwareId = $(if ($_.HardwareID) { @($_.HardwareID)[0] } else { $null })
            }
        })
    $evidence = [ordered]@{ problemDeviceCount = $bad.Count; devices = $devices }
    if ($bad.Count -gt 0) {
        $names = ($devices | Select-Object -First 3 | ForEach-Object { '{0} (code {1})' -f $_.name, $_.errorCode }) -join ', '
        Add-Check -Id 'DRV.DEVICE.ERROR' -Area 'drivers' -Status 'fail' -Title 'Devices with driver problems' `
            -Detail ("{0} device(s): {1}" -f $bad.Count, $names) -Evidence $evidence
    }
    else {
        Add-Check -Id 'DRV.DEVICE.ERROR' -Area 'drivers' -Status 'pass' -Title 'No devices with driver problems' -Evidence $evidence
    }
}

Invoke-Check -Id 'DRV.WU.EXCLUDED' -Area 'drivers' -Title 'Driver updates from Windows Update' -Script {
    $gpoKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $values = [ordered]@{
        excludeDriversGpo   = Get-RegValue -Path $gpoKey -Name 'ExcludeWUDriversInQualityUpdate'
        excludeDriversMdm   = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -Name 'ExcludeWUDriversInQualityUpdate'
        driverSourceIsWsus  = Get-RegValue -Path $gpoKey -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
        wuServer            = Get-RegValue -Path $gpoKey -Name 'WUServer'
    }
    if ($values.excludeDriversGpo -eq 1 -or $values.excludeDriversMdm -eq 1) {
        Add-Check -Id 'DRV.WU.EXCLUDED' -Area 'drivers' -Status 'warn' -Title 'Driver updates from Windows Update are blocked by policy' `
            -Detail 'Fine if drivers come from another source (OEM tool, ConfigMgr). Otherwise drivers never update.' -Evidence $values
    }
    elseif ($values.driverSourceIsWsus -eq 1 -and $values.wuServer) {
        Add-Check -Id 'DRV.WU.EXCLUDED' -Area 'drivers' -Status 'warn' -Title 'Driver updates come from WSUS' `
            -Detail 'Drivers are only offered when WSUS approves them.' -Evidence $values
    }
    else {
        Add-Check -Id 'DRV.WU.EXCLUDED' -Area 'drivers' -Status 'pass' -Title 'Driver updates from Windows Update are allowed' -Evidence $values
    }
}
#endregion

#region Defender
$script:Mp = $null
$script:MpError = $null
try {
    $script:Mp = Get-MpComputerStatus -ErrorAction Stop
}
catch {
    $script:MpError = $_.Exception.Message
}

Invoke-Check -Id 'DEF.SERVICE.STOPPED' -Area 'defender' -Title 'Defender antivirus service' -Script {
    $winDefend = Get-ServiceState -Name 'WinDefend'
    $evidence = [ordered]@{ winDefend = $winDefend; amRunningMode = $null; amServiceEnabled = $null; error = $script:MpError }
    if ($script:Mp) {
        $evidence.amRunningMode = [string]$script:Mp.AMRunningMode
        $evidence.amServiceEnabled = $script:Mp.AMServiceEnabled
    }
    if (-not $winDefend) {
        Add-Check -Id 'DEF.SERVICE.STOPPED' -Area 'defender' -Status 'fail' -Title 'Defender antivirus service is missing' -Evidence $evidence
    }
    elseif ($winDefend.Status -ne 'Running') {
        Add-Check -Id 'DEF.SERVICE.STOPPED' -Area 'defender' -Status 'fail' -Title 'Defender antivirus service is not running' `
            -Detail ("Status {0}, start type {1}. This is expected only if another antivirus product is installed." -f $winDefend.Status, $winDefend.StartType) -Evidence $evidence
    }
    elseif (-not $script:Mp) {
        Add-Check -Id 'DEF.SERVICE.STOPPED' -Area 'defender' -Status 'unknown' -Title 'Defender status could not be read' -Detail $script:MpError -Evidence $evidence
    }
    elseif ($evidence.amRunningMode -and $evidence.amRunningMode -notin @('Normal', 'EDR Block Mode')) {
        Add-Check -Id 'DEF.SERVICE.STOPPED' -Area 'defender' -Status 'warn' -Title 'Defender antivirus is not the active antivirus' `
            -Detail ("Running mode: {0}. This is expected only if another antivirus product is installed." -f $evidence.amRunningMode) -Evidence $evidence
    }
    else {
        Add-Check -Id 'DEF.SERVICE.STOPPED' -Area 'defender' -Status 'pass' -Title 'Defender antivirus is running' -Evidence $evidence
    }
}

Invoke-Check -Id 'DEF.SIGNATURE.OUTDATED' -Area 'defender' -Title 'Defender signatures' -Script {
    if (-not $script:Mp) {
        Add-Check -Id 'DEF.SIGNATURE.OUTDATED' -Area 'defender' -Status 'unknown' -Title 'Defender signature age unknown' -Detail $script:MpError
        return
    }
    $age = [int]$script:Mp.AntivirusSignatureAge
    $evidence = [ordered]@{
        signatureAgeDays = $age
        signatureVersion = [string]$script:Mp.AntivirusSignatureVersion
        engineVersion    = [string]$script:Mp.AMEngineVersion
        platformVersion  = [string]$script:Mp.AMProductVersion
    }
    if ($age -gt $MaxSignatureAgeDays) {
        Add-Check -Id 'DEF.SIGNATURE.OUTDATED' -Area 'defender' -Status 'fail' -Title 'Defender signatures are outdated' `
            -Detail ("Signatures are {0} days old (limit {1})." -f $age, $MaxSignatureAgeDays) -Evidence $evidence
    }
    else {
        Add-Check -Id 'DEF.SIGNATURE.OUTDATED' -Area 'defender' -Status 'pass' -Title 'Defender signatures are current' -Evidence $evidence
    }
}

Invoke-Check -Id 'DEF.RTP.DISABLED' -Area 'defender' -Title 'Defender protection features' -Script {
    if (-not $script:Mp) {
        Add-Check -Id 'DEF.RTP.DISABLED' -Area 'defender' -Status 'unknown' -Title 'Defender protection state unknown' -Detail $script:MpError
        return
    }
    $evidence = [ordered]@{
        realTimeProtection = $script:Mp.RealTimeProtectionEnabled
        tamperProtection   = $script:Mp.IsTamperProtected
        behaviorMonitor    = $script:Mp.BehaviorMonitorEnabled
        antivirusEnabled   = $script:Mp.AntivirusEnabled
        runningMode        = [string]$script:Mp.AMRunningMode
    }
    $passive = ($evidence.runningMode -and $evidence.runningMode -notin @('Normal', 'EDR Block Mode'))
    if (-not $script:Mp.RealTimeProtectionEnabled -and -not $passive) {
        Add-Check -Id 'DEF.RTP.DISABLED' -Area 'defender' -Status 'fail' -Title 'Real-time protection is off' -Evidence $evidence
    }
    elseif ($passive) {
        Add-Check -Id 'DEF.RTP.DISABLED' -Area 'defender' -Status 'info' -Title 'Defender is in passive mode' `
            -Detail 'Real-time protection is provided by another antivirus product.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'DEF.RTP.DISABLED' -Area 'defender' -Status 'pass' -Title 'Real-time protection is on' -Evidence $evidence
    }
}

Invoke-Check -Id 'DEF.TAMPER.OFF' -Area 'defender' -Title 'Defender tamper protection' -Script {
    if (-not $script:Mp) {
        Add-Check -Id 'DEF.TAMPER.OFF' -Area 'defender' -Status 'unknown' -Title 'Tamper protection state unknown' -Detail $script:MpError
        return
    }
    $mode = [string]$script:Mp.AMRunningMode
    $evidence = [ordered]@{ tamperProtection = $script:Mp.IsTamperProtected; runningMode = $mode }
    if ($mode -and $mode -notin @('Normal', 'EDR Block Mode')) {
        Add-Check -Id 'DEF.TAMPER.OFF' -Area 'defender' -Status 'info' -Title 'Tamper protection not checked: Defender is in passive mode' -Evidence $evidence
    }
    elseif (-not $script:Mp.IsTamperProtected) {
        Add-Check -Id 'DEF.TAMPER.OFF' -Area 'defender' -Status 'warn' -Title 'Tamper protection is off' `
            -Detail 'Tamper protection can only be turned on by an Intune or Defender portal policy, not by a script on the device.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'DEF.TAMPER.OFF' -Area 'defender' -Status 'pass' -Title 'Tamper protection is on' -Evidence $evidence
    }
}

Invoke-Check -Id 'DEF.MDE.NOTONBOARDED' -Area 'defender' -Title 'Defender for Endpoint onboarding' -Script {
    $state = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OnboardingState'
    $sense = Get-ServiceState -Name 'Sense'
    $evidence = [ordered]@{ onboardingState = $state; sense = $sense }
    if ($state -eq 1 -and $sense -and $sense.Status -eq 'Running') {
        Add-Check -Id 'DEF.MDE.NOTONBOARDED' -Area 'defender' -Status 'pass' -Title 'Device is onboarded to Defender for Endpoint' -Evidence $evidence
    }
    elseif ($state -eq 1) {
        Add-Check -Id 'DEF.MDE.NOTONBOARDED' -Area 'defender' -Status 'fail' -Title 'Defender for Endpoint sensor is not running' `
            -Detail 'The device is onboarded, but the Sense service is not running.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'DEF.MDE.NOTONBOARDED' -Area 'defender' -Status 'warn' -Title 'Device is not onboarded to Defender for Endpoint' `
            -Detail 'Ignore this if your organisation does not use Defender for Endpoint.' -Evidence $evidence
    }
}
#endregion

#region Patching: uptime, pause, Delivery Optimization, end of servicing
Invoke-Check -Id 'SYS.UPTIME.LONG' -Area 'patching' -Title 'Uptime' -Script {
    $boot = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    $days = [math]::Round(((Get-Date) - $boot).TotalDays, 1)
    $fastStartup = (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled') -eq 1
    $evidence = [ordered]@{ uptimeDays = $days; fastStartupEnabled = $fastStartup }
    if ($days -gt $MaxUptimeDays) {
        Add-Check -Id 'SYS.UPTIME.LONG' -Area 'patching' -Status 'warn' -Title 'No real restart for a long time' `
            -Detail ("Uptime {0} days (limit {1}). With Fast Startup, 'Shut down' does not restart the kernel, so updates and policies that wait for a restart are not finished." -f $days, $MaxUptimeDays) -Evidence $evidence
    }
    else {
        Add-Check -Id 'SYS.UPTIME.LONG' -Area 'patching' -Status 'pass' -Title 'Device was restarted recently' -Detail ("Uptime {0} days." -f $days) -Evidence $evidence
    }
}

Invoke-Check -Id 'WU.UPDATES.PAUSED' -Area 'patching' -Title 'Update pause' -Script {
    $ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $pauseEnd = $null
    foreach ($name in 'PauseUpdatesExpiryTime', 'PauseQualityUpdatesEndTime', 'PauseFeatureUpdatesEndTime') {
        $value = [string](Get-RegValue -Path $ux -Name $name)
        if (-not $value) { continue }
        try { $date = [datetime]::Parse($value, [System.Globalization.CultureInfo]::InvariantCulture, $styles) } catch { continue }
        if ($date -gt [datetime]::UtcNow -and (-not $pauseEnd -or $date -gt $pauseEnd)) { $pauseEnd = $date }
    }
    $mdm = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    $gpo = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $policyPause = ((Get-RegValue -Path $mdm -Name 'PauseQualityUpdates') -eq 1) -or ((Get-RegValue -Path $mdm -Name 'PauseFeatureUpdates') -eq 1) -or
                   [bool][string](Get-RegValue -Path $gpo -Name 'PauseQualityUpdatesStartTime') -or [bool][string](Get-RegValue -Path $gpo -Name 'PauseFeatureUpdatesStartTime')
    $evidence = [ordered]@{ localPauseUntilUtc = $null; pausedByPolicy = $policyPause }
    if ($pauseEnd) { $evidence.localPauseUntilUtc = $pauseEnd.ToString('o') }
    if ($pauseEnd) {
        Add-Check -Id 'WU.UPDATES.PAUSED' -Area 'patching' -Status 'fail' -Title 'Updates are paused on the device' `
            -Detail ("Paused in Settings until {0} UTC." -f $pauseEnd.ToString('yyyy-MM-dd HH:mm')) -Evidence $evidence
    }
    elseif ($policyPause) {
        Add-Check -Id 'WU.UPDATES.PAUSED' -Area 'patching' -Status 'info' -Title 'Updates are paused by policy' `
            -Detail 'An update ring or Group Policy pauses updates. That is deliberate; resume it in the policy.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'WU.UPDATES.PAUSED' -Area 'patching' -Status 'pass' -Title 'Updates are not paused' -Evidence $evidence
    }
}

Invoke-Check -Id 'WU.DO.BROKEN' -Area 'patching' -Title 'Delivery Optimization' -Script {
    $start = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc' -Name 'Start'
    $mode = $null
    foreach ($path in 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization') {
        $value = Get-RegValue -Path $path -Name 'DODownloadMode'
        if ($null -ne $value -and $null -eq $mode) { $mode = [int]$value }
    }
    $evidence = [ordered]@{ doSvcStart = $start; downloadModePolicy = $mode }
    $isWin11 = $false
    try { $isWin11 = ([int]$device.build -ge 22000) } catch { }
    if ($null -eq $start) {
        Add-Check -Id 'WU.DO.BROKEN' -Area 'patching' -Status 'fail' -Title 'Delivery Optimization service is missing' -Evidence $evidence
    }
    elseif ($start -eq 4) {
        Add-Check -Id 'WU.DO.BROKEN' -Area 'patching' -Status 'fail' -Title 'Delivery Optimization service is disabled' `
            -Detail 'Windows Update, Store and Intune app downloads go through this service.' -Evidence $evidence
    }
    elseif ($mode -eq 100 -and $isWin11) {
        Add-Check -Id 'WU.DO.BROKEN' -Area 'patching' -Status 'warn' -Title 'Delivery Optimization download mode 100 (Bypass) is set' `
            -Detail 'Bypass is deprecated on Windows 11. Set the policy to 0 (HTTP only) or 1 (LAN).' -Evidence $evidence
    }
    else {
        Add-Check -Id 'WU.DO.BROKEN' -Area 'patching' -Status 'pass' -Title 'Delivery Optimization service is enabled' -Evidence $evidence
    }
}

Invoke-Check -Id 'WU.OSVERSION.EOS' -Area 'patching' -Title 'Windows version servicing' -Script {
    $edition = [string](Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID')
    $build = 0
    try { $build = [int]$device.build } catch { }
    $evidence = [ordered]@{ build = $build; displayVersion = $device.displayVersion; edition = $edition; endOfServicing = $null; daysLeft = $null }
    if ($edition -match 'EnterpriseS') {
        Add-Check -Id 'WU.OSVERSION.EOS' -Area 'patching' -Status 'info' -Title 'LTSC edition: servicing end not checked' -Evidence $evidence
        return
    }
    $entry = $ServicingEnd | Where-Object { $_.Build -eq $build } | Select-Object -First 1
    if (-not $entry) {
        Add-Check -Id 'WU.OSVERSION.EOS' -Area 'patching' -Status 'info' -Title 'Servicing end of this Windows build is not in the script table' `
            -Detail ("Build {0}. Check https://learn.microsoft.com/windows/release-health/." -f $build) -Evidence $evidence
        return
    }
    $endText = if ($edition -match 'Enterprise|Education') { $entry.Enterprise } else { $entry.Pro }
    $end = [datetime]::ParseExact($endText, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $daysLeft = [int][math]::Floor(($end - (Get-Date).Date).TotalDays)
    $evidence.endOfServicing = $endText
    $evidence.daysLeft = $daysLeft
    if ($daysLeft -lt 0) {
        Add-Check -Id 'WU.OSVERSION.EOS' -Area 'patching' -Status 'fail' -Title 'This Windows version is out of servicing' `
            -Detail ("{0} ({1}) got its last security update on {2}. Install a current feature update." -f $entry.Name, $edition, $endText) -Evidence $evidence
    }
    elseif ($daysLeft -le $ServicingWarnDays) {
        Add-Check -Id 'WU.OSVERSION.EOS' -Area 'patching' -Status 'warn' -Title 'This Windows version reaches end of servicing soon' `
            -Detail ("{0} ({1}) is serviced until {2} ({3} days left)." -f $entry.Name, $edition, $endText, $daysLeft) -Evidence $evidence
    }
    else {
        Add-Check -Id 'WU.OSVERSION.EOS' -Area 'patching' -Status 'pass' -Title 'This Windows version is in servicing' `
            -Detail ("{0} is serviced until {1}." -f $entry.Name, $endText) -Evidence $evidence
    }
}
#endregion

#region Intune: app installations and policy errors
Invoke-Check -Id 'MDM.APP.INSTALLFAILED' -Area 'intune' -Title 'Intune app installations' -Script {
    $root = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
    if (-not (Test-Path -LiteralPath $root)) {
        Add-Check -Id 'MDM.APP.INSTALLFAILED' -Area 'intune' -Status 'info' -Title 'No Win32 app state on this device'
        return
    }
    # Each app has an EnforcementStateMessage (JSON). EnforcementState 5000-5999 means the installation failed.
    $failed = @{}
    $total = @{}
    foreach ($key in @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue)) {
        $raw = $key.GetValue('EnforcementStateMessage')
        if (-not ($raw -is [string]) -or -not $raw) { continue }
        if ($key.Name -notmatch '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})_\d+') { continue }
        $appId = $Matches[1].ToLower()
        $state = $null
        try { $state = $raw | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        $enforcement = 0
        $errorCode = 0
        foreach ($property in $state.PSObject.Properties) {
            if ($property.Name -eq 'EnforcementState') { try { $enforcement = [int]$property.Value } catch { } }
            if ($property.Name -eq 'ErrorCode' -and $null -ne $property.Value) { try { $errorCode = [int64]$property.Value } catch { } }
        }
        $total[$appId] = $true
        if ($enforcement -ge 5000 -and $enforcement -le 5999) {
            $failed[$appId] = [ordered]@{ appId = $appId; enforcementState = $enforcement; errorCode = ('0x{0:X8}' -f ($errorCode -band 0xFFFFFFFFL)) }
        }
    }
    $evidence = [ordered]@{ appsWithState = $total.Count; failedApps = @($failed.Values | Select-Object -First 10) }
    if ($failed.Count -gt 0) {
        Add-Check -Id 'MDM.APP.INSTALLFAILED' -Area 'intune' -Status 'warn' -Title 'Intune app installations failed' `
            -Detail ("{0} of {1} Win32 apps are in a failed state. Look up the app IDs in Intune (Apps > All apps, the ID is in the URL) and check AppWorkload.log." -f $failed.Count, $total.Count) -Evidence $evidence
    }
    else {
        Add-Check -Id 'MDM.APP.INSTALLFAILED' -Area 'intune' -Status 'pass' -Title 'No failed Win32 app installations' -Evidence $evidence
    }
}

Invoke-Check -Id 'MDM.POLICY.ERRORS' -Area 'intune' -Title 'MDM policy errors' -Script {
    if ($script:MdmEnrollmentIds.Count -eq 0) {
        Add-Check -Id 'MDM.POLICY.ERRORS' -Area 'intune' -Status 'info' -Title 'MDM policy errors not checked: device is not enrolled'
        return
    }
    $log = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 2; StartTime = (Get-Date).AddDays(-$PolicyErrorDays) } -MaxEvents 500 -ErrorAction Stop) }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found' -and $_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw }
    }
    $top = @($events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { [ordered]@{ eventId = [int]$_.Name; count = $_.Count } })
    $sample = $null
    if ($events.Count -gt 0) {
        $sample = ([string]$events[0].Message -replace '\s+', ' ').Trim()
        if ($sample.Length -gt 300) { $sample = $sample.Substring(0, 300) + '...' }
    }
    $evidence = [ordered]@{ days = $PolicyErrorDays; errorCount = $events.Count; topEventIds = $top; newestMessage = $sample }
    if ($events.Count -ge $MinPolicyErrors) {
        Add-Check -Id 'MDM.POLICY.ERRORS' -Area 'intune' -Status 'warn' -Title 'MDM policies fail to apply' `
            -Detail ("{0} error events in the last {1} days in the MDM diagnostics log. Newest: {2}" -f $events.Count, $PolicyErrorDays, $sample) -Evidence $evidence
    }
    else {
        Add-Check -Id 'MDM.POLICY.ERRORS' -Area 'intune' -Status 'pass' -Title 'No unusual number of MDM policy errors' -Evidence $evidence
    }
}
#endregion

#region Identity: Windows Hello for Business
Invoke-Check -Id 'AAD.WHFB.NOTPROVISIONED' -Area 'identity' -Title 'Windows Hello for Business' -Script {
    $policy = ((Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'Enabled') -eq 1) -or ($script:Dsreg['PolicyEnabled'] -eq 'YES')
    if (-not $policy -and $device.tenantId) {
        $policy = (Get-RegValue -Path ("HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\{0}\Device\Policies" -f $device.tenantId) -Name 'UsePassportForWork') -eq 1
    }
    $evidence = [ordered]@{
        policyEnabled = $policy
        ngcSet        = $script:Dsreg['NgcSet']
        preReqResult  = $script:Dsreg['PreReqResult']
        deviceEligible = $script:Dsreg['DeviceEligible']
    }
    if ($isSystem -or -not $script:Dsreg.ContainsKey('NgcSet')) {
        Add-Check -Id 'AAD.WHFB.NOTPROVISIONED' -Area 'identity' -Status 'info' -Title 'Windows Hello for Business not checked' `
            -Detail 'It can only be checked in the context of the signed-in user.' -Evidence $evidence
    }
    elseif ($script:Dsreg['NgcSet'] -eq 'YES') {
        Add-Check -Id 'AAD.WHFB.NOTPROVISIONED' -Area 'identity' -Status 'pass' -Title 'Windows Hello for Business is set up for this user' -Evidence $evidence
    }
    elseif ($policy) {
        Add-Check -Id 'AAD.WHFB.NOTPROVISIONED' -Area 'identity' -Status 'warn' -Title 'Windows Hello for Business is enabled by policy but not set up' `
            -Detail ("Prerequisite check result: {0}." -f $(if ($script:Dsreg['PreReqResult']) { $script:Dsreg['PreReqResult'] } else { 'not reported' })) -Evidence $evidence
    }
    else {
        Add-Check -Id 'AAD.WHFB.NOTPROVISIONED' -Area 'identity' -Status 'info' -Title 'Windows Hello for Business is not enabled by policy' -Evidence $evidence
    }
}
#endregion

#region Security: Secure Boot certificates, LAPS, firewall
Invoke-Check -Id 'SEC.SECUREBOOT.CERT2023' -Area 'security' -Title 'Secure Boot certificates' -Script {
    if (-not $isElevated) {
        Add-Check -Id 'SEC.SECUREBOOT.CERT2023' -Area 'security' -Status 'unknown' -Title 'Secure Boot certificates not checked' -Detail 'Needs elevation.'
        return
    }
    $secureBoot = $false
    try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = $false }
    if (-not $secureBoot) {
        Add-Check -Id 'SEC.SECUREBOOT.CERT2023' -Area 'security' -Status 'info' -Title 'Secure Boot is off or not supported: certificates not checked'
        return
    }
    $servicing = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
    $status = [string](Get-RegValue -Path $servicing -Name 'UEFICA2023Status')
    $errorCode = Get-RegValue -Path $servicing -Name 'UEFICA2023Error'
    $firmware = @{ db = $null; KEK = $null }
    foreach ($pair in @(@('db', 'Windows UEFI CA 2023'), @('KEK', 'Microsoft Corporation KEK 2K CA 2023'))) {
        try {
            $bytes = (Get-SecureBootUEFI -Name $pair[0] -ErrorAction Stop).Bytes
            $firmware[$pair[0]] = ([System.Text.Encoding]::ASCII.GetString($bytes) -match [regex]::Escape($pair[1]))
        }
        catch { }
    }
    $evidence = [ordered]@{
        uefiCa2023Status = $status
        uefiCa2023Error  = $(if ($errorCode) { '0x{0:X8}' -f ([int64]$errorCode -band 0xFFFFFFFFL) } else { $null })
        dbHasWindowsUefiCa2023 = $firmware.db
        kekHasKek2kCa2023      = $firmware.KEK
        availableUpdates = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates'
    }
    if ($status -eq 'Updated' -or (-not $status -and $firmware.db -eq $true -and $firmware.KEK -eq $true)) {
        Add-Check -Id 'SEC.SECUREBOOT.CERT2023' -Area 'security' -Status 'pass' -Title 'The 2023 Secure Boot certificates are installed' -Evidence $evidence
    }
    elseif ($status -eq 'InProgress' -and -not $errorCode) {
        Add-Check -Id 'SEC.SECUREBOOT.CERT2023' -Area 'security' -Status 'warn' -Title 'Secure Boot certificate update is in progress' `
            -Detail 'Windows is installing the 2023 certificates. Restart the device (it can need two restarts).' -Evidence $evidence
    }
    else {
        Add-Check -Id 'SEC.SECUREBOOT.CERT2023' -Area 'security' -Status 'fail' -Title 'The 2023 Secure Boot certificates are not installed' `
            -Detail 'The Microsoft Secure Boot certificates from 2011 expired in 2026. Without the 2023 certificates the device gets no new Secure Boot protections and no new boot manager.' -Evidence $evidence
    }
}

Invoke-Check -Id 'SEC.LAPS.BACKUPFAILED' -Area 'security' -Title 'Windows LAPS' -Script {
    $directory = $null
    foreach ($path in 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config') {
        $value = Get-RegValue -Path $path -Name 'BackupDirectory'
        if ($null -ne $value -and $null -eq $directory) { $directory = [int]$value }
    }
    if (-not $directory) {
        Add-Check -Id 'SEC.LAPS.BACKUPFAILED' -Area 'security' -Status 'info' -Title 'No Windows LAPS policy on this device'
        return
    }
    $target = if ($directory -eq 1) { 'Entra ID' } else { 'Active Directory' }
    $last = $null
    try { $last = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-LAPS/Operational'; Id = 10004, 10005 } -MaxEvents 1 -ErrorAction Stop } catch { }
    $evidence = [ordered]@{ backupDirectory = $target; lastResultEventId = $null; lastResultTime = $null }
    if ($last) { $evidence.lastResultEventId = $last.Id; $evidence.lastResultTime = $last.TimeCreated.ToString('o') }
    if ($last -and $last.Id -eq 10005) {
        $message = ([string]$last.Message -replace '\s+', ' ').Trim()
        if ($message.Length -gt 300) { $message = $message.Substring(0, 300) + '...' }
        Add-Check -Id 'SEC.LAPS.BACKUPFAILED' -Area 'security' -Status 'fail' -Title 'Windows LAPS policy processing fails' `
            -Detail ("Backup to {0} failed: {1}" -f $target, $message) -Evidence $evidence
    }
    elseif ($last) {
        Add-Check -Id 'SEC.LAPS.BACKUPFAILED' -Area 'security' -Status 'pass' -Title 'Windows LAPS policy processing works' -Detail ("Backup directory: {0}." -f $target) -Evidence $evidence
    }
    else {
        Add-Check -Id 'SEC.LAPS.BACKUPFAILED' -Area 'security' -Status 'unknown' -Title 'Windows LAPS policy is set, but there is no processing result yet' -Evidence $evidence
    }
}

Invoke-Check -Id 'SEC.FIREWALL.OFF' -Area 'security' -Title 'Windows Firewall' -Script {
    $thirdParty = ''
    try { $thirdParty = ((@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'FirewallProduct' -ErrorAction Stop) | ForEach-Object { [string]$_.displayName }) -join ', ') } catch { }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $off = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { [string]$_.Name })
    $evidence = [ordered]@{ profilesOff = $off; thirdPartyFirewall = $thirdParty }
    if ($thirdParty) {
        Add-Check -Id 'SEC.FIREWALL.OFF' -Area 'security' -Status 'info' -Title 'Another firewall product is registered' -Detail $thirdParty -Evidence $evidence
    }
    elseif ($off.Count -gt 0) {
        Add-Check -Id 'SEC.FIREWALL.OFF' -Area 'security' -Status 'fail' -Title 'Windows Firewall profile is off' -Detail ('Off: ' + ($off -join ', ')) -Evidence $evidence
    }
    else {
        Add-Check -Id 'SEC.FIREWALL.OFF' -Area 'security' -Status 'pass' -Title 'All Windows Firewall profiles are on' -Evidence $evidence
    }
}
#endregion

#region Identity: Windows activation
Invoke-Check -Id 'SYS.LICENSE.NOTACTIVATED' -Area 'identity' -Title 'Windows activation' -Script {
    $products = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction Stop)
    $edition = [string](Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID')
    $licensed = @($products | Where-Object { $_.LicenseStatus -eq 1 })
    $evidence = [ordered]@{
        edition  = $edition
        products = @($products | ForEach-Object { [ordered]@{ name = [string]$_.Name; licenseStatus = [int]$_.LicenseStatus; channel = [string]$_.ProductKeyChannel } })
    }
    if ($licensed.Count -eq 0) {
        Add-Check -Id 'SYS.LICENSE.NOTACTIVATED' -Area 'identity' -Status 'fail' -Title 'Windows is not activated' `
            -Detail 'No Windows licence with status "Licensed" was found.' -Evidence $evidence
    }
    elseif ($edition -eq 'Professional' -and $device.entraJoined) {
        Add-Check -Id 'SYS.LICENSE.NOTACTIVATED' -Area 'identity' -Status 'info' -Title 'Windows is activated as Pro' `
            -Detail 'If the user has a Windows Enterprise E3/E5 licence, subscription activation should have switched the edition to Enterprise.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'SYS.LICENSE.NOTACTIVATED' -Area 'identity' -Status 'pass' -Title 'Windows is activated' -Detail ("Edition: {0}." -f $edition) -Evidence $evidence
    }
}
#endregion

#region Apps: Microsoft Store, App Installer, Microsoft 365 Apps
Invoke-Check -Id 'APP.STORE.BROKEN' -Area 'apps' -Title 'Microsoft Store and App Installer' -Script {
    $disabled = @('AppXSvc', 'ClipSVC', 'InstallService' | Where-Object { (Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$_" -Name 'Start') -eq 4 })
    $storeRemoved = (Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore') -eq 1
    $problems = @()
    $packages = [ordered]@{}
    foreach ($name in 'Microsoft.WindowsStore', 'Microsoft.DesktopAppInstaller') {
        if ($isElevated) { $found = @(Get-AppxPackage -AllUsers -Name $name -ErrorAction Stop) }
        else { $found = @(Get-AppxPackage -Name $name -ErrorAction Stop) }
        $package = $found | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $package) {
            $packages[$name] = 'missing'
            if (-not ($name -eq 'Microsoft.WindowsStore' -and $storeRemoved)) { $problems += "$name is not installed" }
        }
        else {
            $packages[$name] = ('{0} ({1})' -f $package.Version, $package.Status)
            if ([string]$package.Status -ne 'Ok') { $problems += "$name is damaged (status $($package.Status))" }
        }
    }
    if ($disabled.Count -gt 0) { $problems += 'service disabled: ' + ($disabled -join ', ') }
    $evidence = [ordered]@{ packages = $packages; disabledServices = $disabled; storeRemovedByPolicy = $storeRemoved; allUsers = $isElevated }
    if ($problems.Count -gt 0) {
        Add-Check -Id 'APP.STORE.BROKEN' -Area 'apps' -Status 'fail' -Title 'Microsoft Store or App Installer is broken' `
            -Detail (($problems -join '; ') + '. Store apps from Intune and winget do not work.') -Evidence $evidence
    }
    else {
        Add-Check -Id 'APP.STORE.BROKEN' -Area 'apps' -Status 'pass' -Title 'Microsoft Store and App Installer are OK' -Evidence $evidence
    }
}

Invoke-Check -Id 'APP.M365.UPDATESTUCK' -Area 'apps' -Title 'Microsoft 365 Apps updates' -Script {
    $config = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'
    $version = [string](Get-RegValue -Path $config -Name 'VersionToReport')
    if (-not $version) {
        Add-Check -Id 'APP.M365.UPDATESTUCK' -Area 'apps' -Status 'info' -Title 'Microsoft 365 Apps (Click-to-Run) is not installed'
        return
    }
    $configMgr = ([string](Get-RegValue -Path $config -Name 'OfficeMgmtCOM') -eq 'True') -or ((Get-RegValue -Path $policy -Name 'officemgmtcom') -eq 1)
    $policyOff = (Get-RegValue -Path $policy -Name 'enableautomaticupdates') -eq 0
    $serviceStart = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ClickToRunSvc' -Name 'Start'
    $taskState = $null
    $daysSinceTask = $null
    $task = Get-ScheduledTask -TaskPath '\Microsoft\Office\' -TaskName 'Office Automatic Updates 2.0' -ErrorAction SilentlyContinue
    if ($task) {
        $taskState = [string]$task.State
        $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        if ($info) { $daysSinceTask = ConvertTo-DaysAgo $info.LastRunTime }
    }
    $evidence = [ordered]@{
        version = $version
        updatesEnabled = [string](Get-RegValue -Path $config -Name 'UpdatesEnabled')
        clickToRunSvcStart = $serviceStart
        updateTaskState = $taskState
        daysSinceUpdateTaskRun = $daysSinceTask
        managedByConfigMgr = $configMgr
        updatesOffByPolicy = $policyOff
    }
    if ($configMgr -or $policyOff) {
        Add-Check -Id 'APP.M365.UPDATESTUCK' -Area 'apps' -Status 'info' -Title 'Microsoft 365 Apps updates are managed elsewhere' `
            -Detail $(if ($configMgr) { 'Configuration Manager manages the updates.' } else { 'A policy turns automatic updates off.' }) -Evidence $evidence
        return
    }
    $problems = @()
    if ($null -eq $serviceStart) { $problems += 'Click-to-Run service is missing' }
    elseif ($serviceStart -eq 4) { $problems += 'Click-to-Run service is disabled' }
    if ($evidence.updatesEnabled -eq 'False') { $problems += 'automatic updates are turned off' }
    if (-not $taskState) { $problems += 'update task is missing' }
    elseif ($taskState -eq 'Disabled') { $problems += 'update task is disabled' }
    elseif ($null -ne $daysSinceTask -and $daysSinceTask -gt $MaxDaysSinceOfficeUpdateCheck) { $problems += ("no update check for {0} days" -f $daysSinceTask) }
    if ($problems.Count -gt 0) {
        Add-Check -Id 'APP.M365.UPDATESTUCK' -Area 'apps' -Status 'fail' -Title 'Microsoft 365 Apps cannot update' `
            -Detail (("Version {0}: " -f $version) + ($problems -join '; ') + '.') -Evidence $evidence
    }
    else {
        Add-Check -Id 'APP.M365.UPDATESTUCK' -Area 'apps' -Status 'pass' -Title 'Microsoft 365 Apps update mechanism is OK' -Detail ("Version {0}." -f $version) -Evidence $evidence
    }
}
#endregion

#region Network: TLS 1.2 and proxy
Invoke-Check -Id 'NET.TLS12.DISABLED' -Area 'network' -Title 'TLS 1.2' -Script {
    $client = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $problems = @()
    $evidence = [ordered]@{
        schannelEnabled           = Get-RegValue -Path $client -Name 'Enabled'
        schannelDisabledByDefault = Get-RegValue -Path $client -Name 'DisabledByDefault'
        winHttpDefaultSecureProtocols      = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DefaultSecureProtocols'
        winHttpDefaultSecureProtocols32bit = Get-RegValue -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DefaultSecureProtocols'
    }
    if ($evidence.schannelEnabled -eq 0) { $problems += 'SCHANNEL TLS 1.2 client is disabled' }
    if ($evidence.schannelDisabledByDefault -eq 1) { $problems += 'SCHANNEL TLS 1.2 client is disabled by default' }
    foreach ($name in 'winHttpDefaultSecureProtocols', 'winHttpDefaultSecureProtocols32bit') {
        $value = $evidence[$name]
        if ($null -ne $value -and (([int64]$value -band 0x800) -eq 0)) { $problems += ('WinHTTP DefaultSecureProtocols 0x{0:X} has no TLS 1.2' -f [int64]$value) }
    }
    if ($problems.Count -gt 0) {
        Add-Check -Id 'NET.TLS12.DISABLED' -Area 'network' -Status 'fail' -Title 'TLS 1.2 is disabled' `
            -Detail (($problems -join '; ') + '. Intune, Entra ID, Windows Update and Defender need TLS 1.2.') -Evidence $evidence
    }
    else {
        Add-Check -Id 'NET.TLS12.DISABLED' -Area 'network' -Status 'pass' -Title 'TLS 1.2 is not disabled' -Evidence $evidence
    }
}

Invoke-Check -Id 'NET.PROXY.MISMATCH' -Area 'network' -Title 'Proxy for system services' -Script {
    if ($isSystem) {
        Add-Check -Id 'NET.PROXY.MISMATCH' -Area 'network' -Status 'info' -Title 'Proxy settings not compared' `
            -Detail 'The proxy of the signed-in user can only be read in the context of that user.'
        return
    }
    $userKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $userProxy = ((Get-RegValue -Path $userKey -Name 'ProxyEnable') -eq 1 -and [string](Get-RegValue -Path $userKey -Name 'ProxyServer')) -or
                 [bool][string](Get-RegValue -Path $userKey -Name 'AutoConfigURL')
    $winHttp = Test-WinHttpProxyConfigured
    $evidence = [ordered]@{ userProxyConfigured = [bool]$userProxy; winHttpProxyConfigured = $winHttp; directConnection = $null }
    if (-not $userProxy -or $winHttp) {
        Add-Check -Id 'NET.PROXY.MISMATCH' -Area 'network' -Status 'pass' -Title 'User and system proxy settings match' -Evidence $evidence
        return
    }
    if ($SkipNetwork) {
        Add-Check -Id 'NET.PROXY.MISMATCH' -Area 'network' -Status 'unknown' -Title 'User has a proxy, system services have none (direct connection not tested)' -Evidence $evidence
        return
    }
    $direct = Test-TcpPort -HostName 'login.microsoftonline.com' -Port 443 -TimeoutMs $NetworkTimeoutMs
    $evidence.directConnection = $direct
    if ($direct) {
        Add-Check -Id 'NET.PROXY.MISMATCH' -Area 'network' -Status 'pass' -Title 'User has a proxy, system services connect directly' `
            -Detail 'No WinHTTP proxy is set, but the direct connection works.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'NET.PROXY.MISMATCH' -Area 'network' -Status 'fail' -Title 'The user has a proxy, but system services have none' `
            -Detail 'Windows Update, Intune and Defender run as SYSTEM and use the WinHTTP proxy. None is set and the direct connection fails.' -Evidence $evidence
    }
}
#endregion

#region Defender: passive mode, platform version, attack surface reduction
Invoke-Check -Id 'DEF.PASSIVE.NOAV' -Area 'defender' -Title 'Defender passive mode' -Script {
    if (-not $script:Mp) {
        Add-Check -Id 'DEF.PASSIVE.NOAV' -Area 'defender' -Status 'unknown' -Title 'Defender running mode unknown' -Detail $script:MpError
        return
    }
    $mode = [string]$script:Mp.AMRunningMode
    $others = @()
    try {
        $others = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop |
            Where-Object { [string]$_.displayName -notmatch 'Defender' } | ForEach-Object { [string]$_.displayName })
    }
    catch { }
    $evidence = [ordered]@{ runningMode = $mode; otherAntivirus = $others }
    if ($mode -match 'Passive' -and $others.Count -eq 0) {
        Add-Check -Id 'DEF.PASSIVE.NOAV' -Area 'defender' -Status 'fail' -Title 'Defender is in passive mode, but no other antivirus is registered' `
            -Detail 'Nothing protects this device in real time.' -Evidence $evidence
    }
    elseif ($mode -match 'Passive') {
        Add-Check -Id 'DEF.PASSIVE.NOAV' -Area 'defender' -Status 'info' -Title 'Defender is in passive mode next to another antivirus' -Detail ($others -join ', ') -Evidence $evidence
    }
    else {
        Add-Check -Id 'DEF.PASSIVE.NOAV' -Area 'defender' -Status 'pass' -Title 'Defender is the active antivirus' -Evidence $evidence
    }
}

Invoke-Check -Id 'DEF.PLATFORM.OUTDATED' -Area 'defender' -Title 'Defender platform version' -Script {
    if (-not $script:Mp) {
        Add-Check -Id 'DEF.PLATFORM.OUTDATED' -Area 'defender' -Status 'unknown' -Title 'Defender platform version unknown' -Detail $script:MpError
        return
    }
    # The platform version is 4.18.YYMM.x (for example 4.18.26040.7 = April 2026).
    $version = [string]$script:Mp.AMProductVersion
    $months = $null
    if ($version -match '^\d+\.\d+\.(\d{2})(\d{2})\d*\.') {
        $year = 2000 + [int]$Matches[1]
        $month = [int]$Matches[2]
        if ($month -ge 1 -and $month -le 12) {
            $now = Get-Date
            $months = ($now.Year - $year) * 12 + ($now.Month - $month)
        }
    }
    $evidence = [ordered]@{ platformVersion = $version; engineVersion = [string]$script:Mp.AMEngineVersion; ageMonths = $months }
    if ($null -eq $months) {
        Add-Check -Id 'DEF.PLATFORM.OUTDATED' -Area 'defender' -Status 'info' -Title 'Defender platform age could not be read from the version' -Evidence $evidence
    }
    elseif ($months -gt $MaxPlatformAgeMonths) {
        Add-Check -Id 'DEF.PLATFORM.OUTDATED' -Area 'defender' -Status 'warn' -Title 'Defender platform is outdated' `
            -Detail ("Platform {0} is about {1} months old (limit {2}). Platform updates come monthly through Windows Update." -f $version, $months, $MaxPlatformAgeMonths) -Evidence $evidence
    }
    else {
        Add-Check -Id 'DEF.PLATFORM.OUTDATED' -Area 'defender' -Status 'pass' -Title 'Defender platform is current' -Detail ("Platform {0}." -f $version) -Evidence $evidence
    }
}

Invoke-Check -Id 'DEF.ASR.NOTCONFIGURED' -Area 'defender' -Title 'Attack surface reduction rules' -Script {
    if (-not $script:Mp) {
        Add-Check -Id 'DEF.ASR.NOTCONFIGURED' -Area 'defender' -Status 'unknown' -Title 'Attack surface reduction state unknown' -Detail $script:MpError
        return
    }
    if ([string]$script:Mp.AMRunningMode -match 'Passive') {
        Add-Check -Id 'DEF.ASR.NOTCONFIGURED' -Area 'defender' -Status 'info' -Title 'Attack surface reduction not checked: Defender is in passive mode'
        return
    }
    $preference = Get-MpPreference -ErrorAction Stop
    $actions = @($preference.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
    $evidence = [ordered]@{
        rules   = $actions.Count
        block   = @($actions | Where-Object { $_ -eq 1 }).Count
        audit   = @($actions | Where-Object { $_ -eq 2 }).Count
        warn    = @($actions | Where-Object { $_ -eq 6 }).Count
    }
    if (($evidence.block + $evidence.audit + $evidence.warn) -eq 0) {
        Add-Check -Id 'DEF.ASR.NOTCONFIGURED' -Area 'defender' -Status 'warn' -Title 'No attack surface reduction rule is active' `
            -Detail 'Ignore this if your organisation does not use ASR rules.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'DEF.ASR.NOTCONFIGURED' -Area 'defender' -Status 'pass' -Title 'Attack surface reduction rules are active' `
            -Detail ("{0} block, {1} audit, {2} warn." -f $evidence.block, $evidence.audit, $evidence.warn) -Evidence $evidence
    }
}
#endregion

#region Report
if ($Anonymize) {
    $device.computerName = 'device-' + (Get-ShortHash -Text ([string]$env:COMPUTERNAME))
    $device.userName = $null
    $device.tenantId = $null
}

$checks = $script:Checks.ToArray()
$findings = @($checks | Where-Object { $_.status -in @('fail', 'warn') } | ForEach-Object { $_.id })
$summary = [ordered]@{
    pass    = @($checks | Where-Object { $_.status -eq 'pass' }).Count
    fail    = @($checks | Where-Object { $_.status -eq 'fail' }).Count
    warn    = @($checks | Where-Object { $_.status -eq 'warn' }).Count
    info    = @($checks | Where-Object { $_.status -eq 'info' }).Count
    unknown = @($checks | Where-Object { $_.status -eq 'unknown' }).Count
}
$overall = 'healthy'
if ($summary.fail -gt 0) { $overall = 'unhealthy' }
elseif ($summary.warn -gt 0) { $overall = 'attention' }

$report = [pscustomobject][ordered]@{
    schemaVersion = $SchemaVersion
    tool          = 'Get-ClientHealth.ps1'
    toolVersion   = $ScriptVersion
    generatedAt   = (Get-Date).ToUniversalTime().ToString('o')
    elevated      = $isElevated
    runAsSystem   = $isSystem
    anonymized    = [bool]$Anonymize
    overall       = $overall
    summary       = $summary
    device        = $device
    findings      = $findings
    checks        = $checks
}

$json = $report | ConvertTo-Json -Depth 8

if (-not $OutputPath) {
    $folder = $null
    if ($IntuneMode) {
        $folder = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
        if (-not (Test-Path -LiteralPath $folder)) {
            try { New-Item -Path $folder -ItemType Directory -Force | Out-Null } catch { $folder = $null }
        }
    }
    if (-not $folder) { $folder = $env:TEMP }
    if (-not $folder) { $folder = [System.IO.Path]::GetTempPath() }
    $OutputPath = Join-Path $folder ("ClientHealth-{0}.json" -f $device.computerName)
}
# Write UTF-8 without a byte order mark so browsers and JSON parsers read the file directly.
$writeError = $null
try {
    [System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))
}
catch {
    $writeError = $_.Exception.Message
    if (-not $IntuneMode) { throw }
}

if ($IntuneMode) {
    # One line for the Intune remediation report (Intune keeps up to 2048 characters).
    $line = '{0} | fail {1}, warn {2}, unknown {3}' -f $overall.ToUpper(), $summary.fail, $summary.warn, $summary.unknown
    if ($findings.Count -gt 0) { $line += ' | ' + ($findings -join ', ') }
    if ($writeError) { $line += ' | Report not written: ' + $writeError }
    else { $line += ' | Report: ' + $OutputPath }
    if ($line.Length -gt 2000) { $line = $line.Substring(0, 1997) + '...' }
    Write-Output $line
    if ($PassThru) { $report }
    if ($summary.fail -gt 0) { exit 1 }
    exit 0
}

if ($CopyToClipboard) {
    try {
        Set-Clipboard -Value $json
    }
    catch {
        Write-Warning ("Could not copy the report to the clipboard: " + $_.Exception.Message)
    }
}

$marks = @{ pass = '[ OK ]'; fail = '[FAIL]'; warn = '[WARN]'; info = '[INFO]'; unknown = '[ ?? ]' }
Write-Host ''
Write-Host ("Client health: {0}  (pass {1}, fail {2}, warn {3}, unknown {4})" -f $overall.ToUpper(), $summary.pass, $summary.fail, $summary.warn, $summary.unknown)
Write-Host ''
foreach ($check in $checks) {
    $line = "{0} {1,-28} {2}" -f $marks[$check.status], $check.id, $check.title
    Write-Host $line
    if ($check.detail -and $check.status -in @('fail', 'warn', 'unknown')) { Write-Host ("       " + $check.detail) }
}
Write-Host ''
Write-Host ("Report: {0}" -f $OutputPath)
if ($CopyToClipboard) { Write-Host 'The report was also copied to the clipboard.' }
Write-Host 'Upload or paste the report into the Client Fix Page to see the recommended fixes.'

if ($PassThru) { $report }
#endregion
