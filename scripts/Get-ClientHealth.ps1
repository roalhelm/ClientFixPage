<#
.SYNOPSIS
    Read-only health check for a Windows client (Windows Update, Intune/MDM, Entra ID, Defender, network).

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
    Path of the JSON report. Default: ClientHealth-<COMPUTERNAME>.json in the TEMP folder.

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

.NOTES
    Version : 0.1.1
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
    [switch]$PassThru
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptVersion = '0.1.1'
$SchemaVersion = '1.0'

#region Thresholds
$MinFreeSpaceGB         = 20   # SYS.DISK.LOWSPACE
$MaxDaysSinceWuScan     = 7    # WU.SCAN.FAILED
$MaxDaysSinceWuInstall  = 40   # WU.PATCHLEVEL.BEHIND
$MaxDaysSinceMdmSync    = 7    # MDM.SYNC.STALE
$MaxSignatureAgeDays    = 3    # DEF.SIGNATURE.OUTDATED
$MdmCertWarnDays        = 30   # MDM.ENROLLMENT.BROKEN (certificate expiry warning)
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

#region Intune: enrollment
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
        Add-Check -Id 'MDM.ENROLLMENT.BROKEN' -Area 'intune' -Status 'fail' -Title 'Device is not enrolled in Intune' `
            -Detail 'No enrollment with provider "MS DM Server" found.' -Evidence $evidence
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
    elseif (-not $script:Mp.IsTamperProtected -and -not $passive) {
        Add-Check -Id 'DEF.RTP.DISABLED' -Area 'defender' -Status 'warn' -Title 'Tamper protection is off' -Evidence $evidence
    }
    elseif ($passive) {
        Add-Check -Id 'DEF.RTP.DISABLED' -Area 'defender' -Status 'info' -Title 'Defender is in passive mode' `
            -Detail 'Real-time protection is provided by another antivirus product.' -Evidence $evidence
    }
    else {
        Add-Check -Id 'DEF.RTP.DISABLED' -Area 'defender' -Status 'pass' -Title 'Real-time and tamper protection are on' -Evidence $evidence
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
    $folder = $env:TEMP
    if (-not $folder) { $folder = [System.IO.Path]::GetTempPath() }
    $OutputPath = Join-Path $folder ("ClientHealth-{0}.json" -f $device.computerName)
}
# Write UTF-8 without a byte order mark so browsers and JSON parsers read the file directly.
[System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))

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
