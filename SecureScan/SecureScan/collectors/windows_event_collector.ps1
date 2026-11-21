<#
.SYNOPSIS
    SecureScan Windows Event Log & Sysmon Collector
    Collects Windows Security and Sysmon events and normalises them into JSON for SecureScan.

.DESCRIPTION
    Retrieves events from the Windows Security Log (IDs 4624, 4625, 4688, 4720, 4726, 4672)
    and optionally Microsoft Sysmon (IDs 1, 3, 11).
    Exports a normalised JSON or CSV file that can be imported directly into SecureScan.

.PARAMETER Hours
    Number of past hours to collect events for (default: 24).

.PARAMETER MaxEvents
    Maximum number of events to collect per log (default: 500).

.PARAMETER OutputFile
    Path to the output JSON file (default: "windows_events.json").

.PARAMETER IncludeSysmon
    Switch to include Microsoft-Windows-Sysmon/Operational events if Sysmon is installed.

.PARAMETER Format
    Export format: "JSON" (default) or "CSV".

.EXAMPLE
    .\windows_event_collector.ps1 -Hours 48 -OutputFile "D:\SecureScan\uploads\collected_events.json"
#>

[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$MaxEvents = 500,
    [string]$OutputFile = "windows_events.json",
    [switch]$IncludeSysmon,
    [ValidateSet("JSON", "CSV")]
    [string]$Format = "JSON"
)

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  SecureScan Windows Event Collector v1.0.0" -ForegroundColor Cyan
Write-Host "  Targeting Windows 11 Security & Forensic Events" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$startTime = (Get-Date).AddHours(-$Hours)
Write-Host "[*] Time Window: Past $Hours hours (since $($startTime.ToString('yyyy-MM-dd HH:mm:ss UTC')))"
Write-Host "[*] Event Limit: Up to $MaxEvents events per source"

$collectedRecords = [System.Collections.Generic.List[PSObject]]::new()

# Function to parse EventData XML from Get-WinEvent
function Get-EventDataMap($event) {
    $dataMap = @{}
    try {
        $xml = [xml]$event.ToXml()
        if ($xml.Event.EventData.Data) {
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) {
                    $dataMap[$d.Name] = $d.InnerText
                }
            }
        }
    } catch {
        # Fallback to basic properties
    }
    return $dataMap
}

# ---------------------------------------------------------------------
# 1. Collect Windows Security Events
# ---------------------------------------------------------------------
Write-Host "`n[1/2] Querying Windows Security Log..." -ForegroundColor Yellow

$securityFilter = @{
    LogName = 'Security'
    Id = 4624, 4625, 4688, 4720, 4726, 4672
    StartTime = $startTime
}

try {
    $secEvents = Get-WinEvent -FilterHashtable $securityFilter -MaxEvents $MaxEvents -ErrorAction Stop
    Write-Host " [+] Found $($secEvents.Count) matching Security events." -ForegroundColor Green

    foreach ($e in $secEvents) {
        $data = Get-EventDataMap $e

        # Extract normalized fields
        $user = $data["TargetUserName"]
        if (-not $user -or $user -eq "-") { $user = $data["SubjectUserName"] }
        if (-not $user) { $user = $e.UserId }

        $domain = $data["TargetDomainName"]
        if (-not $domain -or $domain -eq "-") { $domain = $data["SubjectDomainName"] }

        $ip = $data["IpAddress"]
        if ($ip -eq "-" -or $ip -eq "127.0.0.1" -or $ip -eq "::1") { $ip = "" }

        $process = $data["NewProcessName"]
        if (-not $process) { $process = $data["ProcessName"] }

        $commandLine = $data["CommandLine"]

        $record = [PSCustomObject]@{
            id = "win-sec-$($e.RecordId)-$($e.Id)"
            record_id = $e.RecordId
            event_id = $e.Id
            event_time = $e.TimeCreated.ToUniversalTime().ToString("o")
            source = "Windows audit"
            log_name = "Security"
            computer_name = $e.MachineName
            username = [string]$user
            domain = [string]$domain
            source_ip = [string]$ip
            destination_ip = ""
            protocol = ""
            process_name = [string]$process
            command_line = [string]$commandLine
            logon_type = [string]$data["LogonType"]
            privileges = [string]$data["PrivilegeList"]
            description = ($e.Message -split "`r?`n")[0]
            raw_message = $e.Message
        }

        $collectedRecords.Add($record)
    }
} catch [System.UnauthorizedAccessException] {
    Write-Warning "Access Denied reading Windows Security Log."
    Write-Host " TIP: Reading Security Event Logs requires Administrator privileges or membership in the 'Event Log Readers' group." -ForegroundColor Yellow
    Write-Host " Run PowerShell as Administrator to collect live Security events." -ForegroundColor Yellow
} catch {
    Write-Warning "Could not retrieve Security events: $_"
}

# ---------------------------------------------------------------------
# 2. Collect Microsoft Sysmon Events (if requested or available)
# ---------------------------------------------------------------------
if ($IncludeSysmon) {
    Write-Host "`n[2/2] Checking Microsoft-Windows-Sysmon/Operational Log..." -ForegroundColor Yellow

    $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if ($sysmonLog) {
        $sysmonFilter = @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            Id = 1, 3, 11
            StartTime = $startTime
        }

        try {
            $sysEvents = Get-WinEvent -FilterHashtable $sysmonFilter -MaxEvents $MaxEvents -ErrorAction Stop
            Write-Host " [+] Found $($sysEvents.Count) Sysmon events." -ForegroundColor Green

            foreach ($e in $sysEvents) {
                $data = Get-EventDataMap $e

                $record = [PSCustomObject]@{
                    id = "sysmon-$($e.RecordId)-$($e.Id)"
                    record_id = $e.RecordId
                    event_id = $e.Id
                    event_time = $e.TimeCreated.ToUniversalTime().ToString("o")
                    source = "Sysmon"
                    log_name = "Microsoft-Windows-Sysmon/Operational"
                    computer_name = $e.MachineName
                    username = [string]$data["User"]
                    domain = ""
                    source_ip = [string]$data["SourceIp"]
                    destination_ip = [string]$data["DestinationIp"]
                    protocol = [string]$data["Protocol"]
                    process_name = [string]$data["Image"]
                    command_line = [string]$data["CommandLine"]
                    parent_process = [string]$data["ParentImage"]
                    target_filename = [string]$data["TargetFilename"]
                    hashes = [string]$data["Hashes"]
                    destination_port = [string]$data["DestinationPort"]
                    description = "Sysmon Event $($e.Id): $($data['RuleName'] ?? $e.TaskDisplayName ?? 'Sysmon observation')"
                    raw_message = $e.Message
                }

                $collectedRecords.Add($record)
            }
        } catch {
            Write-Warning "Could not query Sysmon log: $_"
        }
    } else {
        Write-Host " [-] Sysmon log not found. Sysmon is not installed on this system." -ForegroundColor DarkGray
        Write-Host "     (Install via: sysmon.exe -i sysmonconfig.xml from Microsoft Sysinternals)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "`n[2/2] Sysmon collection skipped (pass -IncludeSysmon to enable)." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------
# 3. Export Collected Records
# ---------------------------------------------------------------------
Write-Host "`n[*] Exporting $($collectedRecords.Count) total collected records..." -ForegroundColor Cyan

if ($collectedRecords.Count -eq 0) {
    Write-Warning "No records were collected. Ensure appropriate permissions or test with sample records."
} else {
    $parentDir = Split-Path -Path $OutputFile -Parent
    if ($parentDir -and !(Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    if ($Format -eq "JSON") {
        $json = $collectedRecords | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($OutputFile, $json, [System.Text.Encoding]::UTF8)
        Write-Host " [+] Exported normalised JSON to: $OutputFile" -ForegroundColor Green
    } else {
        $collectedRecords | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Host " [+] Exported normalised CSV to: $OutputFile" -ForegroundColor Green
    }

    Write-Host "[*] Ready to import into SecureScan via web interface or POST /api/import/windows-audit" -ForegroundColor Cyan
}
