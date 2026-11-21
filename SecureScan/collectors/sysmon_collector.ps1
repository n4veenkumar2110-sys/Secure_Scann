<#
.SYNOPSIS
    SecureScan Sysmon Event Collector
    Collects Microsoft Sysmon events (IDs 1, 3, 11, 22) from the
    Microsoft-Windows-Sysmon/Operational log and exports normalised JSON.

.DESCRIPTION
    Uses Get-WinEvent with XML-based field extraction to read Sysmon events.
    Extracts structured fields from each event's XML rather than relying
    on formatted text descriptions.

    Supports:
      - Event ID 1:  Process Create
      - Event ID 3:  Network Connect
      - Event ID 11: File Create
      - Event ID 22: DNS Query

    SAFETY:
      - This script is READ-ONLY. It never modifies or deletes any event logs.
      - Requires membership in 'Event Log Readers' or Administrator rights
        to read the Sysmon operational log.

.PARAMETER Hours
    Number of past hours to collect events for (default: 24).

.PARAMETER MaxEvents
    Maximum number of events to return (default: 1000).

.PARAMETER OutputPath
    Path to the output JSON file (default: uploads\sysmon_events.json).

.PARAMETER EventIds
    Array of Sysmon Event IDs to collect (default: 1, 3, 11, 22).

.EXAMPLE
    .\sysmon_collector.ps1 -Hours 24 -OutputPath .\uploads\sysmon_events.json

.EXAMPLE
    .\sysmon_collector.ps1 -Hours 1 -MaxEvents 50 -EventIds 1,22
#>

[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$MaxEvents = 1000,
    [string]$OutputPath = "uploads\sysmon_events.json",
    [int[]]$EventIds = @(1, 3, 11, 22)
)

$ErrorActionPreference = "Continue"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  SecureScan Sysmon Collector v1.0.0" -ForegroundColor Cyan
Write-Host "  Microsoft-Windows-Sysmon/Operational" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

# --- 1. Check that Sysmon log exists ---
$sysmonLogName = "Microsoft-Windows-Sysmon/Operational"
$logExists = Get-WinEvent -ListLog $sysmonLogName -ErrorAction SilentlyContinue

if (-not $logExists) {
    Write-Error "Sysmon log '$sysmonLogName' not found."
    Write-Host ""
    Write-Host "Sysmon does not appear to be installed or running on this system." -ForegroundColor Yellow
    Write-Host "Install Sysmon from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" -ForegroundColor Yellow
    Write-Host "Example install:  sysmon.exe -accepteula -i config\sysmon-config.xml" -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Sysmon log found: $sysmonLogName"
Write-Host "[*] Time window:  Past $Hours hours (since $((Get-Date).AddHours(-$Hours).ToString('yyyy-MM-dd HH:mm:ss')))"
Write-Host "[*] Max events:   $MaxEvents"
Write-Host "[*] Event IDs:    $($EventIds -join ', ')"
Write-Host ""

$startTime = (Get-Date).AddHours(-$Hours)

# --- 2. Function to parse event XML into a hashtable ---
function Get-SysmonEventData($event) {
    $fields = @{}
    try {
        $xml = [xml]$event.ToXml()

        # EventData fields (most Sysmon events)
        if ($xml.Event.EventData.Data) {
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) {
                    $fields[$d.Name] = $d.InnerText
                }
            }
        }

        # System fields
        $sys = $xml.Event.System
        if ($sys) {
            $fields['_Provider'] = $sys.Provider.Name
            $fields['_EventRecordID'] = $sys.EventRecordID
            $fields['_Computer'] = $sys.Computer
            $fields['_TimeCreated'] = $sys.TimeCreated.SystemTime
        }
    } catch {
        Write-Verbose "XML parse fallback for RecordId $($event.RecordId): $_"
    }
    return $fields
}

# --- 3. Collect events ---
$collectedRecords = [System.Collections.Generic.List[PSObject]]::new()

$filter = @{
    LogName   = $sysmonLogName
    Id        = $EventIds
    StartTime = $startTime
}

try {
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    Write-Host "[+] Retrieved $($events.Count) Sysmon events." -ForegroundColor Green
} catch [System.UnauthorizedAccessException] {
    Write-Error "Access denied reading the Sysmon log."
    Write-Host "TIP: Run PowerShell as Administrator or add your user to the 'Event Log Readers' group." -ForegroundColor Yellow
    exit 1
} catch {
    if ($_.Exception.Message -match "No events were found") {
        Write-Host "[*] No matching Sysmon events found in the specified time window." -ForegroundColor DarkGray
        $events = @()
    } else {
        Write-Error "Failed to query Sysmon log: $_"
        exit 1
    }
}

foreach ($evt in $events) {
    $d = Get-SysmonEventData $evt
    $eid = $evt.Id

    # --- Common fields ---
    $record = [ordered]@{
        record_id      = [int]$evt.RecordId
        event_id       = [int]$eid
        event_time     = $evt.TimeCreated.ToUniversalTime().ToString("o")
        source         = "Sysmon"
        log_name       = $sysmonLogName
        computer_name  = [string]($d['_Computer'] ?? $evt.MachineName)
        rule_name      = [string]$d['RuleName']
    }

    # --- Per-event-type fields (only populate what is available) ---
    switch ($eid) {
        1 {
            # Process Create
            $record['process_guid']    = [string]$d['ProcessGuid']
            $record['process_id']      = [string]$d['ProcessId']
            $record['image']           = [string]$d['Image']
            $record['file_version']    = [string]$d['FileVersion']
            $record['description']     = [string]$d['Description']
            $record['product']         = [string]$d['Product']
            $record['company']         = [string]$d['Company']
            $record['original_name']   = [string]$d['OriginalFileName']
            $record['command_line']    = [string]$d['CommandLine']
            $record['current_dir']     = [string]$d['CurrentDirectory']
            $record['username']        = [string]$d['User']
            $record['logon_guid']      = [string]$d['LogonGuid']
            $record['logon_id']        = [string]$d['LogonId']
            $record['terminal_id']     = [string]$d['TerminalSessionId']
            $record['integrity']       = [string]$d['IntegrityLevel']
            $record['hashes']          = [string]$d['Hashes']
            $record['parent_guid']     = [string]$d['ParentProcessGuid']
            $record['parent_id']       = [string]$d['ParentProcessId']
            $record['parent_image']    = [string]$d['ParentImage']
            $record['parent_cmd']      = [string]$d['ParentCommandLine']
            $record['parent_user']     = [string]$d['ParentUser']
        }
        3 {
            # Network Connect
            $record['process_guid']    = [string]$d['ProcessGuid']
            $record['process_id']      = [string]$d['ProcessId']
            $record['image']           = [string]$d['Image']
            $record['username']        = [string]$d['User']
            $record['protocol']        = [string]$d['Protocol']
            $record['initiated']       = [string]$d['Initiated']
            $record['source_ip']       = [string]$d['SourceIp']
            $record['source_hostname'] = [string]$d['SourceHostname']
            $record['source_port']     = [string]$d['SourcePort']
            $record['destination_ip']  = [string]$d['DestinationIp']
            $record['dest_hostname']   = [string]$d['DestinationHostname']
            $record['destination_port']= [string]$d['DestinationPort']
        }
        11 {
            # File Create
            $record['process_guid']    = [string]$d['ProcessGuid']
            $record['process_id']      = [string]$d['ProcessId']
            $record['image']           = [string]$d['Image']
            $record['target_filename'] = [string]$d['TargetFilename']
            $record['creation_time']   = [string]$d['CreationUtcTime']
            $record['username']        = [string]$d['User']
            $record['hashes']          = [string]$d['Hashes']
        }
        22 {
            # DNS Query
            $record['process_guid']    = [string]$d['ProcessGuid']
            $record['process_id']      = [string]$d['ProcessId']
            $record['image']           = [string]$d['Image']
            $record['query_name']      = [string]$d['QueryName']
            $record['query_type']      = [string]$d['QueryType']
            $record['query_status']    = [string]$d['QueryStatus']
            $record['query_results']   = [string]$d['QueryResults']
            $record['username']        = [string]$d['User']
        }
        default {
            $record['username']        = [string]$d['User']
            $record['description']     = "Sysmon Event $eid"
        }
    }

    $collectedRecords.Add([PSCustomObject]$record)
}

# --- 4. Export ---
Write-Host ""
Write-Host "[*] Exporting $($collectedRecords.Count) Sysmon records..." -ForegroundColor Cyan

if ($collectedRecords.Count -eq 0) {
    Write-Warning "No records collected. Ensure Sysmon is running and you have permissions."
    Write-Host "   Check with: Get-WinEvent -LogName '$sysmonLogName' -MaxEvents 1" -ForegroundColor DarkGray
} else {
    $parentDir = Split-Path -Path $OutputPath -Parent
    if ($parentDir -and !(Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    $json = $collectedRecords | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText(
        (Resolve-Path $OutputPath -ErrorAction SilentlyContinue ?? $OutputPath),
        $json,
        [System.Text.Encoding]::UTF8
    )
    Write-Host "[+] Exported to: $OutputPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] Import into SecureScan:" -ForegroundColor Cyan
    Write-Host "    1. Web UI:  System Audit -> Import Sysmon JSON" -ForegroundColor White
    Write-Host "    2. API:     POST /api/import/sysmon  (multipart file upload)" -ForegroundColor White
}

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  Collection complete. $($collectedRecords.Count) records." -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
