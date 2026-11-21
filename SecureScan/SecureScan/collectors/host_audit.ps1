<#
.SYNOPSIS
  SecureScan Windows host security audit (read-only).

.DESCRIPTION
  Collects the security configuration and live state of the local Windows machine
  and prints ONE JSON document to stdout. Nothing on the system is changed.
  Every section is independent: if a check needs Administrator rights and is
  denied, that section reports {"error": "..."} and the rest still runs.

  Run by SecureScan (POST /api/audit/host) or manually:
    powershell -NoProfile -ExecutionPolicy Bypass -File collectors\host_audit.ps1 > audit.json
#>
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Invoke-Section([scriptblock]$Block) {
    try { & $Block } catch { @{ error = $_.Exception.Message } }
}

$result = [ordered]@{}

$result.host = Invoke-Section {
    $os = Get-CimInstance Win32_OperatingSystem
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    [ordered]@{
        computer   = $env:COMPUTERNAME
        user       = $id.Name
        is_admin   = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        os         = $os.Caption
        version    = $os.Version
        build      = $os.BuildNumber
        last_boot  = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        audit_time = (Get-Date).ToUniversalTime().ToString('o')
    }
}

$result.local_users = Invoke-Section {
    @(Get-LocalUser | ForEach-Object {
        [ordered]@{
            name                   = $_.Name
            enabled                = $_.Enabled
            password_required      = $_.PasswordRequired
            password_expires       = [bool]$_.PasswordExpires
            password_last_set      = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToUniversalTime().ToString('o') } else { $null }
            last_logon             = if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('o') } else { $null }
            description            = $_.Description
        }
    })
}

$result.administrators = Invoke-Section {
    # Get-LocalGroupMember fails on some machines with orphaned SIDs; fall back to ADSI.
    try {
        @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [ordered]@{ name = $_.Name; type = "$($_.ObjectClass)"; source = "$($_.PrincipalSource)" } })
    } catch {
        $grp = [ADSI]"WinNT://./Administrators,group"
        @($grp.psbase.Invoke('Members') | ForEach-Object { [ordered]@{ name = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null); type = 'unknown'; source = 'ADSI' } })
    }
}

$procNames = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procNames[$_.Id] = $_.ProcessName }

$result.listening_ports = Invoke-Section {
    @(Get-NetTCPConnection -State Listen | ForEach-Object {
        [ordered]@{ address = $_.LocalAddress; port = $_.LocalPort; pid = $_.OwningProcess; process = $procNames[[int]$_.OwningProcess] }
    })
}

$result.connections = Invoke-Section {
    @(Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notin @('127.0.0.1', '::1') } | ForEach-Object {
        [ordered]@{ local = $_.LocalAddress; local_port = $_.LocalPort; remote = $_.RemoteAddress; remote_port = $_.RemotePort; pid = $_.OwningProcess; process = $procNames[[int]$_.OwningProcess] }
    })
}

$result.firewall = Invoke-Section {
    @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = $_.Name; enabled = [bool]$_.Enabled; inbound_default = "$($_.DefaultInboundAction)" } })
}

$result.defender = Invoke-Section {
    $d = Get-MpComputerStatus
    [ordered]@{
        antivirus_enabled         = $d.AntivirusEnabled
        realtime_protection       = $d.RealTimeProtectionEnabled
        tamper_protection         = $d.IsTamperProtected
        signature_age_days        = $d.AntivirusSignatureAge
        signature_last_updated    = if ($d.AntivirusSignatureLastUpdated) { $d.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') } else { $null }
    }
}

$result.uac = Invoke-Section {
    $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    [ordered]@{ enable_lua = $k.EnableLUA; consent_prompt_admin = $k.ConsentPromptBehaviorAdmin }
}

$result.rdp = Invoke-Section {
    $k = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    [ordered]@{ enabled = ($k.fDenyTSConnections -eq 0) }
}

$result.smb1 = Invoke-Section {
    $k = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue
    $svc = Get-Service mrxsmb10 -ErrorAction SilentlyContinue
    [ordered]@{ server_smb1 = if ($k -and $null -ne $k.SMB1) { [bool]$k.SMB1 } else { $null }; client_driver_present = [bool]$svc }
}

$result.autoruns = Invoke-Section {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    $items = foreach ($key in $keys) {
        if (Test-Path $key) {
            $p = Get-ItemProperty $key
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -notlike 'PS*') { [ordered]@{ location = $key; name = $prop.Name; command = "$($prop.Value)" } }
            }
        }
    }
    $folders = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    $files = foreach ($f in $folders) { if (Test-Path $f) { Get-ChildItem $f -File | ForEach-Object { [ordered]@{ location = $f; name = $_.Name; command = $_.FullName } } } }
    @($items) + @($files)
}

$result.scheduled_tasks = Invoke-Section {
    @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object {
        $a = $_.Actions | Select-Object -First 1
        [ordered]@{ name = $_.TaskName; path = $_.TaskPath; state = "$($_.State)"; author = $_.Author; command = "$($a.Execute) $($a.Arguments)".Trim() }
    })
}

$result.hotfixes = Invoke-Section {
    $h = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending
    [ordered]@{ count = @($h).Count; latest_id = ($h | Select-Object -First 1).HotFixID
                latest_installed = if ($h) { ($h | Select-Object -First 1).InstalledOn.ToUniversalTime().ToString('o') } else { $null } }
}

$result.risky_processes = Invoke-Section {
    @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ($_.Path -match '\\(Temp|Downloads|Public)\\' -or $_.Path -match '\\AppData\\Local\\Temp\\') } |
      ForEach-Object { [ordered]@{ name = $_.ProcessName; pid = $_.Id; path = $_.Path } })
}

$result.security_log = Invoke-Section {
    # Needs Administrator (or 'Event Log Readers'). Failure is reported, not fatal.
    $since = (Get-Date).AddHours(-24)
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625, 4720, 4726, 4732; StartTime = $since } -MaxEvents 500 -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -like '*No events were found*') { return ,@() }
        throw
    }
    @($ev | ForEach-Object { [ordered]@{ id = $_.Id; time = $_.TimeCreated.ToUniversalTime().ToString('o'); message = ($_.Message -split "`n")[0] } })
}

$result | ConvertTo-Json -Depth 6 -Compress
