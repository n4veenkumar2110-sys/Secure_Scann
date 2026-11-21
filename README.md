# SECURESCAN – Security Audit & Digital Forensics Workbench

SecureScan is a local cybersecurity intelligence and digital forensics application. It consolidates Windows Security Event Logs, Microsoft Sysmon telemetry, Linux audit records (`auditd`), Wireshark network packet analysis, and Autopsy digital forensic findings into a unified, professional SQLite database and browser workbench.

---

## 1. Project Overview

- **Frontend**: SOC-style interface with investigation modules (Overview, Windows Audit, Process, Network, Threat Detections, Evidence Explorer, Timeline, Relationship Graph, Reports, Settings).
- **Correlation engine**: `detections.py` links events across sources into MITRE ATT&CK-mapped detections with a 0-100 risk score.
- **Backend**: Python Flask REST API running locally at `http://127.0.0.1:5000`.
- **Database**: SQLite 3 (`instance/securescan.db`) with parameterised queries and indexed tables.
- **Evidence Handling**: Read-only evidence ingest, SHA-256 integrity hashing, and strict preservation of original evidence files in `uploads/`.

---

## 2. Folder Structure

```
D:\SecureScan\
├── .venv\                     # Dedicated Python 3.14 virtual environment
├── config\
│   └── sysmon-config.xml      # Sysmon configuration (schema 4.91, Sysmon v18)
├── collectors\
│   ├── windows_event_collector.ps1   # Windows Security Event Log collector
│   ├── windows_audit.py              # Windows event parser & normaliser
│   ├── sysmon_collector.ps1          # Microsoft Sysmon event collector
│   └── sysmon_parser.py             # Sysmon event parser & normaliser
├── instance\
│   └── securescan.db          # Authoritative SQLite database
├── uploads\                   # Safely stored uploaded evidence files
├── sample_data\
│   ├── audit_sample.log               # Linux audit sample
│   ├── wireshark_sample.csv           # Wireshark CSV sample
│   ├── autopsy_sample.csv            # Autopsy findings sample
│   ├── windows_events_sample.json    # Windows Security event sample
│   ├── sysmon_events_sample.json     # Sysmon sample (Events 1, 3, 11)
│   └── sysmon_events_extended.json   # Sysmon extended sample (Events 1, 3, 11, 22)
├── sysmon-test\               # Monitored directory for Sysmon Event 11
├── tests\
│   └── test_securescan.py     # Automated unit & integration test suite
├── app.py                     # Flask application routes and API endpoints
├── config.py                  # Environment and server configuration
├── database.py                # SQLite connection pool, schema, and helpers
├── parser_linux.py            # Linux auditd parser and detection rules
├── parser_wireshark.py        # Wireshark CSV parser and detection rules
├── parser_autopsy.py          # Autopsy findings CSV parser and rules
├── index.html                 # Main single-page application shell
├── style.css                  # Cybersecurity dark UI theme & print styles
├── app.js                     # Frontend API client and reactive controller
├── schema.sql                 # Reference SQLite database schema
├── requirements.txt           # Project dependencies (Flask>=3.1.0)
└── README.md                  # Project documentation
```

---

## 3. Installation & Requirements

### Prerequisites
- Python 3.10+ (Tested on Python 3.14.2)
- Windows 10/11 or Linux / macOS
- Microsoft Sysmon (optional, for live Sysmon event collection)

### Installation Steps
1. Open PowerShell or Terminal in `D:\SecureScan`.
2. Activate or use the project virtual environment:
   ```powershell
   # If re-creating the virtual environment:
   py -3 -m venv .venv

   # Install dependencies inside the virtual environment:
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

---

## 4. How to Start the Application

Start the Flask server using the virtual environment:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open your web browser and navigate to:

```
http://127.0.0.1:5000
```

*Note: The server binds strictly to `127.0.0.1:5000` to prevent exposure to external network interfaces.*

---

## 5. Automated Test Suite

Run the complete test suite to verify database initialization, APIs, parsers, and static asset serving:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

---

## 6. How to Use SecureScan

### A. Generate Demo Events
1. In the **Security Overview** screen, click **＋ Generate demo events**.
2. SecureScan generates 10 sample records across Linux audit, Wireshark, Autopsy, Windows Security and Sysmon.
3. Every sample record is clearly labeled with a `DEMO` badge.
4. Click **Clear demo** in the top banner or Overview page to purge synthetic records while safely keeping all imported real evidence.

### B. Import Windows Security Event Logs
1. Run the PowerShell collector as Administrator:
   ```powershell
   .\collectors\windows_event_collector.ps1 -Hours 24 -OutputFile .\uploads\windows_events.json
   ```
2. Navigate to **System Audit** or **Process Audit** in the sidebar.
3. Click **＋ Import Windows audit** and select the exported JSON file.
4. SecureScan parses Event IDs 4624, 4625, 4688, 4720, 4726, and 4672.

### C. Import Microsoft Sysmon Events
1. **Install Sysmon** (if not already installed) – see section 9 below.
2. **Apply the SecureScan configuration** (requires Administrator):
   ```powershell
   sysmon.exe -c config\sysmon-config.xml
   ```
3. **Collect Sysmon events** using the dedicated collector:
   ```powershell
   .\collectors\sysmon_collector.ps1 -Hours 24 -OutputPath .\uploads\sysmon_events.json
   ```
4. Navigate to **System Audit**, **Process Audit**, or **Network Analysis** in the sidebar.
5. Click **＋ Import Sysmon JSON** and select the exported JSON file.
6. SecureScan parses Event IDs 1 (Process Create), 3 (Network Connect), 11 (File Create), and 22 (DNS Query).

### D. Import Linux Audit Logs (`auditd`)
1. Navigate to **System Audit** or **Process Audit** in the sidebar.
2. Click **＋ Import log / CSV**.
3. Select an audit log file (`.log` or `.txt`).
4. SecureScan parses standard `auditd` records (`USER_AUTH`, `USER_LOGIN`, `ADD_USER`, `DEL_USER`, `EXECVE`, `SYSCALL`, `PATH`), extracts users, commands, source IPs (`addr`), and records SHA-256 checksums into the `imports` table.

### E. Import Wireshark Packet Dissections
1. In Wireshark, export packets as CSV (`File > Export Packet Dissections > As CSV...`).
2. In SecureScan, navigate to **Network Analysis**.
3. Click **＋ Import Wireshark CSV**.
4. SecureScan maps standard and custom headers (`Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`), identifies protocols (DNS, TLS, SMB, TCP SYN), and applies security rules.

### F. Import Autopsy Forensic Findings
1. In Autopsy, generate or export a table report as CSV.
2. In SecureScan, navigate to **Forensic Evidence**.
3. Click **＋ Import Autopsy CSV**.
4. SecureScan maps file names, paths, sizes, timestamps, and comments, highlighting deleted files, credential artifacts, or temporary staging directories.

### F1. Live System Audit (Wireshark + Autopsy + Windows) — main workflow
Open **System Audit Console** in the sidebar:
1. **Run system audit**: 14 read-only checks of this PC (accounts, admins, open ports, live connections,
   firewall, Defender, UAC, RDP, SMBv1, autoruns, scheduled tasks, updates, risky processes, Security log).
   No Administrator rights needed.
2. **Start live capture**: pick an interface (e.g. Wi-Fi), a duration and a packet limit. TShark captures real
   traffic to a `.pcapng` evidence file (SHA-256 recorded), which is dissected and analysed.
   Requires Wireshark with TShark and Npcap.
3. **Analyse with Autopsy**: enter a folder or disk image path. SecureScan runs Autopsy's command-line ingest
   (case stored in `instance/autopsy_cases/`) and reads the case database read-only. You can also
   **Import Autopsy case** for any case built in the Autopsy GUI (case folder, `.aut` or `autopsy.db`).
   Typically takes 1–5 minutes.
Results appear in the Windows Audit, Network Intelligence, Evidence Explorer, Timeline, Threat Detections and Report pages.

### F2. Threat Detections (correlation engine)
- Open **Threat Detections** in the sidebar. `detections.py` runs 14 correlation rules over all evidence
  (brute force → success, discovery bursts, credential dumping, port scans, C2 beaconing, DGA/tunnelling DNS,
  cross-source corroboration, log clearing, …), each mapped to MITRE ATT&CK with the triggering events listed.
- Click **Load attack scenario** to push five coordinated evidence files (`sample_data/scenario/`) through the
  real parsers and watch the full attack chain light up. **Clear Demo Data** removes it.
- Full design, rule table and security review: see `PROJECT_REPORT.md`.

### G. Investigation Timeline & Search
- Use the **Investigation Timeline** module to see all evidence sources sequenced chronologically.
- Filter records in real time using the search box (matching title, category, source, user, IP, protocol, command, details, and reference) and the severity dropdown (`Critical`, `High`, `Medium`, `Low`, `Informational`).

### H. Reports & Investigation Summary
- Open the **Reports** module for an executive summary, severity breakdown, source metrics, and investigation notes.
- Click **Print / Save PDF** to generate a clean, print-optimized report.
- Click **Export CSV** to stream an authoritative CSV export of the database.

---

## 7. API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health`, `/api/health` | Application health & database status |
| GET | `/api/stats` | Dashboard counts and distributions |
| GET | `/api/events` | Query events (with search, source, severity filters) |
| GET | `/api/timeline` | Chronological timeline of all events |
| POST | `/api/events/demo` | Generate demo records |
| DELETE | `/api/events/demo` | Clear demo records only |
| POST | `/api/import/linux-audit` | Import Linux audit log file |
| POST | `/api/import/wireshark` | Import Wireshark CSV export |
| POST | `/api/import/autopsy` | Import Autopsy findings CSV |
| POST | `/api/import/windows-audit` | Import Windows Security event JSON/CSV |
| POST | `/api/import/sysmon` | Import Sysmon event JSON |
| POST | `/api/import/pcap` | Import raw PCAP / PCAPNG packet captures via TShark |
| GET | `/api/network/stats` | Aggregated network traffic & protocol statistics |
| GET | `/api/detections` | Correlation engine: MITRE ATT&CK detections, risk score, kill chain |
| POST | `/api/scenario` | Load the "Operation Night Owl" multi-source attack scenario (DEMO) |
| GET | `/api/imports` | Evidence import audit trail |
| GET | `/api/reports/summary` | Investigation summary report |
| GET | `/api/reports/export.csv` | Full CSV evidence export |

---

## 8. Forensic Integrity & Upload Security

- **Size Limit**: Enforces a strict 10 MB maximum file upload limit.
- **Allowed Formats**: Accepts `.log`, `.txt`, `.csv`, `.json`, `.pcap`, and `.pcapng`.
- **Integrity**: Calculates and stores SHA-256 hashes for all uploaded evidence files in the `imports` table.
- **Safety**: Uploaded files are stored in `uploads/` with unique filenames; they are never executed.
- **Web hardening**: only the UI files are served over HTTP (database, uploads and source are not reachable), cross-origin write requests are rejected (CSRF), and CSP / X-Frame-Options / nosniff headers are set.

---

## 9. Microsoft Sysmon Setup Guide

### What is Sysmon?

Microsoft Sysmon (System Monitor) is a Windows system service and device driver that logs detailed information about process creation, network connections, file creation, and DNS queries to the Windows Event Log.

### Installation

1. Download Sysmon from Microsoft Sysinternals:
   https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

2. Extract the archive to a convenient location (e.g., `C:\Tools\Sysmon\`).

3. Install Sysmon with the SecureScan configuration (**run as Administrator**):
   ```powershell
   sysmon.exe -accepteula -i D:\SecureScan\config\sysmon-config.xml
   ```

### Applying or Updating Configuration

If Sysmon is already installed, update the configuration (**run as Administrator**):

```powershell
sysmon.exe -c D:\SecureScan\config\sysmon-config.xml
```

### Verifying Sysmon

Check the installed Sysmon version and schema:
```powershell
sysmon -s
```

Verify the Sysmon service is running:
```powershell
Get-Service Sysmon64
```

Check the Sysmon event log:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### SecureScan Sysmon Configuration Details

The configuration file `config/sysmon-config.xml` uses **schema version 4.91** (Sysmon v18) and monitors:

| Event ID | Event Type | Description | Volume Note |
|----------|-----------|-------------|-------------|
| 1 | Process Create | Logs all process creation with command line, parent process, and SHA256 hash. Excludes noisy background processes. | Moderate |
| 3 | Network Connect | Logs outbound network connections. Excludes browser and Windows Update traffic. | **High – can generate many records** |
| 11 | File Create | **Scoped to `D:\SecureScan\sysmon-test\` only**. Extend the TargetFilename rule to monitor other directories. | Low (scoped) |
| 22 | DNS Query | Logs DNS name resolution from all processes. Excludes common Microsoft domains. | **High on active systems** |

### Collecting Sysmon Events

```powershell
# Collect events from the last 24 hours:
.\collectors\sysmon_collector.ps1 -Hours 24 -OutputPath .\uploads\sysmon_events.json

# Collect only Event IDs 1 and 22, limit to 50 events:
.\collectors\sysmon_collector.ps1 -Hours 1 -MaxEvents 50 -EventIds 1,22

# Collect from the last 48 hours with higher limit:
.\collectors\sysmon_collector.ps1 -Hours 48 -MaxEvents 5000
```

### Importing Sysmon Events into SecureScan

**Via the web interface:**
1. Start the Flask server: `.\.venv\Scripts\python.exe app.py`
2. Open `http://127.0.0.1:5000`
3. Navigate to System Audit, Process Audit, or Network Analysis
4. Click **＋ Import Sysmon JSON**
5. Select the exported JSON file

**Via the API (curl):**
```powershell
curl -X POST -F "file=@uploads/sysmon_events.json" http://127.0.0.1:5000/api/import/sysmon
```

---

## 10. Windows Event Collection Guide

### Required Audit Policies

To generate the Windows Security events that SecureScan can import, enable these audit policies (**run as Administrator**):

| Event ID | Required Audit Policy | Enable Command |
|----------|----------------------|----------------|
| 4624/4625 | Logon | `auditpol /set /subcategory:"Logon" /success:enable /failure:enable` |
| 4688 | Detailed Tracking | `auditpol /set /subcategory:"Detailed Tracking" /success:enable` |
| 4720/4726 | Account Management | `auditpol /set /subcategory:"Account Management" /success:enable` |
| 4672 | Special Logon | `auditpol /set /subcategory:"Special Logon" /success:enable` |

> **Note**: Windows Home editions may lack some audit policy capabilities. Reading the Security log requires Administrator privileges or membership in the 'Event Log Readers' group.

### Collecting Windows Events

```powershell
# As Administrator:
.\collectors\windows_event_collector.ps1 -Hours 24 -OutputFile .\uploads\windows_events.json
```

---

## 11. Wireshark & TShark Network Analysis Guide

### Roles & Responsibilities

- **Wireshark**: GUI packet capture tool and dissector. Captures raw network frames via Npcap and allows interactive protocol inspection.
- **TShark**: Terminal-based packet capture and dissection engine shipped with Wireshark. Extracts specific packet fields from `.pcap` and `.pcapng` files without requiring a GUI.
- **SecureScan**: Ingests, normalises, and correlates exported network observations into the local SQLite database alongside Windows Security, Sysmon, Linux auditd, and Autopsy findings.

> **Important**: SecureScan does not perform raw packet capture or replace Wireshark. It processes exported CSV records or uses TShark to read `.pcap`/`.pcapng` files.

### Wireshark & TShark Installation

1. Download Wireshark from the official portal:
   https://www.wireshark.org/download.html
2. Run the installer and ensure:
   - The **TShark** component is checked.
   - The **Npcap** packet capture driver is installed (required for live capture on Windows).
3. Default installation paths:
   - Wireshark: `C:\Program Files\Wireshark\Wireshark.exe`
   - TShark: `C:\Program Files\Wireshark\tshark.exe`

### Verifying TShark

Check that TShark is installed and accessible:

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -v
```

SecureScan automatically detects TShark in PATH or standard installation folders (`C:\Program Files\Wireshark\tshark.exe`).

### How to Capture Network Traffic

1. Open **Wireshark** as Administrator.
2. Select your active network interface (e.g., Ethernet or Wi-Fi).
3. (Optional) Apply a capture filter (e.g., `not broadcast and not multicast` or `tcp or udp`).
4. Click the blue shark fin icon to **Start capturing packets**.
5. Reproduce the network activity or incident you wish to investigate.
6. Click the red square icon to **Stop capturing packets**.

### How to Save Capture Files (`.pcapng` / `.pcap`)

1. In Wireshark, click **File > Save As...**.
2. Select **Wireshark/tcpdump/... - pcapng (*.pcapng)** or **Wireshark/tcpdump/... - pcap (*.pcap)**.
3. Save the file (e.g., `incident_traffic.pcapng`).
4. In SecureScan, go to **Network Analysis** > **＋ Import PCAP / PCAPNG** and select your file.
   - SecureScan invokes TShark with a strict argument list (no shell expansion) to extract timestamps, source/dest IPs (IPv4 and IPv6), protocols, ports, DNS queries, TCP flags, and packet lengths.

### How to Export Packet Dissections as CSV

If TShark is not available, or you prefer a lightweight text export:
1. In Wireshark, go to **File > Export Packet Dissections > As CSV...**.
2. Ensure columns include: `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`.
3. Save as CSV (e.g., `traffic_export.csv`).
4. In SecureScan, go to **Network Analysis** > **＋ Import Wireshark CSV**.

### Transparent Network Observation Rules

SecureScan applies transparent rules to highlight observations for analyst review:

| Rule Observation | Description | Investigative Lead Note |
|------------------|-------------|-------------------------|
| **Unusual Destination Port** | Traffic directed to non-standard ports (e.g., 4444, 1337, 31337, 6667, 8888, 9001) | May indicate reverse shells, custom proxies, or staging servers. Requires checking the originating process. |
| **DNS Resolution Activity** | Queries for external domains, dynamic DNS (e.g., ngrok, duckdns), or internal hosts | Correlates host network attempts with specific remote domains. |
| **TCP SYN Initiation** | Connection requests (`[SYN]`) without completed handshakes | Helps identify connection initiation, outbound beacons, or connection attempts to inactive services. |
| **TCP RST Termination** | Connection reset packets (`[RST]`) | Can indicate closed destination ports or firewall terminations. |
| **Lateral Administration** | SMB2, RPC, or RDP traffic | Expected in domain administration; unexpected lateral sessions should be verified against authorized change management. |
| **Encrypted TLS Sessions** | TLS 1.2 / TLS 1.3 handshakes | Standard secure transport. Payloads are ciphertext by design. |

*Note: Observations are flagged as leads for investigation; they do not automatically prove malicious cyberattacks.*

---

## 12. Important Forensic Disclaimers & Known Limitations

1. **Sysmon Integration**: SecureScan ingests Sysmon event JSON exports for correlation and reporting. It does not install, configure, or manage the Sysmon service. The Sysmon configuration and collector scripts are provided for convenience; apply them only after reviewing the configuration.
2. **Wireshark Integration**: Wireshark is the tool responsible for packet capture and packet dissection. SecureScan ingests exported CSV metadata for correlation and reporting; it does not replace Wireshark or capture raw network packets in real time.
3. **Autopsy Integration**: Autopsy performs forensic analysis, file recovery, and disk image indexing. SecureScan organizes selected findings exported from Autopsy; it does not directly parse or recover raw disk images.
4. **CAINE Workstation**: SecureScan is designed to be hosted on or used alongside forensic distributions such as CAINE. Forensic tools must be operated independently to generate export findings.
5. **Investigation Leads vs Attacks**: Rule-generated alerts (such as failed logins or privileged commands) are flagged as investigative leads. They require manual analyst validation and do not automatically prove a malicious cyberattack.
6. **Sample Data**: Files in `sample_data/` are clearly labelled as test data and must NOT be used as real evidence.
