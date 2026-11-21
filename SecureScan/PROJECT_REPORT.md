# SecureScan — System Audit Workbench using Wireshark & Autopsy

**Project report · Cybersecurity course project**

---

## 1. Abstract

SecureScan is a **system-audit workbench** for a Windows workstation. It audits the machine on
three levels and combines the results into one evidence base:

| Audit layer | Tool used | What SecureScan does with it |
|---|---|---|
| **Host configuration & live state** | Windows built-ins (PowerShell, Security log) | Runs 14 read-only checks: accounts, admins, open ports, live connections per process, firewall, Defender, UAC, RDP, SMBv1, autoruns, scheduled tasks, patch age, risky process paths, failed logons |
| **Network** | **Wireshark / TShark** | Captures live packets from the chosen interface, stores the `.pcapng` with its SHA-256, dissects it and flags scans, backdoor ports, suspicious DNS, etc. Also imports Wireshark CSV/PCAP files |
| **Disk & files** | **Autopsy** (The Sleuth Kit) | Drives Autopsy headlessly (create case → add folder/disk image → run ingest), then reads the case database read-only and flags deleted files, disguised executables, credential files, known-bad hashes, USB devices, duplicates |

All three feed the same correlation engine (e.g. *the host audit says `powershell.exe` holds a
connection to 198.51.100.7:4444, and the Wireshark capture independently saw that traffic*).

More broadly, SecureScan is a locally hosted **mini-SIEM and digital-forensics workbench**. It ingests evidence
produced by five standard security tools — **Windows Security Event Log, Microsoft Sysmon, Linux
`auditd`, Wireshark/TShark, and Autopsy** — normalises every record into one common event model in
SQLite, applies explainable detection rules, and then **correlates events across sources** into
incidents mapped to the **MITRE ATT&CK** framework. An analyst uses a browser dashboard to triage
detections, rebuild a cross-source timeline, explore an entity-relationship graph, and export a
printable investigation report. Evidence integrity is preserved with SHA-256 hashing, deterministic
de-duplication and strict separation of demo data from real evidence.

---

## 2. Problem statement

During an incident, the evidence is scattered across tools that do not talk to each other:

| Tool | What it sees | What it cannot see |
|---|---|---|
| Windows Security log | Logons, account changes, process creation | Network traffic, file contents |
| Sysmon | Detailed process, network, file, DNS activity on Windows | Other hosts, raw packets |
| Linux `auditd` | Logons and commands on Linux servers | Windows hosts |
| Wireshark | Every packet on the wire | Which *program* sent it |
| Autopsy | Files on disk, including deleted ones | *When/why* they were used |

An analyst has to open each tool, read thousands of entries, and mentally connect them. A single
failed logon or a single SYN packet means nothing on its own; **the attack is only visible when
events are linked** (e.g. *7 failed logons → 1 success from the same IP → discovery commands →
credential dumping → connection to a C2 server seen in both Sysmon and the PCAP*).

## 3. Objectives

1. Ingest exports from all five tools through one upload interface.
2. Normalise them into a single, searchable, indexed event schema.
3. Flag individually suspicious events with transparent, explained rules.
4. **Correlate** events across time and sources into MITRE ATT&CK-mapped detections with a risk score.
5. Provide timeline, graph and report views for investigation and documentation.
6. Preserve forensic integrity (hashing, originals kept, no duplicates, demo/real separation).
7. Be secure itself — a security tool must not become an attack surface.

---

## 4. What the project is (analysis of the existing code)

Before any changes, the folder contained a working Flask + SQLite application of ~5,000 lines:

| Component | File(s) | Role |
|---|---|---|
| Web server / REST API | `app.py`, `config.py` | 20 endpoints: imports, events, stats, timeline, graph, reports |
| Database layer | `database.py`, `schema.sql` | SQLite connection handling, `events` + `imports` tables, indexes |
| Windows parser | `collectors/windows_audit.py` | Event IDs 4624, 4625, 4672, 4688, 4720, 4726 (+ Sysmon fallback) |
| Sysmon parser | `collectors/sysmon_parser.py` | Event IDs 1 (process), 3 (network), 11 (file), 22 (DNS) |
| Linux parser | `parser_linux.py` | `USER_AUTH`, `USER_LOGIN`, `ADD_USER`, `DEL_USER`, `EXECVE`, `SYSCALL`, `PATH` |
| Network parser | `collectors/wireshark_parser.py` | Wireshark CSV + raw PCAP/PCAPNG through TShark (no shell) |
| Forensic parser | `parser_autopsy.py` | Autopsy CSV / TSV / JSON and SleuthKit bodyfile |
| Collectors | `collectors/*.ps1`, `config/sysmon-config.xml` | PowerShell scripts that export live Windows/Sysmon logs to JSON |
| Frontend | `index.html`, `app.js`, `style.css` | Single-page dashboard (overview, audit, process, network, evidence, timeline, graph, report, settings) |
| Tests | `tests/test_securescan.py` | 25 unit/integration tests |

**Verdict:** the ingestion, normalisation and per-event rules were complete and well built. What was
missing was the part that makes it a *threat-detection* system rather than a log viewer — the
**correlation layer** — and the application had **serious security flaws of its own**.

---

## 5. Architecture

```
  ┌──────────────── Evidence sources (tools run independently) ────────────────┐
  │ Windows Event Log   Sysmon        Linux auditd    Wireshark/TShark  Autopsy │
  │ (collector .ps1)    (collector)   (audit.log)     (CSV / PCAP)      (CSV/JSON│
  └────────┬──────────────┬──────────────┬───────────────┬────────────────┬────┘
           │  upload (multipart, ≤10 MB, extension allow-list, SHA-256)  │
           ▼              ▼              ▼               ▼                ▼
  ┌────────────────────────────── Flask API (app.py) ──────────────────────────┐
  │  CSRF origin check · security headers · only UI assets served              │
  │                                                                             │
  │  Parsers ──► TIER 1: per-event rules (severity + explanation per record)   │
  │      │                                                                      │
  │      ▼                                                                      │
  │  SQLite  events / imports  (deterministic IDs → no duplicates)             │
  │      │                                                                      │
  │      ▼                                                                      │
  │  TIER 2: detections.py — correlation engine (14 rules, MITRE ATT&CK,       │
  │          risk score, kill chain, entity ranking) — computed on demand       │
  └──────┬──────────────────────────────────────────────────────────────────────┘
         ▼  JSON
  ┌──────────────────────── Browser UI (app.js) ─────────────────────────────┐
  │ Overview + risk banner │ Threat Detections │ Windows/Process/Network audit │
  │ Evidence Explorer │ Timeline │ Relationship Graph │ Report (print/PDF, CSV)│
  └──────────────────────────────────────────────────────────────────────────┘
```

**Technology:** Python 3.10+ / Flask 3.1, SQLite 3, vanilla JavaScript (no framework, no CDN
scripts), optional Wireshark TShark for PCAP parsing. Runs entirely on `127.0.0.1:5000`.

### 5.1 Common event model

Every tool's output is mapped into one row shape (`events` table):
`event_time, source, category, severity, title, username, source_ip, destination_ip, protocol,
command, details, evidence_reference, is_demo, raw_payload`.
This is what makes cross-tool search, timeline and correlation possible.
See `schema.sql` for the documented schema.

---

## 6. Detection logic

### 6.1 Tier 1 — per-event rules (in the parsers)

| Source | Example rule | Severity |
|---|---|---|
| Windows | 4625 failed logon | High |
| Windows | 4726 account deleted · 4720 account created · 4672 special privileges | High · Medium · Medium |
| Windows / Sysmon | Process is a recon/LOLBin (whoami, net, nltest, certutil, rundll32, mshta…) | Medium |
| Sysmon | `mimikatz` or `vssadmin` in command line | High |
| Sysmon | Script interpreter (PowerShell, cmd…) opens a network connection | Medium |
| Sysmon | File created in Temp / Startup | Medium |
| Sysmon 22 | DNS to ngrok / pastebin / transfer.sh … | Medium |
| Linux | Failed `USER_AUTH`/`USER_LOGIN`, `DEL_USER` · privileged command (`sudo`, `passwd`, `chmod`) | High · Medium |
| Wireshark | Destination port 4444/1337/31337/6667/9001… · SYN to unassigned high port | Medium–High |
| Autopsy | Credential artefact (id_rsa, SAM hive, .kdbx) · deleted file · Temp staging | High · Medium · Medium |

### 6.2 Tier 2 — correlation engine (`detections.py`, new)

Each rule looks at **many events together** (sliding time windows, grouping by user/IP/domain,
and cross-source joins). Every detection lists the exact triggering events, the ATT&CK
technique, a plain-English explanation and a recommended response.

| Rule | Detection | Logic | ATT&CK | Severity |
|---|---|---|---|---|
| SS-001 | Password brute force | ≥5 failed logons from one IP/user within 10 min | T1110 | High |
| SS-002 | Brute force **followed by success** | SS-001 burst + successful logon by same IP/targeted user within 60 min | T1110, T1078 | Critical |
| SS-003 | Discovery burst | ≥3 *distinct* discovery commands by one user within 15 min | T1033, T1087, T1082 | Medium/High |
| SS-004 | Short-lived account | Account created then deleted within 24 h | T1136, T1531 | High |
| SS-005 | Credential dumping | Mimikatz/`sekurlsa`, LSASS MiniDump, `reg save HKLM\SAM`, `lsass.dmp` on disk | T1003 | Critical |
| SS-006 | Backup destruction | `vssadmin delete shadows`, `wbadmin delete`, `bcdedit recoveryenabled no` | T1490 | Critical |
| SS-007 | Malicious script / download cradle | `-enc` Base64, `IEX`, `DownloadString`, `certutil -urlcache`, `bitsadmin /transfer`, hidden window | T1059.001, T1105 | High |
| SS-008 | Port scan | One source → ≥10 distinct destination ports in 5 min (connection *attempts* only; SYN-ACK/RST replies ignored) | T1046 | High |
| SS-009 | C2 beaconing / backdoor port | Connections to known backdoor ports; ≥3 = beaconing | T1571, T1071 | High/Critical |
| SS-010 | Suspicious DNS | Tunnelling/dynamic-DNS/paste domains, or DGA-like label (length ≥16, Shannon entropy ≥3.5) | T1071.004, T1568.002 | Medium |
| SS-011 | **Cross-source corroboration** | Same remote IP in host telemetry (Sysmon/Windows/Linux) **and** in the packet capture | T1071 | inherits |
| SS-012 | Log clearing | `wevtutil cl`, `Clear-EventLog`, `auditctl -D`, `shred /var/log/...`, `history -c` | T1070.001 | High |
| SS-013 | Deletion during incident | Autopsy deleted-file entries within ±24 h of a High/Critical detection | T1070.004 | Medium |
| SS-014 | Private key exposure | id_rsa, .pem, .ppk, .kdbx, wallet.dat artefacts | T1552.004 | Medium |

**Risk score** = Σ(Critical 30, High 15, Medium 6, Low 2) capped at 100 →
`Critical ≥70 · High ≥40 · Medium ≥15 · Low >0`. Entities (users, IPs) are ranked by the total
weight of detections they appear in. Detections are grouped into an 8-stage kill chain
(Initial Access → Execution → Persistence → Credential Access → Discovery → C2 → Defense Evasion → Impact).

Design choices worth explaining in a viva:

* **Explainable, not black-box.** Every threshold is a named constant at the top of
  `detections.py`; every detection quotes the evidence. This matters in forensics, where a
  conclusion must be defensible.
* **Computed on demand, never stored.** Detections always match the current evidence; clearing demo
  data removes its detections automatically; there is no stale alert table.
* **Leads, not verdicts.** The UI and report state that detections require analyst validation.

---

## 6A. Live system audit — how each tool is used

Open **System Audit Console** in the sidebar. It has three panels.

### 6A.1 Windows host security audit (`collectors/host_audit.ps1` + `host_audit.py`)

A read-only PowerShell collector gathers the machine's security state as JSON. No Administrator
rights are needed; checks that need them (the Security log) are reported as *skipped*, not failed.
The raw JSON is stored in `uploads/` with its SHA-256, and every check becomes evidence
(source `System audit`).

| Check | Fails / warns when | Severity |
|---|---|---|
| Local accounts | Guest enabled · blank password allowed · password never expires | High · Medium · Low |
| Administrators group | More than 2 human administrators (least privilege) | Medium |
| Listening ports | FTP/Telnet/VNC/SMB/RDP/DB exposed on all interfaces, or a backdoor port (4444, 31337) | Medium–Critical |
| Active connections | Script interpreter with a network session · connection to a C2 port | Medium · High |
| Windows Firewall | Any profile disabled | High |
| Microsoft Defender | AV or real-time protection off · signatures > 7 days old | High |
| UAC | `EnableLUA = 0` | High |
| Remote Desktop | Enabled | Medium |
| SMBv1 | Enabled (WannaCry vector, MS17-010) | High |
| Autoruns (Run keys, Startup) | Entry launches from Temp/Downloads or via a script/LOLBin (T1547.001) | Medium |
| Scheduled tasks (non-Microsoft) | Runs from Temp or uses `-enc`/mshta/certutil (T1053.005) | Medium |
| Windows Update | Last update > 45 days (Medium) / > 90 days (High) | Medium/High |
| Process locations | Executables running from Temp/Downloads/Public | Medium |
| Security event log | Failed logons (4625), account creation/deletion, group changes in last 24 h | High/Medium |

**Result on the development laptop:** 12 passed, 2 warnings (an account allowed a blank
password; NetBIOS port 139 listening). 44 live connections were attributed to their processes.

### 6A.2 Network audit with Wireshark/TShark (`collectors/live_capture.py`)

* Interfaces are listed with `tshark -D`; only those can be chosen (no free-form input).
* Capture: `tshark -i <id> -a duration:<5-120> -c <10-20000> -w <file>.pcapng [-f <BPF filter>]`,
  run with an argument list (never a shell). The BPF filter is limited to its own character set.
* The `.pcapng` is hashed (SHA-256), kept in `uploads/`, dissected by TShark field extraction and
  stored as `Wireshark` events, then correlated with everything else.
* **Result:** a 10-second capture on Wi-Fi without admin rights → 291 packets imported.

### 6A.3 Disk & file forensics with Autopsy (`collectors/autopsy_case.py`)

1. **Run Autopsy:**
   `autopsy64.exe --nosplash --createCase --caseName=… --caseBaseDir=instance/autopsy_cases --addDataSource --dataSourcePath=<folder or image> --runIngest`
   (Autopsy's own ingest modules: hash calculation, file-type identification, recent activity,
   EXIF, PhotoRec carving, etc.). This runs as a background job and the UI polls its progress.
   Autopsy can open modal start-up dialogs (first-run notice, optional plug-in errors) that block
   command-line mode; SecureScan presses their default button for that Autopsy process only.
2. **Read the case:** `autopsy.db` (The Sleuth Kit SQLite case database) is opened with
   `mode=ro&immutable=1`, so the evidence database is never modified. It is hashed for custody.
3. **Findings produced:**
   * deleted files (unallocated `dir_flags`/`meta_flags`)
   * **extension mismatch** using Autopsy's MIME detection (e.g. `holiday_photo.jpg` is really
     `application/x-msdownload`, MITRE T1036.008)
   * executables in Temp/Downloads; credential files (`id_rsa`, `passwords.txt`, SAM hive, `.kdbx`)
   * **known-bad hash** hits (`known = 2`)
   * the same executable stored under different names (identical MD5)
   * every Autopsy *blackboard artifact*: USB devices, web history/downloads, recent documents,
     program runs, encryption detection, interesting-file hits, keyword hits
4. Cases built manually in the Autopsy GUI can be imported the same way (case folder, `.aut` or `autopsy.db`).

**Result on a test folder with five planted files:** Autopsy hashed and typed all five, and
SecureScan flagged all the planted items: `id_rsa` (High), `passwords.txt` (High), an
executable disguised as `holiday_photo.jpg` (High, extension mismatch), `svc_update.exe` in Temp
(Medium) and the duplicate executable (Medium). Only `notes.txt` stayed informational.

---

## 7. Security of SecureScan itself (vulnerabilities found and fixed)

A security review of the original code found the following. All are fixed and covered by tests.

| # | Severity | Vulnerability | Impact | Fix |
|---|---|---|---|---|
| 1 | **Critical** | `Flask(static_folder='.', static_url_path='')` served **every file in the project** | Anyone who can reach port 5000 could download `instance/securescan.db` (all evidence), every uploaded evidence file in `uploads/`, all source code and `.venv` | `static_folder=None`; only `index.html`, `style.css`, `app.js` served through explicit routes |
| 2 | High | No CSRF protection on state-changing endpoints | Any website the analyst visits could silently POST fake "evidence" into the case or trigger imports | `before_request` origin check: browser requests whose `Origin`/`Referer` host ≠ server host get **403** |
| 3 | Medium | `POST /api/events/sync` accepted arbitrary records with no validation and was unused by the UI | Evidence tampering — fabricated events indistinguishable from real ones | Endpoint removed |
| 4 | Medium | No browser security headers | Clickjacking, MIME sniffing, weaker XSS defence | `Content-Security-Policy` (`script-src 'self'`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Cache-Control: no-store` on API |
| 5 | Low | Two inline `onclick=""` handlers prevented a strict CSP | — | Replaced by a delegated `data-action` listener |

Verified safe already: all SQL is parameterised (no SQL injection); all dynamic HTML passes through
an `esc()` encoder (an injected `<img onerror>` payload rendered as text on every page); TShark is
invoked with an argument list, never a shell; uploads are size-limited, extension-checked,
renamed with `secure_filename`, never executed.

---

## 8. Forensic integrity

* **SHA-256** of every uploaded file is recorded in the `imports` table (chain of custody).
* **Originals preserved** unmodified in `uploads/` with a timestamped unique name.
* **Deterministic record IDs** (hash of record content) for all five parsers → re-importing the same
  file never creates duplicate evidence. *(The Linux parser used random UUIDs; it now uses content
  hashes like the others.)*
* **Demo vs real separation**: synthetic records carry `is_demo=1`, a visible `DEMO` badge, and are
  the only rows "Clear demo" can delete.
* `raw_payload` keeps the original line/row for every event, so any finding can be traced back.

---

## 9. How to run

```powershell
cd SecureScan
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
# open http://127.0.0.1:5000
```

Optional: install Wireshark with the TShark component to import raw `.pcap`/`.pcapng` files.

### 9.1 Demonstration script (≈5 minutes)

1. **Overview** — show the empty/real-evidence state and the risk banner.
2. **Threat Detections → Load attack scenario.** 78 events from 5 different evidence files are pushed
   through the real parsers ("Operation Night Owl", see `sample_data/scenario/README.md`).
3. Risk jumps to **100 / Critical**; all 8 kill-chain tactics light up; `j.mercer`, the attacker IP
   and the C2 IP top the entity ranking.
4. Open **SS-002 Brute force followed by successful logon** → expand *Show triggering evidence*:
   7 × Event 4625 then 4624 from `203.0.113.66`.
5. Open **SS-011 Cross-source corroboration** — Sysmon says *powershell.exe* talked to
   `198.51.100.23`; Wireshark independently captured the packets. Two tools agree.
6. **Investigation Timeline** — the whole attack in order across all five sources.
7. **Relationship Graph** — user → process → IP → domain links.
8. **Investigation Studio** — section 3 lists every detection with ATT&CK IDs; *Print / Save PDF*.
9. **Clear Demo Data** — scenario disappears; real evidence untouched.

### 9.2 Importing real evidence

| Tool | How to export | Where to import |
|---|---|---|
| Windows Security | `collectors\windows_event_collector.ps1 -Hours 24 -OutputFile .\uploads\windows_events.json` (admin) | Windows Audit → Import |
| Sysmon | Install with `config\sysmon-config.xml`, then `collectors\sysmon_collector.ps1` | Import Sysmon JSON |
| Linux | `/var/log/audit/audit.log` | Import log |
| Wireshark | *File → Export Packet Dissections → As CSV*, or the `.pcapng` itself | Network Intelligence → Import |
| Autopsy | *Generate Report → CSV/TSV/JSON* or a TSK bodyfile | Evidence Explorer → Import |

---

## 10. API reference (new / changed endpoints in bold)

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health + DB status |
| GET | `/api/stats` | Counts by severity/source/category **+ detection summary & risk score** |
| GET | `/api/events` | Search/filter events |
| GET | `/api/timeline` | Chronological events |
| GET | `/api/graph` | Entity-relationship graph |
| GET | **`/api/detections`** | **Run correlation engine → detections, risk, kill chain, entities** |
| POST | **`/api/scenario`** | **Load the multi-source attack scenario (DEMO)** |
| POST / DELETE | `/api/events/demo` | Create / purge demo records |
| POST | `/api/import/{windows-audit, sysmon, linux-audit, wireshark, pcap, autopsy}` | Evidence ingest |
| GET | `/api/network/stats` | Protocols, top talkers, DNS, TShark status |
| GET | `/api/imports` | Chain-of-custody log |
| GET | `/api/reports/summary` | Report data **+ detections section** |
| GET | `/api/reports/export.csv` | Full CSV export |
| POST | **`/api/audit/host`** · GET **`/api/audit/host/latest`** | **Run the Windows host audit / last audit's check results** |
| GET | **`/api/capture/interfaces`** · POST **`/api/capture/live`** | **TShark interfaces / live capture → .pcapng evidence** |
| GET | **`/api/autopsy/status`** · POST **`/api/autopsy/analyze`** · GET **`/api/autopsy/jobs/<id>`** | **Run Autopsy on a folder or image (background job)** |
| POST | **`/api/autopsy/import-case`** | **Import an existing Autopsy case read-only** |
| ~~POST~~ | ~~`/api/events/sync`~~ | **Removed (unauthenticated evidence injection)** |

---

## 11. Testing

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

**58 tests, all passing** — 25 original (`tests/test_securescan.py`) + 18 (`tests/test_detections_security.py`) + 15 (`tests/test_system_audit.py`: host-audit rules, TShark interface parsing / clamping / filter validation, Autopsy case import on a synthetic Sleuth Kit database incl. read-only guarantee, API routes and CSRF on the new endpoints). The remaining tests are listed below; first 18 new ones:
(`tests/test_detections_security.py`):

* Detection engine: brute force with/without success, below-threshold and spread-out failures do
  **not** fire, port scan ignores reply packets, beaconing + cross-source join, credential dumping,
  DGA entropy vs. normal domains, stable detection IDs.
* Regression: Autopsy no longer flags `sample.txt`/`Samsung.jpg` as credential files; real SAM hive
  still flagged.
* Security: project files return 404; UI assets still 200; security headers present; cross-origin
  DELETE / upload / scenario → 403; same-origin and CLI requests allowed; `/api/events/sync` gone.
* End-to-end: scenario fires 13 of 14 rules (SS-001 is correctly superseded by SS-002), all 8
  tactics, Critical risk; reloading does not duplicate events; clearing demo removes all detections.

---

## 12. Changes made in this review

| Area | Change |
|---|---|
| **Redesigned** `index.html`, `app.js`, `style.css` | Interface rebuilt from scratch following `DESIGN.md` (rules from the Impeccable and Anthropic frontend-design skills): IBM Plex type, OKLCH light and dark themes, one SVG icon set, a severity system of shape plus colour plus word, event details in a side panel, no emoji, glyph icons, gradients, glows or card grids. The previous UI is kept in `instance/ui_backup_2026-11-21/` |
| **New** `DESIGN.md` | Design system: sources, principles, type scale, colour tokens, layout, motion, refused patterns, UX-writing rules |
| **New** `collectors/host_audit.ps1`, `host_audit.py` | Read-only Windows host security audit (14 checks) stored as evidence |
| **New** `collectors/live_capture.py` | Live Wireshark/TShark capture with validated interface, clamped limits, no shell |
| **New** `collectors/autopsy_case.py` | Runs Autopsy command-line ingest and imports Autopsy case databases read-only |
| **New** System Audit Console page | One screen to run the host audit, a live capture and an Autopsy analysis |
| **New** `tests/test_system_audit.py` | 15 tests for the three integrations |
| **New** `detections.py` | 14-rule correlation engine with MITRE ATT&CK mapping, risk score, kill chain, entity ranking |
| **New** `sample_data/scenario/` | 5 coordinated evidence files telling one intrusion story + README |
| **New** `tests/test_detections_security.py` | 18 tests |
| **New** `PROJECT_REPORT.md` | This document |
| `app.py` | Closed file-exposure hole; CSRF origin check; security headers; removed `/api/events/sync`; added `/api/detections`, `/api/scenario`; detection data in stats & report; Linux import reports duplicates |
| `app.js`, `index.html`, `style.css` | New **Threat Detections** page (risk gauge, kill chain, entity ranking, filterable detection cards with evidence drill-down and ATT&CK links); risk banner on Overview; nav badge; detections section in report; CSP-safe handlers; upload limit text corrected 50 MB → 10 MB |
| `parser_autopsy.py` | Fixed `'sam'` substring false positive (High alerts on any file containing "sam") |
| `parser_linux.py` | Deterministic IDs → no duplicate evidence on re-import |
| `schema.sql` | Rewritten to match the real database (documented tables that did not exist; omitted `imports`) |
| `.venv` | The bundled venv pointed to another PC's Python and could not run; recreated. The old one is kept as `.venv_broken_old` and can be deleted |

---

## 13. Limitations & future work

* **No authentication.** Mitigated by binding to `127.0.0.1` only; a multi-user deployment would need
  login + roles.
* **Batch, not real-time.** Evidence is uploaded as exports; a live agent (e.g. Windows Event
  Forwarding, Beats) could stream events.
* **Rule-based.** Thresholds are static; a baseline/anomaly model (per-user normal logon hours, per-host
  normal destinations) would reduce false positives in large environments.
* **Single host per scenario.** Host name is kept in `details`, not a dedicated column; adding a
  `hostname` column would allow per-host correlation.
* **Threat intelligence.** IPs, domains and hashes could be enriched against feeds (AbuseIPDB,
  VirusTotal) — deliberately omitted to keep the tool fully offline.
* Sigma-rule import would let the engine reuse community detection content.

---

## 14. References

* MITRE ATT&CK Enterprise Matrix — https://attack.mitre.org/
* Microsoft Sysinternals Sysmon — https://learn.microsoft.com/sysinternals/downloads/sysmon
* Windows Security Auditing event reference (4624, 4625, 4672, 4688, 4720, 4726)
* Linux Audit (`auditd`) documentation — `man auditd`, `man ausearch`
* Wireshark / TShark user guide — https://www.wireshark.org/docs/
* Autopsy / The Sleuth Kit — https://www.sleuthkit.org/
* OWASP: CSRF Prevention, Secure Headers, Content Security Policy cheat sheets
* RFC 5737 — IPv4 address blocks reserved for documentation (used in the scenario)
