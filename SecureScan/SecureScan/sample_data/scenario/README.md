# Operation Night Owl — attack scenario dataset

> **SCENARIO DATA — synthetic. NOT real evidence.** All public IPs are from the RFC 5737
> documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`).

Load it from **Threat Detections → Load attack scenario** (or `POST /api/scenario`).
Each file goes through the **same parser a real upload would use**, so the scenario exercises
the full ingest pipeline. Records are tagged `DEMO` and removed by **Clear Demo Data**.

**Cast**

| Role | Value |
|---|---|
| Victim workstation | `WS-FIN-07` / `10.10.20.15`, user `j.mercer` |
| Attacker | `203.0.113.66` |
| C2 server | `198.51.100.23:4444` (domain `update-cdn.ngrok-free.app`) |
| Linux file server (lateral movement) | `10.10.20.5`, account `backup` (uid 1001) |

**Storyline (2026-11-18, UTC)**

| Time | Evidence file | What happens | Detection that fires |
|---|---|---|---|
| 02:00–02:02 | `network_capture.csv` | Attacker SYN-scans 12 ports on the workstation | SS-008 Port scan (T1046) |
| 02:06–02:09 | `windows_security.json` | 7 × Event 4625 failed RDP logons for `j.mercer` | SS-002 (T1110) |
| 02:10 | `windows_security.json` | Event 4624 success from same IP + 4672 SeDebugPrivilege | SS-002 Brute force → success (T1078) |
| 02:12–02:15 | `windows_security.json` | whoami, net user, net localgroup, nltest, systeminfo, ipconfig | SS-003 Discovery burst |
| 02:18 | `sysmon.json` | Hidden Base64 PowerShell; DNS to ngrok + DGA-like domain | SS-007, SS-010 |
| 02:19–02:29 | `sysmon.json` + `network_capture.csv` | 3 beacons to `198.51.100.23:4444` seen by **both** sources | SS-009 C2 beaconing, SS-011 cross-source |
| 02:23–02:27 | `sysmon.json` | certutil download; Mimikatz `sekurlsa`; comsvcs MiniDump of LSASS | SS-007, SS-005 Credential dumping |
| 02:31 / 03:55 | `windows_security.json` | `svc_backup2` created (4720), deleted 1.4 h later (4726) | SS-004 Account churn |
| 02:33–02:35 | `linux_audit.log` | SSH pivot to file server; `id`, `uname`, `cat /etc/passwd`; `wget`; `shred /var/log/auth.log` | SS-003, SS-012 |
| 02:40–02:44 | `sysmon.json` / `windows_security.json` | `vssadmin delete shadows`; `wevtutil cl Security` | SS-006, SS-012 |
| 02:46–02:47 | `autopsy_findings.csv` | `m.exe` and `lsass.dmp` recovered as deleted; `id_rsa` found | SS-013, SS-005, SS-014 |

Expected result: risk score **100/100 (Critical)** with all eight ATT&CK tactics in the kill chain lit.
