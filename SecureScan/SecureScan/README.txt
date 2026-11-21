SECURESCAN – Security Audit & Digital Forensics Workbench
==========================================================

Overview
--------
SecureScan is a local cybersecurity intelligence and digital forensics application.
It integrates Linux audit records (auditd), Wireshark network packet analysis, and
Autopsy digital forensic findings into a unified SQLite database and browser workbench.

Architecture
------------
- Frontend: Single-page dark cybersecurity interface (index.html, style.css, app.js).
- Backend: Python Flask REST API running locally at http://127.0.0.1:5000 (app.py).
- Database: SQLite 3 database at instance/securescan.db with parameterised queries and indexes.
- Evidence Storage: Uploaded original files safely stored in uploads/ with SHA-256 hashes.

Quick Start
-----------
1. Start the Flask application:
   .\.venv\Scripts\python.exe app.py

2. Open your browser:
   http://127.0.0.1:5000

Run Automated Tests
-------------------
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v

Features
--------
1. Seven integrated investigation modules:
   - Security Overview / Dashboard (/api/stats)
   - System Audit (Linux auditd logs / CSV)
   - Process Audit (Process execution events)
   - Network Analysis (Wireshark packet observation CSV exports)
   - Forensic Evidence (Autopsy artifact & file finding exports)
   - Investigation Timeline (/api/timeline)
   - Reports (/api/reports/summary, printable PDF, and CSV export)
2. Live search across all metadata fields and severity filtering.
3. Realistic demo event generation (POST /api/events/demo) and cleanup (DELETE /api/events/demo).
4. File upload security: 10 MB limit, extension validation, safe filenames, SHA-256 verification.
5. SQLite is the authoritative data source; records persist across sessions.

Important Disclaimers
---------------------
- Wireshark performs packet capture; SecureScan correlates exported CSV data.
- Autopsy performs forensic examination; SecureScan organizes exported findings.
- CAINE is the forensic platform; SecureScan acts as the reporting workbench.
