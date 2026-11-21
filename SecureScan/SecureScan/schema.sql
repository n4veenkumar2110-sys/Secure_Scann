-- =====================================================================
-- SecureScan SQLite Database Schema
-- Version: 1.1.0
-- Mirrors database.py:init_db() exactly (database.py is authoritative).
-- =====================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- Table: events
-- One normalised row per security / network / forensic observation,
-- regardless of which tool produced it (common event model).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,                       -- Deterministic content hash (e.g. win-1a2b..., audit-..., autopsy-...)
                                               -- -> re-importing the same evidence never creates duplicates
    event_time TEXT NOT NULL,                  -- ISO 8601 UTC timestamp of the observation
    source TEXT NOT NULL,                      -- 'Windows audit' | 'Sysmon' | 'Linux audit' | 'Wireshark' | 'Autopsy'
    category TEXT NOT NULL,                    -- 'Authentication' | 'Process' | 'Network' | 'Forensic' | 'Account' | 'System'
    severity TEXT NOT NULL DEFAULT 'Informational', -- 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
    title TEXT NOT NULL,                       -- Human-readable summary produced by the parser rule
    username TEXT,                             -- Account associated with the event
    source_ip TEXT,                            -- Source IPv4/IPv6
    destination_ip TEXT,                       -- Destination IPv4/IPv6
    protocol TEXT,                             -- DNS, TLS, TCP, NTLM, SSH ...
    command TEXT,                              -- Command line / executable / "srcport → dstport"
    details TEXT,                              -- Rule explanation + structured key/value context
    evidence_reference TEXT,                   -- Chain-of-custody reference (e.g. WIN-4625-1001, SCN-PCAP-0007)
    is_demo INTEGER NOT NULL DEFAULT 0,        -- 1 = synthetic demo / scenario record, 0 = real imported evidence
    imported_at TEXT NOT NULL,                 -- ISO 8601 UTC time the row was stored
    raw_payload TEXT                           -- Original log line / CSV row / JSON object (truncated to 1000 chars)
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_source ON events (source);
CREATE INDEX IF NOT EXISTS idx_events_category ON events (category);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_demo ON events (is_demo);

-- ---------------------------------------------------------------------
-- Table: imports
-- Evidence intake log / chain of custody: one row per uploaded file.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS imports (
    id TEXT PRIMARY KEY,                       -- e.g. imp-win-3f9a1c2b7d
    original_filename TEXT NOT NULL,           -- Sanitised client filename
    stored_filename TEXT NOT NULL,             -- Timestamped copy preserved in uploads/
    source_type TEXT NOT NULL,                 -- Which parser handled it
    sha256_hash TEXT NOT NULL,                 -- SHA-256 of the exact bytes received (integrity)
    total_records INTEGER NOT NULL DEFAULT 0,
    successful_records INTEGER NOT NULL DEFAULT 0,
    failed_records INTEGER NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_imports_time ON imports (imported_at DESC);

-- NOTE: Correlated detections (detections.py) are NOT stored. They are computed
-- on demand from the events table by GET /api/detections, so they always match
-- the current evidence and disappear automatically when demo data is cleared.
