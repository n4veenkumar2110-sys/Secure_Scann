import sqlite3
import os
from pathlib import Path
from flask import g, current_app

def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if 'db' not in g:
        db_path = current_app.config['DATABASE']
        # Ensure instance directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def close_db(e=None):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(app=None):
    """Initialises the database tables and indexes."""
    db_path = app.config['DATABASE'] if app else current_app.config['DATABASE']
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    # 1. Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        event_time TEXT NOT NULL,
        source TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'Informational',
        title TEXT NOT NULL,
        username TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        command TEXT,
        details TEXT,
        evidence_reference TEXT,
        is_demo INTEGER NOT NULL DEFAULT 0,
        imported_at TEXT NOT NULL,
        raw_payload TEXT
    )
    """)

    # 2. Imports Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS imports (
        id TEXT PRIMARY KEY,
        original_filename TEXT NOT NULL,
        stored_filename TEXT NOT NULL,
        source_type TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        total_records INTEGER NOT NULL DEFAULT 0,
        successful_records INTEGER NOT NULL DEFAULT 0,
        failed_records INTEGER NOT NULL DEFAULT 0,
        imported_at TEXT NOT NULL
    )
    """)

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events (event_time DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events (source)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_category ON events (category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_demo ON events (is_demo)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_imports_time ON imports (imported_at DESC)")

    conn.commit()
    conn.close()

def query_db(query, args=(), one=False):
    """Helper to query the database with parameterised queries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def modify_db(query, args=()):
    """Helper to execute an INSERT, UPDATE, or DELETE parameterised query."""
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    last_id = cur.lastrowid
    cur.close()
    return last_id
