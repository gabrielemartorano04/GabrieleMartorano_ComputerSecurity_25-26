"""
db_logger.py
SQLite-backed audit log and replay-attack prevention.

Tables:
  audit_log        — every action taken by any role
  processed_orders — order IDs the Department has already processed
                     (prevents replaying a supervisor→dept message)
"""

import sqlite3
from datetime import datetime
from config import DB_PATH


def _get_conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = _get_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT    NOT NULL,
            actor      TEXT    NOT NULL,
            action     TEXT    NOT NULL,
            order_id   TEXT,
            details    TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS processed_orders (
            order_id     TEXT PRIMARY KEY,
            processed_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# Audit logging
# ─────────────────────────────────────────────

def log_action(actor: str, action: str, order_id: str = None, details: str = ""):
    """Insert one row into audit_log."""
    init_db()
    conn = _get_conn()
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_log (timestamp, actor, action, order_id, details) "
        "VALUES (?, ?, ?, ?, ?)",
        (datetime.utcnow().isoformat(timespec="seconds") + "Z",
         actor, action, order_id, details)
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# Replay protection
# ─────────────────────────────────────────────

def is_replay(order_id: str) -> bool:
    """Return True if this order_id has already been processed by the Department."""
    init_db()
    conn = _get_conn()
    c = conn.cursor()
    c.execute("SELECT 1 FROM processed_orders WHERE order_id = ?", (order_id,))
    exists = c.fetchone() is not None
    conn.close()
    return exists


def mark_order_processed(order_id: str):
    """Record that the Department has processed this order_id."""
    init_db()
    conn = _get_conn()
    c = conn.cursor()
    c.execute(
        "INSERT OR IGNORE INTO processed_orders (order_id, processed_at) VALUES (?, ?)",
        (order_id, datetime.utcnow().isoformat(timespec="seconds") + "Z")
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────

def print_audit_log():
    """Pretty-print the full audit log to stdout."""
    init_db()
    conn = _get_conn()
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, actor, action, order_id, details "
        "FROM audit_log ORDER BY id"
    )
    rows = c.fetchall()
    conn.close()

    W = 76
    print("\n" + "=" * W)
    print(f"{'  FULL AUDIT LOG':^{W}}")
    print("=" * W)
    print(f"  {'Timestamp':<24} {'Actor':<14} {'Action':<26} Order ID")
    print("-" * W)
    for ts, actor, action, oid, details in rows:
        short_oid = (oid[:18] + "..") if oid and len(oid) > 20 else (oid or "-")
        print(f"  {ts:<24} {actor:<14} {action:<26} {short_oid}")
        if details:
            print(f"    └─ {details}")
    print("=" * W + "\n")
