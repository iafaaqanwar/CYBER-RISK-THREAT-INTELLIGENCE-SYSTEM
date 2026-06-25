"""
============================================================
 db_manager.py — Secure SQLite Vault Manager
 Cyber Risk & Threat Intelligence System
============================================================
 Manages the encrypted threat log database (threat_logs.db).
 All incident data is encrypted with AES-256-GCM via
 encryption.py before being stored, implementing a
 Zero Trust architecture for log integrity.
============================================================
"""

import os
import json
import sqlite3
from datetime import datetime

from encryption import encrypt_dict, decrypt_dict

# ============================================================
# Configuration
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "threat_logs.db")


def _get_connection() -> sqlite3.Connection:
    """
    Creates and returns a new SQLite connection with WAL mode
    enabled for concurrent read performance.

    Returns:
        sqlite3.Connection: Database connection object.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Enable dict-like row access
    conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """
    Initializes the threat_logs database.

    Creates the 'threat_logs' table if it doesn't exist.
    The table stores encrypted incident data with metadata
    columns for efficient querying without decryption.

    Table Schema:
      - id:                 Auto-increment primary key
      - timestamp:          ISO 8601 timestamp of the incident
      - src_ip:             Source IP address (plaintext for filtering)
      - dst_ip:             Destination IP address (plaintext for filtering)
      - threat_type:        Attack category (plaintext for dashboard)
      - risk_level:         Severity rating (plaintext for dashboard)
      - encrypted_payload:  AES-256-GCM encrypted full incident JSON
      - nonce:              GCM nonce (base64 encoded)
      - salt:               PBKDF2 salt (base64 encoded)
      - created_at:         Record creation timestamp
    """
    conn = _get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp           TEXT NOT NULL,
                src_ip              TEXT NOT NULL DEFAULT '0.0.0.0',
                dst_ip              TEXT NOT NULL DEFAULT '0.0.0.0',
                threat_type         TEXT NOT NULL DEFAULT 'unknown',
                risk_level          TEXT NOT NULL DEFAULT 'low',
                encrypted_payload   TEXT NOT NULL,
                nonce               TEXT NOT NULL,
                salt                TEXT NOT NULL,
                created_at          TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)

        # Index on risk_level for fast filtering on the dashboard
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_risk_level
            ON threat_logs(risk_level)
        """)

        # Index on timestamp for chronological queries
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp
            ON threat_logs(timestamp)
        """)

        conn.commit()
        print(f"[DB] Threat logs database initialized: {DB_PATH}")

    except sqlite3.Error as e:
        print(f"[ERROR] Database initialization failed: {e}")
        raise

    finally:
        conn.close()


def insert_threat_log(threat_entry: dict) -> int:
    """
    Encrypts and inserts a threat incident into the secure vault.

    The full incident dictionary is serialized to JSON and encrypted
    using AES-256-GCM before storage. Selected fields (src_ip,
    dst_ip, threat_type, risk_level) are stored in plaintext
    columns for efficient dashboard queries.

    Args:
        threat_entry: Dictionary containing threat diagnosis data.
                      Expected keys: 'src_ip', 'dst_ip', 'threat_type',
                      'risk_level', 'timestamp', and any additional fields.

    Returns:
        int: The row ID of the inserted record.

    Raises:
        sqlite3.Error: If the database insert fails.
    """
    # Encrypt the entire incident payload
    encrypted = encrypt_dict(threat_entry)

    # Extract plaintext metadata for queryable columns
    timestamp = threat_entry.get("timestamp", datetime.now().isoformat())
    src_ip = threat_entry.get("src_ip", "0.0.0.0")
    dst_ip = threat_entry.get("dst_ip", "0.0.0.0")
    threat_type = threat_entry.get("threat_type", "unknown")
    risk_level = threat_entry.get("risk_level", "low")

    conn = _get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO threat_logs
                (timestamp, src_ip, dst_ip, threat_type, risk_level,
                 encrypted_payload, nonce, salt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                src_ip,
                dst_ip,
                threat_type,
                risk_level,
                encrypted["ciphertext"],
                encrypted["nonce"],
                encrypted["salt"],
            ),
        )
        conn.commit()
        row_id = cursor.lastrowid
        print(f"[DB] Threat logged: ID={row_id}, Type={threat_type}, "
              f"Risk={risk_level}, Src={src_ip}")
        return row_id

    except sqlite3.Error as e:
        print(f"[ERROR] Failed to insert threat log: {e}")
        raise

    finally:
        conn.close()


def get_all_logs(limit: int = 100, offset: int = 0) -> list:
    """
    Retrieves and decrypts all threat logs from the vault.

    Logs are returned in reverse chronological order (newest first).
    Each entry is decrypted from its AES-256-GCM encrypted payload.

    Args:
        limit:  Maximum number of records to return (default: 100).
        offset: Number of records to skip (for pagination).

    Returns:
        list: List of decrypted threat log dictionaries, each
              augmented with 'id' and 'created_at' fields.
    """
    conn = _get_connection()
    try:
        rows = conn.execute(
            """
            SELECT id, timestamp, src_ip, dst_ip, threat_type, risk_level,
                   encrypted_payload, nonce, salt, created_at
            FROM threat_logs
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

        logs = []
        for row in rows:
            try:
                # Reconstruct the encrypted data dict for decryption
                encrypted_data = {
                    "ciphertext": row["encrypted_payload"],
                    "nonce": row["nonce"],
                    "salt": row["salt"],
                }

                # Decrypt the full incident payload
                decrypted = decrypt_dict(encrypted_data)

                # Augment with database metadata
                decrypted["id"] = row["id"]
                decrypted["created_at"] = row["created_at"]

                logs.append(decrypted)

            except Exception as e:
                # If a single record fails to decrypt, log it and continue
                print(f"[ERROR] Failed to decrypt log ID={row['id']}: {e}")
                logs.append({
                    "id": row["id"],
                    "threat_type": row["threat_type"],
                    "risk_level": row["risk_level"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "timestamp": row["timestamp"],
                    "created_at": row["created_at"],
                    "decryption_error": True,
                })

        return logs

    except sqlite3.Error as e:
        print(f"[ERROR] Failed to retrieve logs: {e}")
        return []

    finally:
        conn.close()


def get_log_by_id(log_id: int) -> dict:
    """
    Retrieves and decrypts a single threat log by its ID.

    Args:
        log_id: Integer primary key of the log entry.

    Returns:
        dict: Decrypted threat log, or None if not found.
    """
    conn = _get_connection()
    try:
        row = conn.execute(
            """
            SELECT id, timestamp, src_ip, dst_ip, threat_type, risk_level,
                   encrypted_payload, nonce, salt, created_at
            FROM threat_logs
            WHERE id = ?
            """,
            (log_id,),
        ).fetchone()

        if row is None:
            return None

        # Decrypt
        encrypted_data = {
            "ciphertext": row["encrypted_payload"],
            "nonce": row["nonce"],
            "salt": row["salt"],
        }
        decrypted = decrypt_dict(encrypted_data)
        decrypted["id"] = row["id"]
        decrypted["created_at"] = row["created_at"]

        return decrypted

    except sqlite3.Error as e:
        print(f"[ERROR] Failed to retrieve log ID={log_id}: {e}")
        return None

    finally:
        conn.close()


def get_log_count() -> int:
    """
    Returns the total number of threat logs in the vault.

    Returns:
        int: Total log count.
    """
    conn = _get_connection()
    try:
        result = conn.execute("SELECT COUNT(*) FROM threat_logs").fetchone()
        return result[0] if result else 0
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


def get_threat_summary() -> dict:
    """
    Returns an aggregated summary of threats by type and risk level.
    Uses the plaintext metadata columns (no decryption needed).

    Returns:
        dict with 'by_type' and 'by_risk' aggregation dicts.
    """
    conn = _get_connection()
    try:
        # Count by threat type
        type_rows = conn.execute(
            """
            SELECT threat_type, COUNT(*) as count
            FROM threat_logs
            GROUP BY threat_type
            ORDER BY count DESC
            """
        ).fetchall()

        # Count by risk level
        risk_rows = conn.execute(
            """
            SELECT risk_level, COUNT(*) as count
            FROM threat_logs
            GROUP BY risk_level
            ORDER BY count DESC
            """
        ).fetchall()

        return {
            "by_type": {row["threat_type"]: row["count"] for row in type_rows},
            "by_risk": {row["risk_level"]: row["count"] for row in risk_rows},
            "total": get_log_count(),
        }

    except sqlite3.Error as e:
        print(f"[ERROR] Failed to get threat summary: {e}")
        return {"by_type": {}, "by_risk": {}, "total": 0}

    finally:
        conn.close()


# ============================================================
# Self-Test
# ============================================================
if __name__ == "__main__":
    print("=" * 50)
    print(" Secure Vault Manager — Self-Test")
    print("=" * 50)

    # Initialize database
    init_db()

    # Insert a test threat
    test_threat = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "protocol": "tcp",
        "dst_port": 80,
        "threat_type": "ddos",
        "risk_level": "critical",
        "mitigation": "Deploy rate limiting and SYN cookies.",
        "timestamp": datetime.now().isoformat(),
    }

    print(f"\n[TEST] Inserting threat: {test_threat['threat_type']}")
    row_id = insert_threat_log(test_threat)
    print(f"[TEST] Inserted with ID: {row_id}")

    # Retrieve and decrypt
    print(f"\n[TEST] Retrieving log ID={row_id}...")
    retrieved = get_log_by_id(row_id)
    print(f"[TEST] Decrypted: {retrieved}")

    # Verify integrity
    assert retrieved["threat_type"] == test_threat["threat_type"]
    assert retrieved["src_ip"] == test_threat["src_ip"]
    print("\n[PASS] Secure Vault self-test PASSED ✓")

    # Summary
    summary = get_threat_summary()
    print(f"\n[TEST] Threat summary: {summary}")
