import json
import sqlite3
from pathlib import Path


DB_PATH = Path(
    __file__).resolve().parent / "mailroom.db"


def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS evaluations (
            evaluation_id TEXT PRIMARY KEY,
            input_digest TEXT NOT NULL,
            request_json TEXT NOT NULL,
            response_json TEXT NOT NULL,
            verifier_json TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS dossier_cache (
            content_fingerprint TEXT PRIMARY KEY,
            proposal_json TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS receipts (
            evaluation_id TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            PRIMARY KEY (evaluation_id, receipt_id)
        )
    """)

    conn.commit()
    conn.close()


def get_evaluation(evaluation_id):
    conn = get_connection()

    row = conn.execute(
        """
        SELECT *
        FROM evaluations
        WHERE evaluation_id = ?
        """,
        (evaluation_id,)
    ).fetchone()

    conn.close()

    if not row:
        return None

    return {
        "evaluation_id": row["evaluation_id"],
        "input_digest": row["input_digest"],
        "request": json.loads(row["request_json"]),
        "response": json.loads(row["response_json"]),
        "verifier": json.loads(row["verifier_json"])
    }


def save_evaluation(
    evaluation_id,
    input_digest,
    request,
    response,
    verifier
):
    conn = get_connection()

    conn.execute(
        """
        INSERT INTO evaluations
        (
            evaluation_id,
            input_digest,
            request_json,
            response_json,
            verifier_json
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            evaluation_id,
            input_digest,
            json.dumps(request, sort_keys=True),
            json.dumps(response, sort_keys=True),
            json.dumps(verifier, sort_keys=True)
        )
    )

    conn.commit()
    conn.close()


def get_cached_proposal(fingerprint):
    conn = get_connection()

    row = conn.execute(
        """
        SELECT proposal_json
        FROM dossier_cache
        WHERE content_fingerprint = ?
        """,
        (fingerprint,)
    ).fetchone()

    conn.close()

    if not row:
        return None

    return json.loads(row["proposal_json"])


def save_cached_proposal(fingerprint, proposal):
    conn = get_connection()

    conn.execute(
        """
        INSERT OR IGNORE INTO dossier_cache
        (
            content_fingerprint,
            proposal_json
        )
        VALUES (?, ?)
        """,
        (
            fingerprint,
            json.dumps(proposal, sort_keys=True)
        )
    )

    conn.commit()
    conn.close()


def save_receipt(evaluation_id, receipt):
    conn = get_connection()

    conn.execute(
        """
        INSERT OR IGNORE INTO receipts
        (
            evaluation_id,
            receipt_id,
            receipt_json
        )
        VALUES (?, ?, ?)
        """,
        (
            evaluation_id,
            receipt["receiptId"],
            json.dumps(receipt, sort_keys=True)
        )
    )

    conn.commit()
    conn.close()


def get_receipts(evaluation_id):
    conn = get_connection()

    rows = conn.execute(
        """
        SELECT receipt_json
        FROM receipts
        WHERE evaluation_id = ?
        """,
        (evaluation_id,)
    ).fetchall()

    conn.close()

    return [
        json.loads(row["receipt_json"])
        for row in rows
    ]
