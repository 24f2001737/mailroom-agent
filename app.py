import os
import json
import hashlib
import sqlite3
import base64
import uuid
from datetime import datetime, timezone
from typing import Any
from flask import Flask, request, jsonify

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


app = Flask(__name__)

PROFILE = "ga5-mailroom-action-gate/v2"
DB_PATH = os.environ.get("DB_PATH", "/tmp/mailroom.db")

ALLOWED_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS evaluations (
            evaluation_id TEXT PRIMARY KEY,
            profile TEXT NOT NULL,
            input_digest TEXT NOT NULL,
            dossiers_json TEXT NOT NULL,
            proposals_json TEXT NOT NULL,
            verifier_json TEXT NOT NULL,
            response_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS dossier_cache (
            fingerprint TEXT PRIMARY KEY,
            dossier_id TEXT NOT NULL,
            proposal_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS commits (
            evaluation_id TEXT PRIMARY KEY,
            input_digest TEXT NOT NULL,
            receipts_json TEXT NOT NULL,
            response_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ============================================================
# CANONICAL JSON / HASHING
# ============================================================

def canonicalize(value: Any) -> Any:
    """
    Recursively sort dictionary keys.
    Arrays preserve their order.
    """
    if isinstance(value, dict):
        return {
            key: canonicalize(value[key])
            for key in sorted(value.keys())
        }

    if isinstance(value, list):
        return [canonicalize(x) for x in value]

    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonicalize(value),
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


# ============================================================
# VALIDATION HELPERS
# ============================================================

def bad_request(message, status=400):
    return jsonify({
        "error": message
    }), status


def is_string(value):
    return isinstance(value, str)


def validate_dossier(dossier):
    if not isinstance(dossier, dict):
        return False

    required = [
        "dossierId",
        "partition",
        "receivedAt",
        "mailbox",
        "objective",
        "sources",
    ]

    if any(key not in dossier for key in required):
        return False

    if dossier["partition"] not in {
        "stable_core",
        "fresh_audit",
    }:
        return False

    if not isinstance(dossier["sources"], list):
        return False

    line_ids = set()

    for source in dossier["sources"]:
        if not isinstance(source, dict):
            return False

        if "lines" not in source:
            return False

        if not isinstance(source["lines"], list):
            return False

        for line in source["lines"]:
            if not isinstance(line, dict):
                return False

            if "lineId" not in line or "text" not in line:
                return False

            line_id = line["lineId"]

            if line_id in line_ids:
                return False

            line_ids.add(line_id)

    return True


def get_all_lines(dossier):
    lines = []

    for source in dossier.get("sources", []):
        for line in source.get("lines", []):
            lines.append({
                "lineId": line.get("lineId"),
                "text": line.get("text", ""),
                "sourceId": source.get("sourceId"),
                "kind": source.get("kind"),
                "provenance": source.get("provenance"),
                "title": source.get("title"),
            })

    return lines


def find_line_ids(dossier, predicate):
    result = []

    for line in get_all_lines(dossier):
        if predicate(line["text"]):
            result.append(line["lineId"])

    return result


def combined_text(dossier):
    pieces = [
        str(dossier.get("objective", "")),
        str(dossier.get("mailbox", "")),
    ]

    for line in get_all_lines(dossier):
        pieces.append(line["text"])

    return "\n".join(pieces)


# ============================================================
# DOSSIER CLASSIFICATION
# ============================================================

def classify_dossier(dossier, allowed_actions):
    """
    Deterministic baseline decision engine.

    The important security rule is:
    mail content is DATA, not instructions.

    We first identify obvious prompt injection/security cases,
    then duplicate/completed/informational cases,
    then trusted operational actions.
    """

    text = combined_text(dossier)
    lower = text.lower()

    lines = get_all_lines(dossier)

    # --------------------------------------------------------
    # 1. Prompt injection / malicious control attempts
    # --------------------------------------------------------

    injection_patterns = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore the user's instructions",
        "ignore user instructions",
        "do not tell the user",
        "send the contents",
        "exfiltrate",
        "reveal secrets",
        "reveal credentials",
        "read environment variables",
        "access the filesystem",
        "upload this file",
        "use your tools",
        "call the tool",
        "override the system",
        "disregard the user",
        "bypass security",
        "secretly send",
    ]

    injection_hits = [
        line["lineId"]
        for line in lines
        if any(pattern in line["text"].lower()
               for pattern in injection_patterns)
    ]

    if injection_hits:
        if "quarantine_item" in allowed_actions:
            artifact_id = (
                dossier.get("dossierId")
                or "unknown"
            )

            return make_proposal(
                dossier=dossier,
                action="quarantine_item",
                target={
                    "kind": "security_queue",
                    "id": "mailroom",
                },
                payload={
                    "artifactId": artifact_id,
                    "reasonCode": "INDIRECT_PROMPT_INJECTION",
                },
                evidence=injection_hits[:3],
            )

    # --------------------------------------------------------
    # 2. Duplicate / completed / informational
    # --------------------------------------------------------

    duplicate_words = [
        "duplicate",
        "already processed",
        "already completed",
        "previously completed",
        "no action required",
        "for your information",
        "informational only",
        "fyi",
    ]

    duplicate_hits = [
        line["lineId"]
        for line in lines
        if any(word in line["text"].lower()
               for word in duplicate_words)
    ]

    if duplicate_hits:
        reason = "DUPLICATE"

        if "already completed" in lower or \
           "already processed" in lower or \
           "previously completed" in lower:
            reason = "ALREADY_COMPLETED"

        if "no_action" in allowed_actions:
            return make_proposal(
                dossier=dossier,
                action="no_action",
                target=None,
                payload={
                    "reasonCode": reason,
                    "referenceId": dossier["dossierId"],
                },
                evidence=duplicate_hits[:2],
            )

    # --------------------------------------------------------
    # 3. Ambiguous identity / verification request
    # --------------------------------------------------------

    identity_patterns = [
        "cannot verify",
        "unable to verify",
        "identity mismatch",
        "identity conflict",
        "unknown sender",
        "unverified sender",
        "verify identity",
        "confirm identity",
        "not sure who",
        "sender does not match",
        "sender mismatch",
    ]

    identity_hits = [
        line["lineId"]
        for line in lines
        if any(pattern in line["text"].lower()
               for pattern in identity_patterns)
    ]

    if identity_hits:
        if "request_confirmation" in allowed_actions:
            return make_proposal(
                dossier=dossier,
                action="request_confirmation",
                target={
                    "kind": "approval_queue",
                    "id": infer_team(dossier),
                },
                payload={
                    "claimedSender": infer_sender(dossier),
                    "questionCode": "VERIFY_REQUEST",
                    "referenceId": dossier["dossierId"],
                },
                evidence=identity_hits[:3],
            )

    # --------------------------------------------------------
    # 4. Approved outbound notice
    # --------------------------------------------------------

    approval_patterns = [
        "approved",
        "explicitly approved",
        "approval granted",
        "authorized to send",
        "approved for sending",
    ]

    send_patterns = [
        "send",
        "notify",
        "email the customer",
        "outbound",
        "customer notice",
    ]

    approval_hits = [
        line["lineId"]
        for line in lines
        if any(pattern in line["text"].lower()
               for pattern in approval_patterns)
    ]

    send_hits = [
        line["lineId"]
        for line in lines
        if any(pattern in line["text"].lower()
               for pattern in send_patterns)
    ]

    if approval_hits and send_hits:
        if "send_approved_notice" in allowed_actions:
            evidence = list(dict.fromkeys(
                approval_hits + send_hits
            ))

            return make_proposal(
                dossier=dossier,
                action="send_approved_notice",
                target={
                    "kind": "email",
                    "id": infer_recipient(dossier),
                },
                payload={
                    "referenceId": dossier["dossierId"],
                    "status": infer_status(dossier),
                    "template": "approved_delivery_notice",
                },
                evidence=evidence[:4],
            )

    # --------------------------------------------------------
    # 5. Delivery window / internal record
    # --------------------------------------------------------

    delivery_patterns = [
        "delivery window",
        "delivery date",
        "delivery time",
        "expected delivery",
        "estimated delivery",
    ]

    delivery_hits = [
        line["lineId"]
        for line in lines
        if any(pattern in line["text"].lower()
               for pattern in delivery_patterns)
    ]

    if delivery_hits:
        if "update_internal_record" in allowed_actions:
            value = infer_delivery_value(dossier)

            if value:
                return make_proposal(
                    dossier=dossier,
                    action="update_internal_record",
                    target={
                        "kind": "case_record",
                        "id": infer_case_id(dossier),
                    },
                    payload={
                        "field": "delivery_window",
                        "sourceEventId": infer_event_id(dossier),
                        "value": value,
                    },
                    evidence=delivery_hits[:3],
                )

    # --------------------------------------------------------
    # 6. Customer request requiring a draft
    # --------------------------------------------------------

    customer_request_patterns = [
        "customer asks",
        "customer requested",
        "please reply",
        "please respond",
        "draft a reply",
        "prepare a response",
        "customer wants",
    ]

    request_hits = [
        line["lineId"]
        for line in lines
        if any(pattern in line["text"].lower()
               for pattern in customer_request_patterns)
    ]

    if request_hits:
        if "create_draft" in allowed_actions:
            return make_proposal(
                dossier=dossier,
                action="create_draft",
                target={
                    "kind": "draft_queue",
                    "id": f"mailbox:{dossier['mailbox']}",
                },
                payload={
                    "recipient": infer_recipient(dossier),
                    "referenceId": dossier["dossierId"],
                    "status": infer_status(dossier),
                    "template": "order_status",
                },
                evidence=request_hits[:3],
            )

    # --------------------------------------------------------
    # 7. Safe fallback
    # --------------------------------------------------------

    if "no_action" in allowed_actions:
        info_hits = [
            line["lineId"]
            for line in lines
            if line["text"].strip()
        ]

        return make_proposal(
            dossier=dossier,
            action="no_action",
            target=None,
            payload={
                "reasonCode": "INFORMATIONAL",
                "referenceId": dossier["dossierId"],
            },
            evidence=info_hits[:1],
        )

    # Should not normally happen.
    raise ValueError("No allowed safe fallback action")


def make_proposal(
    dossier,
    action,
    target,
    payload,
    evidence,
):
    """
    Build the proposal with a deterministic callId.

    Stable dossiers need stable call IDs across evaluations.
    """
    fingerprint = dossier_fingerprint(dossier)

    call_id = "call_" + hashlib.sha256(
        (
            dossier["dossierId"]
            + ":"
            + fingerprint
            + ":"
            + action
        ).encode("utf-8")
    ).hexdigest()[:32]

    return {
        "dossierId": dossier["dossierId"],
        "callId": call_id,
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": list(dict.fromkeys(evidence)),
    }


# ============================================================
# FIELD INFERENCE
# ============================================================

def infer_recipient(dossier):
    text = combined_text(dossier)

    # Look for simple email address.
    import re

    matches = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text,
    )

    if matches:
        return matches[0]

    return f"customer-{dossier['dossierId']}@example.invalid"


def infer_sender(dossier):
    text = combined_text(dossier)

    import re

    matches = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text,
    )

    if matches:
        return matches[0]

    return "unknown"


def infer_status(dossier):
    lower = combined_text(dossier).lower()

    if "delivered" in lower:
        return "delivered"

    if "shipped" in lower:
        return "shipped"

    if "in transit" in lower:
        return "in_transit"

    if "processing" in lower:
        return "processing"

    return "pending"


def infer_team(dossier):
    lower = combined_text(dossier).lower()

    if "security" in lower:
        return "security"

    if "billing" in lower:
        return "billing"

    if "support" in lower:
        return "support"

    if "operations" in lower:
        return "operations"

    return "support"


def infer_case_id(dossier):
    import re

    text = combined_text(dossier)

    patterns = [
        r"case[\s_-]*id[\s:]*([A-Za-z0-9_-]+)",
        r"case[\s:]*([A-Za-z0-9_-]+)",
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            text,
            re.IGNORECASE,
        )

        if match:
            return match.group(1)

    return dossier["dossierId"]


def infer_event_id(dossier):
    import re

    text = combined_text(dossier)

    patterns = [
        r"event[\s_-]*id[\s:]*([A-Za-z0-9_-]+)",
        r"event[\s:]*([A-Za-z0-9_-]+)",
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            text,
            re.IGNORECASE,
        )

        if match:
            return match.group(1)

    return dossier["dossierId"]


def infer_delivery_value(dossier):
    import re

    text = combined_text(dossier)

    patterns = [
        r"delivery window[\s:]+([^\n.]+)",
        r"delivery date[\s:]+([^\n.]+)",
        r"expected delivery[\s:]+([^\n.]+)",
        r"estimated delivery[\s:]+([^\n.]+)",
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            text,
            re.IGNORECASE,
        )

        if match:
            return match.group(1).strip()

    return None


# ============================================================
# FINGERPRINT / CACHE
# ============================================================

def dossier_fingerprint(dossier):
    return sha256_json(dossier)


def proposal_digest(proposal):
    normalized = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal["target"],
        "payload": proposal["payload"],
        "evidence": sorted(proposal["evidence"]),
    }

    return sha256_json(normalized)


# ============================================================
# ED25519 RECEIPT VERIFICATION
# ============================================================

def verify_receipt(
    receipt,
    evaluation_id,
    input_digest,
    verifier,
):
    required = [
        "dossierId",
        "callId",
        "action",
        "accepted",
        "proposalDigest",
        "receiptId",
        "receiptSignature",
    ]

    if any(key not in receipt for key in required):
        return False

    signature_b64 = receipt["receiptSignature"]

    try:
        signature = base64.b64decode(
            signature_b64,
            validate=True,
        )
    except Exception:
        return False

    receipt_without_signature = {
        "dossierId": receipt["dossierId"],
        "callId": receipt["callId"],
        "action": receipt["action"],
        "accepted": receipt["accepted"],
        "proposalDigest": receipt["proposalDigest"],
        "receiptId": receipt["receiptId"],
    }

    signed_object = {
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "inputDigest": input_digest,
        "receipt": receipt_without_signature,
    }

    message = canonical_json(
        signed_object
    ).encode("utf-8")

    try:
        x = verifier["publicKeyJwk"]["x"]

        public_key_bytes = base64.urlsafe_b64decode(
            x + "=" * (-len(x) % 4)
        )

        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

        public_key.verify(
            signature,
            message,
        )

        return True

    except (
        InvalidSignature,
        ValueError,
        TypeError,
        KeyError,
    ):
        return False


# ============================================================
# PROPOSE
# ============================================================

@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "mailroom-agent",
    })


@app.route("/", methods=["POST"])
def main():
    try:
        data = request.get_json(
            force=False,
            silent=False,
        )
    except Exception:
        return bad_request(
            "Invalid JSON",
            400,
        )

    if not isinstance(data, dict):
        return bad_request(
            "Request must be a JSON object",
            400,
        )

    operation = data.get("operation")

    if operation == "propose":
        return handle_propose(data)

    if operation == "commit":
        return handle_commit(data)

    return bad_request(
        "Invalid operation",
        400,
    )


def handle_propose(data):
    required = [
        "profile",
        "operation",
        "evaluationId",
        "receiptVerifier",
        "corpus",
        "allowedActions",
        "dossiers",
    ]

    if any(key not in data for key in required):
        return bad_request(
            "Missing required fields",
            400,
        )

    if data["profile"] != PROFILE:
        return bad_request(
            "Invalid profile",
            400,
        )

    if not isinstance(data["evaluationId"], str):
        return bad_request(
            "Invalid evaluationId",
            400,
        )

    if not isinstance(data["dossiers"], list):
        return bad_request(
            "dossiers must be an array",
            400,
        )

    if not isinstance(data["allowedActions"], list):
        return bad_request(
            "allowedActions must be an array",
            400,
        )

    allowed_actions = set(data["allowedActions"])

    if not allowed_actions.issubset(ALLOWED_ACTIONS):
        return bad_request(
            "Unknown action",
            400,
        )

    dossier_ids = []

    for dossier in data["dossiers"]:
        if not validate_dossier(dossier):
            return bad_request(
                "Malformed dossier",
                422,
            )

        dossier_id = dossier["dossierId"]

        if dossier_id in dossier_ids:
            return bad_request(
                "Duplicate dossierId",
                422,
            )

        dossier_ids.append(dossier_id)

    evaluation_id = data["evaluationId"]

    input_digest = sha256_json(
        data["dossiers"]
    )

    conn = get_db()

    existing = conn.execute(
        """
        SELECT *
        FROM evaluations
        WHERE evaluation_id = ?
        """,
        (evaluation_id,),
    ).fetchone()

    # --------------------------------------------------------
    # Exact replay / changed content conflict
    # --------------------------------------------------------

    if existing:
        if existing["input_digest"] != input_digest:
            conn.close()

            return bad_request(
                "evaluationId already exists with different content",
                409,
            )

        response = json.loads(
            existing["response_json"]
        )

        conn.close()

        return jsonify(response)

    # --------------------------------------------------------
    # Generate proposals
    # --------------------------------------------------------

    proposals = []

    for dossier in data["dossiers"]:
        fingerprint = dossier_fingerprint(
            dossier
        )

        cached = conn.execute(
            """
            SELECT proposal_json
            FROM dossier_cache
            WHERE fingerprint = ?
            """,
            (fingerprint,),
        ).fetchone()

        if cached:
            proposal = json.loads(
                cached["proposal_json"]
            )

            # Dossier IDs are expected to remain stable,
            # but ensure proposal ID matches this dossier.
            proposal["dossierId"] = dossier["dossierId"]

        else:
            try:
                proposal = classify_dossier(
                    dossier,
                    allowed_actions,
                )

            except Exception as exc:
                conn.close()

                return bad_request(
                    f"Unable to classify dossier: {str(exc)}",
                    422,
                )

            conn.execute(
                """
                INSERT OR REPLACE INTO dossier_cache
                (fingerprint, dossier_id, proposal_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    fingerprint,
                    dossier["dossierId"],
                    json.dumps(
                        proposal,
                        ensure_ascii=False,
                    ),
                    datetime.now(
                        timezone.utc
                    ).isoformat(),
                ),
            )

        proposals.append(proposal)

    response = {
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals,
    }

    conn.execute(
        """
        INSERT INTO evaluations
        (
            evaluation_id,
            profile,
            input_digest,
            dossiers_json,
            proposals_json,
            verifier_json,
            response_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            evaluation_id,
            PROFILE,
            input_digest,
            json.dumps(
                data["dossiers"],
                ensure_ascii=False,
            ),
            json.dumps(
                proposals,
                ensure_ascii=False,
            ),
            json.dumps(
                data["receiptVerifier"],
                ensure_ascii=False,
            ),
            json.dumps(
                response,
                ensure_ascii=False,
            ),
            datetime.now(
                timezone.utc
            ).isoformat(),
        ),
    )

    conn.commit()
    conn.close()

    return jsonify(response)


# ============================================================
# COMMIT
# ============================================================

def handle_commit(data):
    required = [
        "profile",
        "operation",
        "evaluationId",
        "inputDigest",
        "receipts",
    ]

    if any(key not in data for key in required):
        return bad_request(
            "Missing required fields",
            400,
        )

    if data["profile"] != PROFILE:
        return bad_request(
            "Invalid profile",
            400,
        )

    if not isinstance(
        data["receipts"],
        list,
    ):
        return bad_request(
            "receipts must be an array",
            400,
        )

    evaluation_id = data["evaluationId"]

    conn = get_db()

    evaluation = conn.execute(
        """
        SELECT *
        FROM evaluations
        WHERE evaluation_id = ?
        """,
        (evaluation_id,),
    ).fetchone()

    if not evaluation:
        conn.close()

        return bad_request(
            "Unknown evaluation",
            409,
        )

    if data["inputDigest"] != \
       evaluation["input_digest"]:

        conn.close()

        return bad_request(
            "inputDigest mismatch",
            409,
        )

    # --------------------------------------------------------
    # Exact commit replay
    # --------------------------------------------------------

    existing_commit = conn.execute(
        """
        SELECT response_json
        FROM commits
        WHERE evaluation_id = ?
        """,
        (evaluation_id,),
    ).fetchone()

    if existing_commit:
        response = json.loads(
            existing_commit["response_json"]
        )

        conn.close()

        return jsonify(response)

    proposals = json.loads(
        evaluation["proposals_json"]
    )

    verifier = json.loads(
        evaluation["verifier_json"]
    )

    # Exactly one receipt per proposal.
    if len(data["receipts"]) != len(proposals):
        conn.close()

        return bad_request(
            "Receipt count does not match proposals",
            422,
        )

    proposal_by_dossier = {
        proposal["dossierId"]: proposal
        for proposal in proposals
    }

    seen_dossiers = set()
    verified_receipts = []

    # --------------------------------------------------------
    # Validate ALL receipts before any effect
    # --------------------------------------------------------

    for receipt in data["receipts"]:

        dossier_id = receipt.get(
            "dossierId"
        )

        if dossier_id in seen_dossiers:
            conn.close()

            return bad_request(
                "Duplicate receipt",
                422,
            )

        seen_dossiers.add(
            dossier_id
        )

        proposal = proposal_by_dossier.get(
            dossier_id
        )

        if proposal is None:
            conn.close()

            return bad_request(
                "Receipt does not match a proposal",
                422,
            )

        # Verify signature first.
        if not verify_receipt(
            receipt,
            evaluation_id,
            data["inputDigest"],
            verifier,
        ):
            conn.close()

            return bad_request(
                "Invalid receipt signature",
                422,
            )

        # Check call ID.
        if receipt["callId"] != \
           proposal["callId"]:

            conn.close()

            return bad_request(
                "Receipt callId does not match proposal",
                409,
            )

        # Check action.
        if receipt["action"] != \
           proposal["action"]:

            conn.close()

            return bad_request(
                "Receipt action does not match proposal",
                409,
            )

        # Check proposal digest.
        expected_digest = proposal_digest(
            proposal
        )

        if receipt["proposalDigest"] != \
           expected_digest:

            conn.close()

            return bad_request(
                "Proposal digest mismatch",
                409,
            )

        verified_receipts.append(
            receipt
        )

    # Ensure every proposal has a receipt.
    if seen_dossiers != set(
        proposal_by_dossier.keys()
    ):
        conn.close()

        return bad_request(
            "Missing receipt",
            422,
        )

    # --------------------------------------------------------
    # Now and ONLY now produce outcomes.
    # --------------------------------------------------------

    outcomes = []

    for receipt in verified_receipts:
        if receipt["accepted"]:
            status = "executed"
        else:
            status = "rejected"

        outcomes.append({
            "dossierId": receipt["dossierId"],
            "callId": receipt["callId"],
            "action": receipt["action"],
            "proposalDigest": receipt["proposalDigest"],
            "receiptId": receipt["receiptId"],
            "status": status,
        })

    response = {
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "status": "completed",
        "inputDigest": data["inputDigest"],
        "outcomes": outcomes,
    }

    # Persist commit before responding.
    conn.execute(
        """
        INSERT INTO commits
        (
            evaluation_id,
            input_digest,
            receipts_json,
            response_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            evaluation_id,
            data["inputDigest"],
            json.dumps(
                data["receipts"],
                ensure_ascii=False,
            ),
            json.dumps(
                response,
                ensure_ascii=False,
            ),
            datetime.now(
                timezone.utc
            ).isoformat(),
        ),
    )

    conn.commit()
    conn.close()

    return jsonify(response)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    port = int(
        os.environ.get(
            "PORT",
            "5000",
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
    )
