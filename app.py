import base64
import json
import uuid

from flask import (
    Flask,
    jsonify,
    request
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey
)

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)

from storage import (
    init_db,
    get_evaluation,
    save_evaluation,
    get_cached_proposal,
    save_cached_proposal,
    save_receipt,
    get_receipts
)

from validation import (
    PROFILE,
    canonical_json,
    sha256_json,
    dossier_fingerprint,
    calculate_input_digest,
    proposal_digest,
    validate_proposal,
    validate_dossier
)

from decision_engine import (
    decide_dossier
)


app = Flask(__name__)

app.config[
    "MAX_CONTENT_LENGTH"
] = 5 * 1024 * 1024


init_db()


def error(message, status=400):

    return jsonify({
        "error": message
    }), status


def new_call_id():

    return uuid.uuid4().hex


def make_proposal(
    dossier,
    allowed_actions
):

    fingerprint = (
        dossier_fingerprint(
            dossier
        )
    )

    cached = get_cached_proposal(
        fingerprint
    )

    if cached:

        return cached

    decision = decide_dossier(
        dossier,
        allowed_actions
    )

    proposal = {
        "dossierId": dossier[
            "dossierId"
        ],

        "callId": new_call_id(),

        "action": decision[
            "action"
        ],

        "target": decision[
            "target"
        ],

        "payload": decision[
            "payload"
        ],

        "evidence": sorted(
            decision[
                "evidence"
            ]
        )
    }

    validate_proposal(
        proposal,
        dossier,
        allowed_actions
    )

    save_cached_proposal(
        fingerprint,
        proposal
    )

    return proposal


def verify_receipt(
    receipt,
    evaluation,
    proposal
):

    verifier = evaluation[
        "verifier"
    ]

    public_key_jwk = verifier[
        "publicKeyJwk"
    ]

    if public_key_jwk.get(
        "kty"
    ) != "OKP":

        return False

    if public_key_jwk.get(
        "crv"
    ) != "Ed25519":

        return False

    if not isinstance(
        receipt.get(
            "receiptSignature"
        ),
        str
    ):

        return False

    try:

        x = base64.urlsafe_b64decode(
            public_key_jwk[
                "x"
            ] + "=="
        )

        public_key = (
            Ed25519PublicKey
            .from_public_bytes(x)
        )

        signed_receipt = {

            "profile": PROFILE,

            "evaluationId":
                evaluation[
                    "evaluation_id"
                ],

            "inputDigest":
                evaluation[
                    "input_digest"
                ],

            "receipt": {

                "dossierId":
                    receipt[
                        "dossierId"
                    ],

                "callId":
                    receipt[
                        "callId"
                    ],

                "action":
                    receipt[
                        "action"
                    ],

                "accepted":
                    receipt[
                        "accepted"
                    ],

                "proposalDigest":
                    receipt[
                        "proposalDigest"
                    ],

                "receiptId":
                    receipt[
                        "receiptId"
                    ]
            }
        }

        message = canonical_json(
            signed_receipt
        ).encode(
            "utf-8"
        )

        signature = (
            base64.b64decode(
                receipt[
                    "receiptSignature"
                ]
            )
        )

        public_key.verify(
            signature,
            message
        )

        return True

    except Exception:

        return False


@app.route(
    "/",
    methods=["GET"]
)
def health():

    return jsonify({
        "status": "ok"
    })


@app.route(
    "/",
    methods=["POST"]
)
def main():

    body = request.get_json(
        silent=True
    )

    if not isinstance(
        body,
        dict
    ):

        return error(
            "Invalid JSON"
        )

    if body.get(
        "profile"
    ) != PROFILE:

        return error(
            "Invalid profile"
        )

    operation = body.get(
        "operation"
    )

    if operation == "propose":

        return handle_propose(
            body
        )

    if operation == "commit":

        return handle_commit(
            body
        )

    return error(
        "Invalid operation"
    )


def handle_propose(
    body
):

    required = {
        "profile",
        "operation",
        "evaluationId",
        "receiptVerifier",
        "corpus",
        "allowedActions",
        "dossiers"
    }

    if set(body.keys()) != required:

        return error(
            "Malformed propose request"
        )

    evaluation_id = body[
        "evaluationId"
    ]

    dossiers = body[
        "dossiers"
    ]

    allowed_actions = body[
        "allowedActions"
    ]

    if not isinstance(
        evaluation_id,
        str
    ):

        return error(
            "Invalid evaluationId"
        )

    if not isinstance(
        dossiers,
        list
    ):

        return error(
            "Invalid dossiers"
        )

    if len(
        dossiers
    ) == 0:

        return error(
            "No dossiers"
        )

    if len(
        set(
            d["dossierId"]
            for d in dossiers
        )
    ) != len(
        dossiers
    ):

        return error(
            "Duplicate dossier IDs"
        )

    try:

        for dossier in dossiers:

            validate_dossier(
                dossier
            )

    except Exception as exc:

        return error(
            str(exc),
            422
        )

    input_digest = (
        calculate_input_digest(
            dossiers
        )
    )

    existing = get_evaluation(
        evaluation_id
    )

    # CRITICAL CONFLICT CHECK
    if existing:

        if existing[
            "input_digest"
        ] != input_digest:

            return error(
                "evaluationId conflict",
                409
            )

        return jsonify(
            existing[
                "response"
            ]
        )

    proposals = []

    try:

        for dossier in dossiers:

            proposal = make_proposal(
                dossier,
                allowed_actions
            )

            proposals.append(
                proposal
            )

    except Exception as exc:

        return error(
            f"Decision failed: {exc}",
            422
        )

    response = {

        "profile":
            PROFILE,

        "evaluationId":
            evaluation_id,

        "status":
            "awaiting_receipts",

        "inputDigest":
            input_digest,

        "proposals":
            proposals
    }

    save_evaluation(

        evaluation_id,

        input_digest,

        body,

        response,

        body[
            "receiptVerifier"
        ]
    )

    return jsonify(
        response
    )


def handle_commit(
    body
):

    required = {
        "profile",
        "operation",
        "evaluationId",
        "inputDigest",
        "receipts"
    }

    if set(body.keys()) != required:

        return error(
            "Malformed commit request"
        )

    evaluation_id = body[
        "evaluationId"
    ]

    input_digest = body[
        "inputDigest"
    ]

    receipts = body[
        "receipts"
    ]

    evaluation = get_evaluation(
        evaluation_id
    )

    if not evaluation:

        return error(
            "Unknown evaluation",
            409
        )

    if (
        evaluation[
            "input_digest"
        ]
        != input_digest
    ):

        return error(
            "Input digest mismatch",
            409
        )

    proposals = {
        p["dossierId"]: p
        for p in evaluation[
            "response"
        ]["proposals"]
    }

    if len(receipts) != len(
        proposals
    ):

        return error(
            "Receipt count mismatch",
            422
        )

    seen = set()

    # FIRST PASS:
    # validate everything atomically
    for receipt in receipts:

        receipt_id = receipt.get(
            "receiptId"
        )

        dossier_id = receipt.get(
            "dossierId"
        )

        if not receipt_id:
            return error(
                "Missing receipt ID",
                422
            )

        if receipt_id in seen:

            return error(
                "Duplicate receipt",
                422
            )

        seen.add(
            receipt_id
        )

        if dossier_id not in proposals:

            return error(
                "Unknown dossier",
                422
            )

        proposal = proposals[
            dossier_id
        ]

        if receipt.get(
            "callId"
        ) != proposal[
            "callId"
        ]:

            return error(
                "Call ID mismatch",
                422
            )

        if receipt.get(
            "action"
        ) != proposal[
            "action"
        ]:

            return error(
                "Action mismatch",
                422
            )

        expected_digest = (
            proposal_digest(
                proposal
            )
        )

        if receipt.get(
            "proposalDigest"
        ) != expected_digest:

            return error(
                "Proposal digest mismatch",
                422
            )

        if not verify_receipt(
            receipt,
            evaluation,
            proposal
        ):

            return error(
                "Invalid receipt signature",
                422
            )

    # SECOND PASS:
    # persist receipts
    for receipt in receipts:

        save_receipt(
            evaluation_id,
            receipt
        )

    outcomes = []

    for receipt in receipts:

        outcomes.append({

            "dossierId":
                receipt[
                    "dossierId"
                ],

            "callId":
                receipt[
                    "callId"
                ],

            "action":
                receipt[
                    "action"
                ],

            "proposalDigest":
                receipt[
                    "proposalDigest"
                ],

            "receiptId":
                receipt[
                    "receiptId"
                ],

            "status":
                (
                    "executed"
                    if receipt[
                        "accepted"
                    ]
                    else
                    "rejected"
                )
        })

    response = {

        "profile":
            PROFILE,

        "evaluationId":
            evaluation_id,

        "status":
            "completed",

        "inputDigest":
            input_digest,

        "outcomes":
            outcomes
    }

    return jsonify(
        response
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
