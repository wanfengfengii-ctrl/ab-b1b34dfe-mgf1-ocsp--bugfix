"""End-to-end HTTP API regression for the RSASSA-PSS MGF mismatch bug.

Drives the real Flask application: upload objects, seal, adjudicate, download
the evidence pack and verify it offline.  The MGF-mismatched OCSP response
must produce UNSUPPORTED end to end, and the offline verifier must agree.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from app.canonical import dumps, sha256_hex
from app.verify import CheckLog, verify_pack
from acceptance.pki_fixtures import (
    make_ocsp,
    ocsp_corrupt_signature,
    ocsp_replace_signature_algorithm,
    pss_algorithm_identifier,
    sign_data,
)
from tests.conftest import Bag, T
from tests.test_api import _make_set_with_objects, _post

SERIAL = 4242
THIS, NEXT = T("2024-05-20"), T("2024-06-20")
EARLY = "2024-01-01T00:00:00Z"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from app.api import create_app

    app = create_app()
    app.testing = True
    with app.test_client() as c:
        yield c


def _build_case(client, mutate):
    """Build the fixed RSA chain, produce the (possibly mutated) serial-4242
    OCSP response, bag everything, seal and adjudicate through the HTTP API."""
    from acceptance.pss_regression import _rsa_chain

    bag = Bag()
    root, inter, leaf = _rsa_chain(bag)
    ocsp = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS, next_update=NEXT)
    if mutate is not None:
        ocsp = mutate(ocsp)
    bag.add(ocsp, "ocsp", EARLY)

    set_id = _make_set_with_objects(client, bag)
    _post(client, f"/v1/evidence-sets/{set_id}/seal", {"request_id": "seal"})

    digest = hashlib.sha256(b"api pss artifact").hexdigest()
    sig = sign_data(leaf.key, bytes.fromhex(digest))
    inp = {
        "artifact_digest": digest,
        "signature": base64.b64encode(sig).decode(),
        "signature_algorithm": "rsa-pss-sha256",
        "signed_at": "2024-06-01T00:00:00Z",
        "knowledge_cutoff": "2025-01-01T00:00:00Z",
        "leaf_fingerprint": sha256_hex(leaf.der),
        "trust_anchors": [sha256_hex(root.der)],
    }
    r = _post(client, "/v1/adjudications",
              {"request_id": "adj", "evidence_set_id": set_id, "input": inp}, 201)
    body = json.loads(r.data)
    pack = client.get(f"/v1/adjudications/{body['adjudication_id']}/evidence-pack")
    assert pack.status_code == 200
    assert verify_pack(pack.data, CheckLog())
    return leaf, body, json.loads(pack.data)


def test_api_valid_pss_ocsp_is_valid(client):
    leaf, body, _pack = _build_case(client, None)
    assert body["verdict"] == "VALID", dumps(body["decision"]).decode()
    assert body["revocation"][sha256_hex(leaf.der)]["status"] == "GOOD"


def test_api_mgf_mismatch_is_unsupported(client):
    mgf384 = pss_algorithm_identifier(hash_name="sha256", mgf_hash="sha384")
    leaf, body, pack = _build_case(
        client, lambda d: ocsp_replace_signature_algorithm(d, mgf384))
    assert body["verdict"] == "UNSUPPORTED", dumps(body["decision"]).decode()
    assert body["revocation"][sha256_hex(leaf.der)]["status"] == "UNSUPPORTED"
    # offline pack recomputation reaches the same verdict
    assert pack["result"]["verdict"] == "UNSUPPORTED"


def test_api_conforming_params_bad_signature_is_invalid(client):
    leaf, body, _pack = _build_case(client, ocsp_corrupt_signature)
    assert body["verdict"] == "INVALID"
    assert body["revocation"][sha256_hex(leaf.der)]["status"] == "MALFORMED_EVIDENCE"
