"""Code-level regression for RSASSA-PSS parameter handling.

Covers the case where a legitimate, RSA-issuer-signed OCSP response had its
(unsignatured) RSASSA-PSS ``AlgorithmIdentifier`` parameters retargeted from
MGF1-SHA-256 to MGF1-SHA-384 while the signature value and
``tbsResponseData`` stayed byte-identical.  The declaration then disagrees
with the real signature and violates the profile ("MGF-1 hash must equal the
message hash"), so the response must be classified as structured
``UNSUPPORTED`` and must never be authorized.  It must also not be conflated
with the ordinary "signature invalid" outcome that a profile-conformant
encoding with broken signature bytes produces.

The same RSASSA-PSS semantics (message hash, MGF-1 inner hash, salt length
and ``trailerField``) are exercised at every entry point that parses or
verifies signatures: certificates, CRLs, OCSP responses and the offline
evidence-pack review (``python -m app.verify``).

Runnable directly (the code-level acceptance path used inside ``api-a``)::

    python -m acceptance.regression_pss
    # or: python -c "from acceptance.regression_pss import main; \
    #                raise SystemExit(main())"

Exit status is 0 only when every assertion holds.  The line
``BUG_MGF_MISMATCH_ACCEPTED=False`` is printed on success; the process exits
non-zero before any ``BUG_MGF_MISMATCH_ACCEPTED=True`` could be reported.

The identical checks are also executed by the docker-compose ``verify``
service (``acceptance.acceptance``) and by the pytest suite
(``tests/test_pss_mgf_regression.py``).
"""
from __future__ import annotations

import sys
import traceback
from datetime import datetime, timezone

from app import profile
from app.adjudicate import DictObjectSource, run_engine, validate_input
from app.canonical import b64e, dumps, sha256_hex
from app.pki import parse_certificate
from app.revocation import parse_crl, parse_ocsp, _verify_ocsp_authorization
from app.verify import CheckLog, verify_pack

from acceptance.pki_fixtures import (
    build_pss_algorithm_der,
    corrupt_cert_or_crl_signature,
    corrupt_ocsp_signature,
    make_ca,
    make_crl,
    make_leaf,
    make_ocsp,
    rewrite_cert_or_crl_sig_algorithm,
    rewrite_ocsp_sig_algorithm,
)

UTC = timezone.utc
T = lambda s: datetime.fromisoformat(s + "T00:00:00+00:00")

# --- fixed reproduction data (identical to the original report) -------------
SERIAL = 4242
THIS_UPDATE = T("2024-05-20")
NEXT_UPDATE = T("2024-06-20")
SIGNED_AT = "2024-06-01T00:00:00Z"
CUTOFF = "2025-01-01T00:00:00Z"
EARLY = "2024-01-01T00:00:00Z"

# profile-conformant declaration: PSS SHA-256 / MGF1-SHA-256 / salt 32 / tf 1
_PSS_SHA256 = build_pss_algorithm_der(
    hash_name="sha256", mgf_hash_name="sha256", salt_length=32, trailer_field=1
)
# attack declaration: same message hash, MGF1 inner hash retargeted to SHA-384
_PSS_MGF384 = build_pss_algorithm_der(
    hash_name="sha256", mgf_hash_name="sha384", salt_length=32, trailer_field=1
)
# another out-of-profile declaration: trailerField 2
_PSS_TRAILER2 = build_pss_algorithm_der(
    hash_name="sha256", mgf_hash_name="sha256", salt_length=32, trailer_field=2
)
# consistent SHA-384 declaration (in profile; signature below is still SHA-256)
_PSS_SHA384 = build_pss_algorithm_der(
    hash_name="sha384", mgf_hash_name="sha384", salt_length=32, trailer_field=1
)


class RegressionFailure(AssertionError):
    pass


def _check(name: str, cond, detail: str = ""):
    if not cond:
        raise RegressionFailure(f"{name}: {detail}")


def _build_entities():
    """RSA root -> RSA intermediate (the direct OCSP issuer) -> code-signing leaf."""
    root = make_ca("PSS Reg Root", "rsa",
                   not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("PSS Reg Inter", "rsa", issuer=root,
                    not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "PSS Reg Leaf", "ed", serial=SERIAL,
                     not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"])
    return root, inter, leaf


# ---------------------------------------------------------------------------
# 1. Direct business-module reproduction (the docker-compose exec python -c path)
# ---------------------------------------------------------------------------

def direct_business_module_repro() -> dict:
    root, inter, leaf = _build_entities()
    valid_der = make_ocsp(inter, serial=SERIAL, status="good",
                         this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    issuer = parse_certificate(inter.der)

    # (a) unmodified legitimate RSA-PSS response stays authorized
    valid = parse_ocsp(valid_der)
    ok_valid, desc_valid, _, _ = _verify_ocsp_authorization(valid, issuer)
    _check("legit PSS response authorized", ok_valid, str(desc_valid))
    _check("legit descriptor declares MGF1-SHA-256",
           valid.sig_alg == {
               "algorithm": "rsa-pss-sha256", "hash": "sha256",
               "mgf": profile.OID_MGF1, "mgf_hash": "sha256",
               "salt_length": 32, "trailer_field": 1,
           }, str(valid.sig_alg))

    # (b) signature + tbs untouched, only MGF1 inner hash changed 256 -> 384
    tampered_der = rewrite_ocsp_sig_algorithm(valid_der, _PSS_MGF384)
    tampered = parse_ocsp(tampered_der)  # parsing still completes
    from cryptography.x509.ocsp import load_der_ocsp_response

    raw_valid = load_der_ocsp_response(valid_der)
    raw_tampered = load_der_ocsp_response(tampered_der)
    _check("tbsResponseData unchanged",
           raw_tampered.tbs_response_bytes == raw_valid.tbs_response_bytes)
    _check("signature value unchanged",
           raw_tampered.signature == raw_valid.signature)
    _check("tampered response parses", True)
    _check("tampered encoding flagged unsupported",
           tampered.sig_alg is None
           and any(u["code"] == "UNSUPPORTED_SIGNATURE_ALGORITHM"
                   for u in tampered.unsupported),
           str(tampered.unsupported))
    ok_bad, _, _, failure = _verify_ocsp_authorization(tampered, issuer)
    _check("MGF-mismatch response NOT authorized", not ok_bad)
    _check("MGF mismatch is structured UNSUPPORTED",
           failure is not None and failure["reason"] == "UNSUPPORTED",
           str(failure))

    # (c) profile-conformant declaration, but signature bytes broken: this is
    #     the ordinary signature-invalid class, never UNSUPPORTED
    corrupt_der = corrupt_ocsp_signature(valid_der)
    corrupt = parse_ocsp(corrupt_der)
    _check("corrupt-signature encoding stays in profile",
           corrupt.sig_alg is not None and not corrupt.unsupported)
    ok_corrupt, _, _, failure_c = _verify_ocsp_authorization(corrupt, issuer)
    _check("corrupt-signature response NOT authorized", not ok_corrupt)
    _check("corrupt signature is plain RESPONDER_UNAUTHORIZED, not UNSUPPORTED",
           failure_c is not None
           and failure_c["reason"] == "RESPONDER_UNAUTHORIZED", str(failure_c))

    # (d) consistent SHA-384 declaration (MGF hash == message hash) is in
    #     profile; the SHA-256-made signature simply fails verification
    sha384_der = rewrite_ocsp_sig_algorithm(valid_der, _PSS_SHA384)
    sha384 = parse_ocsp(sha384_der)
    _check("consistent PSS-SHA-384 declaration is in profile",
           sha384.sig_alg is not None
           and sha384.sig_alg["algorithm"] == "rsa-pss-sha384"
           and sha384.sig_alg["mgf_hash"] == "sha384",
           str(sha384.sig_alg))
    ok384, _, _, failure384 = _verify_ocsp_authorization(sha384, issuer)
    _check("SHA-384 declaration with stale signature not authorized", not ok384)
    _check("consistent-but-stale signature is a plain failure, not UNSUPPORTED",
           failure384["reason"] == "RESPONDER_UNAUTHORIZED", str(failure384))

    return {
        "legit_authorized": ok_valid,
        "mgf_mismatch_authorized": ok_bad,
        "mgf_mismatch_reason": failure["reason"],
        "corrupt_signature_reason": failure_c["reason"],
        "BUG_MGF_MISMATCH_ACCEPTED": bool(ok_bad),
    }


# ---------------------------------------------------------------------------
# 2. Same semantics at every entry point: certificate, CRL, OCSP
# ---------------------------------------------------------------------------

def entry_point_consistency() -> dict:
    root, inter, leaf = _build_entities()
    crl_der = make_crl(root, entries=[], crl_number=1,
                       this_update=THIS_UPDATE, next_update=NEXT_UPDATE)

    # --- legitimate PSS objects parse with identical descriptor semantics ---
    cert_info = parse_certificate(inter.der)
    crl_info = parse_crl(crl_der)
    ocsp_info = parse_ocsp(make_ocsp(
        inter, serial=SERIAL, status="good",
        this_update=THIS_UPDATE, next_update=NEXT_UPDATE))
    for label, info in (("certificate", cert_info), ("crl", crl_info),
                        ("ocsp", ocsp_info)):
        _check(f"{label}: legitimate PSS descriptor present",
               info.sig_alg is not None, str(getattr(info, "unsupported", None)))
        _check(f"{label}: message hash sha256", info.sig_alg["hash"] == "sha256")
        _check(f"{label}: mgf is id-mgf1", info.sig_alg["mgf"] == profile.OID_MGF1)
        _check(f"{label}: MGF1 inner hash equals message hash",
               info.sig_alg["mgf_hash"] == "sha256")
        _check(f"{label}: salt length recorded from declaration",
               info.sig_alg["salt_length"] == 32)
        _check(f"{label}: trailerField declared as 1",
               info.sig_alg["trailer_field"] == 1)
        _check(f"{label}: no unsupported findings", not info.unsupported,
               str(info.unsupported))

    # --- MGF1 inner-hash mismatch: every entry point says UNSUPPORTED ------
    bad_cert = parse_certificate(rewrite_cert_or_crl_sig_algorithm(inter.der, _PSS_MGF384))
    bad_crl = parse_crl(rewrite_cert_or_crl_sig_algorithm(crl_der, _PSS_MGF384))
    bad_ocsp = parse_ocsp(rewrite_ocsp_sig_algorithm(
        make_ocsp(inter, serial=SERIAL, status="good",
                  this_update=THIS_UPDATE, next_update=NEXT_UPDATE),
        _PSS_MGF384))
    for label, info in (("certificate", bad_cert), ("crl", bad_crl), ("ocsp", bad_ocsp)):
        _check(f"{label}: MGF mismatch removes descriptor", info.sig_alg is None)
        _check(f"{label}: MGF mismatch is UNSUPPORTED_SIGNATURE_ALGORITHM",
               any(u["code"] == "UNSUPPORTED_SIGNATURE_ALGORITHM"
                   for u in info.unsupported), str(info.unsupported))

    # --- trailerField != 1 is equally out of profile at every entry point --
    tf_cert = parse_certificate(rewrite_cert_or_crl_sig_algorithm(inter.der, _PSS_TRAILER2))
    tf_crl = parse_crl(rewrite_cert_or_crl_sig_algorithm(crl_der, _PSS_TRAILER2))
    tf_ocsp = parse_ocsp(rewrite_ocsp_sig_algorithm(
        make_ocsp(inter, serial=SERIAL, status="good",
                  this_update=THIS_UPDATE, next_update=NEXT_UPDATE),
        _PSS_TRAILER2))
    for label, info in (("certificate", tf_cert), ("crl", tf_crl), ("ocsp", tf_ocsp)):
        _check(f"{label}: trailerField 2 is UNSUPPORTED",
               info.sig_alg is None
               and any(u["code"] == "UNSUPPORTED_SIGNATURE_ALGORITHM"
                       for u in info.unsupported), str(info.unsupported))

    # --- in-profile parameters with broken signatures: plain SIGNATURE_INVALID
    corrupt_cert_info = parse_certificate(
        corrupt_cert_or_crl_signature(inter.der))
    corrupt_crl_info = parse_crl(corrupt_cert_or_crl_signature(crl_der))
    _check("cert: broken signature bytes keep a valid PSS descriptor",
           corrupt_cert_info.sig_alg is not None
           and not corrupt_cert_info.unsupported)
    _check("crl: broken signature bytes keep a valid PSS descriptor",
           corrupt_crl_info.sig_alg is not None
           and not corrupt_crl_info.unsupported)
    issuer = parse_certificate(root.der)
    _check("cert: broken signature bytes fail verification (not profile failure)",
           not profile.verify_signature(
               issuer.public_key(), corrupt_cert_info.sig_alg,
               corrupt_cert_info.cert.signature,
               corrupt_cert_info.cert.tbs_certificate_bytes))
    _check("crl: broken signature bytes fail verification (not profile failure)",
           not profile.verify_signature(
               issuer.public_key(), corrupt_crl_info.sig_alg,
               corrupt_crl_info.crl.signature,
               corrupt_crl_info.crl.tbs_certlist_bytes))

    return {
        "certificate_mgf_unsupported": bad_cert.sig_alg is None,
        "crl_mgf_unsupported": bad_crl.sig_alg is None,
        "ocsp_mgf_unsupported": bad_ocsp.sig_alg is None,
    }


# ---------------------------------------------------------------------------
# 3. Full-engine adjudication + offline evidence-pack review
# ---------------------------------------------------------------------------

def _manifest(fps_meta: dict):
    """Mirror the manifest the HTTP API freezes at seal time (touched set)."""
    objects = [
        {"fingerprint": fp, "type": m["type"], "received_at": m["received_at"]}
        for fp, m in sorted(fps_meta.items())
    ]
    n_cert = sum(1 for o in objects if o["type"] == "certificate")
    n_crl = sum(1 for o in objects if o["type"] == "crl")
    n_ocsp = sum(1 for o in objects if o["type"] == "ocsp")
    return {
        "format": "evidence-set-manifest/1",
        "counts": {
            "certificates": n_cert,
            "crls": n_crl,
            "ocsp_responses": n_ocsp,
            "revocation_entries": n_crl + n_ocsp,
            "total_objects": len(objects),
        },
        "limits": profile.LIMITS,
        "objects": objects,
    }


def _adjudication_input(leaf, root):
    import base64
    import hashlib

    from acceptance.pki_fixtures import artifact_algorithm_for, sign_data

    digest = hashlib.sha256(b"pss-mgf-regression-artifact").hexdigest()
    signature = sign_data(leaf.key, bytes.fromhex(digest))
    return {
        "artifact_digest": digest,
        "signature": base64.b64encode(signature).decode(),
        "signature_algorithm": artifact_algorithm_for(leaf.key),
        "signed_at": SIGNED_AT,
        "knowledge_cutoff": CUTOFF,
        "leaf_fingerprint": sha256_hex(leaf.der),
        "trust_anchors": [sha256_hex(root.der)],
    }


def _engine_bag(root, inter, leaf, ocsp_der):
    """Build the in-memory object source for the full-engine scenarios.

    Deliberately does not depend on the pytest ``tests`` package, which is
    not copied into the runtime image: this module runs unmodified inside
    the ``api-a`` container.
    """
    objects: dict = {}

    def add(der: bytes, otype: str, received_at: str = EARLY):
        objects[sha256_hex(der)] = {"type": otype, "der": der,
                                   "received_at": received_at}

    add(root.der, "certificate")
    add(inter.der, "certificate")
    add(leaf.der, "certificate")
    # empty root-signed CRL so the intermediate itself is GOOD on the path
    add(make_crl(root, entries=[], crl_number=1,
                 this_update=THIS_UPDATE, next_update=NEXT_UPDATE), "crl")
    add(ocsp_der, "ocsp")
    return objects


def _build_pack(objects: dict, raw_input):
    inp = validate_input(raw_input)
    manifest = _manifest(objects)
    content_digest = sha256_hex(dumps(manifest))
    source = DictObjectSource(objects)
    result, touched = run_engine(source, inp, content_digest)
    pack_objects = []
    for fp in sorted(touched):
        m = objects[fp]
        pack_objects.append({
            "fingerprint": fp,
            "type": m["type"],
            "received_at": m["received_at"],
            "der": b64e(m["der"]),
        })
    pack = {
        "pack_version": 1,
        "adjudication_id": result["adjudication_id"],
        "input": inp,
        "evidence_set": {"content_digest": content_digest, "manifest": manifest},
        "objects": pack_objects,
        "result": result,
    }
    return dumps(pack), result


def _offline_review(pack_bytes: bytes, label: str):
    log = CheckLog()
    ok = verify_pack(pack_bytes, log)
    _check(f"{label}: offline evidence-pack review passes", ok,
           "; ".join(line for line in log.lines if line.startswith("FAIL")))


def engine_and_offline_review() -> dict:
    root, inter, leaf = _build_entities()
    valid_ocsp = make_ocsp(inter, serial=SERIAL, status="good",
                          this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    mgf_mismatch_ocsp = rewrite_ocsp_sig_algorithm(valid_ocsp, _PSS_MGF384)
    corrupt_ocsp = corrupt_ocsp_signature(valid_ocsp)

    leaf_fp = sha256_hex(leaf.der)

    # (a) legitimate evidence -> VALID, and the pack verifies offline
    bag_ok = _engine_bag(root, inter, leaf, valid_ocsp)
    inp = _adjudication_input(leaf, root)
    pack_ok, result_ok = _build_pack(bag_ok, inp)
    _check("engine: legit PSS OCSP yields VALID",
           result_ok["verdict"] == "VALID", result_ok["verdict"])
    _check("engine: legit OCSP revocation status GOOD",
           result_ok["revocation"][leaf_fp]["status"] == "GOOD")
    used = {r["fingerprint"]: r for r in result_ok["evidence_accounting"]
            if r["disposition"] == "used"}
    _check("engine: legit OCSP view selected",
           sha256_hex(valid_ocsp) in used)
    _offline_review(pack_ok, "legit PSS")

    # (b) MGF-mismatch evidence -> UNSUPPORTED (verdict + revocation outcome),
    #     and the recomputed pack reproduces that verdict offline
    bag_bad = _engine_bag(root, inter, leaf, mgf_mismatch_ocsp)
    pack_bad, result_bad = _build_pack(bag_bad, inp)
    _check("engine: MGF-mismatch OCSP yields verdict UNSUPPORTED",
           result_bad["verdict"] == "UNSUPPORTED", result_bad["verdict"])
    outcome_bad = result_bad["revocation"][leaf_fp]
    _check("engine: MGF-mismatch outcome is MALFORMED_EVIDENCE",
           outcome_bad["status"] == "MALFORMED_EVIDENCE", outcome_bad["status"])
    _check("engine: MGF-mismatch outcome carries unsupported_evidence",
           outcome_bad.get("unsupported_evidence") is True)
    acct_bad = {r["fingerprint"]: r for r in result_bad["evidence_accounting"]}
    _check("engine: MGF-mismatch OCSP excluded as UNSUPPORTED",
           acct_bad[sha256_hex(mgf_mismatch_ocsp)]["reason"] == "UNSUPPORTED",
           str(acct_bad.get(sha256_hex(mgf_mismatch_ocsp))))
    _check("engine: rejection proof contains an UNSUPPORTED rule",
           "UNSUPPORTED" in result_bad["summary"]["failure_codes"],
           str(result_bad["summary"]["failure_codes"]))
    _offline_review(pack_bad, "MGF-mismatch PSS")

    # (c) in-profile declaration + broken signature bytes -> INVALID with the
    #     established signature-invalid classification, never UNSUPPORTED
    bag_corrupt = _engine_bag(root, inter, leaf, corrupt_ocsp)
    pack_c, result_c = _build_pack(bag_corrupt, inp)
    _check("engine: broken-signature OCSP yields verdict INVALID",
           result_c["verdict"] == "INVALID", result_c["verdict"])
    outcome_c = result_c["revocation"][leaf_fp]
    _check("engine: broken-signature outcome is MALFORMED_EVIDENCE",
           outcome_c["status"] == "MALFORMED_EVIDENCE", outcome_c["status"])
    _check("engine: broken-signature outcome not tagged unsupported",
           not outcome_c.get("unsupported_evidence"))
    acct_c = {r["fingerprint"]: r for r in result_c["evidence_accounting"]}
    _check("engine: broken-signature OCSP excluded as RESPONDER_UNAUTHORIZED",
           acct_c[sha256_hex(corrupt_ocsp)]["reason"] == "RESPONDER_UNAUTHORIZED",
           str(acct_c.get(sha256_hex(corrupt_ocsp))))
    _check("engine: broken-signature failure codes never say UNSUPPORTED",
           "UNSUPPORTED" not in result_c["summary"]["failure_codes"],
           str(result_c["summary"]["failure_codes"]))
    _offline_review(pack_c, "broken-signature PSS")

    return {
        "legit_verdict": result_ok["verdict"],
        "mgf_mismatch_verdict": result_bad["verdict"],
        "broken_signature_verdict": result_c["verdict"],
    }


# ---------------------------------------------------------------------------
# 4. Certificate and CRL entries end-to-end (graph verdict + offline review)
# ---------------------------------------------------------------------------

def cert_and_crl_end_to_end() -> dict:
    root, inter, leaf = _build_entities()
    inp = _adjudication_input(leaf, root)

    # --- certificate: an intermediate whose PSS declaration is tampered ----
    bad_inter_der = rewrite_cert_or_crl_sig_algorithm(inter.der, _PSS_MGF384)
    cert_objects: dict = {}
    for der, otype in ((root.der, "certificate"), (bad_inter_der, "certificate"),
                       (leaf.der, "certificate")):
        cert_objects[sha256_hex(der)] = {"type": otype, "der": der,
                                         "received_at": EARLY}
    # valid root CRL so the intermediate has GOOD revocation evidence; the
    # branch must still fail on the intermediate's out-of-profile encoding
    root_crl = make_crl(root, entries=[], crl_number=1,
                        this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    cert_objects[sha256_hex(root_crl)] = {
        "type": "crl", "der": root_crl, "received_at": EARLY,
    }
    pack_cert, result_cert = _build_pack(cert_objects, inp)
    _check("cert: MGF-mismatch intermediate yields UNSUPPORTED",
           result_cert["verdict"] == "UNSUPPORTED", result_cert["verdict"])
    _check("cert: proof reports the encoding as CERT_PROFILE/UNSUPPORTED",
           any(b["failure"]["code"] == "UNSUPPORTED"
               for b in result_cert["decision"]["rejection_proof"]["branches"]),
           str(result_cert["summary"]["failure_codes"]))
    _offline_review(pack_cert, "MGF-mismatch certificate")

    # --- CRL: the only leaf revocation evidence is a tampered CRL ----------
    valid_root_crl = make_crl(root, entries=[], crl_number=1,
                              this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    leaf_crl = make_crl(inter, entries=[], crl_number=2,
                        this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    bad_leaf_crl = rewrite_cert_or_crl_sig_algorithm(leaf_crl, _PSS_MGF384)
    crl_objects: dict = {}
    for der, otype in ((root.der, "certificate"), (inter.der, "certificate"),
                       (leaf.der, "certificate"),
                       (valid_root_crl, "crl"), (bad_leaf_crl, "crl")):
        crl_objects[sha256_hex(der)] = {"type": otype, "der": der,
                                        "received_at": EARLY}
    pack_crl, result_crl = _build_pack(crl_objects, inp)
    _check("crl: MGF-mismatch CRL yields UNSUPPORTED",
           result_crl["verdict"] == "UNSUPPORTED", result_crl["verdict"])
    leaf_outcome = result_crl["revocation"][sha256_hex(leaf.der)]
    _check("crl: leaf outcome is defective and tagged unsupported",
           leaf_outcome["status"] == "MALFORMED_EVIDENCE"
           and leaf_outcome.get("unsupported_evidence") is True,
           str(leaf_outcome))
    acct = {r["fingerprint"]: r for r in result_crl["evidence_accounting"]}
    _check("crl: tampered CRL excluded as UNSUPPORTED",
           acct[sha256_hex(bad_leaf_crl)]["reason"] == "UNSUPPORTED",
           str(acct.get(sha256_hex(bad_leaf_crl))))
    _offline_review(pack_crl, "MGF-mismatch CRL")

    return {
        "cert_mgf_verdict": result_cert["verdict"],
        "crl_mgf_verdict": result_crl["verdict"],
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

CHECKS = [
    ("direct business-module repro", direct_business_module_repro),
    ("certificate/CRL/OCSP entry-point consistency", entry_point_consistency),
    ("engine adjudication + offline evidence-pack review", engine_and_offline_review),
    ("certificate/CRL end-to-end + offline evidence-pack review",
     cert_and_crl_end_to_end),
]


def run_all() -> list[tuple[str, bool, object]]:
    results = []
    for name, fn in CHECKS:
        try:
            details = fn()
            results.append((name, True, details))
        except Exception as exc:  # noqa: BLE001 - reported as a structured failure
            results.append((name, False, f"{type(exc).__name__}: {exc}"))
    return results


def main() -> int:
    results = run_all()
    bug_flag = None
    for name, ok, details in results:
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name}", flush=True)
        if ok and isinstance(details, dict):
            for key in sorted(details):
                print(f"       {key}={details[key]}", flush=True)
            if "BUG_MGF_MISMATCH_ACCEPTED" in details:
                bug_flag = details["BUG_MGF_MISMATCH_ACCEPTED"]
        elif not ok:
            print(f"       {details}", flush=True)
    # the direct repro must exist and must report the bug as fixed
    if bug_flag is None:
        print("BUG_MGF_MISMATCH_ACCEPTED=UNKNOWN (direct repro did not run)", flush=True)
        ok_all = False
    else:
        print(f"BUG_MGF_MISMATCH_ACCEPTED={'True' if bug_flag else 'False'}", flush=True)
        ok_all = (bug_flag is False)
    ok_all = ok_all and all(ok for _, ok, _ in results)
    print("PSS-MGF REGRESSION PASSED" if ok_all else "PSS-MGF REGRESSION FAILED",
          flush=True)
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
