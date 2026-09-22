"""Code-level RSASSA-PSS parameter regression (MGF-1 mismatch authorization).

Runnable three ways, all exercising the *business* modules directly (the
same code path as ``docker compose exec api-a python -c ...``):

    python -m acceptance.pss_regression            # inside the api-a image
    python -m pytest tests/test_pss_regression.py  # unit/regression suite
    # and as the final phase of the ``verify`` acceptance service

The historical bug: an OCSP response whose RSASSA-PSS AlgorithmIdentifier
declared MGF1-SHA384 while the signature was still produced with MGF1-SHA256
was accepted (``BUG_MGF_MISMATCH_ACCEPTED=True``).  A mismatch between the
declared MGF-1 hash and the message hash is outside the project's
"MGF-1 with the same hash" profile and must classify structurally as
UNSUPPORTED; a genuinely bad signature under *conforming* parameters keeps
the ordinary signature-invalid classification.

Certificate, CRL and OCSP entry points must all parse the four RSASSA-PSS
fields (message hash, MGF-1 inner hash, salt length, trailerField) straight
from the operative AlgorithmIdentifier DER, and the offline evidence-pack
verifier must reach the same conclusions.
"""
from __future__ import annotations

import base64
import hashlib
import sys
import os
from dataclasses import dataclass
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import profile  # noqa: E402
from app.adjudicate import DictObjectSource, run_engine, validate_input  # noqa: E402
from app.canonical import b64e, dumps, sha256_hex  # noqa: E402
from app.pki import parse_certificate  # noqa: E402
from app.revocation import (  # noqa: E402
    parse_crl,
    parse_ocsp,
    _verify_crl_signature,
    _verify_ocsp_authorization,
)
from app.verify import CheckLog, verify_pack  # noqa: E402
from acceptance.pki_fixtures import (  # noqa: E402
    cert_replace_signature_algorithm,
    corrupt_object_signature,
    crl_replace_signature_algorithm,
    make_ca,
    make_crl,
    make_leaf,
    make_ocsp,
    ocsp_corrupt_signature,
    ocsp_replace_signature_algorithm,
    pss_algorithm_identifier,
    sign_data,
)

UTC = timezone.utc
T = lambda s: datetime.fromisoformat(s + "T00:00:00+00:00")

# Fixed reproduction data from the original report.
SERIAL = 4242
THIS_UPDATE = T("2024-05-20")
NEXT_UPDATE = T("2024-06-20")
SIGNED_AT = "2024-06-01T00:00:00Z"
CUTOFF = "2025-01-01T00:00:00Z"
EARLY = "2024-01-01T00:00:00Z"


@dataclass
class Finding:
    name: str
    ok: bool
    detail: str = ""


class Bag:
    def __init__(self):
        self.objects = {}

    def add(self, der, otype, received_at=EARLY):
        fp = sha256_hex(der)
        self.objects[fp] = {"type": otype, "der": der, "received_at": received_at}
        return fp

    def cert(self, entity):
        return self.add(entity.der, "certificate")


def _rsa_chain(bag=None):
    """root(RSA) -> inter(RSA, PSS issuer) -> leaf(RSA, serial 4242).

    When a *bag* is supplied the three certificates and a covering root CRL
    are added to it (used by both the engine and HTTP API regressions).
    """
    root = make_ca("PSS Root", "rsa", not_before=T("2020-01-01"),
                   not_after=T("2040-01-01"))
    inter = make_ca("PSS Inter", "rsa", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "PSS Leaf", "rsa", serial=SERIAL,
                     not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"])
    if bag is not None:
        for e in (root, inter, leaf):
            bag.cert(e)
        bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                         next_update=T("2024-07-01")), "crl")
    return root, inter, leaf


def _adjudication_input(leaf):
    digest = hashlib.sha256(b"pss regression artifact").hexdigest()
    sig = sign_data(leaf.key, bytes.fromhex(digest))
    return {
        "artifact_digest": digest,
        "signature": base64.b64encode(sig).decode(),
        "signature_algorithm": "rsa-pss-sha256",
        "signed_at": SIGNED_AT,
        "knowledge_cutoff": CUTOFF,
        "leaf_fingerprint": sha256_hex(leaf.der),
        "trust_anchors": [],  # filled by caller
    }


def _adjudicate(bag, leaf, root, content_digest="0" * 64):
    inp = _adjudication_input(leaf)
    inp["trust_anchors"] = [sha256_hex(root.der)]
    inp = validate_input(inp)
    result, touched = run_engine(DictObjectSource(bag.objects), inp, content_digest)
    return inp, result, touched


def _manifest_for_bag(bag):
    objs = []
    for fp in sorted(bag.objects):
        o = bag.objects[fp]
        objs.append({"fingerprint": fp, "type": o["type"],
                     "received_at": o["received_at"]})
    manifest = {
        "format": "evidence-set-manifest/1",
        "counts": {},
        "limits": profile.LIMITS,
        "objects": objs,
    }
    return manifest, sha256_hex(dumps(manifest))


def _adjudicate_sealed(bag, leaf, root):
    """Adjudicate against a manifest/content digest derived from the whole
    bag, mirroring a sealed evidence set."""
    _manifest, content_digest = _manifest_for_bag(bag)
    return _adjudicate(bag, leaf, root, content_digest)


def _build_pack(bag, inp, result, touched):
    """Assemble an evidence pack over the sealed bag; include exactly the
    objects the engine touched."""
    manifest, content_digest = _manifest_for_bag(bag)
    pack_objects = []
    for fp in sorted(touched):
        o = bag.objects[fp]
        pack_objects.append({"fingerprint": fp, "type": o["type"],
                             "received_at": o["received_at"],
                             "der": b64e(o["der"])})
    return {
        "pack_version": 1,
        "adjudication_id": result["adjudication_id"],
        "input": inp,
        "evidence_set": {"content_digest": content_digest, "manifest": manifest},
        "objects": pack_objects,
        "result": result,
    }


# ---------------------------------------------------------------------------
# Individual scenarios
# ---------------------------------------------------------------------------

def scenario_valid_response() -> Finding:
    """Unmodified conforming RSA-PSS OCSP response stays authorized."""
    root, inter, leaf = _rsa_chain()
    ocsp = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    info = parse_ocsp(ocsp)
    inter_ci = parse_certificate(inter.der)
    ok, desc, _ = _verify_ocsp_authorization(info, inter_ci)
    if not ok:
        return Finding("valid-pss-ocsp-authorized", False, f"auth={desc}")
    if info.sig_alg is None or info.sig_alg["mgf_hash"] != "sha256":
        return Finding("valid-pss-ocsp-authorized", False, f"sig_alg={info.sig_alg}")
    # full engine: GOOD and VALID
    bag = Bag()
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl")
    bag.add(ocsp, "ocsp")
    _, result, _ = _adjudicate(bag, leaf, root)
    if result["verdict"] != "VALID":
        return Finding("valid-pss-ocsp-authorized", False,
                       f"verdict={result['verdict']}")
    if result["revocation"][sha256_hex(leaf.der)]["status"] != "GOOD":
        return Finding("valid-pss-ocsp-authorized", False, "leaf not GOOD")
    return Finding("valid-pss-ocsp-authorized", True)


def scenario_mgf_mismatch() -> Finding:
    """Declared MGF1-SHA384 over a MGF1-SHA256 signature: parses, never
    authorized, structurally UNSUPPORTED; BUG flag stays False."""
    root, inter, leaf = _rsa_chain()
    good = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    mgf384 = pss_algorithm_identifier(hash_name="sha256", mgf_hash="sha384")
    tampered = ocsp_replace_signature_algorithm(good, mgf384)

    good_info = parse_ocsp(good)
    bad = parse_ocsp(tampered)
    # parsing still succeeds and the signed content is byte-identical
    if bad.tbs != good_info.tbs or bad.signature != good_info.signature:
        return Finding("mgf-mismatch-unsupported", False, "tbs/signature changed")
    inter_ci = parse_certificate(inter.der)
    ok, desc, _ = _verify_ocsp_authorization(bad, inter_ci)
    bug_flag = bool(ok and not bad.unsupported)
    if ok:
        return Finding("mgf-mismatch-unsupported", False, f"authorized: {desc}")
    if not bad.unsupported or bad.sig_alg is not None:
        return Finding("mgf-mismatch-unsupported", False,
                       f"unsupported={bad.unsupported} sig_alg={bad.sig_alg}")
    if bug_flag:
        return Finding("mgf-mismatch-unsupported", False,
                       "BUG_MGF_MISMATCH_ACCEPTED=True")

    # full business layer: revocation outcome and verdict must be UNSUPPORTED
    bag = Bag()
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl")
    fp = bag.add(tampered, "ocsp")
    _, result, _ = _adjudicate(bag, leaf, root)
    leaf_status = result["revocation"][sha256_hex(leaf.der)]["status"]
    if leaf_status != "UNSUPPORTED":
        return Finding("mgf-mismatch-unsupported", False,
                       f"revocation status={leaf_status}")
    if result["verdict"] != "UNSUPPORTED":
        return Finding("mgf-mismatch-unsupported", False,
                       f"verdict={result['verdict']}")
    acct = {r["fingerprint"]: r for r in result["evidence_accounting"]}
    if acct.get(fp, {}).get("reason") != "UNSUPPORTED":
        return Finding("mgf-mismatch-unsupported", False,
                       f"accounting={acct.get(fp)}")
    return Finding("mgf-mismatch-unsupported", True,
                   "BUG_MGF_MISMATCH_ACCEPTED=False")


def scenario_conforming_params_bad_signature() -> Finding:
    """Conforming PSS parameters + corrupted signature bytes stay in the
    ordinary signature-invalid bucket (never UNSUPPORTED), for OCSP, CRL and
    a certificate edge signature."""
    root, inter, leaf = _rsa_chain()

    # --- OCSP: RESPONDER_UNAUTHORIZED -> MALFORMED_EVIDENCE -> INVALID ---
    good = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    bad_ocsp = ocsp_corrupt_signature(good)
    oi = parse_ocsp(bad_ocsp)
    if oi.unsupported:
        return Finding("conforming-badsig-invalid", False, "ocsp flagged unsupported")
    inter_ci = parse_certificate(inter.der)
    if _verify_ocsp_authorization(oi, inter_ci)[0]:
        return Finding("conforming-badsig-invalid", False, "ocsp still authorized")
    bag = Bag()
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl")
    bag.add(bad_ocsp, "ocsp")
    _, res, _ = _adjudicate(bag, leaf, root)
    if res["revocation"][sha256_hex(leaf.der)]["status"] != "MALFORMED_EVIDENCE":
        return Finding("conforming-badsig-invalid", False, "ocsp not MALFORMED_EVIDENCE")
    if res["verdict"] == "UNSUPPORTED":
        return Finding("conforming-badsig-invalid", False, "ocsp verdict UNSUPPORTED")

    # --- CRL: SIGNATURE_INVALID -> MALFORMED_EVIDENCE, parses fine ---
    crl = make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                   next_update=T("2024-07-01"))
    bad_crl = corrupt_object_signature(crl)
    cl = parse_crl(bad_crl)
    if cl.unsupported:
        return Finding("conforming-badsig-invalid", False, "crl flagged unsupported")
    if _verify_crl_signature(cl, inter_ci):
        return Finding("conforming-badsig-invalid", False, "crl signature verified")

    # --- certificate: edge SIGNATURE_INVALID -> INVALID (not UNSUPPORTED) ---
    bad_inter_der = corrupt_object_signature(inter.der)
    bci = parse_certificate(bad_inter_der)
    if bci.unsupported:
        return Finding("conforming-badsig-invalid", False, "cert flagged unsupported")
    bag2 = Bag()
    bag2.cert(root)
    bag2.add(bad_inter_der, "certificate")
    bag2.cert(leaf)
    # leaf must have GOOD revocation so the search proceeds to the edge whose
    # signature we corrupted (inter -> root); use an inter-signed empty CRL
    bag2.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                      next_update=T("2024-07-01")), "crl")
    bag2.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                      next_update=T("2024-07-01")), "crl")
    _, res2, _ = _adjudicate(bag2, leaf, root)
    if res2["verdict"] == "UNSUPPORTED":
        return Finding("conforming-badsig-invalid", False, "cert verdict UNSUPPORTED")
    codes = res2["summary"].get("failure_codes", [])
    if "SIGNATURE_INVALID" not in codes:
        return Finding("conforming-badsig-invalid", False, f"codes={codes}")
    return Finding("conforming-badsig-invalid", True)


def _descriptor_consistency(label, der, parser, kind):
    """Parse *der* at one entry point and return its PSS descriptor findings."""
    info = parser(der)
    d = info.sig_alg
    if d is None:
        return None, f"{label}: descriptor is None"
    required = {"algorithm", "hash", "mgf_hash", "salt_length", "trailer_field"}
    if not required.issubset(d):
        return None, f"{label}: descriptor missing fields: {d}"
    return d, ""


def scenario_pss_field_semantics() -> Finding:
    """message hash / MGF-1 inner hash / salt length / trailerField carry the
    same meaning across certificate, CRL and OCSP parsers."""
    root, inter, _leaf = _rsa_chain()
    crl = make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                   next_update=T("2024-07-01"))
    ocsp = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    targets = [
        ("cert", inter.der, parse_certificate, cert_replace_signature_algorithm),
        ("crl", crl, parse_crl, crl_replace_signature_algorithm),
        ("ocsp", ocsp, parse_ocsp, ocsp_replace_signature_algorithm),
    ]

    # (a) conforming SHA-256/MGF1-SHA256 descriptor fields at every entry
    for label, der, parser, _ in targets:
        d, err = _descriptor_consistency(label, der, parser, label)
        if d is None:
            return Finding("pss-field-semantics", False, err)
        if not (d["hash"] == "sha256" and d["mgf_hash"] == "sha256"
                and d["salt_length"] == 32 and d["trailer_field"] == 1):
            return Finding("pss-field-semantics", False, f"{label}: {d}")

    # (b) each out-of-profile encoding independently yields no descriptor
    mutations = {
        "mgf-mismatch": pss_algorithm_identifier(hash_name="sha256", mgf_hash="sha384"),
        "trailer-2": pss_algorithm_identifier(trailer_field=2),
    }
    for label, der, parser, replace in targets:
        for mname, alg in mutations.items():
            bad = replace(der, alg)
            info = parser(bad)
            if not info.unsupported or info.sig_alg is not None:
                return Finding("pss-field-semantics", False,
                               f"{label}/{mname} accepted: {info.sig_alg}")

    # (c) a consistent SHA-384/SHA384 declaration is in profile as a shape;
    # over a SHA-256 signature it must be a plain signature failure, never an
    # MGF-style UNSUPPORTED (message-hash-only change is internally consistent).
    sha384 = pss_algorithm_identifier(hash_name="sha384", mgf_hash="sha384")
    bad_ocsp = ocsp_replace_signature_algorithm(ocsp, sha384)
    oi = parse_ocsp(bad_ocsp)
    if oi.unsupported or oi.sig_alg is None or oi.sig_alg["algorithm"] != "rsa-pss-sha384":
        return Finding("pss-field-semantics", False,
                       f"consistent sha384 declaration mishandled: {oi.sig_alg}")

    # (d) declared salt length is recorded verbatim; any non-negative value is
    # in profile (the salt is recovered at verification time, per README).
    salt16 = pss_algorithm_identifier(salt_length=16)
    for label, der, parser, replace in targets:
        d, err = _descriptor_consistency(label, replace(der, salt16), parser, label)
        if d is None:
            return Finding("pss-field-semantics", False, f"{label}: {err}")
        if d["salt_length"] != 16:
            return Finding("pss-field-semantics", False,
                           f"{label}: salt_length not recorded: {d}")
    return Finding("pss-field-semantics", True)


def scenario_offline_pack() -> Finding:
    """Offline evidence-pack review must reproduce the UNSUPPORTED verdict for
    the MGF mismatch and reject tampered packs; a valid pack verifies and its
    prior verdict is unchanged."""
    root, inter, leaf = _rsa_chain()
    good = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS_UPDATE, next_update=NEXT_UPDATE)
    mgf384 = pss_algorithm_identifier(hash_name="sha256", mgf_hash="sha384")
    bad = ocsp_replace_signature_algorithm(good, mgf384)

    def pack_for(ocsp_der):
        bag = Bag()
        for e in (root, inter, leaf):
            bag.cert(e)
        bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                         next_update=T("2024-07-01")), "crl")
        bag.add(ocsp_der, "ocsp")
        inp, result, touched = _adjudicate_sealed(bag, leaf, root)
        return bag, inp, _build_pack(bag, inp, result, touched)

    # valid pack verifies offline and keeps the VALID verdict
    _, inp_ok, pack_ok = pack_for(good)
    if not verify_pack(dumps(pack_ok), CheckLog()):
        return Finding("offline-pack", False, "valid pack failed verification")
    if pack_ok["result"]["verdict"] != "VALID":
        return Finding("offline-pack", False, "valid pack verdict changed")

    # MGF-mismatch pack is internally consistent (recompute => UNSUPPORTED)
    _, _, pack_bad = pack_for(bad)
    if pack_bad["result"]["verdict"] != "UNSUPPORTED":
        return Finding("offline-pack", False, "bad pack verdict not UNSUPPORTED")
    if not verify_pack(dumps(pack_bad), CheckLog()):
        return Finding("offline-pack", False, "unsupported pack must verify offline")

    # tampering the stored verdict must be detected by the offline verifier
    tampered = {**pack_bad, "result": {**pack_bad["result"], "verdict": "VALID"}}
    if verify_pack(dumps(tampered), CheckLog()):
        return Finding("offline-pack", False, "verdict tampering not detected")
    return Finding("offline-pack", True)


SCENARIOS = (
    scenario_valid_response,
    scenario_mgf_mismatch,
    scenario_conforming_params_bad_signature,
    scenario_pss_field_semantics,
    scenario_offline_pack,
)


def run_all() -> list[Finding]:
    findings = []
    for fn in SCENARIOS:
        try:
            findings.append(fn())
        except Exception as exc:  # a crash is a failed regression check
            findings.append(Finding(fn.__name__, False,
                                    f"{type(exc).__name__}: {exc}"))
    return findings


def main() -> int:
    findings = run_all()
    for f in findings:
        status = "PASS" if f.ok else "FAIL"
        print(f"[{status}] {f.name}" + (f" - {f.detail}" if f.detail else ""),
              flush=True)
    # explicit marker mirroring the original code-level reproduction chain
    mismatch = next(f for f in findings if f.name == "mgf-mismatch-unsupported")
    print("BUG_MGF_MISMATCH_ACCEPTED=" + ("False" if mismatch.ok else "True"))
    failed = [f.name for f in findings if not f.ok]
    if failed:
        print(f"PSS REGRESSION FAILED: {failed}", flush=True)
        return 1
    print("PSS REGRESSION PASSED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
