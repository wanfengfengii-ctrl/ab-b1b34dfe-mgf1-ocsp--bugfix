"""Engine-level regression for RSASSA-PSS AlgorithmIdentifier semantics.

Covers the MGF-1 mismatch authorization bug across certificates, CRLs and
OCSP responses, and confirms that a genuinely invalid signature under
*conforming* PSS parameters keeps the ordinary signature-invalid
classification rather than the structured UNSUPPORTED outcome.
"""
from __future__ import annotations

from app.canonical import dumps, sha256_hex
from app.revocation import parse_crl, parse_ocsp
from acceptance.pki_fixtures import (
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
)
from tests.conftest import Bag, EARLY, T, adjudicate

SERIAL = 4242
THIS = T("2024-05-20")
NEXT = T("2024-06-20")


def _rsa_chain(bag, **leaf_kw):
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "rsa", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "rsa", serial=SERIAL, not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"], **leaf_kw)
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    return root, inter, leaf


def _adjudicate(bag, leaf, root):
    return adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                      leaf_key=leaf.key)


def test_valid_pss_ocsp_is_authorized():
    bag = Bag()
    root, inter, leaf = _rsa_chain(bag)
    ocsp = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS, next_update=NEXT)
    bag.add(ocsp, "ocsp", EARLY)
    res = _adjudicate(bag, leaf, root)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "GOOD"


def test_ocsp_mgf_mismatch_is_structured_unsupported():
    bag = Bag()
    root, inter, leaf = _rsa_chain(bag)
    good = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS, next_update=NEXT)
    mgf384 = pss_algorithm_identifier(hash_name="sha256", mgf_hash="sha384")
    bad = ocsp_replace_signature_algorithm(good, mgf384)

    # it parses, but tbs/signature are byte-identical to the valid response
    ok_info, bad_info = parse_ocsp(good), parse_ocsp(bad)
    assert bad_info.tbs == ok_info.tbs
    assert bad_info.signature == ok_info.signature
    assert bad_info.unsupported and bad_info.sig_alg is None

    fp = bag.add(bad, "ocsp", EARLY)
    res = _adjudicate(bag, leaf, root)
    assert res["verdict"] == "UNSUPPORTED", dumps(res["decision"]).decode()
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "UNSUPPORTED"
    acct = {r["fingerprint"]: r for r in res["evidence_accounting"]}
    assert acct[fp]["reason"] == "UNSUPPORTED"


def test_ocsp_conforming_params_bad_signature_is_invalid():
    bag = Bag()
    root, inter, leaf = _rsa_chain(bag)
    good = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS, next_update=NEXT)
    bad = ocsp_corrupt_signature(good)
    # parameters remain in profile; only the signature bytes are broken
    assert not parse_ocsp(bad).unsupported
    bag.add(bad, "ocsp", EARLY)
    res = _adjudicate(bag, leaf, root)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "MALFORMED_EVIDENCE"
    fp_acct = [r for r in res["evidence_accounting"] if r["type"] == "ocsp"]
    assert fp_acct and fp_acct[0]["reason"] == "RESPONDER_UNAUTHORIZED"


def test_crl_mgf_mismatch_is_unsupported():
    bag = Bag()
    root, inter, leaf = _rsa_chain(bag)
    crl = make_crl(inter, entries=[], crl_number=2, this_update=THIS, next_update=NEXT)
    mgf384 = pss_algorithm_identifier(hash_name="sha256", mgf_hash="sha384")
    bad = crl_replace_signature_algorithm(crl, mgf384)
    assert parse_crl(bad).unsupported and parse_crl(bad).sig_alg is None
    bag.add(bad, "crl", EARLY)
    res = _adjudicate(bag, leaf, root)
    assert res["verdict"] == "UNSUPPORTED"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "UNSUPPORTED"


def test_crl_conforming_params_bad_signature_is_invalid():
    bag = Bag()
    root, inter, leaf = _rsa_chain(bag)
    crl = make_crl(inter, entries=[], crl_number=2, this_update=THIS, next_update=NEXT)
    bad = corrupt_object_signature(crl)
    assert not parse_crl(bad).unsupported
    bag.add(bad, "crl", EARLY)
    res = _adjudicate(bag, leaf, root)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "MALFORMED_EVIDENCE"
    crl_acct = [r for r in res["evidence_accounting"] if r["type"] == "crl"
                and r["reason"] == "SIGNATURE_INVALID"]
    assert crl_acct


def test_ocsp_delegated_responder_mgf_mismatch_is_unsupported():
    from acceptance.pki_fixtures import make_leaf as _ml

    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "rsa", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "rsa", serial=SERIAL, not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    # RSA delegated OCSP responder carrying id-kp-OCSPSigning
    responder = _ml(inter, "OCSP Responder", "rsa", not_before=T("2022-01-01"),
                    not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.9"])
    for e in (root, inter, leaf, responder):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    good = make_ocsp(inter, serial=SERIAL, status="good", this_update=THIS,
                     next_update=NEXT, responder=responder)
    mgf384 = pss_algorithm_identifier(hash_name="sha256", mgf_hash="sha384")
    bad = ocsp_replace_signature_algorithm(good, mgf384)
    assert parse_ocsp(bad).unsupported
    bag.add(bad, "ocsp", EARLY)
    res = _adjudicate(bag, leaf, root)
    assert res["verdict"] == "UNSUPPORTED"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "UNSUPPORTED"


def test_ocsp_consistent_hash_change_is_plain_signature_invalid():
    """Declaring SHA-384/MGF1-SHA384 (internally consistent, in profile as a
    shape) while the signature is still SHA-256 must be an ordinary signature
    failure (RESPONDER_UNAUTHORIZED), not the structured UNSUPPORTED bucket.
    """
    bag = Bag()
    root, inter, leaf = _rsa_chain(bag)
    good = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS, next_update=NEXT)
    sha384 = pss_algorithm_identifier(hash_name="sha384", mgf_hash="sha384")
    bad = ocsp_replace_signature_algorithm(good, sha384)
    info = parse_ocsp(bad)
    assert not info.unsupported
    assert info.sig_alg["algorithm"] == "rsa-pss-sha384"
    bag.add(bad, "ocsp", EARLY)
    res = _adjudicate(bag, leaf, root)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "MALFORMED_EVIDENCE"


def test_cert_mgf_mismatch_is_unsupported():
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "rsa", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "rsa", serial=SERIAL, not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    mgf384 = pss_algorithm_identifier(hash_name="sha256", mgf_hash="sha384")
    bad_inter = cert_replace_signature_algorithm(inter.der, mgf384)
    bag.cert(root)
    bag.add(bad_inter, "certificate")
    bag.cert(leaf)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "UNSUPPORTED"


def test_cert_conforming_params_bad_signature_is_signature_invalid():
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "rsa", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "rsa", serial=SERIAL, not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    bag.cert(root)
    bag.add(corrupt_object_signature(inter.der), "certificate")
    bag.cert(leaf)
    # GOOD leaf revocation so the edge reaches the corrupted inter signature
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert "SIGNATURE_INVALID" in res["summary"]["failure_codes"]


def test_pss_fields_consistent_across_entry_points():
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "rsa", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    crl = make_crl(inter, entries=[], crl_number=1, this_update=THIS, next_update=NEXT)
    ocsp = make_ocsp(inter, serial=SERIAL, status="good",
                     this_update=THIS, next_update=NEXT)

    from app.pki import parse_certificate

    for der, parser in ((inter.der, parse_certificate),
                        (crl, parse_crl),
                        (ocsp, parse_ocsp)):
        d = parser(der).sig_alg
        assert d["hash"] == "sha256" and d["mgf_hash"] == "sha256"
        assert d["salt_length"] == 32 and d["trailer_field"] == 1

    # trailerField 2 is out of profile at every entry point
    trailer2 = pss_algorithm_identifier(trailer_field=2)
    assert parse_certificate(cert_replace_signature_algorithm(inter.der, trailer2)).unsupported
    assert parse_crl(crl_replace_signature_algorithm(crl, trailer2)).unsupported
    assert parse_ocsp(ocsp_replace_signature_algorithm(ocsp, trailer2)).unsupported

    # a declared non-default salt length is recorded verbatim and in profile
    salt16 = pss_algorithm_identifier(salt_length=16)
    assert parse_ocsp(ocsp_replace_signature_algorithm(ocsp, salt16)).sig_alg[
        "salt_length"] == 16
