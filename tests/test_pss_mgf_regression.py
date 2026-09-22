"""Pytest entry point for the RSASSA-PSS parameter regression.

The checks themselves live in :mod:`acceptance.regression_pss` so the exact
same code runs in three places with one implementation:

* ``pytest tests/`` (this file),
* ``python -m acceptance.regression_pss`` directly (also inside ``api-a`` via
  ``docker compose exec -T api-a python -m acceptance.regression_pss``),
* the docker-compose ``verify`` acceptance service.

All assertions passing means the process exits 0; any failure is non-zero.
"""
from __future__ import annotations

from acceptance import regression_pss
from acceptance.regression_pss import main, run_all
from app import profile
from app.derutil import parse_pss_params, read_algorithm_identifier


def test_pss_parameter_regression_groups_all_pass():
    results = run_all()
    failures = [(name, detail) for name, ok, detail in results if not ok]
    assert not failures, failures
    names = {name for name, _ok, _d in results}
    assert names == {
        "direct business-module repro",
        "certificate/CRL/OCSP entry-point consistency",
        "engine adjudication + offline evidence-pack review",
        "certificate/CRL end-to-end + offline evidence-pack review",
    }


def test_module_main_exits_zero_on_success():
    # exercises the same exit-status contract the docker exec link relies on
    assert main() == 0


def test_direct_repro_reports_bug_fixed():
    details = regression_pss.direct_business_module_repro()
    assert details["BUG_MGF_MISMATCH_ACCEPTED"] is False
    assert details["legit_authorized"] is True
    assert details["mgf_mismatch_authorized"] is False
    assert details["mgf_mismatch_reason"] == "UNSUPPORTED"
    assert details["corrupt_signature_reason"] == "RESPONDER_UNAUTHORIZED"


# ---------------------------------------------------------------------------
# Focused unit coverage for the strict RSASSA-PSS parameter declaration.
# ---------------------------------------------------------------------------

def _params(alg_der: bytes):
    return read_algorithm_identifier(alg_der)[1]


def test_pss_descriptor_accepts_profile_conformant_variants():
    from acceptance.pki_fixtures import build_pss_algorithm_der

    for name in ("sha256", "sha384", "sha512"):
        alg = build_pss_algorithm_der(hash_name=name, mgf_hash_name=name)
        desc = profile.signature_algorithm_descriptor(profile.OID_RSASSA_PSS,
                                                      _params(alg))
        assert desc is not None
        assert desc["algorithm"] == f"rsa-pss-{name}"
        assert desc["hash"] == name
        assert desc["mgf"] == profile.OID_MGF1
        assert desc["mgf_hash"] == name
        assert desc["salt_length"] == 32
        assert desc["trailer_field"] == 1


def test_pss_descriptor_rejects_mgf_inner_hash_mismatch():
    from acceptance.pki_fixtures import build_pss_algorithm_der

    # message hash sha256 but MGF1-SHA384: the reported vulnerability
    alg = build_pss_algorithm_der(hash_name="sha256", mgf_hash_name="sha384")
    assert profile.signature_algorithm_descriptor(
        profile.OID_RSASSA_PSS, _params(alg)) is None
    # and the reverse direction is rejected identically
    alg = build_pss_algorithm_der(hash_name="sha384", mgf_hash_name="sha256")
    assert profile.signature_algorithm_descriptor(
        profile.OID_RSASSA_PSS, _params(alg)) is None


def test_pss_descriptor_rejects_trailer_field_other_than_one():
    from acceptance.pki_fixtures import build_pss_algorithm_der

    alg = build_pss_algorithm_der(trailer_field=2)
    assert profile.signature_algorithm_descriptor(
        profile.OID_RSASSA_PSS, _params(alg)) is None


def test_pss_descriptor_rejects_absent_or_sha1_default_params():
    # no params at all -> RFC defaults are SHA-1/MGF1-SHA1: out of profile
    assert profile.signature_algorithm_descriptor(
        profile.OID_RSASSA_PSS, None) is None
    # malformed params element -> out of profile, never silently accepted
    assert profile.signature_algorithm_descriptor(
        profile.OID_RSASSA_PSS, b"\x04\x03abc") is None
    # explicit SHA-1 message hash -> out of profile
    from acceptance.pki_fixtures import build_pss_algorithm_der

    alg = build_pss_algorithm_der(hash_name="sha1", mgf_hash_name="sha1")
    assert profile.signature_algorithm_descriptor(
        profile.OID_RSASSA_PSS, _params(alg)) is None


def test_parse_pss_params_records_every_declared_field():
    from acceptance.pki_fixtures import build_pss_algorithm_der

    alg = build_pss_algorithm_der(hash_name="sha384", mgf_hash_name="sha384",
                                  salt_length=48, trailer_field=1)
    spec = parse_pss_params(_params(alg))
    assert spec == {
        "hash": "sha384",
        "mgf": profile.OID_MGF1,
        "mgf_hash": "sha384",
        "salt_length": 48,
        "trailer_field": 1,
    }


def test_parse_pss_params_salt_length_boundaries():
    from acceptance.pki_fixtures import build_pss_algorithm_der

    # values spanning 1-, 2- and 3-byte INTEGER encodings, incl. 128 which
    # needs a leading 0x00 octet to stay positive under DER
    for salt_length in (0, 1, 127, 128, 255, 256, 65535):
        alg = build_pss_algorithm_der(salt_length=salt_length)
        spec = parse_pss_params(_params(alg))
        assert spec is not None and spec["salt_length"] == salt_length
        desc = profile.signature_algorithm_descriptor(
            profile.OID_RSASSA_PSS, _params(alg))
        assert desc is not None and desc["salt_length"] == salt_length


def test_parse_pss_params_rejects_malformed_encodings():
    from app.derutil import encode_tlv, oid_to_der

    def alg_id(oid):
        return encode_tlv(0x30, oid_to_der(oid) + encode_tlv(0x05, b""))

    mgf = encode_tlv(
        0x30,
        oid_to_der("1.2.840.113549.1.1.8")
        + alg_id("2.16.840.1.101.3.4.2.1"),
    )
    sha256 = "2.16.840.1.101.3.4.2.1"

    def wrap(fields):
        return encode_tlv(0x30, b"".join(fields))

    base = [
        encode_tlv(0xA0, alg_id(sha256)),
        encode_tlv(0xA1, mgf),
        encode_tlv(0xA2, encode_tlv(0x02, b"\x20")),
    ]
    # duplicate hash field
    dup = wrap(base + [encode_tlv(0xA0, alg_id(sha256))])
    assert parse_pss_params(dup) is None
    # unknown field tag
    unknown = wrap(base + [encode_tlv(0xA4, encode_tlv(0x02, b"\x01"))])
    assert parse_pss_params(unknown) is None
    # negative salt length
    neg = wrap([
        encode_tlv(0xA0, alg_id(sha256)),
        encode_tlv(0xA1, mgf),
        encode_tlv(0xA2, encode_tlv(0x02, b"\xff")),
    ])
    assert parse_pss_params(neg) is None
    # non-MGF mask algorithm is parsed but rejected by the profile
    other_mgf = wrap([
        encode_tlv(0xA0, alg_id(sha256)),
        encode_tlv(0xA1, alg_id(sha256)),  # not id-mgf1
        encode_tlv(0xA2, encode_tlv(0x02, b"\x20")),
    ])
    spec = parse_pss_params(other_mgf)
    assert spec is not None and spec["mgf"] == sha256
    assert profile.signature_algorithm_descriptor(
        profile.OID_RSASSA_PSS, other_mgf) is None
