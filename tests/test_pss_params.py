"""Unit tests for the raw-DER RSASSA-PSS parameter parser and descriptor.

These pin the exact semantics shared by the certificate, CRL and OCSP entry
points: message hash, MGF-1 inner hash, salt length and trailerField are all
read from the operative AlgorithmIdentifier and the profile requires MGF-1 to
use the same hash as the message and trailerField == 1.
"""
from __future__ import annotations

import pytest

from app import profile
from app.derutil import encode_tlv, oid_to_der, parse_pss_parameters

_OID_PSS = "1.2.840.113549.1.1.10"
_OID_MGF1 = "1.2.840.113549.1.1.8"
_OID = {
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "sha1": "1.3.14.3.2.26",
}


def _ai(oid, with_null=True):
    return encode_tlv(0x30, oid_to_der(oid) + (encode_tlv(0x05, b"") if with_null else b""))


def _pss_params(*, hash_name="sha256", mgf_hash="sha256", salt_length=32,
                trailer_field=None, include_hash=True, include_mgf=True,
                include_salt=True, mgf_oid=_OID_MGF1):
    content = b""
    if include_hash:
        content += encode_tlv(0xA0, _ai(_OID[hash_name]))
    if include_mgf:
        mgf_ai = encode_tlv(0x30, oid_to_der(mgf_oid) + _ai(_OID[mgf_hash]))
        content += encode_tlv(0xA1, mgf_ai)
    if include_salt:
        content += encode_tlv(0xA2, encode_tlv(0x02, bytes([salt_length])))
    if trailer_field is not None:
        content += encode_tlv(0xA3, encode_tlv(0x02, bytes([trailer_field])))
    return encode_tlv(0x30, content)


def test_conforming_sha256_parameters():
    p = parse_pss_parameters(_pss_params())
    assert p == {"hash": "sha256", "mgf": "mgf1", "mgf_hash": "sha256",
                 "salt_length": 32, "trailer_field": 1}


@pytest.mark.parametrize("name", ["sha256", "sha384", "sha512"])
def test_supported_message_hashes(name):
    p = parse_pss_parameters(_pss_params(hash_name=name, mgf_hash=name))
    assert p["hash"] == name and p["mgf_hash"] == name


def test_mgf_hash_mismatch_parses_but_is_out_of_profile():
    parsed = parse_pss_parameters(_pss_params(hash_name="sha256", mgf_hash="sha384"))
    assert parsed is not None and parsed["mgf_hash"] == "sha384"  # structurally valid
    assert profile.pss_descriptor(_pss_params(hash_name="sha256", mgf_hash="sha384")) is None


def test_trailer_field_other_than_one_returns_none():
    assert parse_pss_parameters(_pss_params(trailer_field=2)) is not None  # parses
    assert profile.pss_descriptor(_pss_params(trailer_field=2)) is None     # out of profile


def test_absent_fields_use_sha1_defaults_and_are_out_of_profile():
    # missing hashAlgorithm -> SHA-1 default; must not be accepted
    assert profile.pss_descriptor(_pss_params(include_hash=False)) is None
    # missing maskGenAlgorithm -> not MGF-1; must not be accepted
    assert profile.pss_descriptor(_pss_params(include_mgf=False)) is None


def test_sha1_hash_out_of_profile():
    assert profile.pss_descriptor(_pss_params(hash_name="sha1", mgf_hash="sha1")) is None


def test_non_mgf1_mask_returns_none():
    assert profile.pss_descriptor(
        _pss_params(mgf_oid="1.2.840.113549.1.1.9")) is None  # id-mgf2


def test_negative_salt_length_parses_but_is_out_of_profile():
    params = encode_tlv(0x30,
                        encode_tlv(0xA0, _ai(_OID["sha256"]))
                        + encode_tlv(0xA1, encode_tlv(0x30,
                            oid_to_der(_OID_MGF1) + _ai(_OID["sha256"])))
                        + encode_tlv(0xA2, encode_tlv(0x02, b"\xff")))  # -1
    parsed = parse_pss_parameters(params)
    assert parsed is not None and parsed["salt_length"] == -1  # structurally valid
    assert profile.pss_descriptor(params) is None              # out of profile


def test_zero_salt_length_is_in_profile():
    p = parse_pss_parameters(_pss_params(salt_length=0))
    assert p["salt_length"] == 0
    assert profile.pss_descriptor(_pss_params(salt_length=0)) is not None


def test_unknown_pss_field_returns_none():
    # inject an unsupported [4] field inside the params SEQUENCE
    raw = (
        encode_tlv(0xA0, _ai(_OID["sha256"]))
        + encode_tlv(0xA1, encode_tlv(0x30, oid_to_der(_OID_MGF1) + _ai(_OID["sha256"])))
        + encode_tlv(0xA2, encode_tlv(0x02, b"\x20"))
        + encode_tlv(0xA4, encode_tlv(0x02, b"\x01"))
    )
    assert profile.pss_descriptor(encode_tlv(0x30, raw)) is None


def test_malformed_and_absent_params_return_none():
    assert parse_pss_parameters(None) is None
    assert parse_pss_parameters(b"") is None
    assert parse_pss_parameters(encode_tlv(0x31, b"")) is None  # not a SEQUENCE
    assert profile.pss_descriptor(b"\x04\x00") is None


def test_descriptor_is_rejected_for_non_pss_oid_with_pss_params():
    # signature_algorithm_descriptor must route only RSASSA-PSS through params
    assert profile.signature_algorithm_descriptor(
        _OID_MGF1, _pss_params()) is None
