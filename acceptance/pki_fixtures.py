"""Deterministic PKI fixture generation for tests and the acceptance service.

Everything here is test tooling - none of it is part of the service's
business logic.  Keys are generated fresh per run (the service must never
see fixture fingerprints hard-coded anywhere).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
)

UTC = timezone.utc
_serial_counter = itertools.count(1000)

CODE_SIGNING = ExtendedKeyUsageOID.CODE_SIGNING.dotted_string
OCSP_SIGNING = ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string


def make_key(kind: str):
    if kind == "rsa":
        return rsa.generate_private_key(65537, 2048)
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ed":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(kind)


def sign_algorithm(key):
    pub = key.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return hashes.SHA256(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return hashes.SHA256(), None
    return None, None


def sign_data(key, data: bytes) -> bytes:
    """Sign *data* with the profile artifact-signature algorithm for the key."""
    pub = key.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=32), hashes.SHA256())
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    return key.sign(data)


def artifact_algorithm_for(key) -> str:
    pub = key.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "rsa-pss-sha256"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ecdsa-p256-sha256"
    return "ed25519"


def xname(cn: str, org: str = "Forensics Tests", country: str = "ZZ") -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
    return x509.Name(attrs)


@dataclass
class Entity:
    cn: str
    key: object
    cert: x509.Certificate
    name: x509.Name

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def pub(self):
        return self.cert.public_key()


def _sign_builder(builder, key):
    alg, pad = sign_algorithm(key)
    if pad is not None:
        return builder.sign(key, alg, rsa_padding=pad)
    return builder.sign(key, alg)


def make_ca(cn: str, kind: str, *, issuer: Entity | None = None, key=None,
            not_before: datetime, not_after: datetime, path_len=None,
            key_usage=True, name_constraints=None, policies=None,
            policy_mappings=None, policy_constraints=None, inhibit_any=None,
            serial: int | None = None, subject_name: x509.Name | None = None,
            pkcs1v15: bool = False) -> Entity:
    key = key or make_key(kind)
    name = subject_name or xname(cn)
    issuer_name = issuer.name if issuer else name
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial or next(_serial_counter))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
    )
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )
    if issuer is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.pub),
            critical=False,
        )
    if name_constraints:
        builder = builder.add_extension(name_constraints, critical=True)
    if policies is not None:
        builder = builder.add_extension(
            x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(p), None)
                                      for p in policies]),
            critical=False,
        )
    if policy_mappings is not None:
        from app.derutil import encode_tlv, oid_to_der

        mappings_der = encode_tlv(
            0x30,
            b"".join(
                encode_tlv(0x30, oid_to_der(i) + oid_to_der(s))
                for i, s in policy_mappings
            ),
        )
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.oid.ExtensionOID.POLICY_MAPPINGS, mappings_der
            ),
            critical=False,
        )
    if policy_constraints is not None:
        builder = builder.add_extension(
            x509.PolicyConstraints(
                require_explicit_policy=policy_constraints.get("require_explicit"),
                inhibit_policy_mapping=policy_constraints.get("inhibit_mapping"),
            ),
            critical=True,
        )
    if inhibit_any is not None:
        builder = builder.add_extension(x509.InhibitAnyPolicy(inhibit_any), critical=True)
    signing_key = issuer.key if issuer else key
    if pkcs1v15:
        cert = builder.sign(signing_key, hashes.SHA256(), rsa_padding=padding.PKCS1v15())
    else:
        cert = _sign_builder(builder, signing_key)
    return Entity(cn=cn, key=key, cert=cert, name=name)


def make_leaf(issuer: Entity, cn: str, kind: str, *, not_before, not_after,
              eku=None, key_usage=("digitalSignature",), san_dns=None, san_uri=None,
              policies=None, serial=None, pkcs1v15=False) -> Entity:
    key = make_key(kind)
    builder = (
        x509.CertificateBuilder()
        .subject_name(xname(cn))
        .issuer_name(issuer.name)
        .public_key(key.public_key())
        .serial_number(serial or next(_serial_counter))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.pub), critical=False
        )
    )
    if key_usage is not None:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature="digitalSignature" in key_usage,
                content_commitment="nonRepudiation" in key_usage,
                key_encipherment="keyEncipherment" in key_usage,
                data_encipherment="dataEncipherment" in key_usage,
                key_agreement="keyAgreement" in key_usage,
                key_cert_sign="keyCertSign" in key_usage,
                crl_sign="cRLSign" in key_usage,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    if eku is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(o) for o in eku]), critical=False
        )
    gnames = []
    for d in san_dns or []:
        gnames.append(x509.DNSName(d))
    for u in san_uri or []:
        gnames.append(x509.UniformResourceIdentifier(u))
    if gnames:
        builder = builder.add_extension(x509.SubjectAlternativeName(gnames), critical=False)
    if policies is not None:
        builder = builder.add_extension(
            x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(p), None)
                                      for p in policies]),
            critical=False,
        )
    if pkcs1v15:
        cert = builder.sign(issuer.key, hashes.SHA256(), rsa_padding=padding.PKCS1v15())
    else:
        cert = _sign_builder(builder, issuer.key)
    return Entity(cn=cn, key=key, cert=cert, name=cert.subject)


def make_crl(issuer: Entity, *, entries, crl_number: int, this_update: datetime,
             next_update: datetime | None, delta_base_number: int | None = None,
             idp_uris=None) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.name)
        .last_update(this_update)
        .next_update(next_update)
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.pub), critical=False
        )
    )
    if delta_base_number is not None:
        builder = builder.add_extension(
            x509.DeltaCRLIndicator(delta_base_number), critical=True
        )
    if idp_uris:
        builder = builder.add_extension(
            x509.IssuingDistributionPoint(
                full_name=[x509.UniformResourceIdentifier(u) for u in idp_uris],
                relative_name=None, only_contains_user_certs=False,
                only_contains_ca_certs=False, only_contains_attribute_certs=False,
                only_some_reasons=None, indirect_crl=False,
            ),
            critical=True,
        )
    for serial, rev_date, reason in entries:
        rb = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(rev_date)
        )
        if reason:
            rb = rb.add_extension(
                x509.CRLReason(getattr(x509.ReasonFlags, _REASON_ATTR[reason])),
                critical=False,
            )
        builder = builder.add_revoked_certificate(rb.build())
    return _sign_builder(builder, issuer.key).public_bytes(serialization.Encoding.DER)


_REASON_ATTR = {
    "keyCompromise": "key_compromise",
    "cessationOfOperation": "cessation_of_operation",
    "certificateHold": "certificate_hold",
    "removeFromCRL": "remove_from_crl",
    "superseded": "superseded",
    "unspecified": "unspecified",
}


def make_ocsp(issuer: Entity, *, serial: int, status: str, this_update: datetime,
              next_update: datetime | None, revocation_time=None, reason=None,
              responder: Entity | None = None, hash_alg=None,
              responder_encoding="hash") -> bytes:
    from cryptography.x509.ocsp import (
        OCSPCertStatus,
        OCSPResponderEncoding,
        OCSPResponseBuilder,
    )

    hash_alg = hash_alg or hashes.SHA1()
    cert_status = {
        "good": OCSPCertStatus.GOOD,
        "revoked": OCSPCertStatus.REVOKED,
        "unknown": OCSPCertStatus.UNKNOWN,
    }[status]
    rev_reason = None
    if reason:
        rev_reason = getattr(x509.ReasonFlags, _REASON_ATTR[reason])
    # build a minimal placeholder cert for certID hashing via add_response_by_hash
    id_hashes = _issuer_hashes(issuer, hash_alg)
    builder = OCSPResponseBuilder().add_response_by_hash(
        issuer_name_hash=id_hashes[0],
        issuer_key_hash=id_hashes[1],
        serial_number=serial,
        algorithm=hash_alg,
        cert_status=cert_status,
        this_update=this_update,
        next_update=next_update,
        revocation_time=revocation_time,
        revocation_reason=rev_reason,
    )
    resp_entity = responder or issuer
    enc = (
        OCSPResponderEncoding.HASH
        if responder_encoding == "hash"
        else OCSPResponderEncoding.NAME
    )
    builder = builder.responder_id(enc, resp_entity.cert)
    if responder is not None:
        builder = OCSPResponseBuilder(
            response=builder._response,
            responder_id=builder._responder_id,
            certs=[responder.cert],
        )
    alg, pad = sign_algorithm(resp_entity.key)
    if pad is not None:
        # cryptography's OCSP builder cannot do RSA-PSS; sign PKCS#1 then
        # rewrite the signatureAlgorithm to RSASSA-PSS (fixture surgery).
        resp = builder.sign(resp_entity.key, alg)
        return _pss_ocsp_surgery(resp.public_bytes(serialization.Encoding.DER),
                                 resp_entity.key)
    return builder.sign(resp_entity.key, alg).public_bytes(serialization.Encoding.DER)


def _issuer_hashes(issuer: Entity, hash_alg) -> tuple:
    from app.revocation import public_key_bitstring_bytes

    h1 = hashes.Hash(hash_alg)
    h1.update(issuer.cert.subject.public_bytes())
    h2 = hashes.Hash(hash_alg)
    h2.update(public_key_bitstring_bytes(issuer.pub))
    return h1.finalize(), h2.finalize()


# --- minimal DER rewriting to turn an RSA PKCS#1 OCSP response into PSS -----

def _der_read(data: bytes, pos: int):
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    return tag, length, pos


def _der_encode(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        hdr = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        hdr = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + hdr + content


# RSASSA-PSS AlgorithmIdentifier: sha256, MGF-1-sha256, salt length 32
_PSS_ALG = bytes.fromhex(
    "304106092a864886f70d01010a3034a00f300d06096086480165030402010500"
    "a11c301a06092a864886f70d010108300d06096086480165030402010500"
    "a203020120"
)

# hash OIDs used to build RSASSA-PSS AlgorithmIdentifier variants (tests only)
_PSS_HASH_OIDS = {
    "sha1": "1.3.14.3.2.26",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}
_OID_MGF1 = "1.2.840.113549.1.1.8"
_OID_RSASSA_PSS = "1.2.840.113549.1.1.10"


def build_pss_algorithm_der(*, hash_name="sha256", mgf_hash_name=None,
                            salt_length=32, trailer_field=1) -> bytes:
    """Build an RSASSA-PSS signatureAlgorithm TLV (test tooling only).

    The result is the full AlgorithmIdentifier (id-RSASSA-PSS OID plus the
    explicit RSASSA-PSS-params).  All params are encoded explicitly
    (including trailerField) so the bytes declare exactly the requested
    message hash, MGF-1 inner hash, salt length and trailer field.
    """
    from app.derutil import oid_to_der

    mgf_hash_name = mgf_hash_name or hash_name

    def _alg_id(oid: str) -> bytes:
        return _der_encode(0x30, oid_to_der(oid) + _der_encode(0x05, b""))

    if salt_length < 0 or salt_length > 0xFFFFFFFF:
        raise ValueError("bad salt length")
    salt_int = salt_length.to_bytes(
        max(1, (salt_length.bit_length() + 7) // 8), "big")
    if salt_int[0] & 0x80:          # keep the INTEGER positive in DER
        salt_int = b"\x00" + salt_int
    params = _der_encode(0x30, b"".join([
        _der_encode(0xA0, _alg_id(_PSS_HASH_OIDS[hash_name])),
        _der_encode(0xA1, _der_encode(0x30, oid_to_der(_OID_MGF1)
                                      + _alg_id(_PSS_HASH_OIDS[mgf_hash_name]))),
        _der_encode(0xA2, _der_encode(0x02, salt_int)),
        _der_encode(0xA3, _der_encode(0x02, bytes([trailer_field & 0xFF]))),
    ]))
    return _der_encode(0x30, oid_to_der(_OID_RSASSA_PSS) + params)


def rewrite_cert_or_crl_sig_algorithm(der: bytes, new_alg: bytes) -> bytes:
    """Replace BOTH signatureAlgorithm copies of a DER Certificate or
    CertificateList (the one inside the tbs and the outer one), keeping all
    tbs data and the signature BIT STRING unchanged.

    RFC 5280 requires the two AlgorithmIdentifiers to be identical, so a
    conformant tamper that only changes parameters must change both.  Test
    tooling only.
    """

    def _fr(buf: bytes, pos: int):
        """Read a TLV; return (tag, content_start, content_end)."""
        tag, length, cstart = _der_read(buf, pos)
        return tag, cstart, cstart + length

    _, outer_cs, outer_ce = _fr(der, 0)
    _, tbs_cs, tbs_ce = _fr(der, outer_cs)        # tbsCertificate/tbsCertList
    tbs_tlv = der[outer_cs:tbs_ce]
    # locate the AlgorithmIdentifier inside the tbs:
    #   Certificate: [0] version?, serial INTEGER, signature AlgId, ...
    #   CertList:    version INTEGER?, signature AlgId, issuer, ...
    _, inner_cs, inner_ce = _fr(tbs_tlv, 0)
    pos = inner_cs
    if tbs_tlv[pos] == 0xA0:                      # certificate [0] version
        _, _, pos = _fr(tbs_tlv, pos)
    if tbs_tlv[pos] == 0x02:                      # serial (cert) / version (CRL)
        _, _, pos = _fr(tbs_tlv, pos)
    if tbs_tlv[pos] != 0x30:
        raise ValueError("could not locate inner signatureAlgorithm in tbs")
    _, alg_cs, alg_ce = _fr(tbs_tlv, pos)
    new_tbs = _der_encode(
        0x30,
        tbs_tlv[inner_cs:pos] + new_alg + tbs_tlv[alg_ce:inner_ce],
    )
    # outer: tbs, outer signatureAlgorithm, signature BIT STRING
    _, outer_alg_cs, outer_alg_ce = _fr(der, tbs_ce)
    content = new_tbs + new_alg + der[outer_alg_ce:outer_ce]
    return _der_encode(0x30, content)


def corrupt_cert_or_crl_signature(der: bytes) -> bytes:
    """Flip the last byte of the outer signature BIT STRING of a DER
    Certificate/CertificateList, leaving the AlgorithmIdentifier untouched."""
    _, _, outer_cs = _der_read(der, 0)                  # outer SEQUENCE
    _, tbs_len, tbs_cs = _der_read(der, outer_cs)      # tbs SEQUENCE
    _, alg_len, alg_cs = _der_read(der, tbs_cs + tbs_len)
    _, sig_len, sig_cs = _der_read(der, alg_cs + alg_len)
    out = bytearray(der)
    out[sig_cs + sig_len - 1] ^= 0x01
    return bytes(out)


def _ocsp_basic_parts(der: bytes):
    """Return (status_part, oid_part, basic) slices of a DER OCSP response."""
    _, _, p = _der_read(der, 0)
    _, status_len, _ = _der_read(der, p)
    status_part = der[p : p + 2 + status_len]
    assert status_part[0] == 0x0A, "expected ENUMERATED responseStatus"
    _, _, p2 = _der_read(der, p + 2 + status_len)   # [0] EXPLICIT
    assert der[p + 2 + status_len] == 0xA0
    _, _, p3 = _der_read(der, p2)                   # ResponseBytes SEQUENCE
    _, oid_len, p4 = _der_read(der, p3)             # responseType OID
    oid_part = der[p3 : p4 + oid_len]
    _, oct_len, p5 = _der_read(der, p4 + oid_len)   # response OCTET STRING
    return status_part, oid_part, der[p5 : p5 + oct_len], p5


def _wrap_ocsp_basic(status_part: bytes, oid_part: bytes, basic: bytes) -> bytes:
    response_bytes = _der_encode(0x30, oid_part + _der_encode(0x04, basic))
    return _der_encode(0x30, status_part + _der_encode(0xA0, response_bytes))


def rewrite_ocsp_sig_algorithm(der: bytes, new_alg: bytes) -> bytes:
    """Replace the signatureAlgorithm inside a BasicOCSPResponse, keeping
    tbsResponseData and the signature BIT STRING unchanged.  Tests only."""
    status_part, oid_part, basic, _ = _ocsp_basic_parts(der)
    _, _, bp = _der_read(basic, 0)
    _, tbs_len, bp2 = _der_read(basic, bp)
    tbs = basic[bp : bp2 + tbs_len]
    _, sa_len, sp = _der_read(basic, bp2 + tbs_len)
    after = basic[sp + sa_len:]                     # signature BIT STRING + certs
    new_basic = _der_encode(0x30, tbs + new_alg + after)
    return _wrap_ocsp_basic(status_part, oid_part, new_basic)


def corrupt_ocsp_signature(der: bytes) -> bytes:
    """Flip the last byte of the OCSP signature value, leaving the declared
    AlgorithmIdentifier and all DER lengths untouched.  Tests only."""
    status_part, oid_part, basic, _ = _ocsp_basic_parts(der)
    _, _, bp = _der_read(basic, 0)
    _, tbs_len, bp2 = _der_read(basic, bp)
    _, sa_len, sp = _der_read(basic, bp2 + tbs_len)
    _, sig_len, sig_c = _der_read(basic, sp + sa_len)
    basic2 = bytearray(basic)
    basic2[sig_c + sig_len - 1] ^= 0x01
    return _wrap_ocsp_basic(status_part, oid_part, bytes(basic2))


def _pss_ocsp_surgery(der: bytes, key) -> bytes:
    """Replace the signatureAlgorithm/signature of a BasicOCSPResponse with
    RSASSA-PSS(SHA-256, MGF-1-SHA-256, saltlen=32).  Test tooling only."""
    # OCSPResponse ::= SEQUENCE { status ENUMERATED, responseBytes [0] EXPLICIT }
    _, _, p = _der_read(der, 0)
    assert der[p] == 0x0A and der[p + 2] == 0x00, "expected successful status"
    status_part = der[p : p + 3]
    _, _, p2 = _der_read(der, p + 3)          # [0] EXPLICIT
    _, _, p3 = _der_read(der, p2)             # SEQUENCE (ResponseBytes)
    _, oid_len, p4 = _der_read(der, p3)       # responseType OID
    oid_part = der[p3 : p4 + oid_len]
    _, oct_len, p5 = _der_read(der, p4 + oid_len)
    basic = der[p5 : p5 + oct_len]
    # BasicOCSPResponse ::= SEQUENCE { tbs, sigAlg, signature, certs [0] OPT }
    _, _, bp = _der_read(basic, 0)
    _, tbs_len, bp2 = _der_read(basic, bp)
    tbs = basic[bp : bp2 + tbs_len]
    pos = bp2 + tbs_len
    _, sa_len, sp = _der_read(basic, pos)     # old signatureAlgorithm
    pos = sp + sa_len
    _, sig_len, sp2 = _der_read(basic, pos)   # old signature BIT STRING
    pos = sp2 + sig_len
    certs_part = basic[pos:]                  # optional [0] certificates
    signature = sign_data(key, tbs)
    new_basic = _der_encode(
        0x30, tbs + _PSS_ALG + _der_encode(0x03, b"\x00" + signature) + certs_part
    )
    response_bytes = _der_encode(0x30, oid_part + _der_encode(0x04, new_basic))
    return _der_encode(0x30, status_part + _der_encode(0xA0, response_bytes))


@dataclass
class Dataset:
    objects: dict = field(default_factory=dict)   # name -> der bytes
    received: dict = field(default_factory=dict)  # name -> received_at
    keys: dict = field(default_factory=dict)      # name -> Entity
    anchors: dict = field(default_factory=dict)   # name -> Entity

    def add(self, name: str, der: bytes, received_at: str):
        self.objects[name] = der
        self.received[name] = received_at
