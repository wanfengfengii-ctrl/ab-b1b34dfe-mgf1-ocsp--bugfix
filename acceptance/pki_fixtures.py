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


# --- DER surgery for RSASSA-PSS objects (certificates, CRLs, OCSP) ---------
#
# cryptography's builders can only emit PKCS#1 v1.5 OCSP responses and do not
# expose every RSASSA-PSS parameter, so the fixtures construct and mutate the
# AlgorithmIdentifier DER directly.  These helpers are test tooling only.

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


_OID_RSASSA_PSS = bytes.fromhex("2a864886f70d01010a")
_OID_MGF1 = bytes.fromhex("2a864886f70d010108")
_OID_BY_HASH = {
    "sha256": bytes.fromhex("608648016503040201"),
    "sha384": bytes.fromhex("608648016503040202"),
    "sha512": bytes.fromhex("608648016503040203"),
}


def _oid_tlv(oid_der: bytes) -> bytes:
    return _der_encode(0x06, oid_der)


def _hash_ai(hash_name: str) -> bytes:
    # AlgorithmIdentifier { hash OID, NULL }
    return _der_encode(0x30, _oid_tlv(_OID_BY_HASH[hash_name]) + _der_encode(0x05, b""))


def pss_algorithm_identifier(*, hash_name: str = "sha256",
                             mgf_hash: str | None = None,
                             salt_length: int = 32,
                             trailer_field: int = 1) -> bytes:
    """Build a full RSASSA-PSS AlgorithmIdentifier TLV (RFC 4055).

    hashAlgorithm [0], maskGenAlgorithm [1] (MGF-1), saltLength [2] and
    trailerField [3] are all emitted explicitly.
    """
    mgf_hash = mgf_hash or hash_name
    if hash_name not in _OID_BY_HASH or mgf_hash not in _OID_BY_HASH:
        raise ValueError("unsupported PSS hash")
    if salt_length < 0 or trailer_field < 0 or salt_length > 255 or trailer_field > 255:
        raise ValueError("PSS integer fields out of fixture builder range")
    hash_ai = _hash_ai(hash_name)
    mgf_ai = _der_encode(0x30, _oid_tlv(_OID_MGF1) + _hash_ai(mgf_hash))
    salt = _der_encode(0x02, bytes([salt_length]))
    params_content = (
        _der_encode(0xA0, hash_ai)
        + _der_encode(0xA1, mgf_ai)
        + _der_encode(0xA2, salt)
    )
    if trailer_field != 1:
        params_content += _der_encode(
            0xA3, _der_encode(0x02, bytes([trailer_field])))
    params = _der_encode(0x30, params_content)
    return _der_encode(0x30, _oid_tlv(_OID_RSASSA_PSS) + params)


# RSASSA-PSS AlgorithmIdentifier: sha256, MGF-1-sha256, salt length 32
_PSS_ALG = pss_algorithm_identifier()


def _pss_ocsp_surgery(der: bytes, key, alg_der: bytes = _PSS_ALG,
                      salt_length: int = 32) -> bytes:
    """Replace the signatureAlgorithm/signature of a BasicOCSPResponse with
    RSASSA-PSS.  Test tooling only."""
    tbs, _alg, sig_tlv, certs_tail, envelope = _split_ocsp_basic(der)
    signature = _sign_pss(key, tbs, salt_length)
    return _assemble_ocsp(envelope, tbs, alg_der,
                          _der_encode(0x03, b"\x00" + signature), certs_tail)


def _sign_pss(key, tbs: bytes, salt_length: int) -> bytes:
    return key.sign(tbs,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=salt_length),
                    hashes.SHA256())


def _split_ocsp_basic(der: bytes):
    """Decompose a successful DER OCSP response into the pieces a test needs
    to tamper with: tbsResponseData, signatureAlgorithm TLV, signature BIT
    STRING TLV, the optional certs tail, and the fixed envelope prefix.
    """
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
    alg_s, alg_len, ap = _der_read(basic, pos)
    alg_tlv = basic[pos : ap + alg_len]
    pos = ap + alg_len
    sig_s, sig_len, sp = _der_read(basic, pos)
    sig_tlv = basic[pos : sp + sig_len]
    certs_tail = basic[sp + sig_len :]
    envelope = (status_part, oid_part)
    return tbs, alg_tlv, sig_tlv, certs_tail, envelope


def _assemble_ocsp(envelope, tbs: bytes, alg_tlv: bytes, sig_tlv: bytes,
                   certs_tail: bytes) -> bytes:
    status_part, oid_part = envelope
    new_basic = _der_encode(0x30, tbs + alg_tlv + sig_tlv + certs_tail)
    response_bytes = _der_encode(0x30, oid_part + _der_encode(0x04, new_basic))
    return _der_encode(0x30, status_part + _der_encode(0xA0, response_bytes))


def ocsp_replace_signature_algorithm(der: bytes, alg_tlv: bytes) -> bytes:
    """Replace ONLY the BasicOCSPResponse.signatureAlgorithm; tbsResponseData
    and the signature BIT STRING are preserved byte-for-byte."""
    tbs, _old_alg, sig_tlv, certs_tail, envelope = _split_ocsp_basic(der)
    return _assemble_ocsp(envelope, tbs, alg_tlv, sig_tlv, certs_tail)


def ocsp_corrupt_signature(der: bytes) -> bytes:
    """Flip a byte inside the OCSP signature BIT STRING; the tbs and the
    (profile-conforming) signatureAlgorithm are preserved."""
    tbs, alg_tlv, sig_tlv, certs_tail, envelope = _split_ocsp_basic(der)
    body = bytearray(sig_tlv)
    body[-1] ^= 0x01  # last byte is inside the signature octets (after 0x00 pad)
    return _assemble_ocsp(envelope, tbs, alg_tlv, bytes(body), certs_tail)


def _locate_tbs_signature_algorithm(tbs_full: bytes, *, crl: bool):
    """Return (alg_tlv_start, alg_tlv_end) offsets within *tbs_full* (which
    begins at the tbs SEQUENCE tag) of the signatureAlgorithm inside the tbs.
    """
    from app.derutil import read_tlv

    _, pos, content_end = read_tlv(tbs_full, 0)
    if crl:
        if tbs_full[pos] == 0x02:  # optional version INTEGER
            _, _, ve = read_tlv(tbs_full, pos)
            pos = ve
    else:
        # [0] EXPLICIT version, serial INTEGER, then signatureAlgorithm
        _, _, ve = read_tlv(tbs_full, pos)
        _, _, se = read_tlv(tbs_full, ve)
        pos = se
    tag, as_, ae = read_tlv(tbs_full, pos)
    assert tag == 0x30, "expected signatureAlgorithm SEQUENCE inside tbs"
    assert ae <= content_end
    return pos, ae


def signed_object_replace_signature_algorithm(der: bytes, alg_tlv: bytes,
                                              *, crl: bool = False) -> bytes:
    """Replace the signatureAlgorithm both inside the tbs (certificate's
    tbsCertificate.signature / CRL's tbsCertList.signature) and in the outer
    position.  The signature bytes are preserved, so no re-signing happens:
    the object parses but its signature cannot verify.
    """
    from app.derutil import encode_tlv, read_tlv

    _, s, e = read_tlv(der, 0)
    _, ts, te = read_tlv(der, s)             # tbs SEQUENCE
    tbs_full = der[s:te]
    inner_lo, inner_hi = _locate_tbs_signature_algorithm(tbs_full, crl=crl)
    _, cs, _ = read_tlv(tbs_full, 0)
    # inner_lo/inner_hi are absolute indices in tbs_full; rebuild tbs content
    new_tbs_content = tbs_full[cs:inner_lo] + alg_tlv + tbs_full[inner_hi:]
    new_tbs = encode_tlv(0x30, new_tbs_content)
    _, oas, oae = read_tlv(der, te)          # outer signatureAlgorithm
    sig_tlv = der[oae:e]
    # the object is a single top-level SEQUENCE; re-encode it wholesale
    return encode_tlv(0x30, new_tbs + alg_tlv + sig_tlv)


def cert_replace_signature_algorithm(der: bytes, alg_tlv: bytes) -> bytes:
    return signed_object_replace_signature_algorithm(der, alg_tlv, crl=False)


def crl_replace_signature_algorithm(der: bytes, alg_tlv: bytes) -> bytes:
    return signed_object_replace_signature_algorithm(der, alg_tlv, crl=True)


def corrupt_object_signature(der: bytes) -> bytes:
    """Flip the last byte of the trailing signature BIT STRING of a
    Certificate/CertificateList; tbs and algorithms are preserved."""
    body = bytearray(der)
    body[-1] ^= 0x01
    return bytes(body)


@dataclass
class Dataset:
    objects: dict = field(default_factory=dict)   # name -> der bytes
    received: dict = field(default_factory=dict)  # name -> received_at
    keys: dict = field(default_factory=dict)      # name -> Entity
    anchors: dict = field(default_factory=dict)   # name -> Entity

    def add(self, name: str, der: bytes, received_at: str):
        self.objects[name] = der
        self.received[name] = received_at
