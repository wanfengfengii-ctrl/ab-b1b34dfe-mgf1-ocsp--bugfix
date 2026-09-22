"""Minimal DER reader/encoder helpers.

Used for the parts of X.509/PKIX structures that the cryptography library
does not expose (e.g. enumerating CRL revokedCertificates entries).  Only
definite-length, DER-encoded input is accepted.
"""
from __future__ import annotations

from datetime import datetime, timezone


def read_tlv(data: bytes, pos: int):
    """Read one TLV; returns (tag, content_start, content_end)."""
    if pos >= len(data):
        raise ValueError("truncated DER: expected tag")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("multi-byte tags are not supported")
    pos += 1
    if pos >= len(data):
        raise ValueError("truncated DER: expected length")
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0:
            raise ValueError("indefinite length is not DER")
        if pos + n > len(data):
            raise ValueError("truncated DER: length bytes")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise ValueError("truncated DER: content")
    return tag, pos, end


def encode_tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        hdr = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        hdr = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + hdr + content


def parse_der_time(data: bytes, pos: int):
    """Parse a UTCTime/GeneralizedTime TLV; returns (datetime, next_pos)."""
    tag, start, end = read_tlv(data, pos)
    raw = data[start:end]
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid time encoding") from exc
    if not text.endswith("Z"):
        raise ValueError("only Zulu times are supported")
    text = text[:-1]
    if tag == 0x17:  # UTCTime
        if len(text) != 10 and len(text) != 12:
            raise ValueError("bad UTCTime length")
        fmt = "%y%m%d%H%M%S" if len(text) == 12 else "%y%m%d%H%M"
        dt = datetime.strptime(text, fmt)
        year = dt.year
        year = year - 100 if year >= 2050 else year
        dt = dt.replace(year=year)
    elif tag == 0x18:  # GeneralizedTime
        fmt = "%Y%m%d%H%M%S" if len(text) == 14 else "%Y%m%d%H%M"
        dt = datetime.strptime(text, fmt)
    else:
        raise ValueError(f"expected time tag, got 0x{tag:02x}")
    return dt.replace(tzinfo=timezone.utc), end


def iter_crl_entries(der: bytes):
    """Yield (serial:int, revocation_date:datetime, extensions_tlv:bytes|None)
    for each revokedCertificates entry of a DER CRL.

    *extensions_tlv* is the raw TLV bytes of the Extensions SEQUENCE when
    present (tag included).
    """
    tag, tbs_start, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("CRL must be a SEQUENCE")
    tag, tbs_content, tbs_end = read_tlv(der, tbs_start)
    if tag != 0x30:
        raise ValueError("tbsCertList must be a SEQUENCE")
    pos = tbs_content
    # optional version (a bare INTEGER in TBSCertList, unlike certificates)
    tag, start, end = read_tlv(der, pos)
    if tag == 0x02:
        pos = end
    # signature AlgorithmIdentifier
    _, _, end = read_tlv(der, pos)
    pos = end
    # issuer Name
    _, _, end = read_tlv(der, pos)
    pos = end
    # thisUpdate
    _, pos = parse_der_time(der, pos)
    # optional nextUpdate
    tag = der[pos]
    if tag in (0x17, 0x18):
        _, pos = parse_der_time(der, pos)
    if pos >= tbs_end:
        return
    tag, start, end = read_tlv(der, pos)
    if tag != 0x30:
        return  # no revokedCertificates
    pos = start
    while pos < end:
        etag, estart, eend = read_tlv(der, pos)
        if etag != 0x30:
            raise ValueError("revoked certificate entry must be a SEQUENCE")
        epos = estart
        stag, sstart, send = read_tlv(der, epos)
        if stag != 0x02:
            raise ValueError("entry serial must be an INTEGER")
        serial = int.from_bytes(der[sstart:send], "big", signed=False)
        rev_date, epos = parse_der_time(der, send)
        ext_tlv = None
        if epos < eend:
            xtag, xstart, xend = read_tlv(der, epos)
            if xtag != 0x30:
                raise ValueError("entry extensions must be a SEQUENCE")
            ext_tlv = der[epos:xend]
        yield serial, rev_date, ext_tlv
        pos = eend


_OID_REASON_CODE = bytes.fromhex("551d15")       # 2.5.29.21 (content bytes)
_OID_CERT_ISSUER = bytes.fromhex("551d1d")       # 2.5.29.29
_OID_INVALIDITY_DATE = bytes.fromhex("551d18")   # 2.5.29.24


def iter_extensions(ext_tlv: bytes):
    """Yield (oid_bytes, critical:bool, value:bytes) for an Extensions TLV."""
    _, start, end = read_tlv(ext_tlv, 0)
    pos = start
    while pos < end:
        _, es, ee = read_tlv(ext_tlv, pos)
        epos = es
        otag, os_, oe = read_tlv(ext_tlv, epos)
        if otag != 0x06:
            raise ValueError("extension id must be an OID")
        oid = ext_tlv[os_:oe]
        epos = oe
        critical = False
        if ext_tlv[epos] == 0x01:
            _, cs, ce = read_tlv(ext_tlv, epos)
            critical = ext_tlv[cs] != 0
            epos = ce
        vtag, vs, ve = read_tlv(ext_tlv, epos)
        if vtag != 0x04:
            raise ValueError("extension value must be an OCTET STRING")
        yield oid, critical, ext_tlv[vs:ve]
        pos = ee


def parse_reason_code(value: bytes) -> int:
    tag, start, end = read_tlv(value, 0)
    if tag != 0x0A or end - start != 1:
        raise ValueError("bad reasonCode")
    return value[start]


def _read_base128(data: bytes, pos: int):
    value = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated base-128 integer")
        b = data[pos]
        pos += 1
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            return value, pos


def der_to_oid(tlv: bytes):
    """Decode an OID TLV (tag included) to (dotted_string, next_pos)."""
    tag, start, end = read_tlv(tlv, 0)
    if tag != 0x06:
        raise ValueError("expected OID")
    first, pos = _read_base128(tlv, start)
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    while pos < end:
        arc, pos = _read_base128(tlv, pos)
        arcs.append(arc)
    return ".".join(str(a) for a in arcs), end


def oid_to_der(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    if len(parts) < 2 or parts[0] > 2 or parts[1] > 39 and parts[0] < 2:
        raise ValueError(f"invalid OID {dotted!r}")
    out = bytearray()
    first = 40 * parts[0] + parts[1]
    stack = [first & 0x7F]
    first >>= 7
    while first:
        stack.append(0x80 | (first & 0x7F))
        first >>= 7
    out += bytes(reversed(stack))
    for arc in parts[2:]:
        stack = [arc & 0x7F]
        arc >>= 7
        while arc:
            stack.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(stack))
    return encode_tlv(0x06, bytes(out))


def parse_policy_mappings(extn_value: bytes):
    """PolicyMappings ::= SEQUENCE OF SEQUENCE { issuerDomainPolicy OID,
    subjectDomainPolicy OID }.  Returns a tuple of (issuer, subject) dotted
    OID pairs."""
    tag, start, end = read_tlv(extn_value, 0)
    if tag != 0x30:
        raise ValueError("policyMappings must be a SEQUENCE")
    out = []
    pos = start
    while pos < end:
        tag, es, ee = read_tlv(extn_value, pos)
        if tag != 0x30:
            raise ValueError("policyMapping must be a SEQUENCE")
        inner = extn_value[es:ee]
        issuer_oid, p2 = der_to_oid(inner)
        subject_oid, p3 = der_to_oid(inner[p2:])
        if p2 + p3 != len(inner):
            raise ValueError("policyMapping must contain exactly two OIDs")
        out.append((issuer_oid, subject_oid))
        pos = ee
    return tuple(out)


_HASH_OIDS = {
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "1.3.14.3.2.26": "sha1",
}

# id-mgf1 (RFC 4055)
OID_MGF1 = "1.2.840.113549.1.1.8"


def _decode_integer_tlv(tlv: bytes) -> int:
    tag, start, end = read_tlv(tlv, 0)
    if tag != 0x02 or start == end:
        raise ValueError("expected an INTEGER")
    return int.from_bytes(tlv[start:end], "big", signed=True)


def _decode_algorithm_identifier(ai_tlv: bytes):
    """Decode an AlgorithmIdentifier SEQUENCE TLV into (oid, params_tlv|None).

    The raw parameters TLV is returned untouched (NULL included); callers
    decide which parameter forms are in profile.
    """
    tag, start, end = read_tlv(ai_tlv, 0)
    if tag != 0x30:
        raise ValueError("AlgorithmIdentifier must be a SEQUENCE")
    oid, n = der_to_oid(ai_tlv[start:])
    pos = start + n
    params = None
    if pos < end:
        _, ps, pe = read_tlv(ai_tlv, pos)
        if pe != end:
            raise ValueError("trailing bytes after AlgorithmIdentifier parameters")
        params = ai_tlv[pos:pe]
    return oid, params


def _decode_explicit_wrapper(params_tlv: bytes, cs: int, ce: int) -> bytes:
    """Return the single TLV wrapped by an EXPLICIT tagged element."""
    _, s, e = read_tlv(params_tlv, cs)
    if e != ce:
        raise ValueError("explicit wrapper must contain exactly one element")
    return params_tlv[cs:ce]


def _is_null_params(params_tlv: bytes | None) -> bool:
    if params_tlv is None:
        return True
    tag, start, end = read_tlv(params_tlv, 0)
    return tag == 0x05 and start == end


def parse_pss_parameters(params_tlv: bytes | None) -> dict | None:
    """Parse RSASSA-PSS params (RFC 4055) straight from the DER.

    Returns ``{"hash", "mgf", "mgf_hash", "salt_length", "trailer_field"}``
    or ``None`` only when the encoding is absent or structurally malformed
    (unknown PSS field, wrong tags, truncated DER).  Absent optional fields
    carry their RFC 4055 defaults (saltLength 20, trailerField 1); an absent
    hashAlgorithm or maskGenAlgorithm means SHA-1 and is reported as such (or
    ``None`` when the OID is unrecognized).  This routine is deliberately a
    pure structural parser; the supported *profile* is enforced by
    :func:`app.profile.pss_descriptor`.
    """
    try:
        if not params_tlv:
            return None
        tag, start, end = read_tlv(params_tlv, 0)
        if tag != 0x30:
            return None
        hash_name = None
        mgf_oid = None
        mgf_hash = None
        salt_length = 20          # RFC 4055 default
        trailer_field = 1        # RFC 4055 default
        pos = start
        while pos < end:
            tag, cs, ce = read_tlv(params_tlv, pos)
            if tag == 0xA0:  # hashAlgorithm [0] EXPLICIT AlgorithmIdentifier
                ai_tlv = _decode_explicit_wrapper(params_tlv, cs, ce)
                oid, params = _decode_algorithm_identifier(ai_tlv)
                if not _is_null_params(params):
                    return None
                hash_name = _HASH_OIDS.get(oid)
            elif tag == 0xA1:  # maskGenAlgorithm [1] EXPLICIT AlgorithmIdentifier
                ai_tlv = _decode_explicit_wrapper(params_tlv, cs, ce)
                mgf_oid, mgf_params = _decode_algorithm_identifier(ai_tlv)
                if mgf_oid == OID_MGF1 and mgf_params:
                    inner_oid, inner_params = _decode_algorithm_identifier(mgf_params)
                    if not _is_null_params(inner_params):
                        return None
                    mgf_hash = _HASH_OIDS.get(inner_oid)
            elif tag == 0xA2:  # saltLength [2] EXPLICIT INTEGER
                salt_length = _decode_integer_tlv(
                    _decode_explicit_wrapper(params_tlv, cs, ce))
            elif tag == 0xA3:  # trailerField [3] EXPLICIT INTEGER
                trailer_field = _decode_integer_tlv(
                    _decode_explicit_wrapper(params_tlv, cs, ce))
            else:
                return None  # unknown RSASSA-PSS field
            pos = ce
        return {
            "hash": hash_name,
            "mgf": "mgf1" if mgf_oid == OID_MGF1 else mgf_oid,
            "mgf_hash": mgf_hash,
            "salt_length": salt_length,
            "trailer_field": trailer_field,
        }
    except (ValueError, IndexError):
        return None


def extract_outer_signature_algorithm(der: bytes):
    """Pull the signatureAlgorithm (oid, raw params TLV) that follows the
    tbsCertificate/tbsCertList in a Certificate or CertificateList.

    The outer AlgorithmIdentifier is the operative one for verification;
    cryptography does not expose every RSASSA-PSS parameter (e.g. it accepts
    trailerField values silently), so callers parse the raw DER themselves.
    """
    _, s, _ = read_tlv(der, 0)
    tag, _, te = read_tlv(der, s)              # tbs SEQUENCE
    if tag != 0x30:
        raise ValueError("expected a tbs SEQUENCE")
    tag, as_, ae = read_tlv(der, te)           # signatureAlgorithm
    if tag != 0x30:
        raise ValueError("expected signatureAlgorithm")
    return _decode_algorithm_identifier(der[te:ae])


def extract_ocsp_signature_algorithm(der: bytes):
    """Pull the signatureAlgorithm OID and raw params out of a DER OCSP
    response (cryptography does not expose PSS params for OCSP)."""
    _, c, _ = read_tlv(der, 0)
    _, _, e = read_tlv(der, c)              # responseStatus
    tag, s, _ = read_tlv(der, e)            # [0] EXPLICIT ResponseBytes
    if tag != 0xA0:
        raise ValueError("missing responseBytes")
    _, s2, _ = read_tlv(der, s)             # SEQUENCE ResponseBytes
    _, _, e3 = read_tlv(der, s2)            # responseType OID
    _, bs, be = read_tlv(der, e3)           # response OCTET STRING
    basic = der[bs:be]
    _, c2, _ = read_tlv(basic, 0)
    _, _, e4 = read_tlv(basic, c2)          # tbsResponseData
    tag, as_, ae = read_tlv(basic, e4)      # signatureAlgorithm
    if tag != 0x30:
        raise ValueError("missing signatureAlgorithm")
    return _decode_algorithm_identifier(basic[e4:ae])
