"""content info, signed data and the digested and encrypted variants (RFC 5652).

``load`` reads a SignedData (RFC 5652 sec. 5) out of a ContentInfo (sec. 3), on asn1core, and
keeps every slice it parsed: each object carries ``raw``, the bytes as they arrived, because the
signature a later row verifies is over those bytes and never over a re-encoding. Nothing here
verifies, hashes or decrypts, and nothing normalises: a version number that disagrees with
sec. 5.1 is reported in ``version_issue`` and left as it was.

Input may be BER, which is what CMS looks like in the wild (indefinite lengths, constructed
OCTET STRINGs); ``der=True`` refuses every BER toleration. Only SignedAttributes must be DER
(RFC 5652 sec. 5.3), and checking that is the verify step's job, not this one's.

``dump`` is not implemented yet.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

import asn1core

__all__ = [
    "AlgorithmIdentifier",
    "Attribute",
    "CertificateChoice",
    "CertificateKind",
    "CmsError",
    "ContentInfo",
    "SignedData",
    "SignerInfo",
    "UnsupportedContentTypeError",
    "certificates_only",
    "dump",
    "load",
    "parse_content_info",
]

ID_DATA = "1.2.840.113549.1.7.1"
ID_SIGNED_DATA = "1.2.840.113549.1.7.2"

_UNIVERSAL = asn1core.TagClass.universal
_SEQUENCE = 16
_SET = 17
_INTEGER = 2
_OID = 6
_OCTET_STRING = 4


class CmsError(ValueError):
    """Bytes that are not the CMS structure asked for. Wraps every asn1core decode error."""


class UnsupportedContentTypeError(CmsError):
    """A well-formed ContentInfo whose content type this function does not read."""


class CertificateKind(enum.Enum):
    """The alternatives of CertificateChoices (RFC 5652 sec. 10.2.2) and RevocationInfoChoice."""

    CERTIFICATE = "certificate"
    EXTENDED_CERTIFICATE = "extended_certificate"
    V1_ATTRIBUTE_CERTIFICATE = "v1_attribute_certificate"
    V2_ATTRIBUTE_CERTIFICATE = "v2_attribute_certificate"
    OTHER_CERTIFICATE = "other_certificate"
    CRL = "crl"
    OTHER_REVOCATION_INFO = "other_revocation_info"


@dataclass(frozen=True, slots=True)
class CertificateChoice:
    """One member of ``certificates`` or ``crls``: its kind, and its complete TLV as it arrived.

    Alternatives that are not an X.509 certificate or CRL are kept opaque, as the roadmap row
    says: reading them is another row's work, losing them would change the version rule.
    """

    kind: CertificateKind
    raw: bytes


@dataclass(frozen=True, slots=True)
class AlgorithmIdentifier:
    """``AlgorithmIdentifier``: the OID, the parameters TLV when present, and the whole TLV."""

    oid: str
    parameters: bytes | None
    raw: bytes


@dataclass(frozen=True, slots=True)
class Attribute:
    """``Attribute``: ``values`` are the TLVs of the members of the SET, in encoded order."""

    oid: str
    values: tuple[bytes, ...]
    raw: bytes


@dataclass(frozen=True, slots=True)
class SignerInfo:
    """``SignerInfo`` (RFC 5652 sec. 5.3).

    The signer is named either by ``issuer`` (the DER of the Name) and ``serial``, or by
    ``subject_key_identifier``; exactly one form is set. ``signed_attrs_raw`` is the whole ``[0]``
    TLV as it arrived, which begins ``A0`` when definite and is what sec. 5.4 re-tags to ``31``
    for the digest input. It is retained, never re-encoded.
    """

    version: int
    issuer: bytes | None
    serial: int | None
    subject_key_identifier: bytes | None
    digest_algorithm: AlgorithmIdentifier
    signed_attrs: tuple[Attribute, ...] | None
    signed_attrs_raw: bytes | None
    signature_algorithm: AlgorithmIdentifier
    signature: bytes
    unsigned_attrs: tuple[Attribute, ...] | None
    raw: bytes
    version_issue: str | None = None


@dataclass(frozen=True, slots=True)
class ContentInfo:
    """``ContentInfo`` (RFC 5652 sec. 3): the type OID and the one TLV inside ``[0] EXPLICIT``."""

    content_type: str
    content: bytes
    raw: bytes


@dataclass(frozen=True, slots=True)
class SignedData:
    """``SignedData`` (RFC 5652 sec. 5.1) with every part retained.

    ``econtent`` is the value of the eContent OCTET STRING (BER constructed forms are joined), or
    None when it is absent: that is a detached signature. ``econtent_raw`` is the TLV inside
    ``[0]``; when it is present but ``econtent`` is None the content is not an OCTET STRING, the
    PKCS #7 form RFC 5652 sec. 5.2.1 warns about (Authenticode is one).
    """

    version: int
    digest_algorithms: tuple[AlgorithmIdentifier, ...]
    encap_content_type: str
    econtent: bytes | None
    econtent_raw: bytes | None
    certificates: tuple[CertificateChoice, ...]
    crls: tuple[CertificateChoice, ...]
    signer_infos: tuple[SignerInfo, ...]
    raw: bytes
    version_issue: str | None = None

    @property
    def is_certificates_only(self) -> bool:
        """The degenerate form of RFC 5652 sec. 5.2: no signers, id-data, no content."""
        return (
            not self.signer_infos
            and self.encap_content_type == ID_DATA
            and self.econtent_raw is None
        )


def _fail(message: str) -> CmsError:
    return CmsError(message)


def _is(node: asn1core.Node, number: int, *, constructed: bool | None = None) -> bool:
    tag = node.tag
    return (
        tag.tag_class is _UNIVERSAL
        and tag.number == number
        and (constructed is None or tag.constructed == constructed)
    )


def _is_ctx(node: asn1core.Node, number: int) -> bool:
    return node.tag.is_context(number)


def _decode(data: bytes, *, der: bool, what: str) -> asn1core.Node:
    if not isinstance(data, bytes):
        raise TypeError("CMS input must be bytes")
    try:
        node, end = asn1core.decode(data, der=der)
    except asn1core.Asn1Error as error:
        raise _fail(f"{what} is not valid {'DER' if der else 'BER'}: {error}") from error
    if end != len(data):
        raise _fail(f"{what}: {len(data) - end} trailing bytes after the object")
    return node


def _oid(node: asn1core.Node, what: str) -> str:
    if not _is(node, _OID, constructed=False) or node.payload is None:
        raise _fail(f"{what} must be an OBJECT IDENTIFIER")
    try:
        return ".".join(str(arc) for arc in asn1core.decode_oid(node.payload))
    except asn1core.Asn1Error as error:
        raise _fail(f"{what} is a bad OBJECT IDENTIFIER: {error}") from error


def _integer(node: asn1core.Node, what: str, *, der: bool) -> int:
    if not _is(node, _INTEGER, constructed=False) or not node.payload:
        raise _fail(f"{what} must be an INTEGER")
    if der:
        try:
            return asn1core.check_integer(node.payload)
        except asn1core.Asn1Error as error:
            raise _fail(f"{what}: {error}") from error
    return int.from_bytes(node.payload, "big", signed=True)


def _segments(item: asn1core.Node, what: str) -> bytes:
    if not item.constructed:
        if item.payload is None:
            raise _fail(f"{what} has no content")
        return item.payload
    out = b""
    for child in item.children:
        if not _is(child, _OCTET_STRING):
            raise _fail(f"{what} has a segment that is not an OCTET STRING")
        out += _segments(child, what)
    return out


def _octets(
    node: asn1core.Node, what: str, *, number: int | None = None, der: bool = False
) -> bytes:
    """Value of an OCTET STRING, or of an IMPLICIT one when ``number`` names its context tag.

    BER allows the constructed form, whose children are OCTET STRING segments; they are joined.
    DER does not (X.690 10.2), and asn1core does not yet refuse it on its own, so ``der`` does.
    """
    if der and node.constructed:
        raise _fail(f"{what}: a constructed OCTET STRING is not DER")
    if number is None:
        if not _is(node, _OCTET_STRING):
            raise _fail(f"{what} must be an OCTET STRING")
    elif not _is_ctx(node, number):
        raise _fail(f"{what} must be [{number}] IMPLICIT OCTET STRING")
    return _segments(node, what)


def _algorithm(node: asn1core.Node, what: str) -> AlgorithmIdentifier:
    if not _is(node, _SEQUENCE, constructed=True) or not 1 <= len(node.children) <= 2:
        raise _fail(f"{what} must be an AlgorithmIdentifier")
    parameters = node.children[1].raw if len(node.children) == 2 else None
    return AlgorithmIdentifier(_oid(node.children[0], what), parameters, node.raw)


def _attributes(node: asn1core.Node, what: str) -> tuple[Attribute, ...]:
    out = []
    for item in node.children:
        if not _is(item, _SEQUENCE, constructed=True) or len(item.children) != 2:
            raise _fail(f"{what} has a member that is not an Attribute")
        values = item.children[1]
        if not _is(values, _SET, constructed=True):
            raise _fail(f"{what} attribute values must be a SET")
        out.append(
            Attribute(_oid(item.children[0], what), tuple(v.raw for v in values.children), item.raw)
        )
    if not out:
        raise _fail(f"{what} must have at least one Attribute (SIZE (1..MAX))")
    return tuple(out)


def _signer_info(node: asn1core.Node, *, der: bool) -> SignerInfo:
    if not _is(node, _SEQUENCE, constructed=True):
        raise _fail("a SignerInfo must be a SEQUENCE")
    items = list(node.children)
    if len(items) < 5:
        raise _fail("a SignerInfo has at least five fields")
    version = _integer(items.pop(0), "SignerInfo version", der=der)
    sid = items.pop(0)
    issuer = serial = ski = None
    if _is(sid, _SEQUENCE, constructed=True):
        if len(sid.children) != 2 or not _is(sid.children[0], _SEQUENCE, constructed=True):
            raise _fail("IssuerAndSerialNumber is SEQUENCE { Name, INTEGER }")
        issuer = sid.children[0].raw
        serial = _integer(sid.children[1], "signer serial number", der=der)
        expected = 1
    elif _is_ctx(sid, 0):
        ski = _octets(sid, "SubjectKeyIdentifier", number=0, der=der)
        expected = 3
    else:
        raise _fail("a SignerIdentifier is issuerAndSerialNumber or [0] subjectKeyIdentifier")
    digest = _algorithm(items.pop(0), "digestAlgorithm")
    signed_attrs = signed_raw = None
    if items and _is_ctx(items[0], 0):
        slot = items.pop(0)
        signed_attrs = _attributes(slot, "signedAttrs")
        signed_raw = slot.raw
    if len(items) < 2:
        raise _fail("a SignerInfo needs a signatureAlgorithm and a signature")
    signature_algorithm = _algorithm(items.pop(0), "signatureAlgorithm")
    signature = _octets(items.pop(0), "signature", der=der)
    unsigned = None
    if items and _is_ctx(items[0], 1):
        unsigned = _attributes(items.pop(0), "unsignedAttrs")
    if items:
        raise _fail("unexpected fields at the end of a SignerInfo")
    issue = None
    if version != expected:
        issue = (
            f"sid form needs version {expected} (RFC 5652 sec. 5.3), the structure says {version}"
        )
    return SignerInfo(
        version,
        issuer,
        serial,
        ski,
        digest,
        signed_attrs,
        signed_raw,
        signature_algorithm,
        signature,
        unsigned,
        node.raw,
        issue,
    )


def _choice(node: asn1core.Node, *, crl: bool) -> CertificateChoice:
    if crl:
        if _is(node, _SEQUENCE, constructed=True):
            return CertificateChoice(CertificateKind.CRL, node.raw)
        if _is_ctx(node, 1):
            return CertificateChoice(CertificateKind.OTHER_REVOCATION_INFO, node.raw)
        raise _fail("a RevocationInfoChoice is a CertificateList or [1] other")
    if _is(node, _SEQUENCE, constructed=True):
        return CertificateChoice(CertificateKind.CERTIFICATE, node.raw)
    kinds = {
        0: CertificateKind.EXTENDED_CERTIFICATE,
        1: CertificateKind.V1_ATTRIBUTE_CERTIFICATE,
        2: CertificateKind.V2_ATTRIBUTE_CERTIFICATE,
        3: CertificateKind.OTHER_CERTIFICATE,
    }
    for number, kind in kinds.items():
        if _is_ctx(node, number):
            return CertificateChoice(kind, node.raw)
    raise _fail("a CertificateChoices member is a Certificate or [0]..[3]")


def _expected_version(
    certificates: tuple[CertificateChoice, ...],
    crls: tuple[CertificateChoice, ...],
    signers: tuple[SignerInfo, ...],
    encap_type: str,
) -> int:
    """The version RFC 5652 sec. 5.1 says MUST be assigned."""
    cert_kinds = {c.kind for c in certificates}
    if CertificateKind.OTHER_CERTIFICATE in cert_kinds or any(
        c.kind is CertificateKind.OTHER_REVOCATION_INFO for c in crls
    ):
        return 5
    if CertificateKind.V2_ATTRIBUTE_CERTIFICATE in cert_kinds:
        return 4
    if (
        CertificateKind.V1_ATTRIBUTE_CERTIFICATE in cert_kinds
        or any(s.version == 3 for s in signers)
        or encap_type != ID_DATA
    ):
        return 3
    return 1


def _signed_data(node: asn1core.Node, *, der: bool) -> SignedData:
    if not _is(node, _SEQUENCE, constructed=True):
        raise _fail("SignedData must be a SEQUENCE")
    items = list(node.children)
    if len(items) < 4:
        raise _fail("SignedData needs version, digestAlgorithms, encapContentInfo, signerInfos")
    version = _integer(items.pop(0), "SignedData version", der=der)
    algorithms = items.pop(0)
    if not _is(algorithms, _SET, constructed=True):
        raise _fail("digestAlgorithms must be a SET")
    digests = tuple(_algorithm(a, "digestAlgorithm") for a in algorithms.children)

    encap = items.pop(0)
    if not _is(encap, _SEQUENCE, constructed=True) or not 1 <= len(encap.children) <= 2:
        raise _fail("EncapsulatedContentInfo is SEQUENCE { eContentType, [0] eContent OPTIONAL }")
    encap_type = _oid(encap.children[0], "eContentType")
    econtent = econtent_raw = None
    if len(encap.children) == 2:
        slot = encap.children[1]
        if not _is_ctx(slot, 0) or len(slot.children) != 1:
            raise _fail("eContent must be [0] EXPLICIT with exactly one object")
        inner = slot.children[0]
        econtent_raw = inner.raw
        if _is(inner, _OCTET_STRING):
            econtent = _octets(inner, "eContent", der=der)

    certificates: tuple[CertificateChoice, ...] = ()
    crls: tuple[CertificateChoice, ...] = ()
    if items and _is_ctx(items[0], 0):
        certificates = tuple(_choice(c, crl=False) for c in items.pop(0).children)
    if items and _is_ctx(items[0], 1):
        crls = tuple(_choice(c, crl=True) for c in items.pop(0).children)
    if len(items) != 1 or not _is(items[0], _SET, constructed=True):
        raise _fail("signerInfos must be the last field of SignedData, a SET")
    signers = tuple(_signer_info(s, der=der) for s in items[0].children)

    issue = None
    wanted = _expected_version(certificates, crls, signers, encap_type)
    if version != wanted:
        issue = f"RFC 5652 sec. 5.1 requires version {wanted} here, the structure says {version}"
    return SignedData(
        version,
        digests,
        encap_type,
        econtent,
        econtent_raw,
        certificates,
        crls,
        signers,
        node.raw,
        issue,
    )


def parse_content_info(raw: bytes, *, der: bool = False) -> ContentInfo:
    """Read ``ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT content }`` (RFC 5652 sec. 3).

    Trailing bytes are refused. ``content`` is the single object inside ``[0]``, as it arrived.
    """
    node = _decode(raw, der=der, what="ContentInfo")
    if not _is(node, _SEQUENCE, constructed=True) or len(node.children) != 2:
        raise _fail("ContentInfo must be SEQUENCE { contentType, [0] EXPLICIT content }")
    slot = node.children[1]
    if not _is_ctx(slot, 0) or len(slot.children) != 1:
        raise _fail("ContentInfo content must be [0] EXPLICIT with exactly one object")
    return ContentInfo(_oid(node.children[0], "contentType"), slot.children[0].raw, node.raw)


def load(raw: bytes, *, der: bool = False) -> SignedData:
    """Parse a ContentInfo carrying SignedData (RFC 5652 sec. 3, 5.1, 5.2, 5.3, 10.2.4).

    Returns a ``SignedData`` that retains every parsed slice. Accepts BER unless ``der`` is true.
    The certificates-only form (RFC 5652 sec. 5.2: no signers, id-data, no content) loads like any
    other; ``SignedData.is_certificates_only`` says whether it is one. A content type other than
    id-signedData raises ``UnsupportedContentTypeError``; malformed bytes, trailing bytes and nesting
    beyond asn1core's depth limit raise ``CmsError``. Nothing is verified.
    """
    info = parse_content_info(raw, der=der)
    if info.content_type != ID_SIGNED_DATA:
        raise UnsupportedContentTypeError(f"content type {info.content_type} is not id-signedData")
    node = _decode(info.content, der=der, what="SignedData")
    return _signed_data(node, der=der)


def certificates_only(raw: bytes, *, der: bool = False) -> tuple[bytes, ...]:
    """The X.509 certificates, as DER, of a certificates-only SignedData.

    This is the shape of an EST ``/cacerts`` response (RFC 7030 sec. 4.1.3 as replaced by RFC 8951
    sec. 3.2.1, a CMC Simple PKI Response, now RFC 10002 sec. 4.1). The input is the decoded CMS,
    not the base64 text. Anything with a signer, a content, or a content type other than id-data
    is refused, because it is not that form. Non-certificate choices are skipped, not returned;
    nothing is trusted: a certificate being present says nothing about whether to anchor it.
    """
    signed = load(raw, der=der)
    if not signed.is_certificates_only:
        raise _fail("not a certificates-only SignedData (signers, content or a non-data type)")
    return tuple(c.raw for c in signed.certificates if c.kind is CertificateKind.CERTIFICATE)


def dump(info: object) -> bytes:
    """Pending behaviour defined by RFC 5652 sec. 3.

    Not implemented yet. See the ``cms.dump()`` row in ROADMAP.md; this stub raises on
    purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("dump() is not implemented: RFC 5652 sec. 3")
