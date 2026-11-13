"""digest and signature checks plus algorithm policy enforcement (RFC 3370).

``verify_signer`` and ``verify_signatures`` are the M2 verify steps of RFC 5652 sec. 5.6 over a
loaded ``SignedData``: signer selection (sec. 5.3, 10.2.4), the message digest of sec. 5.4 and the
``message-digest`` and ``content-type`` attributes (sec. 11.1, 11.2), the same-digest-algorithm
rule of RFC 8933 sec. 3, the CMSAlgorithmProtection comparison of RFC 6211 sec. 3.1, and the
signature itself, which is checked by ``sigwire.verify`` (the ``sigwire[verify]`` extra, imported
lazily so this module loads without ``cryptography``).

What these functions do not decide is whether the signer's certificate may be trusted: the key is
taken from the ``certificates`` field or from a caller-supplied SubjectPublicKeyInfo (RFC 5652
sec. 5.6 allows either), and a result says so in its notes. Path building and validation belong
to pkix, and ``verify()`` is the entry point that adds it (``pkix.result.validate``). A bad signature is a
result with ``valid`` false and a ``code``, never an exception; only an unusable environment (no
``cryptography``) or a caller error raises.

``countersign`` is still a placeholder until the milestone named in ROADMAP.md lands. A stub raises instead of returning a plausible empty value: a protocol library that
silently answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import asn1core
import asn1core.keys

from . import cms

if TYPE_CHECKING:
    import datetime
    from collections.abc import Sequence

    from pkix.anchors import TrustAnchor
    from pkix.result import PathInputs

    ContentInfo = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "SignerVerification",
    "Verification",
    "countersign",
    "signed_attrs_digest_input",
    "verify",
    "verify_signatures",
    "verify_signer",
]

ID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
# RFC 6211 sec. 2 prints this OID; errata 9144 and 9145 (reported, not verified) say the IANA
# registry has it under smime(16) aa(2) instead. The printed value is what implementations send.
ID_CMS_ALGORITHM_PROTECTION = "1.2.840.113549.1.9.52"

_SKI_EXTENSION = "2.5.29.14"

_ID_SHA1 = "1.3.14.3.2.26"
_ID_SHA224 = "2.16.840.1.101.3.4.2.4"
_ID_SHA256 = "2.16.840.1.101.3.4.2.1"
_ID_SHA384 = "2.16.840.1.101.3.4.2.2"
_ID_SHA512 = "2.16.840.1.101.3.4.2.3"
_ID_SHAKE256 = "2.16.840.1.101.3.4.2.12"
_ID_SHAKE256_LEN = "2.16.840.1.101.3.4.2.18"
_ID_MD5 = "1.2.840.113549.2.5"

# digestAlgorithm OID -> sigwire/hashlib name.
_DIGESTS = {
    _ID_SHA1: "sha1",
    _ID_SHA224: "sha224",
    _ID_SHA256: "sha256",
    _ID_SHA384: "sha384",
    _ID_SHA512: "sha512",
    _ID_MD5: "md5",
}

_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_ID_RSASSA_PSS = "1.2.840.113549.1.1.10"
_ID_MGF1 = "1.2.840.113549.1.1.8"
# RFC 3370 sec. 3.2 and RFC 5754 sec. 3.2: rsaEncryption names no hash, the others name one.
_RSA_PKCS1 = {
    _RSA_ENCRYPTION: None,
    "1.2.840.113549.1.1.4": "md5",
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.14": "sha224",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}
# RFC 5754 sec. 3.3: ecdsa-with-SHA224..512, parameters absent.
_ECDSA = {
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
# RFC 3370 sec. 3.1 and RFC 5754 sec. 3.1.
_DSA = {
    "1.2.840.10040.4.3": "sha1",
    "2.16.840.1.101.3.4.3.1": "sha224",
    "2.16.840.1.101.3.4.3.2": "sha256",
}
_ID_ED25519 = "1.3.101.112"
_ID_ED448 = "1.3.101.113"

_ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
_ID_DSA = "1.2.840.10040.4.1"
# RFC 5480 sec. 2.1.1.1.
_CURVES = {
    "1.2.840.10045.3.1.7": ("P-256", 32),
    "1.3.132.0.34": ("P-384", 48),
    "1.3.132.0.35": ("P-521", 66),
}

_UNIVERSAL = asn1core.TagClass.universal
_CONTEXT = asn1core.TagClass.context


@dataclass(frozen=True, slots=True)
class SignerVerification:
    """The outcome for one SignerInfo.

    ``code`` is None when ``valid``, and otherwise the short name of the first check that failed
    (``digest-mismatch``, ``signature-invalid``, ``algorithm-protection-mismatch``, ...);
    ``reason`` is the sentence. ``notes`` are findings that did not fail the signer, for example
    ``chain-not-evaluated`` or ``algorithm-protection-absent``. ``certificate`` is the DER of the
    certificate whose key was used, or None when the caller supplied the key.
    """

    index: int
    valid: bool
    code: str | None
    reason: str | None
    digest_algorithm: str
    signature_algorithm: str
    certificate: bytes | None
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Verification:
    """Every signer's outcome. ``valid`` needs at least one signer and every signer valid."""

    valid: bool
    signers: tuple[SignerVerification, ...]


class _Refused(Exception):  # noqa: N818 - a control-flow carrier, never part of the API
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _is(node: asn1core.Node, number: int, *, constructed: bool | None = None) -> bool:
    tag = node.tag
    return (
        tag.tag_class is _UNIVERSAL
        and tag.number == number
        and (constructed is None or tag.constructed == constructed)
    )


def _decode(data: bytes, *, der: bool = False) -> asn1core.Node:
    try:
        node, end = asn1core.decode(data, der=der)
    except asn1core.Asn1Error as error:
        raise _Refused("malformed", f"not valid {'DER' if der else 'BER'}: {error}") from error
    if end != len(data):
        raise _Refused("malformed", "trailing bytes after a value")
    return node


def _int(node: asn1core.Node) -> int:
    if not _is(node, 2, constructed=False) or not node.payload:
        raise _Refused("malformed", "expected an INTEGER")
    return int.from_bytes(node.payload, "big", signed=True)


def _oid_of(node: asn1core.Node) -> str:
    if not _is(node, 6, constructed=False) or node.payload is None:
        raise _Refused("malformed", "expected an OBJECT IDENTIFIER")
    try:
        return ".".join(str(arc) for arc in asn1core.decode_oid(node.payload))
    except asn1core.Asn1Error as error:
        raise _Refused("malformed", f"bad OBJECT IDENTIFIER: {error}") from error


def signed_attrs_digest_input(signed_attrs_raw: bytes) -> bytes:
    """The bytes RFC 5652 sec. 5.4 digests: the stored ``[0]`` TLV with its tag byte made ``SET``.

    The retained encoding is used as it arrived, only the first octet changes from ``A0`` to
    ``31`` (the explicit SET OF tag replaces the IMPLICIT [0] tag; length and content octets
    stay). Input that is not definite-length DER, or whose SET OF is not in DER order, raises
    ``ValueError``: SignedAttributes MUST be DER (sec. 5.3), and a re-encoding would be a guess.
    """
    if not signed_attrs_raw or signed_attrs_raw[0] != 0xA0:
        raise ValueError("signed_attrs_raw must begin with the [0] tag, 0xA0")
    candidate = b"\x31" + signed_attrs_raw[1:]
    try:
        node, end = asn1core.decode(candidate, der=True)
        if end != len(candidate):
            raise ValueError("signedAttrs has trailing bytes")
        asn1core.check_set_of(node)
    except asn1core.Asn1Error as error:
        raise ValueError(f"signedAttrs is not DER: {error}") from error
    return candidate


def _hash_name(algorithm: cms.AlgorithmIdentifier) -> str:
    name = _DIGESTS.get(algorithm.oid)
    if name is None:
        raise _Refused("unsupported-digest", f"digest algorithm {algorithm.oid} is not supported")
    return name


def _shake_length(algorithm: cms.AlgorithmIdentifier) -> int | None:
    if algorithm.parameters is None:
        return None
    return _int(_decode(algorithm.parameters, der=True))


def _digest(algorithm: cms.AlgorithmIdentifier, data: bytes) -> bytes:
    if algorithm.oid == _ID_SHAKE256_LEN:
        if _shake_length(algorithm) != 512:
            raise _Refused(
                "unsupported-digest", "id-shake256-len is supported with 512 output bits only"
            )
        return hashlib.shake_256(data).digest(64)
    return hashlib.new(_hash_name(algorithm), data).digest()


def _params(algorithm: cms.AlgorithmIdentifier) -> bytes:
    return b"" if algorithm.parameters in (None, b"\x05\x00") else (algorithm.parameters or b"")


def _same_algorithm(left: cms.AlgorithmIdentifier, right: cms.AlgorithmIdentifier) -> bool:
    """RFC 6211 sec. 3: identical modulo encoding; absent and NULL parameters compare equal."""
    return left.oid == right.oid and _params(left) == _params(right)


def _single_value(attribute: cms.Attribute, what: str) -> bytes:
    if len(attribute.values) != 1:
        raise _Refused(
            "attribute-values", f"the {what} attribute must have exactly one value (RFC 5652 11)"
        )
    return attribute.values[0]


def _algorithm_of(node: asn1core.Node, *, implicit: bool = False) -> cms.AlgorithmIdentifier:
    """An AlgorithmIdentifier, or a ``[n] IMPLICIT`` one whose tag the caller has matched."""
    if (not implicit and not _is(node, 16, constructed=True)) or not node.constructed:
        raise _Refused("malformed", "expected an AlgorithmIdentifier")
    if not 1 <= len(node.children) <= 2:
        raise _Refused("malformed", "expected an AlgorithmIdentifier")
    parameters = node.children[1].raw if len(node.children) == 2 else None
    return cms.AlgorithmIdentifier(_oid_of(node.children[0]), parameters, node.raw)


def _check_attributes(
    signer: cms.SignerInfo, signed: cms.SignedData, notes: list[str]
) -> bytes | None:
    """RFC 5652 sec. 5.3, 11.1, 11.2 and RFC 6211: returns the message-digest value, or None."""
    for attribute in signer.unsigned_attrs or ():
        if attribute.oid in (ID_CONTENT_TYPE, ID_MESSAGE_DIGEST, ID_CMS_ALGORITHM_PROTECTION):
            raise _Refused(
                "protected-attribute-unsigned",
                f"attribute {attribute.oid} MUST be a signed attribute, it is unsigned "
                "(RFC 5652 sec. 11.1, 11.2, RFC 6211 sec. 2)",
            )
    attrs = signer.signed_attrs
    if attrs is None:
        if signed.encap_content_type != cms.ID_DATA:
            raise _Refused(
                "signed-attrs-required",
                "signedAttrs MUST be present when the content type is not id-data (RFC 5652 5.3)",
            )
        return None
    by_oid: dict[str, list[cms.Attribute]] = {}
    for attribute in attrs:
        by_oid.setdefault(attribute.oid, []).append(attribute)
    for oid, name in ((ID_CONTENT_TYPE, "content-type"), (ID_MESSAGE_DIGEST, "message-digest")):
        found = by_oid.get(oid, [])
        if not found:
            raise _Refused(
                f"{name}-missing", f"the {name} signed attribute MUST be present (RFC 5652 5.3)"
            )
        if len(found) > 1:
            raise _Refused(
                f"{name}-repeated", f"the {name} attribute MUST NOT appear twice (RFC 5652 11)"
            )
    content_type = _oid_of(_decode(_single_value(by_oid[ID_CONTENT_TYPE][0], "content-type")))
    if content_type != signed.encap_content_type:
        raise _Refused(
            "content-type-mismatch",
            f"content-type attribute {content_type} differs from eContentType "
            f"{signed.encap_content_type} (RFC 5652 sec. 5.6)",
        )
    digest_node = _decode(_single_value(by_oid[ID_MESSAGE_DIGEST][0], "message-digest"))
    if not _is(digest_node, 4, constructed=False) or digest_node.payload is None:
        raise _Refused("message-digest-type", "message-digest MUST be an OCTET STRING")
    protection = by_oid.get(ID_CMS_ALGORITHM_PROTECTION, [])
    if len(protection) > 1:
        raise _Refused(
            "algorithm-protection-repeated",
            "SignedAttributes MUST include only one CMSAlgorithmProtection (RFC 6211 sec. 2)",
        )
    if protection:
        _check_algorithm_protection(signer, _single_value(protection[0], "CMSAlgorithmProtection"))
    else:
        notes.append("algorithm-protection-absent")
    return digest_node.payload


def _check_algorithm_protection(signer: cms.SignerInfo, value: bytes) -> None:
    """RFC 6211 sec. 2 and 3.1: the attribute's copies must equal the SignerInfo's fields."""
    node = _decode(value)
    if not _is(node, 16, constructed=True) or not node.children:
        raise _Refused("algorithm-protection-malformed", "CMSAlgorithmProtection is a SEQUENCE")
    digest = _algorithm_of(node.children[0])
    signature = None
    for child in node.children[1:]:
        if child.tag.is_context(1):
            signature = _algorithm_of(child, implicit=True)
        elif child.tag.is_context(2):
            raise _Refused(
                "algorithm-protection-malformed",
                "macAlgorithm MUST NOT appear in a SignerInfo (RFC 6211 sec. 2)",
            )
        else:
            raise _Refused(
                "algorithm-protection-malformed", "unexpected CMSAlgorithmProtection field"
            )
    if signature is None:
        raise _Refused(
            "algorithm-protection-malformed",
            "signatureAlgorithm MUST be present in a SignerInfo (RFC 6211 sec. 2)",
        )
    if not _same_algorithm(digest, signer.digest_algorithm):
        raise _Refused(
            "algorithm-protection-mismatch",
            "digestAlgorithm differs from the protected copy (RFC 6211 sec. 3.1 step 1)",
        )
    if not _same_algorithm(signature, signer.signature_algorithm):
        raise _Refused(
            "algorithm-protection-mismatch",
            "signatureAlgorithm differs from the protected copy (RFC 6211 sec. 3.1 step 2)",
        )


# ---- keys -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PssParams:
    hash_name: str
    mgf_hash: str
    salt_length: int
    trailer: int


@dataclass(frozen=True, slots=True)
class _Key:
    kind: str  # rsa, rsa-pss, ec, ed25519, ed448, dsa
    values: tuple[Any, ...]


def _pss_params(parameters: bytes | None) -> _PssParams:
    """RSASSA-PSS-params (RFC 8017 appendix A.2.3), defaults filled in."""
    if parameters is None:
        raise _Refused("pss-parameters", "id-RSASSA-PSS needs RSASSA-PSS-params (RFC 4056 sec. 3)")
    node = _decode(parameters, der=True)
    if not _is(node, 16, constructed=True):
        raise _Refused("pss-parameters", "RSASSA-PSS-params is a SEQUENCE")
    hash_oid, mgf_hash, salt, trailer = _ID_SHA1, _ID_SHA1, 20, 1
    last = -1
    for child in node.children:
        number = child.tag.number if child.tag.tag_class is _CONTEXT else -1
        if number not in (0, 1, 2, 3) or number <= last or len(child.children) != 1:
            raise _Refused("pss-parameters", "RSASSA-PSS-params fields malformed or out of order")
        last = number
        inner = child.children[0]
        if number == 0:
            hash_oid = _algorithm_of(inner).oid
        elif number == 1:
            mgf = _algorithm_of(inner)
            if mgf.oid != _ID_MGF1 or mgf.parameters is None:
                raise _Refused("pss-parameters", "maskGenAlgorithm must be MGF1 with a hash")
            mgf_hash = _algorithm_of(_decode(mgf.parameters, der=True)).oid
        elif number == 2:
            salt = _int(inner)
        else:
            trailer = _int(inner)
    if trailer != 1:
        raise _Refused("pss-parameters", "trailerField other than 1 is not supported (RFC 8017)")
    if salt < 0:
        raise _Refused("pss-parameters", "saltLength is negative")
    names = []
    for oid in (hash_oid, mgf_hash):
        name = _DIGESTS.get(oid)
        if name is None:
            raise _Refused("unsupported-digest", f"RSASSA-PSS hash {oid} is not supported")
        names.append(name)
    return _PssParams(names[0], names[1], salt, trailer)


def _read_spki(spki: bytes) -> _Key:
    """SubjectPublicKeyInfo (RFC 5280 sec. 4.1.2.7) for the key types CMS signs with.

    The structure is read by `asn1core.keys.parse_spki` (PORTFOLIO.md section 9 item 15: asn1core is
    the one SPKI reader), which enforces RFC 3279 sec. 2.3.1, RFC 5480 sec. 2.1.1 and 2.2 and RFC
    8410 sec. 3. What is left here is what a CMS verifier adds on top: the RSASSA-PSS restrictions
    (RFC 4056 sec. 3), the curves sigwire verifies, and DSA, which asn1core returns undecoded as
    an `UnknownKey` and whose Dss-Parms (RFC 3279 sec. 2.3.2) are read here.
    """
    try:
        info = asn1core.keys.parse_spki(spki, der=False)
    except asn1core.Asn1Error as error:
        raise _Refused("bad-public-key", str(error)) from error
    algorithm = info.algorithm
    oid = algorithm.dotted
    parameters = None if algorithm.parameters is None else algorithm.parameters.raw
    key = info.key
    if isinstance(key, asn1core.keys.RsaPublicKey):
        n, e = key.modulus, key.public_exponent
        if oid == _RSA_ENCRYPTION:
            return _Key("rsa", (n, e))
        if oid == _ID_RSASSA_PSS:
            restriction = _pss_params(parameters) if parameters else None
            return _Key("rsa-pss", (n, e, restriction))
        raise _Refused("unsupported-key", f"public key algorithm {oid} does not sign")
    if isinstance(key, asn1core.keys.EcPublicKey):
        curve = _CURVES.get(".".join(map(str, key.curve)))
        if curve is None:
            raise _Refused("unsupported-curve", "only P-256, P-384 and P-521 are supported")
        name, width = curve
        if key.compressed:
            raise _Refused("bad-public-key", "a compressed EC point is not supported here")
        x = int.from_bytes(key.point[1 : 1 + width], "big")
        y = int.from_bytes(key.point[1 + width :], "big")
        return _Key("ec", (name, x, y))
    if isinstance(key, asn1core.keys.OkpPublicKey):
        if oid in (_ID_ED25519, _ID_ED448):
            return _Key("ed25519" if oid == _ID_ED25519 else "ed448", (key.key,))
        raise _Refused("unsupported-key", f"public key algorithm {oid} does not sign")
    if oid == _ID_DSA:
        if parameters is None:
            raise _Refused(
                "unsupported-key",
                "a DSA key without parameters takes them from the issuer, which is not supported",
            )
        if key.unused_bits:
            raise _Refused(
                "bad-public-key", "subjectPublicKey must be a BIT STRING of whole octets"
            )
        params = _decode(parameters)
        if not _is(params, 16, constructed=True) or len(params.children) != 3:
            raise _Refused("bad-public-key", "Dss-Parms is SEQUENCE { p, q, g }")
        p, q, g = (_int(c) for c in params.children)
        return _Key("dsa", (p, q, g, _int(_decode(key.key_bits))))
    raise _Refused("unsupported-key", f"public key algorithm {oid} is not supported")


def _certificate_matches(raw: bytes, signer: cms.SignerInfo) -> bool:
    try:
        cert = asn1core.parse_certificate(raw, der=False)
        if signer.subject_key_identifier is not None:
            extension = cert.extension(_SKI_EXTENSION)
            if extension is None:
                return False
            node, _ = asn1core.decode(extension.value, der=False)
            return _is(node, 4, constructed=False) and node.payload == signer.subject_key_identifier
        if cert.serial != signer.serial or signer.issuer is None:
            return False
        node, _ = asn1core.decode(signer.issuer, der=False)
        return asn1core.names_equal(asn1core.parse_name(node), cert.issuer)
    except asn1core.Asn1Error:
        return False


def _find_certificate(signer: cms.SignerInfo, certificates: Sequence[bytes]) -> bytes:
    """RFC 5652 sec. 5.3 and 10.2.4: the certificate the SignerIdentifier names."""
    for raw in certificates:
        if _certificate_matches(raw, signer):
            return raw
    raise _Refused("signer-certificate-not-found", "no certificate matches the SignerIdentifier")


# ---- the signature ---------------------------------------------------------------------------


def _signature_values(signature: bytes) -> tuple[int, int]:
    """ECDSA-Sig-Value and Dss-Sig-Value: SEQUENCE { r INTEGER, s INTEGER }, DER."""
    try:
        node = _decode(signature, der=True)
        if not _is(node, 16, constructed=True) or len(node.children) != 2:
            raise _Refused("signature-invalid", "the signature is not SEQUENCE { r, s }")
        return _int(node.children[0]), _int(node.children[1])
    except _Refused as refusal:
        raise _Refused("signature-invalid", refusal.reason) from refusal


def _check_pss_key(signature: _PssParams, key: _PssParams) -> None:
    """RFC 4056 sec. 3: the key's PSS restrictions against the signature's parameters."""
    if signature.hash_name != key.hash_name or signature.mgf_hash != key.mgf_hash:
        raise _Refused("pss-key-mismatch", "hash or MGF differs from the key's parameters")
    if signature.salt_length < key.salt_length or signature.trailer != key.trailer:
        raise _Refused("pss-key-mismatch", "saltLength or trailerField differs from the key's")


def _check_eddsa_digest(
    oid: str, digest: cms.AlgorithmIdentifier, signed_attrs_present: bool
) -> None:
    """RFC 8419 sec. 3.1 (with signedAttrs) and 3.2 (without): the digestAlgorithm is fixed."""
    if oid == _ID_ED25519:
        ok = digest.oid == _ID_SHA512 and digest.parameters is None
    elif signed_attrs_present:
        try:
            length = _shake_length(digest)
        except _Refused:
            length = None
        ok = digest.oid == _ID_SHAKE256_LEN and length == 512
    else:
        ok = digest.oid == _ID_SHAKE256 and digest.parameters is None
    if not ok:
        raise _Refused(
            "digest-algorithm-mismatch",
            f"digestAlgorithm {digest.oid} is not the one RFC 8419 sec. 3 requires for this EdDSA",
        )


def _check_signature(
    signer: cms.SignerInfo, key: _Key, message: bytes, *, signed_attrs_present: bool, policy: Any
) -> None:
    """Dispatch on signatureAlgorithm; raises ``_Refused`` for anything but a valid signature."""
    from sigwire import verify as sw

    algorithm = signer.signature_algorithm
    oid = algorithm.oid
    digest_alg = signer.digest_algorithm
    digest_hash = _DIGESTS.get(digest_alg.oid)

    def agree(named: str | None, source: str) -> str:
        if digest_hash is None:
            raise _Refused("unsupported-digest", f"digest algorithm {digest_alg.oid}")
        if named is not None and named != digest_hash:
            raise _Refused(
                "digest-algorithm-mismatch",
                f"{source} names {named} but digestAlgorithm is {digest_alg.oid} "
                "(RFC 8933 sec. 3, RFC 5753 sec. 2.1.1)",
            )
        return digest_hash

    def need(kind: str, what: str) -> None:
        if key.kind != kind:
            raise _Refused("key-algorithm-mismatch", f"{what} needs a {kind} key")

    try:
        if oid in _RSA_PKCS1:
            need("rsa", "an rsaEncryption or shaNWithRSAEncryption signature")
            name = agree(_RSA_PKCS1[oid], "the signature algorithm")
            n, e = key.values
            ok = sw.rsa.verify_pkcs1v15(n, e, message, signer.signature, name, policy=policy)
        elif oid == _ID_RSASSA_PSS:
            if key.kind not in ("rsa", "rsa-pss"):
                raise _Refused("key-algorithm-mismatch", "an RSASSA-PSS signature needs an RSA key")
            params = _pss_params(algorithm.parameters)
            # RFC 4056 sec. 3: the hash of the signed attributes is the PSS hashAlgorithm.
            agree(params.hash_name, "RSASSA-PSS-params hashAlgorithm")
            if key.kind == "rsa-pss" and key.values[2] is not None:
                _check_pss_key(params, key.values[2])
            ok = sw.rsa.verify_pss(
                key.values[0],
                key.values[1],
                message,
                signer.signature,
                params.hash_name,
                salt_length=params.salt_length,
                mgf_hash=params.mgf_hash,
                policy=policy,
            )
        elif oid in _ECDSA:
            need("ec", "an ECDSA signature")
            name = agree(_ECDSA[oid], "the signature algorithm")
            curve, qx, qy = key.values
            r, s = _signature_values(signer.signature)
            digest = sw.hashes.lookup(name).digest(message)
            ok = sw.ecdsa.verify(curve, qx, qy, digest, r, s, hash_name=name, policy=policy)
        elif oid in _DSA:
            need("dsa", "a DSA signature")
            name = agree(_DSA[oid], "the signature algorithm")
            p, q, g, y = key.values
            r, s = _signature_values(signer.signature)
            digest = sw.hashes.lookup(name).digest(message)
            ok = sw.dsa.verify(p, q, g, y, digest, r, s, hash_name=name, policy=policy)
        elif oid in (_ID_ED25519, _ID_ED448):
            _check_eddsa_digest(oid, digest_alg, signed_attrs_present)
            if algorithm.parameters is not None:
                raise _Refused("malformed", "EdDSA signature algorithm parameters MUST be absent")
            wanted = "ed25519" if oid == _ID_ED25519 else "ed448"
            need(wanted, f"an {wanted} signature")
            check = sw.eddsa.verify_ed25519 if oid == _ID_ED25519 else sw.eddsa.verify_ed448
            # PureEdDSA signs the message itself: the DER signedAttrs, or the content (RFC 8032).
            ok = check(key.values[0], message, signer.signature, policy=policy)
        else:
            raise _Refused("unsupported-signature-algorithm", f"signature algorithm {oid}")
    except sw.PolicyRefusal as error:
        raise _Refused("policy-refused", str(error)) from error
    except sw.Unsupported as error:
        raise _Refused("unsupported", str(error)) from error
    except sw.MalformedInput as error:
        raise _Refused("bad-public-key", str(error)) from error
    except sw.VerifyError as error:
        raise _Refused("signature-invalid", str(error)) from error
    if not ok:
        raise _Refused("signature-invalid", "the signature does not verify")


# ---- entry points ----------------------------------------------------------------------------


def verify_signer(
    signed: cms.SignedData,
    index: int = 0,
    *,
    content: bytes | None = None,
    spki: bytes | None = None,
    certificates: Sequence[bytes] | None = None,
    policy: Any = None,
) -> SignerVerification:
    """Verify one SignerInfo of a loaded SignedData (RFC 5652 sec. 5.6, RFC 8933 sec. 3).

    ``content`` is the detached content (sec. 5.2); it is required when the SignedData has no
    eContent, and when it has one a differing ``content`` is refused. ``spki`` is a DER
    SubjectPublicKeyInfo to use instead of selecting a certificate; ``certificates`` are the DER
    certificates to select from, defaulting to the SignedData's own. ``policy`` is a
    ``sigwire.verify.Policy`` and defaults to sigwire's strict DEFAULT, which refuses SHA-1, DSA
    and short RSA keys: opt in with ``sigwire.verify.LEGACY`` for old data.

    Returns a ``SignerVerification``; a failed check is ``valid`` false with a ``code``. Raises
    ``IndexError`` for a missing signer, ``ValueError`` for detached content that is missing, and
    ``ImportError`` when ``sigwire[verify]`` is not installed.
    """
    from sigwire import verify as sw

    signer = signed.signer_infos[index]
    notes: list[str] = []
    cert_raw: bytes | None = None

    def result(code: str | None, reason: str | None) -> SignerVerification:
        return SignerVerification(
            index,
            code is None,
            code,
            reason,
            signer.digest_algorithm.oid,
            signer.signature_algorithm.oid,
            cert_raw,
            tuple(notes),
        )

    if content is None and signed.econtent is None:
        raise ValueError("this SignedData has no eContent: pass the detached content")
    if signed.econtent is not None and content is not None and content != signed.econtent:
        return result("content-differs", "the supplied content differs from the eContent")
    data = signed.econtent if signed.econtent is not None else content
    if data is None:  # pragma: no cover - both None was refused above
        raise ValueError("no content")
    if policy is None:
        policy = sw.DEFAULT
    try:
        if all(a.oid != signer.digest_algorithm.oid for a in signed.digest_algorithms):
            notes.append("digest-algorithm-not-in-set")  # RFC 5652 sec. 5.3: SHOULD, not MUST
        claimed = _check_attributes(signer, signed, notes)
        if claimed is not None:
            actual = _digest(signer.digest_algorithm, data)
            if not hmac.compare_digest(actual, claimed):
                raise _Refused(
                    "digest-mismatch",
                    "the message-digest attribute differs from the digest of the content, "
                    "computed with the signer's digestAlgorithm (RFC 5652 sec. 5.6, RFC 8933 sec. 3)",
                )
            if signer.signed_attrs_raw is None:  # pragma: no cover - attrs and raw go together
                raise _Refused("malformed", "signedAttrs was parsed without its encoding")
            try:
                message = signed_attrs_digest_input(signer.signed_attrs_raw)
            except ValueError as error:
                raise _Refused("signed-attrs-not-der", str(error)) from error
        else:
            message = data
        if spki is None:
            pool = (
                certificates
                if certificates is not None
                else [
                    c.raw for c in signed.certificates if c.kind is cms.CertificateKind.CERTIFICATE
                ]
            )
            cert_raw = _find_certificate(signer, pool)
            spki = asn1core.subject_public_key_info(cert_raw, der=False)
            notes.append("chain-not-evaluated")
        else:
            notes.append("key-supplied-by-caller")
        _check_signature(
            signer,
            _read_spki(spki),
            message,
            signed_attrs_present=claimed is not None,
            policy=policy,
        )
    except _Refused as refusal:
        return result(refusal.code, refusal.reason)
    except asn1core.Asn1Error as error:
        return result("malformed", str(error))
    return result(None, None)


def verify_signatures(
    signed: cms.SignedData,
    *,
    content: bytes | None = None,
    spki: bytes | None = None,
    certificates: Sequence[bytes] | None = None,
    policy: Any = None,
) -> Verification:
    """Verify every SignerInfo (RFC 5652 sec. 5.6); ``valid`` needs a signer and all to verify.

    Arguments are those of ``verify_signer``. A certificates-only SignedData has no signer and
    is therefore not valid: it carries nothing that was signed.
    """
    results = tuple(
        verify_signer(
            signed, i, content=content, spki=spki, certificates=certificates, policy=policy
        )
        for i in range(len(signed.signer_infos))
    )
    return Verification(bool(results) and all(r.valid for r in results), results)


ID_SIGNING_TIME = "1.2.840.113549.1.9.5"  # RFC 5652 sec. 11.3


def verify(
    signed: cms.SignedData | bytes,
    content: bytes | None = None,
    *,
    anchors: Sequence[TrustAnchor],
    at: datetime.datetime,
    intermediates: Sequence[bytes] = (),
    inputs: PathInputs | None = None,
    policy: Any = None,
) -> Verification:
    """Signature plus certification path, RFC 5652 sec. 5.6 with RFC 5280 sec. 6 through pkix.

    Each signer is first checked by ``verify_signer`` (the certificate is selected from the
    SignedData's own ``certificates``); a signer whose signature holds then has its certificate
    validated by ``pkix.result.validate`` against ``anchors``, with the SignedData's certificates
    and ``intermediates`` as the pool. RFC 5652 sec. 5.6 leaves "the selection and validation of
    the signer's public key" to the profile; this is that step, and a signer is valid only when
    both hold. A path pkix cannot decide is the code ``chain-unsupported``, never a pass.

    ``at`` is the validation time and is the caller's. The signing-time attribute is never used for
    it: RFC 5652 sec. 11.3 says "acceptance of a purported signing time is a matter of a
    recipient's discretion", and this library's discretion is to report it as the note
    ``signing-time-not-used``. A trusted time needs a timestamp (RFC 3161, the ``tsp`` rows).
    ``inputs`` are pkix's path inputs; revocation is checked only when it carries a checker, and
    the note ``revocation-not-checked`` says when it did not. ``policy`` is as for
    ``verify_signer`` and applies to the signer's signature and to every certificate's.

    Raises ``ImportError`` when ``pkix`` (the ``chain`` extra) or ``sigwire[verify]`` is missing.
    """
    from pkix.result import PathInputs as _PathInputs
    from pkix.result import validate
    from sigwire import verify as sw

    if isinstance(signed, bytes | bytearray):
        signed = cms.load(bytes(signed))
    if policy is None:
        policy = sw.DEFAULT
    base = inputs if inputs is not None else _PathInputs()
    path_inputs = dataclasses.replace(base, signature_policy=policy)
    pool = [c.raw for c in signed.certificates if c.kind is cms.CertificateKind.CERTIFICATE]
    outcomes: list[SignerVerification] = []
    for index in range(len(signed.signer_infos)):
        found = verify_signer(signed, index, content=content, certificates=pool, policy=policy)
        notes = [n for n in found.notes if n != "chain-not-evaluated"]
        signer = signed.signer_infos[index]
        if any(a.oid == ID_SIGNING_TIME for a in signer.signed_attrs or ()):
            notes.append("signing-time-not-used")
        if not found.valid or found.certificate is None:
            outcomes.append(dataclasses.replace(found, notes=tuple(notes)))
            continue
        chain = validate(
            found.certificate, anchors, at, path_inputs, intermediates=[*pool, *intermediates]
        )
        if not chain.revocation_checked:
            notes.append("revocation-not-checked")
        code: str | None = None
        reason: str | None = None
        if not chain.valid:
            code = "chain-unsupported" if chain.status == "unsupported" else "chain-invalid"
            step = chain.failure
            reason = "the signer's certificate path did not validate" + (
                "" if step is None else f": certificate {step.index}, {step.step}: {step.detail}"
            )
        else:
            notes.append("chain-valid")
        outcomes.append(
            dataclasses.replace(
                found, valid=code is None, code=code, reason=reason, notes=tuple(notes)
            )
        )
    results = tuple(outcomes)
    return Verification(bool(results) and all(r.valid for r in results), results)


def countersign(info: ContentInfo, signer: int) -> ContentInfo:
    """Pending behaviour defined by RFC 5652 sec. 11.4.

    Not implemented yet. See the ``verify.countersign()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("countersign() is not implemented: RFC 5652 sec. 11.4")
