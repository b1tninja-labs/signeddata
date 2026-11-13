"""Build small SignedData messages for the verify tests, signing with `cryptography`.

Test-only. The package never signs; these helpers exist so a test can state exactly which field is
wrong and know every other field is right. Nothing here is a model of how to produce CMS.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass, field

import asn1core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

ID_DATA = "1.2.840.113549.1.7.1"
ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
ID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
ID_ALG_PROTECTION = "1.2.840.113549.1.9.52"
SHA256 = "2.16.840.1.101.3.4.2.1"
SHA384 = "2.16.840.1.101.3.4.2.2"
SHA512 = "2.16.840.1.101.3.4.2.3"
RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
SHA256_RSA = "1.2.840.113549.1.1.11"
SHA384_RSA = "1.2.840.113549.1.1.12"
RSA_PSS = "1.2.840.113549.1.1.10"
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
ECDSA_SHA384 = "1.2.840.10045.4.3.3"
ED25519 = "1.3.101.112"
CONTENT = b"signeddata verify test content"


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + asn1core.encode_length(len(content)) + content


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def oid(dotted: str) -> bytes:
    return tlv(6, asn1core.encode_oid(asn1core.parse_oid_string(dotted)))


def integer(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return tlv(2, value.to_bytes(length, "big", signed=True))


def octets(data: bytes) -> bytes:
    return tlv(4, data)


def alg(dotted: str, params: bytes | None = None) -> bytes:
    return seq(oid(dotted), params if params is not None else b"")


def attribute(dotted: str, *values: bytes) -> bytes:
    return seq(oid(dotted), tlv(0x31, b"".join(sorted(values))))


def set_of(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))


def make_certificate(key, *, serial: int = 7, ski: bool = True) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "signeddata test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
    )
    if ski:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm).public_bytes(serialization.Encoding.DER)


def spki_of(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def ski_of(key) -> bytes:
    return x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest


@dataclass
class Spec:
    """What to put in the message. Every field defaults to a correct message."""

    key: object
    digest_oid: str = SHA256
    sig_oid: str = RSA_ENCRYPTION
    sig_params: bytes | None = b"\x05\x00"
    digest_params: bytes | None = None
    sign: object = None  # callable(message) -> signature bytes
    content: bytes = CONTENT
    attrs: bool = True
    by_ski: bool = False
    detached: bool = False
    message_digest: bytes | None = None
    attr_content_type: str = ID_DATA
    extra_attrs: list[bytes] = field(default_factory=list)
    unsigned: list[bytes] = field(default_factory=list)
    protection: bytes | None = None
    digest_set: list[str] | None = None
    drop: set[str] = field(default_factory=set)
    cert_serial: int = 7


def build(spec: Spec) -> bytes:
    key = spec.key
    cert = make_certificate(key, serial=spec.cert_serial)
    digest_alg = alg(spec.digest_oid, spec.digest_params)
    sig_alg = alg(spec.sig_oid, spec.sig_params)
    hash_name = {SHA256: "sha256", SHA384: "sha384", SHA512: "sha512"}[spec.digest_oid]
    attrs_der = b""
    message = spec.content
    if spec.attrs:
        digest = spec.message_digest or hashlib.new(hash_name, spec.content).digest()
        items = [
            attribute(ID_CONTENT_TYPE, oid(spec.attr_content_type)),
            attribute(ID_MESSAGE_DIGEST, octets(digest)),
            *spec.extra_attrs,
        ]
        if "content-type" in spec.drop:
            items.pop(0)
        if "message-digest" in spec.drop:
            items.pop(1 if "content-type" not in spec.drop else 0)
        if spec.protection is not None:
            items.append(attribute(ID_ALG_PROTECTION, spec.protection))
        body = b"".join(sorted(items))
        attrs_der = tlv(0xA0, body)
        message = tlv(0x31, body)
    signature = spec.sign(message)  # type: ignore[operator]
    if spec.by_ski:
        sid = tlv(0x80, ski_of(key))
        version = 3
    else:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "signeddata test")])
        sid = seq(name.public_bytes(), integer(spec.cert_serial))
        version = 1
    signer_info = seq(
        integer(version),
        sid,
        digest_alg,
        attrs_der,
        sig_alg,
        octets(signature),
        tlv(0xA1, b"".join(spec.unsigned)) if spec.unsigned else b"",
    )
    digests = spec.digest_set if spec.digest_set is not None else [spec.digest_oid]
    encap = seq(
        oid(ID_DATA),
        b"" if spec.detached else tlv(0xA0, octets(spec.content)),
    )
    signed_data = seq(
        integer(3 if spec.by_ski else 1),
        set_of(*[alg(d) for d in digests]),
        encap,
        tlv(0xA0, cert),
        set_of(signer_info),
    )
    return seq(oid(ID_SIGNED_DATA), tlv(0xA0, signed_data))


def rsa_key():
    return rsa.generate_private_key(65537, 2048)


def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def ed_key():
    return ed25519.Ed25519PrivateKey.generate()


def pkcs1(key, hash_cls=hashes.SHA256):
    return lambda message: key.sign(message, padding.PKCS1v15(), hash_cls())


def pss_params(hash_oid: str = SHA256, salt: int = 32) -> bytes:
    return seq(
        tlv(0xA0, alg(hash_oid)),
        tlv(0xA1, alg("1.2.840.113549.1.1.8", alg(hash_oid))),
        tlv(0xA2, integer(salt)),
    )


def pss(key, hash_cls=hashes.SHA256, salt: int = 32):
    return lambda message: key.sign(
        message, padding.PSS(padding.MGF1(hash_cls()), salt), hash_cls()
    )


def ecdsa(key, hash_cls=hashes.SHA256):
    return lambda message: key.sign(message, ec.ECDSA(hash_cls()))


def eddsa(key):
    return lambda message: key.sign(message)
