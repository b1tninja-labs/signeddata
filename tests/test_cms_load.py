"""cms.load against the RFC 4134 binaries (tests/fixtures/rfc4134/SOURCES.txt) and hand-built BER."""

from __future__ import annotations

import base64
import pathlib

import asn1core
import pytest

from signeddata import cms
from signeddata.cms import CertificateKind, CmsError

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "rfc4134"
CONTENT = b"This is some sample content."


def _example(name: str) -> bytes:
    return base64.b64decode("".join((FIXTURES / f"{name}.b64").read_text().split()))


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + asn1core.encode_length(len(content)) + content


def test_every_fixture_length_matches_its_outer_header():
    for name in ("4.2", "4.3", "4.6", "4.7", "4.10", "4.11"):
        data = _example(name)
        node, end = asn1core.decode(data, der=True)
        assert end == len(data)
        assert node.raw == data


def test_basic_rsa_signed_content():
    signed = cms.load(_example("4.2"))
    assert signed.version == 1
    assert signed.version_issue is None
    assert signed.encap_content_type == cms.ID_DATA
    assert signed.econtent == CONTENT
    assert [d.oid for d in signed.digest_algorithms] == ["1.3.14.3.2.26"]
    assert len(signed.certificates) == 1
    assert signed.certificates[0].kind is CertificateKind.CERTIFICATE
    asn1core.parse_certificate(signed.certificates[0].raw)
    (signer,) = signed.signer_infos
    assert signer.issuer is not None
    assert signer.subject_key_identifier is None
    assert signer.signed_attrs is None
    assert signer.signature_algorithm.oid == "1.2.840.113549.1.1.1"
    assert len(signer.signature) == 128


def test_signed_attrs_raw_bytes_are_retained():
    data = _example("4.10")
    signed = cms.load(data)
    (signer,) = signed.signer_infos
    raw = signer.signed_attrs_raw
    assert raw is not None
    assert raw[0] == 0xA0
    assert raw in data
    assert signer.signed_attrs is not None
    oids = [a.oid for a in signer.signed_attrs]
    assert "1.2.840.113549.1.9.3" in oids or len(oids) >= 1
    assert all(a.raw in raw for a in signer.signed_attrs)
    assert signer.unsigned_attrs is None


def test_detached_econtent_is_none():
    signed = cms.load(_example("4.3"))
    assert signed.econtent is None
    assert signed.econtent_raw is None
    assert len(signed.signer_infos) == 1


def test_multiple_signers_are_all_returned():
    signed = cms.load(_example("4.6"))
    assert len(signed.signer_infos) == 2
    assert len(signed.certificates) == 2
    serials = {s.serial for s in signed.signer_infos}
    assert len(serials) == 2


def test_sid_by_subject_key_identifier():
    signed = cms.load(_example("4.7"))
    assert signed.version == 3
    assert signed.version_issue is None
    (signer,) = signed.signer_infos
    assert signer.version == 3
    assert signer.issuer is None
    assert signer.serial is None
    assert signer.subject_key_identifier is not None
    assert len(signer.subject_key_identifier) == 20


def test_certificates_only_has_no_signers():
    signed = cms.load(_example("4.11"))
    assert signed.signer_infos == ()
    assert signed.digest_algorithms == ()
    assert signed.econtent_raw is None
    assert signed.is_certificates_only
    assert len(signed.certificates) == 2
    assert [c.kind for c in signed.crls] == [CertificateKind.CRL]
    asn1core.parse_crl(signed.crls[0].raw)


def test_certificates_only_helper_returns_the_certificate_der():
    certs = cms.certificates_only(_example("4.11"))
    assert len(certs) == 2
    assert [asn1core.parse_certificate(c).issuer.values("2.5.4.3") for c in certs] == [
        ("CarlDSS",),
        ("CarlDSS",),
    ]


def test_certificates_only_refuses_a_signed_message():
    with pytest.raises(CmsError, match="certificates-only"):
        cms.certificates_only(_example("4.2"))


def test_unknown_certificate_choice_is_retained_opaque():
    cert = cms.load(_example("4.2")).certificates[0].raw
    other = _tlv(0xA3, b"\x06\x03\x2a\x03\x04\x04\x01\x00")
    for body, kind in (
        (other, CertificateKind.OTHER_CERTIFICATE),
        (_tlv(0xA2, b"\x30\x00"), CertificateKind.V2_ATTRIBUTE_CERTIFICATE),
        (_tlv(0xA1, b"\x30\x00"), CertificateKind.V1_ATTRIBUTE_CERTIFICATE),
    ):
        data = _certs_only([cert, body])
        signed = cms.load(data)
        assert [c.kind for c in signed.certificates] == [CertificateKind.CERTIFICATE, kind]
        assert signed.certificates[1].raw == body


def _certs_only(members: list[bytes], version: int = 1) -> bytes:
    signed = _tlv(
        0x30,
        _tlv(0x02, bytes([version]))
        + _tlv(0x31, b"")
        + _tlv(0x30, _tlv(0x06, bytes.fromhex("2a864886f70d010701")))
        + _tlv(0xA0, b"".join(members))
        + _tlv(0x31, b""),
    )
    return _tlv(0x30, _tlv(0x06, bytes.fromhex("2a864886f70d010702")) + _tlv(0xA0, signed))


def test_version_mismatch_is_reported_not_corrected():
    cert = cms.load(_example("4.2")).certificates[0].raw
    other = _tlv(0xA3, b"\x06\x03\x2a\x03\x04\x04\x01\x00")
    signed = cms.load(_certs_only([cert, other], version=1))
    assert signed.version == 1
    assert signed.version_issue is not None
    assert "5" in signed.version_issue
    assert cms.load(_certs_only([cert], version=1)).version_issue is None
    wrong = cms.load(_certs_only([cert], version=3))
    assert wrong.version == 3
    assert wrong.version_issue is not None


def test_signer_version_disagreeing_with_sid_is_reported():
    data = bytearray(_example("4.7"))
    # SignerInfo version is the INTEGER 3 right before [0] SKI: 02 01 03 80 14
    marker = bytes.fromhex("020103" + "8014")
    at = bytes(data).index(marker)
    data[at + 2] = 1
    signed = cms.load(bytes(data))
    assert signed.signer_infos[0].version == 1
    assert signed.signer_infos[0].version_issue is not None


def _to_indefinite(der: bytes) -> bytes:
    """Rewrite the top two levels of a ContentInfo into indefinite-length BER."""
    top, _ = asn1core.decode(der, der=True)
    oid, slot = top.children
    signed = slot.children[0]
    inner = b"".join(c.raw for c in signed.children)
    signed_ber = b"\x30\x80" + inner + b"\x00\x00"
    slot_ber = b"\xa0\x80" + signed_ber + b"\x00\x00"
    return b"\x30\x80" + oid.raw + slot_ber + b"\x00\x00"


def test_indefinite_length_ber_loads():
    data = _example("4.2")
    ber = _to_indefinite(data)
    assert ber != data
    signed = cms.load(ber)
    assert signed.econtent == CONTENT
    assert len(signed.signer_infos) == 1
    assert signed.signer_infos[0].signature == cms.load(data).signer_infos[0].signature


def test_der_flag_refuses_indefinite():
    with pytest.raises(CmsError, match="DER"):
        cms.load(_to_indefinite(_example("4.2")), der=True)
    assert cms.load(_example("4.2"), der=True).econtent == CONTENT


def test_constructed_econtent_is_joined():
    top, _ = asn1core.decode(_example("4.2"), der=True)
    signed = top.children[1].children[0]
    encap = signed.children[2]
    constructed = _tlv(0x24, _tlv(0x04, CONTENT[:10]) + _tlv(0x04, CONTENT[10:]))
    new_encap = _tlv(0x30, encap.children[0].raw + _tlv(0xA0, constructed))
    kids = list(signed.children)
    kids[2] = asn1core.decode(new_encap, der=True)[0]
    body = _tlv(0x30, b"".join(k.raw for k in kids))
    data = _tlv(0x30, top.children[0].raw + _tlv(0xA0, body))
    assert cms.load(data).econtent == CONTENT
    with pytest.raises(CmsError):
        cms.load(data, der=True)


def test_non_octet_string_content_is_kept_as_raw():
    """RFC 5652 sec. 5.2.1: PKCS #7 content is not an OCTET STRING (Authenticode)."""
    top, _ = asn1core.decode(_example("4.2"), der=True)
    signed = top.children[1].children[0]
    encap = signed.children[2]
    seq = _tlv(0x30, _tlv(0x02, b"\x01"))
    new_encap = _tlv(0x30, encap.children[0].raw + _tlv(0xA0, seq))
    kids = list(signed.children)
    kids[2] = asn1core.decode(new_encap, der=True)[0]
    body = _tlv(0x30, b"".join(k.raw for k in kids))
    data = _tlv(0x30, top.children[0].raw + _tlv(0xA0, body))
    loaded = cms.load(data)
    assert loaded.econtent is None
    assert loaded.econtent_raw == seq
    assert not loaded.is_certificates_only


def test_trailing_bytes_refused():
    with pytest.raises(CmsError, match="trailing"):
        cms.load(_example("4.2") + b"\x00")


def test_other_content_type_is_unsupported_not_malformed():
    data = _tlv(
        0x30, _tlv(0x06, bytes.fromhex("2a864886f70d010701")) + _tlv(0xA0, _tlv(0x04, b"x"))
    )
    assert cms.parse_content_info(data).content_type == cms.ID_DATA
    with pytest.raises(cms.UnsupportedContentTypeError):
        cms.load(data)


def test_truncated_and_garbage_input_raise_cmserror():
    data = _example("4.2")
    for bad in (b"", data[:100], b"\x04\x00", b"\x30\x00", b"\xff" * 8):
        with pytest.raises(CmsError):
            cms.load(bad)
    with pytest.raises(TypeError):
        cms.load("text")


def test_depth_and_size_bounded():
    nested = b"\x30\x00"
    for _ in range(200):
        nested = _tlv(0x30, nested)
    with pytest.raises(CmsError):
        cms.load(nested)
    bomb = _tlv(0x30, _tlv(0x06, bytes.fromhex("2a864886f70d010702")) + _tlv(0xA0, nested))
    with pytest.raises(CmsError):
        cms.load(bomb)


def test_retention_every_signer_slice_is_a_slice_of_the_input():
    data = _example("4.10")
    signed = cms.load(data)
    assert signed.raw in data
    for signer in signed.signer_infos:
        assert signer.raw in data
        assert signer.signature_algorithm.raw in data
    for choice in signed.certificates:
        assert choice.raw in data
