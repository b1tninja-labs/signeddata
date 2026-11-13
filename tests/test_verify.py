"""verify_signer against the RFC 4134 binaries and against messages built with `cryptography`.

The RFC 4134 examples (tests/fixtures/rfc4134/SOURCES.txt) are real third-party signatures: RSA
with SHA-1 and no signed attributes (4.2), DSA detached (4.3), DSA with signed attributes (4.10)
and DSA by subject key identifier (4.7). They use SHA-1 and DSA, so they verify only under
sigwire's LEGACY policy, and the default policy refusing them is a test too. The other messages are
built in `cmsbuild.py` so each test can break exactly one field.
"""

from __future__ import annotations

import base64
import datetime
import pathlib

import cmsbuild as b
import pytest
from cryptography.hazmat.primitives import hashes

from signeddata import cms, verify
from signeddata.verify import verify_signatures, verify_signer

pytest.importorskip("sigwire.verify")
from sigwire.verify import DEFAULT, LEGACY

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "rfc4134"
RFC_CONTENT = b"This is some sample content."


def _example_bytes(name: str) -> bytes:
    text = (FIXTURES / f"{name}.b64").read_text()
    return base64.b64decode("".join(text.split()))


def _example(name: str) -> cms.SignedData:
    return cms.load(_example_bytes(name))


def _loaded(spec: b.Spec) -> cms.SignedData:
    return cms.load(b.build(spec), der=True)


def _rsa(**kw) -> b.Spec:
    key = b.rsa_key()
    return b.Spec(key, sign=b.pkcs1(key), **kw)


# ---- real vectors -----------------------------------------------------------------------------


def test_rfc4134_rsa_sha1_without_signed_attributes_verifies_under_legacy():
    result = verify_signer(_example("4.2"), policy=LEGACY)
    assert result.valid, result.reason
    assert result.certificate is not None
    assert "chain-not-evaluated" in result.notes


def test_default_policy_refuses_sha1_and_dsa_vectors():
    result = verify_signer(_example("4.2"))
    assert not result.valid
    assert result.code == "policy-refused"
    assert verify_signer(_example("4.10")).code == "policy-refused"


def test_detached_content_digest():
    signed = _example("4.3")
    assert signed.econtent is None
    assert verify_signer(signed, content=RFC_CONTENT, policy=LEGACY).valid
    tampered = verify_signer(signed, content=RFC_CONTENT + b"!", policy=LEGACY)
    assert tampered.code == "signature-invalid"
    with pytest.raises(ValueError, match="detached"):
        verify_signer(signed, policy=LEGACY)


def test_signer_found_by_ski():
    signed = _example("4.7")
    assert signed.signer_infos[0].subject_key_identifier is not None
    result = verify_signer(signed, policy=LEGACY)
    assert result.valid, result.reason
    assert result.certificate is not None


def test_signature_is_over_retained_signed_attrs():
    signed = _example("4.10")
    result = verify_signer(signed, policy=LEGACY)
    assert result.valid, result.reason
    # Flip one bit in the last byte of the retained signedAttrs (inside an attribute value that is
    # not the message digest): the content digest still matches, the signature, made over exactly
    # those bytes, must not.
    raw = signed.signer_infos[0].signed_attrs_raw
    assert raw is not None
    broken = bytearray(raw)
    broken[-1] ^= 0x01
    original = _example_bytes("4.10")
    swapped = original.replace(raw, bytes(broken))
    assert swapped != original
    again = verify_signer(cms.load(swapped), policy=LEGACY)
    assert not again.valid
    assert again.code == "signature-invalid"


def test_certificates_only_has_nothing_to_verify():
    signed = _example("4.11")
    assert verify_signatures(signed, policy=LEGACY) == verify.Verification(False, ())


# ---- generated messages -----------------------------------------------------------------------


def test_rsa_with_signed_attributes_by_issuer_and_serial():
    result = verify_signer(_loaded(_rsa()))
    assert result.valid, result.reason
    assert result.notes == ("algorithm-protection-absent", "chain-not-evaluated")


def test_sha256_with_rsa_signature_oid_is_accepted():
    key = b.rsa_key()
    spec = b.Spec(key, sig_oid=b.SHA256_RSA, sign=b.pkcs1(key))
    assert verify_signer(_loaded(spec)).valid


def test_signature_algorithm_hash_must_match_digest_algorithm():
    key = b.rsa_key()
    spec = b.Spec(key, sig_oid=b.SHA384_RSA, sign=b.pkcs1(key, hashes.SHA384))
    result = verify_signer(_loaded(spec))
    assert result.code == "digest-algorithm-mismatch"


def test_different_digest_algorithms_are_refused():
    # ecdsa-with-SHA384 over a SHA-256 digestAlgorithm: the digest of the content (message-digest)
    # and the digest handed to the signature algorithm would differ (RFC 8933 sec. 3,
    # RFC 5753 sec. 2.1.1).
    key = b.ec_key()
    spec = b.Spec(key, sig_oid=b.ECDSA_SHA384, sig_params=None, sign=b.ecdsa(key, hashes.SHA384))
    result = verify_signer(_loaded(spec))
    assert not result.valid
    assert result.code == "digest-algorithm-mismatch"
    assert "RFC 8933" in (result.reason or "")


def test_ecdsa_verifies_and_bad_signature_is_a_result_not_an_exception():
    key = b.ec_key()
    good = b.Spec(key, sig_oid=b.ECDSA_SHA256, sig_params=None, sign=b.ecdsa(key))
    assert verify_signer(_loaded(good)).valid
    other = b.ec_key()
    bad = b.Spec(key, sig_oid=b.ECDSA_SHA256, sig_params=None, sign=b.ecdsa(other))
    assert verify_signer(_loaded(bad)).code == "signature-invalid"


def test_ed25519_signs_the_signed_attributes_themselves():
    key = b.ed_key()
    spec = b.Spec(key, digest_oid=b.SHA512, sig_oid=b.ED25519, sig_params=None, sign=b.eddsa(key))
    assert verify_signer(_loaded(spec)).valid
    wrong_digest = b.Spec(key, sig_oid=b.ED25519, sig_params=None, sign=b.eddsa(key))
    assert verify_signer(_loaded(wrong_digest)).code == "digest-algorithm-mismatch"


def test_rsa_pss_with_parameters():
    key = b.rsa_key()
    spec = b.Spec(key, sig_oid=b.RSA_PSS, sig_params=b.pss_params(), sign=b.pss(key))
    result = verify_signer(_loaded(spec))
    assert result.valid, result.reason
    wrong = b.Spec(
        key,
        sig_oid=b.RSA_PSS,
        sig_params=b.pss_params(b.SHA384, 48),
        sign=b.pss(key, hashes.SHA384, 48),
    )
    assert verify_signer(_loaded(wrong)).code == "digest-algorithm-mismatch"


def test_digest_mismatch_when_content_changes_after_signing():
    key = b.rsa_key()
    spec = b.Spec(key, sign=b.pkcs1(key), message_digest=b"\x00" * 32)
    assert verify_signer(_loaded(spec)).code == "digest-mismatch"


def test_by_ski_with_generated_key():
    key = b.rsa_key()
    spec = b.Spec(key, sign=b.pkcs1(key), by_ski=True)
    assert verify_signer(_loaded(spec)).valid


def test_signer_certificate_not_found():
    result = verify_signer(_loaded(_rsa()), certificates=[])
    assert result.code == "signer-certificate-not-found"


def test_caller_supplied_key_replaces_certificate_selection():
    key = b.rsa_key()
    signed = _loaded(b.Spec(key, sign=b.pkcs1(key)))
    result = verify_signer(signed, certificates=[], spki=b.spki_of(key))
    assert result.valid
    assert "key-supplied-by-caller" in result.notes
    assert verify_signer(signed, spki=b.spki_of(b.rsa_key())).code == "signature-invalid"


def test_content_type_attribute_must_match_econtent_type():
    spec = _rsa(attr_content_type="1.2.840.113549.1.7.2")
    assert verify_signer(_loaded(spec)).code == "content-type-mismatch"


def test_missing_attributes_are_refused():
    assert verify_signer(_loaded(_rsa(drop={"content-type"}))).code == "content-type-missing"
    assert verify_signer(_loaded(_rsa(drop={"message-digest"}))).code == "message-digest-missing"


def test_digest_algorithm_absent_from_set_is_a_note_not_a_failure():
    result = verify_signer(_loaded(_rsa(digest_set=[b.SHA512])))
    assert result.valid
    assert "digest-algorithm-not-in-set" in result.notes


def test_unsigned_attribute_that_must_be_signed_is_refused():
    unsigned = b.attribute(b.ID_CONTENT_TYPE, b.oid(b.ID_DATA))
    assert verify_signer(_loaded(_rsa(unsigned=[unsigned]))).code == "protected-attribute-unsigned"


def test_policy_refusal_names_the_refused_algorithm():
    result = verify_signer(_loaded(_rsa()), policy=DEFAULT.with_rule("rsa-pkcs1v15", min_bits=4096))
    assert result.code == "policy-refused"
    assert "4096" in (result.reason or "")


# ---- RFC 8933 / RFC 6211 algorithm protection -------------------------------------------------


def _implicit1(algorithm_identifier: bytes) -> bytes:
    """[1] IMPLICIT AlgorithmIdentifier: the SEQUENCE tag byte becomes A1."""
    return b"\xa1" + algorithm_identifier[1:]


def _protection(digest_oid: str, sig_oid: str, sig_params: bytes | None) -> bytes:
    return b.seq(b.alg(digest_oid), _implicit1(b.alg(sig_oid, sig_params)))


def test_algorithm_protection_match_is_accepted():
    key = b.rsa_key()
    protection = _protection(b.SHA256, b.RSA_ENCRYPTION, b"\x05\x00")
    spec = b.Spec(key, sign=b.pkcs1(key), protection=protection)
    result = verify_signer(_loaded(spec))
    assert result.valid, result.reason
    assert "algorithm-protection-absent" not in result.notes


def test_algorithm_protection_null_and_absent_parameters_compare_equal():
    key = b.rsa_key()
    protection = _protection(b.SHA256, b.RSA_ENCRYPTION, None)  # the SignerInfo carries NULL
    spec = b.Spec(key, sign=b.pkcs1(key), protection=protection)
    assert verify_signer(_loaded(spec)).valid


def test_algorithm_protection_mismatch_is_refused():
    key = b.rsa_key()
    # The protected copy says SHA-384 RSA, the SignerInfo says rsaEncryption: a substitution.
    protection = _protection(b.SHA256, b.SHA384_RSA, b"\x05\x00")
    spec = b.Spec(key, sign=b.pkcs1(key), protection=protection)
    result = verify_signer(_loaded(spec))
    assert not result.valid
    assert result.code == "algorithm-protection-mismatch"
    digest_swapped = b.Spec(
        key, sign=b.pkcs1(key), protection=_protection(b.SHA512, b.RSA_ENCRYPTION, b"\x05\x00")
    )
    assert verify_signer(_loaded(digest_swapped)).code == "algorithm-protection-mismatch"


def test_algorithm_protection_with_mac_algorithm_is_malformed_in_signed_data():
    key = b.rsa_key()
    protection = b.seq(b.alg(b.SHA256), b"\xa2" + b.alg("1.2.840.113549.2.9")[1:])
    spec = b.Spec(key, sign=b.pkcs1(key), protection=protection)
    assert verify_signer(_loaded(spec)).code == "algorithm-protection-malformed"


# ---- verify(): the signature plus the pkix chain ------------------------------------------------

AT = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


def _anchor_for(spec: b.Spec):
    load_anchor = pytest.importorskip("pkix.anchors").load_anchor
    return load_anchor(b.make_certificate(spec.key, serial=spec.cert_serial))


def test_chain_decision_comes_from_pkix():
    key = b.rsa_key()
    spec = b.Spec(key, sign=b.pkcs1(key))
    signed = _loaded(spec)
    result = verify.verify(signed, anchors=[_anchor_for(spec)], at=AT)
    assert result.valid
    assert "chain-valid" in result.signers[0].notes
    assert "chain-not-evaluated" not in result.signers[0].notes
    assert "revocation-not-checked" in result.signers[0].notes
    # The same signature, no trust anchor that reaches it: pkix says no, so verify() says no.
    stranger = b.Spec(b.rsa_key(), sign=b.pkcs1(key))
    refused = verify.verify(signed, anchors=[_anchor_for(stranger)], at=AT)
    assert not refused.valid
    assert refused.signers[0].code == "chain-invalid"


def test_a_bad_signature_is_not_rescued_by_a_good_chain():
    key = b.rsa_key()
    spec = b.Spec(key, sign=b.pkcs1(key), content=b.CONTENT)
    signed = _loaded(spec)
    result = verify.verify(signed, b"other content", anchors=[_anchor_for(spec)], at=AT)
    assert not result.valid
    assert result.signers[0].code == "content-differs"


def test_signing_time_is_not_trusted():
    """RFC 5652 sec. 11.3: the signing time is the signer's claim; the chain uses the caller's time."""
    key = b.rsa_key()
    signing_time = b.attribute("1.2.840.113549.1.9.5", b.tlv(0x17, b"260301000000Z"))
    spec = b.Spec(key, sign=b.pkcs1(key), extra_attrs=[signing_time])
    signed = _loaded(spec)
    anchor = _anchor_for(spec)
    now = verify.verify(signed, anchors=[anchor], at=AT)
    assert now.valid
    assert "signing-time-not-used" in now.signers[0].notes
    # At a time outside the certificate's validity the chain fails, whatever signing-time claims.
    later = verify.verify(
        signed, anchors=[anchor], at=datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC)
    )
    assert later.signers[0].code == "chain-invalid"
    assert "validity" in (later.signers[0].reason or "")


def test_spki_reader_is_asn1cores():
    """The SubjectPublicKeyInfo is read by asn1core.keys.parse_spki; its refusals arrive here."""
    key = b.rsa_key()
    spec = b.Spec(key, sign=b.pkcs1(key))
    spki = bytearray(b.spki_of(key))
    # rsaEncryption parameters MUST be NULL (RFC 3279 sec. 2.3.1). Retagging the NULL keeps the
    # length, and asn1core refuses the result as "present but not NULL".
    at = spki.index(b"\x05\x00")
    spki[at : at + 2] = b"\x02\x00"
    result = verify_signer(_loaded(spec), spki=bytes(spki))
    assert result.code == "bad-public-key"
    assert "RFC 3279" in (result.reason or "")


def test_dsa_parameters_are_read_by_asn1core():
    """Row `verify.spki_reader`: DSA's Dss-Parms are asn1core's (`asn1core.keys.DsaPublicKey`), so
    its RFC 3279 sec. 2.3.2 refusal of NULL parameters arrives here, and absent parameters are
    still this verifier's `unsupported-key` (row `verify.dsa_inherited_parameters`)."""
    key = b.rsa_key()
    spec = b.Spec(key, sign=b.pkcs1(key))
    dsa_oid = bytes.fromhex("06072a8648ce380401")
    bits = bytes.fromhex("030400020105")  # BIT STRING { 00, INTEGER 5 }
    null_parameters = bytes.fromhex("3013300b") + dsa_oid + b"\x05\x00" + bits
    result = verify_signer(_loaded(spec), spki=null_parameters)
    assert result.code == "bad-public-key"
    assert "never NULL" in (result.reason or "")
    absent = bytes.fromhex("30113009") + dsa_oid + bits
    result = verify_signer(_loaded(spec), spki=absent)
    assert result.code == "unsupported-key"
    assert "issuer" in (result.reason or "")
