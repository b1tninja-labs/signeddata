"""The signedAttrs digest input (RFC 5652 sec. 5.4) and the single-value rules (sec. 11.1, 11.2)."""

from __future__ import annotations

import base64
import pathlib

import cmsbuild as b
import pytest

from signeddata import cms
from signeddata.verify import signed_attrs_digest_input, verify_signer

pytest.importorskip("sigwire.verify")

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "rfc4134"


def test_explicit_set_tag_replaces_implicit_context_tag():
    text = (FIXTURES / "4.10.b64").read_text()
    signer = cms.load(base64.b64decode("".join(text.split()))).signer_infos[0]
    raw = signer.signed_attrs_raw
    assert raw is not None
    assert raw[0] == 0xA0
    digested = signed_attrs_digest_input(raw)
    assert digested[0] == 0x31
    assert digested[1:] == raw[1:]  # length and content octets are unchanged


def test_digest_input_refuses_what_is_not_the_context_tag():
    with pytest.raises(ValueError, match="0xA0"):
        signed_attrs_digest_input(b"\x31\x00")


def test_digest_input_refuses_set_of_out_of_der_order():
    first, second = sorted(
        [
            b.attribute(b.ID_CONTENT_TYPE, b.oid(b.ID_DATA)),
            b.attribute(b.ID_MESSAGE_DIGEST, b.octets(b"\x00" * 32)),
        ]
    )
    with pytest.raises(ValueError, match="DER"):
        signed_attrs_digest_input(b.tlv(0xA0, second + first))  # reverse of DER order


def test_message_digest_attr_must_be_single_valued():
    key = b.rsa_key()
    two = b.seq(
        b.oid(b.ID_MESSAGE_DIGEST), b.set_of(b.octets(b"\x01" * 32), b.octets(b"\x02" * 32))
    )
    spec = b.Spec(key, sign=b.pkcs1(key), drop={"message-digest"}, extra_attrs=[two])
    result = verify_signer(cms.load(b.build(spec), der=True))
    assert result.code == "attribute-values"
    assert "exactly one value" in (result.reason or "")


def test_message_digest_attr_must_not_repeat():
    key = b.rsa_key()
    again = b.attribute(b.ID_MESSAGE_DIGEST, b.octets(b"\x03" * 32))
    spec = b.Spec(key, sign=b.pkcs1(key), extra_attrs=[again])
    result = verify_signer(cms.load(b.build(spec), der=True))
    assert result.code == "message-digest-repeated"
