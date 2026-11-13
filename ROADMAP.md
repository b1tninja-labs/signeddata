# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation signeddata could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `cms.load()` | RFC 5652 sec. 3, 5.1, 5.2, 5.3, 10.2.4 | `[ok]` | `tests/test_cms_load.py::test_signed_attrs_raw_bytes_are_retained` | M1 |
| `sd.load-certificates-only` | RFC 5652 sec. 5.2 (degenerate form), RFC 10002 sec. 4.1 (Simple PKI Response), RFC 8951 sec. 3.2.1 (EST cacerts) | `[ok]` | `tests/test_cms_load.py::test_certificates_only_has_no_signers` | M1 |
| `sd.load-detached` | RFC 5652 sec. 5.2 | `[ok]` | `tests/test_cms_load.py::test_detached_econtent_is_none` | M1 |
| `sd.load-signer-identifiers` | RFC 5652 sec. 5.3, 10.2.4 | `[ok]` | `tests/test_cms_load.py::test_sid_by_subject_key_identifier` | M1 |
| `sd.load-ber` | RFC 5652 sec. 5.3 (only SignedAttributes must be DER), X.690 8.1.3.6, 10.2 | `[ok]` | `tests/test_cms_load.py::test_indefinite_length_ber_loads` | M1 |
| `sd.load-version-rules` | RFC 5652 sec. 5.1, 5.3 (reported in `version_issue`, never corrected) | `[ok]` | `tests/test_cms_load.py::test_version_mismatch_is_reported_not_corrected` | M1 |
| `sd.load-bounded` | asn1core depth limit surfaced as `CmsError`; size and count limits still owed | `[part]` | `tests/test_cms_load.py::test_depth_and_size_bounded` | M1 |
| `sd.load-limits` | maximum input size, certificates, signers, attributes (owner sentence D6) | `[ ]` | `tests/test_cms_load.py::test_oversized_input_is_refused` (to be written) | M1 |
| `sd.load-estcacerts-base64` | RFC 8951 sec. 3.2.1 (EST body is base64 of the CMS, RFC 4648); a helper that decodes then loads | `[ ]` | `tests/test_cms_load.py::test_est_cacerts_body_loads` (to be written) | M1 |
| `sd.load-no-encapcontentinfo` | RFC 10002 sec. 4.1 says a Simple PKI Response has no EncapsulatedContentInfo, which RFC 5652 sec. 5.1 does not allow; decide whether to tolerate it | `[ ]` | `tests/test_cms_load.py::test_missing_encapcontentinfo_policy` (to be written) | M1 |
| `cms.dump()` | RFC 5652 sec. 3 | `[ ]` | `tests/test_obligations.py::test_dump` (to be written) | M1 |
| `sd.deps-none-third-party` | AGENTS invariant 4, PORTFOLIO self-sufficiency | `[ok]` | `tests/test_no_third_party_import.py::test_package_imports_with_asn1crypto_blocked` | M1 |
| `verify.signed_attrs_input` | RFC 5652 sec. 5.4 (explicit SET OF tag 0x31 replaces the IMPLICIT [0]), sec. 11.2 | `[ok]` | `tests/test_signed_attrs.py::test_explicit_set_tag_replaces_implicit_context_tag` | M2 |
| `verify.message_digest_attr` | RFC 5652 sec. 5.3, 11.1, 11.2 (content-type and message-digest present, single-valued) | `[ok]` | `tests/test_signed_attrs.py::test_message_digest_attr_must_be_single_valued` | M2 |
| `verify.same_digest_algorithm` | RFC 8933 sec. 3 (the digest of eContent and of signedAttrs use the same algorithm: a MUST, read 2026-11-13) | `[ok]` | `tests/test_verify.py::test_different_digest_algorithms_are_refused` | M2 |
| `verify.algorithm_protection` | RFC 6211 sec. 3.1 (a validator that supports the attribute MUST compare digestAlgorithm and signatureAlgorithm with the protected copies, modulo encoding, and fail on a difference; NULL and absent parameters compare equal here); RFC 8933 sec. 4 (originators SHOULD include it: its absence is the note `algorithm-protection-absent`, not a failure); the OID is as RFC 6211 sec. 2 prints it, see section 3 for errata 9144 and 9145 | `[ok]` | `tests/test_verify.py::test_algorithm_protection_mismatch_is_refused` | M2 |
| `verify.detached` | RFC 5652 sec. 5.2, 5.4 (digest over caller-supplied content) | `[ok]` | `tests/test_verify.py::test_detached_content_digest` | M2 |
| `verify.signer_selection` | RFC 5652 sec. 5.3, 10.2.4 (issuerAndSerialNumber or subjectKeyIdentifier) | `[ok]` | `tests/test_verify.py::test_signer_found_by_ski` | M2 |
| `verify.signature_check` | RFC 5652 sec. 5.6; RFC 5754 (SHA-2 identifiers), RFC 8419 (EdDSA), RFC 4056 (PSS), RFC 5753 sec. 2.1.1 (ECDSA); arithmetic through `sigwire[verify]`. Pinned: RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA P-256, Ed25519, and DSA from the RFC 4134 binaries. Missing: Ed448 (shake256-len digest), P-384/P-521 vectors, DSA keys whose parameters come from the issuer | `[part]` | `tests/test_verify.py::test_signature_is_over_retained_signed_attrs` | M2 |
| `verify.signed_attrs_der` | RFC 5652 sec. 5.3 (SignedAttributes MUST be DER): a signedAttrs that is indefinite-length or whose SET OF is out of order is refused, never re-encoded | `[ok]` | `tests/test_signed_attrs.py::test_digest_input_refuses_set_of_out_of_der_order` | M2 |
| `verify.attribute_placement` | RFC 5652 sec. 11.1, 11.2, RFC 6211 sec. 2 (content-type, message-digest, CMSAlgorithmProtection MUST NOT be unsigned; none may repeat or be multi-valued) | `[ok]` | `tests/test_verify.py::test_unsigned_attribute_that_must_be_signed_is_refused` | M2 |
| `verify.content_type_match` | RFC 5652 sec. 5.6, 11.1 (the content-type attribute equals eContentType) | `[ok]` | `tests/test_verify.py::test_content_type_attribute_must_match_econtent_type` | M2 |
| `verify.policy` | `sigwire.verify` policy passed through: DEFAULT refuses SHA-1, DSA and short RSA keys, LEGACY is opt-in; the result names the refused cell | `[ok]` | `tests/test_verify.py::test_default_policy_refuses_sha1_and_dsa_vectors` | M2 |
| `verify.pss_key_parameters` | RFC 4056 sec. 3 (signature PSS parameters against an id-RSASSA-PSS key's restrictions: hash, MGF, saltLength >=, trailer); the compare is written, no test builds an id-RSASSA-PSS certificate | `[ ]` | `tests/test_verify.py::test_pss_key_restrictions_are_enforced` (to be written) | M2 |
| `verify.ed448` | RFC 8419 sec. 3.1 (digestAlgorithm id-shake256-len with 512, message-digest over SHAKE256 with 64 output octets); code written, unpinned | `[ ]` | `tests/test_verify.py::test_ed448_signed_attributes` (to be written) | M2 |
| `verify.dsa_inherited_parameters` | RFC 3370 sec. 3.1 (a DSA key with absent parameters uses the issuer's): refused as `unsupported-key` until the chain gives the issuer | `[ ]` | `tests/test_verify.py::test_dsa_parameters_from_issuer` (to be written) | M2 |
| `verify.spki_reader` | PORTFOLIO.md section 9 item 15: the SubjectPublicKeyInfo is read by `asn1core.keys.parse_spki` (RFC 3279 sec. 2.3.1, RFC 5480 sec. 2.1.1 and 2.2, RFC 8410 sec. 3); what stays here is the PSS restriction (RFC 4056 sec. 3), the curves sigwire verifies, and DSA's Dss-Parms, which asn1core returns as `UnknownKey` | `[ok]` | `tests/test_verify.py::test_spki_reader_is_asn1cores` | M2 |
| `verify.cert_chain` | RFC 5652 sec. 5.6 leaves key validation to the profile: `verify()` asks `pkix.result.validate` (RFC 5280 sec. 6) with the SignedData's certificates as the pool. Purpose (extKeyUsage) is not checked yet | `[ok]` | `tests/test_verify.py::test_chain_decision_comes_from_pkix` | M2 |
| `verify.time` | RFC 5652 sec. 11.3 ¶15: "acceptance of a purported signing time is a matter of a recipient's discretion" (no MUST; this row's earlier wording said "untrusted unless a timestamp covers it", which is this library's choice and not the RFC's). The chain is validated at the caller's `at`; signing-time is the note `signing-time-not-used` | `[ok]` | `tests/test_verify.py::test_signing_time_is_not_trusted` | M2 |
| `ess.signing_certificate_v2()` | RFC 5035 sec. 3, 4 (RFC 2634 sec. 5.4.1 as inserted) | `[ ]` | `tests/test_obligations.py::test_signing_certificate_v2` (to be written) | M2 |
| `verify.verify()` | RFC 5652 sec. 5.6: every signer's signature (`verify_signer`) and then its certificate path through pkix; valid only when both hold, `chain-unsupported` when pkix cannot decide | `[ok]` | `tests/test_verify.py::test_chain_decision_comes_from_pkix`; `tests/test_verify.py::test_a_bad_signature_is_not_rescued_by_a_good_chain` | M2 |
| `policy.refuse_weak()` | design | `[ ]` | `tests/test_obligations.py::test_refuse_weak` (to be written) | M2 |
| `signer.build_signer_info()` | RFC 5652 sec. 5.3 | `[ ]` | `tests/test_obligations.py::test_build_signer_info` (to be written) | M3 |
| `verify.countersign()` | RFC 5652 sec. 11.4 | `[ ]` | `tests/test_obligations.py::test_countersign` (to be written) | M3 |
| `tsp.build_request()` | RFC 3161 sec. 2.4.1 | `[ ]` | `tests/test_obligations.py::test_build_request` (to be written) | M4 |
| `tsp.verify_token()` | RFC 3161 sec. 2.4.2, RFC 5816 (ESSCertIDv2 for SHA-2) | `[ ]` | `tests/test_obligations.py::test_verify_token` (to be written) | M4 |
| `tsp.messageimprint_match` | RFC 3161 sec. 2.4.2 (read before citing) | `[ ]` | `tests/test_tsp.py::test_messageimprint_must_match` (to be written) | M4 |
| `tsp.tsa_eku` | RFC 3161 sec. 2.3 (id-kp-timeStamping, critical; read before citing) | `[ ]` | `tests/test_tsp.py::test_tsa_certificate_needs_the_timestamping_eku` (to be written) | M4 |
| `envelope.decrypt()` | RFC 5652 sec. 6 | `[ ]` | `tests/test_obligations.py::test_decrypt` (to be written) | M5 |
| `sd.authenticode-container` | RFC 5652 sec. 5.2.1 (eContent is not an OCTET STRING; eContentType 1.3.6.1.4.1.311.2.1.4); consumer: pkgtrust R210, R212. The PE certificate table (R209) and the image hash (R211) are not this project's | `[ ]` | `tests/test_authenticode.py::test_pkcs7_signeddata_from_a_pe_certificate_table_loads` (to be written) | - |
| `sd.authenticode-signer-summary` | pkgtrust R212: leaf, chain as presented, code-signing EKU, TSA identity and time, no validity verdict | `[ ]` | `tests/test_authenticode.py::test_summary_never_says_valid` (to be written) | - |
| `sd.authenticode-countersignature` | pkgtrust R210: Microsoft counter-signature and RFC 3161 timestamp attributes present or absent (OIDs outside the RFC corpus: read the Microsoft document first) | `[ ]` | `tests/test_authenticode.py::test_counter_signature_presence_is_reported` (to be written) | - |
| `sd.rfc4134-corpus-more` | RFC 4134 sec. 4.1, 4.4, 4.5, 4.8, 4.9 and the enveloped, digested and encrypted examples | `[ ]` | `tests/test_cms_load.py::test_remaining_rfc4134_examples_load` (to be written) | M1 |
| `verify.chain_purpose` | RFC 5280 sec. 4.2.1.12 (extKeyUsage) and RFC 8550 sec. 4.4: whether the signer certificate may sign mail or content; `verify()` validates the path only (read before citing RFC 8550) | `[ ]` | `tests/test_verify.py::test_signer_purpose_is_checked` (to be written) | M3 |
| `verify.chain_revocation` | RFC 5280 sec. 6.1.3(a)(3) through `pkix.revocation.CrlChecker` built from the SignedData's own `crls` field (RFC 5652 sec. 5.1); today revocation is checked only when the caller passes a checker in `inputs` | `[ ]` | `tests/test_verify.py::test_crls_in_the_signed_data_feed_revocation` (to be written) | M3 |

### Round 3 (2026-11-13)

- `verify()` is signature plus a pkix chain, as PORTFOLIO.md section 9 item 15 decided once pkix's
  `result.path_walk` landed. pkix is the optional `chain` extra, imported lazily inside `verify()`
  like `sigwire[verify]`, so `cms.load` and the base install still need asn1core alone.
- `verify.time`: RFC 5652 sec. 11.3 read through rfclib. It imposes no requirement on the
  correctness of signing-time and leaves acceptance to the recipient; the row's old wording stated
  this library's choice as if it were the RFC's.
- `tests/test_cms_load.py::test_constructed_econtent_is_joined` built its fixture with
  `asn1core.decode(..., der=True)` over a constructed OCTET STRING, which asn1core now refuses under
  X.690 10.2 (its round-2 `constructed-string` rule). The fixture is BER by design and now decodes
  with `der=False`; the assertions are unchanged.

## 2. Milestones

- M1 load (done) and dump for SignedData. The round trip is retention, not re-encoding: every parsed object keeps `raw`, the bytes as they arrived, so a later row verifies over those. Samples are the RFC 4134 binaries
- M2 verify: digest, signature, ESS CertID, message digest attribute
- M3 signed properties, signing time and countersignature
- M4 timestamp request, response and token chain validation
- M5 EnvelopedData and AuthenticatedData, then the S-MIME wrapper
- M6 publication: 0.1.0 with an interop matrix against openssl smime

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 3161 carries 3 verified errata and is updated by RFC 5816, which adds the SHA-2 identifiers everyone actually uses.
- RFC 5035 carries 1 verified erratum and updates RFC 2634: a CertID built the 1999 way is SHA-1 bound.
- RFC 5652 carries 2 verified errata and is updated by RFC 8933 (algorithm identifier protection) and RFC 9629 (KEM recipients); RFC 8551 has no errata on file and is updated by RFC 9788 (header protection). Checked with rfclib on 2026-11-07.
- Rechecked 2026-11-13: RFC 5652 errata are 6250 (sec. 9.2, MAC not digest) and 6546 (sec. 12.1, editorial); RFC 8933 none; RFC 5816 none; RFC 5754 two editorial (2693, 4846); RFC 8419 one editorial (5869, a capital letter in an OID name); RFC 4134 one (1716, MIME headers of examples 4.8 and 4.9, outside the binaries used).
- RFC 8933 is narrower than the first-pass review said. Its MUST (sec. 3, text replacing RFC 5652 sec. 5.3, 5.4 and 5.6) is that the digest of eContent and the digest of signedAttrs use the same hash algorithm. Sec. 4 only says originators SHOULD include the CMSAlgorithmProtection attribute (RFC 6211). The row `verify.same_digest_algorithm` is the MUST; `verify.algorithm_protection` is a convention.
- Round 2 (2026-11-13), read with rfclib: RFC 5652 sec. 5.4 and 5.6 are unchanged by errata (6250 and 6546 touch sec. 9.2 and 12.1); RFC 8933 sec. 3 replaces sec. 5.3, 5.4 and 5.6 and has no errata; RFC 6211 (current, no verified errata) sec. 3.1 makes the comparison a MUST for a validator that supports the attribute. Its two errata, 9144 and 9145, are reported and unverified: both say the OID should be `1.2.840.113549.1.9.16.2.52` (under smime aa) and not the printed `1.2.840.113549.1.9.52`. The code accepts the printed OID only. The IANA smi-numbers registry would settle it; `primarysource iana` has the file only after `primarysource iana import smi-numbers`, which was not run here (it downloads). RFC 5753 sec. 2.1.1 requires the hash in ecdsa-with-SHAn to equal digestAlgorithm, RFC 4056 sec. 3 requires the PSS hashAlgorithm to equal the signedAttrs digest, and RFC 8419 sec. 3.1-3.2 fix the EdDSA digestAlgorithm; all three are enforced as `digest-algorithm-mismatch`. RFC 8419 sec. 3 never says outright what EdDSA signs; PureEdDSA signs the message, so the input is the DER signedAttrs themselves (not their digest), which `test_ed25519_signs_the_signed_attributes_themselves` pins with a signature made by `cryptography`.
- RFC 5272 is obsolete (by RFC 10002, 2026-07). RFC 8951 sec. 3.2.1, which EST cacerts follows, still says "as defined in [RFC5272]"; the same definition is now RFC 10002 sec. 4.1: a SignedData with no EncapsulatedContentInfo and no SignerInfo. RFC 5652 sec. 5.1 makes encapContentInfo mandatory, so real servers send id-data with no eContent (RFC 5652 sec. 5.2); `cms.load` takes that form and the missing-field variant is the row `sd.load-no-encapcontentinfo`.
- The "47 bytes" style of count in the first-pass review needs the same care here: RFC 4134 example 4.7 prints SEQUENCE length 915 in its dump but its binary says 916 (header 3082 0394); the binary is self-consistent and is what the fixture uses.
- asn1core gap found while loading: `decode(..., der=True)` accepts a definite-length constructed OCTET STRING, which X.690 10.2 does not allow in DER. `cms` refuses it itself for eContent, signature and SKI; the fix belongs in asn1core.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| an X.509 or PKI stack: certificate path building and validation belong to pkix; signature arithmetic comes through `sigwire[verify]` (sigprim is merged into it), not from a third-party package | `[no]` | a named document requires it |
| a mail client: this produces and consumes objects, RFC 8551 wrapping is the boundary | `[no]` | a named document requires it |
| business rules for any particular e-invoicing or e-delivery profile | `[no]` | a named document requires it |

## 5. Open questions

- how far the EnvelopedData recipient-info matrix extends: proposed answer, KeyTransRecipientInfo only at M5, the other four (RFC 5652 sec. 6.2.2-6.2.5) become `[no]` with a revisit condition; whether M5 belongs here at all is an owner decision, since decryption needs private-key operations and AES-CBC/GCM primitives that no project owns yet
- Authenticode (pkgtrust R209-R215): proposed split, this project owns the PKCS #7 container, signer info and attributes of any CMS blob (`.p7s`, Authenticode, Microsoft CTL, catalogs); pkix owns the chain decision; the PE certificate table, the Authenticode image hash and the Microsoft OIDs are pkgtrust or a later peauth project, and their specification is not in the RFC corpus. Bringing M1 forward for that consumer needs no wave change, bringing M2 does (two-project rule)
- acceptance for `policy.refuse_weak()` (Spec: design, placed on M2): proposed as 'verify() given a SignedData whose digest or signature algorithm is outside the policy allow list returns a Verification that names the refused algorithm and is not valid'; the row keeps its meaning until the owner accepts a sentence (D24)

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
