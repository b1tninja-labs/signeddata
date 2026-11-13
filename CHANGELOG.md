# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- `cms.load`, `cms.parse_content_info` and `cms.certificates_only`: SignedData read on asn1core with every slice retained, BER or DER, certificates-only form included; the RFC 4134 binaries are the test corpus.

- `verify.verify_signer`, `verify.verify_signatures` and `verify.signed_attrs_digest_input`: the M2 verify steps (signer selection, message-digest and content-type attributes, the RFC 8933 same-digest rule, RFC 6211 algorithm protection, RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA, Ed25519 and DSA signatures) through the optional `sigwire[verify]` extra. The chain decision is still pkix's; `verify.verify` stays a stub.

### Changed

- The runtime dependency `asn1crypto` is removed (it was never imported); `asn1core` is the one dependency, resolved from the sibling checkout.
- The non-goal "certificate path building stays in cryptography" now says pkix and sigprim.
- ROADMAP rows split, and added for RFC 8933, RFC 5816, RFC 5754, RFC 8419 and the Authenticode consumer (pkgtrust R209-R215).

Everything except `cms.load` is still a typed stub that raises `NotImplementedError`; [ROADMAP.md](ROADMAP.md) lists what has to happen first.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for signeddata.
- `signeddata.apps` namespace reserved for composition that is not protocol behaviour.
