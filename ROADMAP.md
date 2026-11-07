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
| `cms.load()` | RFC 5652 sec. 3 | `[ ]` | `tests/test_obligations.py::test_load` (to be written) | M1 |
| `cms.dump()` | RFC 5652 sec. 3 | `[ ]` | `tests/test_obligations.py::test_dump` (to be written) | M1 |
| `signer.build_signer_info()` | RFC 5652 sec. 5.3 | `[ ]` | `tests/test_obligations.py::test_build_signer_info` (to be written) | M3 |
| `ess.signing_certificate_v2()` | RFC 5035 sec. 3 | `[ ]` | `tests/test_obligations.py::test_signing_certificate_v2` (to be written) | M2 |
| `verify.verify()` | RFC 5652 sec. 5.6 | `[ ]` | `tests/test_obligations.py::test_verify` (to be written) | M2 |
| `verify.countersign()` | RFC 5652 sec. 11.4 | `[ ]` | `tests/test_obligations.py::test_countersign` (to be written) | M3 |
| `envelope.decrypt()` | RFC 5652 sec. 6 | `[ ]` | `tests/test_obligations.py::test_decrypt` (to be written) | M5 |
| `tsp.build_request()` | RFC 3161 sec. 2.4.1 | `[ ]` | `tests/test_obligations.py::test_build_request` (to be written) | M4 |
| `tsp.verify_token()` | RFC 3161 sec. 2.4.2 | `[ ]` | `tests/test_obligations.py::test_verify_token` (to be written) | M4 |
| `policy.refuse_weak()` | design | `[ ]` | `tests/test_obligations.py::test_refuse_weak` (to be written) | M2 |

## 2. Milestones

- M1 load and dump for SignedData with byte-exact round trip on captured samples
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

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| an X.509 or PKI stack: certificate path building stays in cryptography | `[no]` | a named document requires it |
| a mail client: this produces and consumes objects, RFC 8551 wrapping is the boundary | `[no]` | a named document requires it |
| business rules for any particular e-invoicing or e-delivery profile | `[no]` | a named document requires it |

## 5. Open questions

- how far the EnvelopedData recipient-info matrix extends in a first release
- acceptance for `policy.refuse_weak()` (Spec: design, placed on M2): proposed as 'verify() given a SignedData whose digest or signature algorithm is outside the policy allow list returns a Verification that names the refused algorithm and is not valid'; the row keeps its meaning until the owner accepts a sentence (D24)

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
