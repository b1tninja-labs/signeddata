# signeddata

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha.** `cms.load` reads a CMS SignedData (BER or DER) on asn1core and keeps every parsed slice, including
the certificates-only form that EST `/cacerts` returns (`cms.certificates_only`); it verifies nothing. Everything else
still raises `NotImplementedError`, and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

**Dependencies.** One, `asn1core`, this workspace's own ASN.1 codec, because CMS is signed DER and the codec has to keep
the bytes it parsed. It is not on an index yet, so it resolves from the sibling checkout. No third-party package:
`asn1crypto` is not used, signature arithmetic comes from `sigwire[verify]` (a strict seam over `cryptography`, the optional `verify` extra), and path validation from `pkix`.

signeddata -- CMS and S-MIME that can actually verify

CMS, the format people still call PKCS number 7, is everywhere: S-MIME mail, European e-invoicing, e-delivery envelopes, firmware manifests, contract signatures. cryptography ships a narrow PKCS7 writer, and the rest of the Python field is abandoned (smime 0.0.5, 2019-07-23), a name squat on an unrelated argument parser (pkcs7 0.1.2, 2017-03-23) or a bare ASN.1 toolkit with no CMS process rules (asn1crypto 1.5.1, 2022-03-15). Countersignatures, signed properties, ESS signing-certificate-v2 and timestamp tokens cannot be verified in Python today, which is why every project that needs them shells out to openssl smime.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| cryptography | current | - | a PKCS7 writer with no countersignature, no ESS, no verify of arbitrary signers |
| smime | 0.0.5 | 2019-07-23 | abandoned before S-MIME v4 |
| asn1crypto | 1.5.1 | 2022-03-15 | ASN.1 toolkit: definitions without process rules |
| pkcs7, cms | 0.1.2, 0.0.2 | 2017-03-23 | unrelated projects holding the obvious names |

What this project intends to add:

- verify arbitrary SignedData with signed properties, message digest and ESS CertID checks
- countersignatures, which is where long term validity actually comes from
- timestamp token creation and validation as a first-class path (RFC 3161)
- EnvelopedData decryption across key transport and password based recipient infos
- an algorithm policy object so a verifier can refuse SHA-1 instead of accepting it silently

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 5652 | Internet Standard | 2009-09 | CMS: the content types and every attribute that rides on them |
| RFC 8551 | Proposed Standard | 2019-04 | S-MIME version 4: how CMS travels in mail |
| RFC 2634 | Proposed Standard | 1999-06 | Enhanced Security Services attributes |
| RFC 5035 | Proposed Standard | 2007-08 | CertID algorithm agility, replacing the SHA-1 binding |
| RFC 3161 | Proposed Standard | 2001-08 | TSP: timestamp requests and the token that outlives the signature |
| RFC 3370 | Proposed Standard | 2002-09 | CMS algorithm bindings: AES-CBC, HMAC, RSA-OAEP |
| RFC 9044 | Proposed Standard | 2021-06 | AES-GMAC with CMS |
| RFC 8702 | Proposed Standard | 2020-01 | SHAKE one-way functions in CMS |
| RFC 8933 | Proposed Standard | 2020-10 | algorithm identifier protection: one digest algorithm for content and attributes |
| RFC 5816 | Proposed Standard | 2010-04 | ESSCertIDv2 in timestamp tokens, updating RFC 3161 |
| RFC 5754 | Proposed Standard | 2010-01 | SHA-2 in CMS, updating RFC 3370 |
| RFC 8419 | Proposed Standard | 2018-08 | EdDSA signatures in CMS |
| RFC 4134 | Informational | 2005-07 | example messages, the source of the test binaries |

### Errata watch

- RFC 3161 carries 3 verified errata and is updated by RFC 5816, which adds the SHA-2 identifiers everyone actually uses.
- RFC 5035 carries 1 verified erratum and updates RFC 2634: a CertID built the 1999 way is SHA-1 bound.
- RFC 5652 carries 2 verified errata and is updated by RFC 8933 (algorithm identifier protection) and RFC 9629 (KEM recipients); RFC 8551 has no errata on file and is updated by RFC 9788 (header protection). Checked with rfclib on 2026-11-07.

## Module layout

| Module | Responsibility |
|---|---|
| `cms` | content info, signed data and the digested and encrypted variants (RFC 5652) |
| `signer` | SignerInfo, signed and unsigned attributes, countersignature (RFC 5652) |
| `ess` | signing-certificate and CertID with algorithm agility (RFC 2634, RFC 5035) |
| `verify` | digest and signature checks plus algorithm policy enforcement (RFC 3370) |
| `envelope` | EnvelopedData and AuthenticatedData recipient handling (RFC 5652, RFC 9044) |
| `tsp` | time stamp request and response, token validation (RFC 3161, RFC 5816) |
| `smime` | the mail facing wrapper and its protection rules (RFC 8551) |
| `policy` | the explicit allow list every verifier consults |

## What it does not do

- an X.509 or PKI stack: certificate path building and validation belong to pkix, and signature arithmetic comes through sigwire[verify]
- a mail client: this produces and consumes objects, RFC 8551 wrapping is the boundary
- business rules for any particular e-invoicing or e-delivery profile



## Why this project has a runtime dependency

This project breaks the portfolio zero-dependency rule deliberately. DER is not something to re-derive per project, and a half-written ASN.1 parser inside a signature verifier is exactly the bug class this library exists to remove.

Declared as a floor with no ceiling: the application that installs this library resolves the final set, and a ceiling inside a library guarantees a conflict the first time something else needs a newer line.
## Install

```bash
git clone https://github.com/b1tninja/signeddata.git
cd signeddata
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy signeddata tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
