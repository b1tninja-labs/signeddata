# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 5652 | Internet Standard | 2009-09 | 2026-11-05 |
| RFC 8551 | Proposed Standard | 2019-04 | 2026-11-05 |
| RFC 2634 | Proposed Standard | 1999-06 | 2026-11-05 |
| RFC 5035 | Proposed Standard | 2007-08 | 2026-11-05 |
| RFC 3161 | Proposed Standard | 2001-08 | 2026-11-05 |
| RFC 3370 | Proposed Standard | 2002-09 | 2026-11-05 |
| RFC 9044 | Proposed Standard | 2021-06 | 2026-11-05 |
| RFC 8702 | Proposed Standard | 2020-01 | 2026-11-05 |
| RFC 8933 | Proposed Standard | 2020-10 | 2026-11-13 |
| RFC 5816 | Proposed Standard | 2010-04 | 2026-11-13 |
| RFC 5754 | Proposed Standard | 2010-01 | 2026-11-13 |
| RFC 8419 | Proposed Standard | 2018-08 | 2026-11-13 |
| RFC 4134 | Informational | 2005-07 | 2026-11-13 |
| RFC 10002 | Proposed Standard | 2026-07 | 2026-11-13 |
| RFC 8951 | Proposed Standard | 2020-11 | 2026-11-13 |

Status detail, read with rfclib on 2026-11-13:

| Document | Relations | Errata | What this project takes from it |
|---|---|---|---|
| RFC 5652 | STD 70, obsoletes RFC 3852, updated by RFC 8933 and RFC 9629 | 2 verified | sec. 3 ContentInfo, 5.1-5.4 SignedData, 10.2 useful types; sec. 5.2.1 names the PKCS #7 and Authenticode content difference |
| RFC 8933 | updates RFC 5652 | none | sec. 3 same digest algorithm for eContent and signedAttrs (MUST); sec. 4 CMSAlgorithmProtection (SHOULD, originator) |
| RFC 5816 | updates RFC 3161 | none | ESSCertIDv2 so a timestamp token can name a SHA-2 certificate hash |
| RFC 5754 | updates RFC 3370 | 2 verified, editorial | SHA-2 identifiers in CMS; RFC 9919 (revokekit) points at its sec. 2.2 |
| RFC 8419 | none | 1 verified, editorial | EdDSA in CMS: Ed25519 and Ed448 identifiers, PureEdDSA only |
| RFC 4134 | informational | 1 verified (examples 4.8, 4.9 headers) | the binaries in `tests/fixtures/rfc4134/`: sec. 4.2, 4.3, 4.6, 4.7, 4.10, 4.11 |
| RFC 10002 | obsoletes RFC 5272 | none verified (2 on file) | sec. 4.1 Simple PKI Response, the certs-only SignedData that EST cacerts returns |
| RFC 8951 | updates RFC 7030 | none | sec. 3.2.1 EST cacerts body is the Simple PKI Response in base64 |
| RFC 5272 | obsolete, by RFC 10002 | 5 verified | cited by RFC 8951 and RFC 7030; read RFC 10002 instead |

Not yet in the spine, to check before use: RFC 4056 and RFC 5756 (RSA-PSS in CMS), RFC 5758 (ECDSA with SHA-2), RFC 5911 (CMS ASN.1 module), RFC 6211 (CMSAlgorithmProtection).

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
