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

Added to the spine 2026-11-13 (read with rfclib, sections named):

| Document | Status | Errata | What this project takes from it |
|---|---|---|---|
| RFC 6211 | Proposed Standard, current | 0 verified, 2 reported (9144, 9145: the OID arc) | sec. 2 CMSAlgorithmProtection (signed attribute, one value, one instance), sec. 3.1 the MUST comparison; code accepts the OID the text prints, 1.2.840.113549.1.9.52 |
| RFC 4056 | Proposed Standard, current | 1 verified, not on sec. 3 | sec. 3: PSS hashAlgorithm equals the signedAttrs digest; the key-parameter comparison |
| RFC 5753 | Informational, current | 1 verified, not on sec. 2.1 | sec. 2.1.1: ecdsa-with-SHAn hash equals digestAlgorithm; signature is DER ECDSA-Sig-Value |
| RFC 5480 | Proposed Standard, current | 2 verified, not on sec. 2.1 | sec. 2.1.1 id-ecPublicKey, sec. 2.1.1.1 named curve OIDs (P-256, P-384, P-521) |
| RFC 8017 | Informational, current | 1 verified on A.2.3 (not read for this use) | appendix A.2.3 RSASSA-PSS-params and defaults, B.2.1 id-mgf1 |
| RFC 6211 text vs IANA | open | | whether the registry arc is smime(16) aa(2) 52: not checked, `primarysource iana import smi-numbers` downloads it |

Not yet in the spine, to check before use: RFC 5756 (RSA-PSS in CMS, updates 4056), RFC 5758 (ECDSA with SHA-2 OIDs; RFC 5754 sec. 3.3 repeats them), RFC 5911 (CMS ASN.1 module).

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
