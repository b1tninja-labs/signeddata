"""signeddata -- CMS and S-MIME that can actually verify.

CMS, the format people still call PKCS number 7, is everywhere: S-MIME mail, European
e-invoicing, e-delivery envelopes, firmware manifests, contract signatures. cryptography
ships a narrow PKCS7 writer, and the rest of the Python field is abandoned (smime 0.0.5,
2019-07-23), a name squat on an unrelated argument parser (pkcs7 0.1.2, 2017-03-23) or a bare
ASN.1 toolkit with no CMS process rules (asn1crypto 1.5.1, 2022-03-15).
"""

from __future__ import annotations

from . import apps, cli, cms, envelope, ess, policy, signer, smime, tsp, verify
from .cms import dump, load
from .envelope import decrypt
from .ess import signing_certificate_v2
from .policy import refuse_weak
from .signer import build_signer_info
from .tsp import build_request, verify_token
from .verify import countersign

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "apps",
    "build_request",
    "build_signer_info",
    "cli",
    "cms",
    "countersign",
    "decrypt",
    "dump",
    "envelope",
    "ess",
    "load",
    "policy",
    "refuse_weak",
    "signer",
    "signing_certificate_v2",
    "smime",
    "tsp",
    "verify",
    "verify_token",
]
