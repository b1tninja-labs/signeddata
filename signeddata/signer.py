"""SignerInfo, signed and unsigned attributes, countersignature (RFC 5652).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    SignerInfo = Any  # placeholder: give it a real type in the milestone that needs it
    SigningKey = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "build_signer_info",
]


def build_signer_info(key: SigningKey, certs: list, attrs: list) -> SignerInfo:
    """Pending behaviour defined by RFC 5652 sec. 5.3.

    Not implemented yet. See the ``signer.build_signer_info()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("build_signer_info() is not implemented: RFC 5652 sec. 5.3")
