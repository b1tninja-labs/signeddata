"""digest and signature checks plus algorithm policy enforcement (RFC 3370).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ContentInfo = Any  # placeholder: give it a real type in the milestone that needs it
    TrustStore = Any  # placeholder: give it a real type in the milestone that needs it
    Verification = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "countersign",
    "verify",
]


def verify(info: ContentInfo, content: bytes, store: TrustStore) -> Verification:
    """Pending behaviour defined by RFC 5652 sec. 5.6.

    Not implemented yet. See the ``verify.verify()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify() is not implemented: RFC 5652 sec. 5.6")


def countersign(info: ContentInfo, signer: int) -> ContentInfo:
    """Pending behaviour defined by RFC 5652 sec. 11.4.

    Not implemented yet. See the ``verify.countersign()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("countersign() is not implemented: RFC 5652 sec. 11.4")
