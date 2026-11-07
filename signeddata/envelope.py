"""EnvelopedData and AuthenticatedData recipient handling (RFC 5652, RFC 9044).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ContentInfo = Any  # placeholder: give it a real type in the milestone that needs it
    PrivateKey = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decrypt",
]


def decrypt(info: ContentInfo, key: PrivateKey) -> bytes:
    """Pending behaviour defined by RFC 5652 sec. 6.

    Not implemented yet. See the ``envelope.decrypt()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decrypt() is not implemented: RFC 5652 sec. 6")
