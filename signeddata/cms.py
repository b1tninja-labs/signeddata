"""content info, signed data and the digested and encrypted variants (RFC 5652).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ContentInfo = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "dump",
    "load",
]


def load(raw: bytes) -> ContentInfo:
    """Pending behaviour defined by RFC 5652.

    Not implemented yet. See the ``cms.load()`` row in ROADMAP.md; this stub raises on
    purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("load() is not implemented: RFC 5652")


def dump(info: ContentInfo) -> bytes:
    """Pending behaviour defined by RFC 5652.

    Not implemented yet. See the ``cms.dump()`` row in ROADMAP.md; this stub raises on
    purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("dump() is not implemented: RFC 5652")
