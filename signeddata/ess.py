"""signing-certificate and CertID with algorithm agility (RFC 2634, RFC 5035).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Attribute = Any  # placeholder: give it a real type in the milestone that needs it
    Certificate = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "signing_certificate_v2",
]


def signing_certificate_v2(cert: Certificate) -> Attribute:
    """Pending behaviour defined by RFC 5035 sec. 3.

    Not implemented yet. See the ``ess.signing_certificate_v2()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("signing_certificate_v2() is not implemented: RFC 5035 sec. 3")
