"""time stamp request and response, token validation (RFC 3161, RFC 5816).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    DateTime = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "build_request",
    "verify_token",
]


def build_request(message_imprint: bytes, nonce: int) -> bytes:
    """Pending behaviour defined by RFC 3161 sec. 2.4.1.

    Not implemented yet. See the ``tsp.build_request()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("build_request() is not implemented: RFC 3161 sec. 2.4.1")


def verify_token(token: bytes, request: bytes, roots: list) -> DateTime:
    """Pending behaviour defined by RFC 3161 sec. 2.4.2.

    Not implemented yet. See the ``tsp.verify_token()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify_token() is not implemented: RFC 3161 sec. 2.4.2")
