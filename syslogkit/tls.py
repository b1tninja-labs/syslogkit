"""TLS transport, profiles and cipher suites (RFC 5425, RFC 9662).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import ssl

__all__ = [
    "client_context",
]


def client_context(ca: bytes, profile: str) -> ssl.SSLContext:
    """Pending behaviour defined by RFC 5425 sec. 4, RFC 9662.

    Not implemented yet. See the ``tls.client_context()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("client_context() is not implemented: RFC 5425 sec. 4, RFC 9662")
