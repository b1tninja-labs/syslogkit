"""listener surface, drop counters, backpressure.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Receiver = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "listen_tls",
    "listen_udp",
]


async def listen_tls(host: str, port: int, context: ssl.SSLContext) -> Receiver:
    """Pending behaviour defined by RFC 5425 sec. 4, RFC 9662.

    Not implemented yet. See the ``receiver.listen_tls()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("listen_tls() is not implemented: RFC 5425 sec. 4, RFC 9662")


async def listen_udp(host: str, port: int) -> Receiver:
    """Pending behaviour defined by RFC 5426 sec. 3.

    Not implemented yet. See the ``receiver.listen_udp()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("listen_udp() is not implemented: RFC 5426 sec. 3")
