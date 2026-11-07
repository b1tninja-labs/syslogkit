"""the 5424 message: PRI, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Message = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "format",
    "parse",
]


def parse(raw: bytes) -> Message:
    """Pending behaviour defined by RFC 5424 sec. 6.

    Not implemented yet. See the ``message.parse()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("parse() is not implemented: RFC 5424 sec. 6")


def format(msg: Message) -> bytes:
    """Pending behaviour defined by RFC 5424 sec. 6.

    Not implemented yet. See the ``message.format()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("format() is not implemented: RFC 5424 sec. 6")
