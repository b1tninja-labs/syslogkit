"""octet counting, non-transparent and the resync rules (RFC 6587).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "frame_octet_counted",
    "unframe",
]


def frame_octet_counted(msg: bytes) -> bytes:
    """Pending behaviour defined by RFC 6587.

    Not implemented yet. See the ``framing.frame_octet_counted()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("frame_octet_counted() is not implemented: RFC 6587")


def unframe(buffer: bytes) -> tuple:
    """Pending behaviour defined by RFC 6587.

    Not implemented yet. See the ``framing.unframe()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("unframe() is not implemented: RFC 6587")
