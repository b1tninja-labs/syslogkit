"""RFC 3164 tolerance, labelled as compatibility rather than correctness.

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
    "parse_3164",
]


def parse_3164(raw: bytes) -> Message:
    """Pending behaviour defined by RFC 3164.

    Not implemented yet. See the ``legacy.parse_3164()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("parse_3164() is not implemented: RFC 3164")
