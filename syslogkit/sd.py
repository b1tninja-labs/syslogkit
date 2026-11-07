"""structured data elements, parameters and the registered SD-IDs (RFC 5424).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "decode_sd",
    "encode_sd",
]


def encode_sd(elements: list) -> str:
    """Pending behaviour defined by RFC 5424 sec. 6.3.

    Not implemented yet. See the ``sd.encode_sd()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_sd() is not implemented: RFC 5424 sec. 6.3")


def decode_sd(text: str) -> list:
    """Pending behaviour defined by RFC 5424 sec. 6.3.

    Not implemented yet. See the ``sd.decode_sd()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_sd() is not implemented: RFC 5424 sec. 6.3")
