"""structured data elements and parameters (RFC 5424 sec. 6.3).

Reading of the SD-NAME grammar (erratum 6927, reported and not verified): the ABNF
says ``SD-NAME = 1*32PRINTUSASCII ; except '=', SP, ']', %d34`` and PRINTUSASCII already
excludes SP, so the comment's "SP" is redundant, and the erratum would also exclude
``[``. The RFC text stays normative: a name is 1 to 32 octets in %d33-126 other than
``=``, ``]`` and ``"`` (sec. 6.3.2 prose adds whitespace and control characters, which
%d33-126 already excludes). ``[`` is therefore *accepted* inside a name. Changing that
is a one-line edit to ``_BAD_NAME`` if the erratum is ever verified.

Policy decisions, each pinned by a test:

* A malformed element raises :class:`SdError`. RFC 5424 sec. 6.3 para 5 lets a collector
  ignore it but requires a relay to forward it unaltered, so a relay must not round-trip
  through this codec; ``SdError`` carries the offset so a caller can keep raw bytes.
* An unescaped ``]`` inside a quoted PARAM-VALUE is accepted on input (the closing quote
  delimits the value); it is always escaped on output.
* A backslash before anything but a quote, a backslash or ``]`` decodes as that backslash
  and that character (sec. 6.3.3 para 5). Re-encoding escapes the backslash, so the
  *value* round-trips while the original bytes need not.
* A PARAM-VALUE that is not valid UTF-8 raises :class:`SdError`.
* The same SD-ID twice raises (sec. 6.3.2 para 1); a PARAM-NAME may repeat.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

__all__ = [
    "SdElement",
    "SdError",
    "decode_sd",
    "decode_sd_bytes",
    "encode_sd",
]

_SP = 0x20
_QUOTE = 0x22
_BACKSLASH = 0x5C
_LBRACKET = 0x5B
_RBRACKET = 0x5D
_BAD_NAME = frozenset(b'="] ')  # '=', '"', ']' (sec. 6) and SP (sec. 6.3.2)
_MAX_NAME = 32
_DEFAULT_MAX_ELEMENTS = 1000


class SdError(ValueError):
    """Malformed STRUCTURED-DATA; ``offset`` is where in the input it was noticed."""

    def __init__(self, message: str, offset: int = 0) -> None:
        super().__init__(f"{message} (at offset {offset})")
        self.offset = offset


@dataclass(frozen=True)
class SdElement:
    """One SD-ELEMENT: an SD-ID and its ordered SD-PARAMs (a name may repeat)."""

    sd_id: str
    params: tuple[tuple[str, str], ...] = ()


def _check_name(name: str, what: str) -> None:
    raw = name.encode("utf-8")
    if not 1 <= len(raw) <= _MAX_NAME or len(raw) != len(name):
        raise SdError(f"{what} must be 1 to {_MAX_NAME} printable ASCII characters", 0)
    for byte in raw:
        if byte < 33 or byte > 126 or byte in _BAD_NAME:
            raise SdError(f"{what} contains a forbidden character", 0)


def _read_name(data: bytes, pos: int, stops: bytes, what: str) -> tuple[str, int]:
    start = pos
    n = len(data)
    while pos < n and data[pos] not in stops:
        byte = data[pos]
        if byte < 33 or byte > 126 or byte in _BAD_NAME:
            raise SdError(f"{what} contains a forbidden character", pos)
        pos += 1
        if pos - start > _MAX_NAME:
            raise SdError(f"{what} is longer than {_MAX_NAME}", start)
    if pos >= n:
        raise SdError("unterminated structured data element", pos)
    if pos == start:
        raise SdError(f"empty {what}", pos)
    return data[start:pos].decode("ascii"), pos


def _read_value(data: bytes, pos: int) -> tuple[str, int]:
    """Read a PARAM-VALUE after its opening quote; return it and the offset after the close."""
    n = len(data)
    out = bytearray()
    start = pos
    while True:
        nxt = pos
        while nxt < n and data[nxt] != _QUOTE and data[nxt] != _BACKSLASH:
            nxt += 1
        out += data[pos:nxt]
        if nxt >= n:
            raise SdError("unterminated parameter value", start)
        if data[nxt] == _QUOTE:
            pos = nxt + 1
            break
        if nxt + 1 >= n:
            raise SdError("unterminated parameter value", start)
        follower = data[nxt + 1]
        if follower in (_QUOTE, _BACKSLASH, _RBRACKET):
            out.append(follower)
        else:
            out += data[nxt : nxt + 2]  # invalid escape: kept as written (sec. 6.3.3 para 5)
        pos = nxt + 2
    try:
        return out.decode("utf-8"), pos
    except UnicodeDecodeError as error:
        raise SdError("parameter value is not valid UTF-8", start) from error


def decode_sd_bytes(
    data: bytes, offset: int = 0, *, max_elements: int = _DEFAULT_MAX_ELEMENTS
) -> tuple[tuple[SdElement, ...], int]:
    """Decode STRUCTURED-DATA from ``data`` at byte ``offset`` (RFC 5424 sec. 6.3).

    Returns the elements and the offset just past the field. ``-`` gives no elements.
    Elements must be adjacent: an SP after ``]`` ends the field (sec. 6.3.5 Example 3), so
    the caller finds the rest of the message at the returned offset.
    """
    n = len(data)
    pos = offset
    if pos >= n:
        raise SdError("missing STRUCTURED-DATA", pos)
    if data[pos] == 0x2D:  # NILVALUE
        return (), pos + 1
    elements: list[SdElement] = []
    seen: set[str] = set()
    while pos < n and data[pos] == _LBRACKET:
        if len(elements) >= max_elements:
            raise SdError(f"more than {max_elements} structured data elements", pos)
        sd_id, pos = _read_name(data, pos + 1, b" ]", "SD-ID")
        if sd_id in seen:
            raise SdError(f"SD-ID {sd_id!r} occurs more than once", pos)
        seen.add(sd_id)
        params: list[tuple[str, str]] = []
        while data[pos] == _SP:
            name, pos = _read_name(data, pos + 1, b"=", "PARAM-NAME")
            pos += 1  # the '='
            if pos >= n or data[pos] != _QUOTE:
                raise SdError("PARAM-VALUE must be quoted", pos)
            value, pos = _read_value(data, pos + 1)
            params.append((name, value))
            if pos >= n:
                raise SdError("unterminated structured data element", pos)
        pos += 1  # the ']' that ended the parameter loop
        elements.append(SdElement(sd_id, tuple(params)))
    if not elements:
        raise SdError("STRUCTURED-DATA is neither '-' nor an element", pos)
    return tuple(elements), pos


def decode_sd(
    text: str | bytes, offset: int = 0, *, max_elements: int = _DEFAULT_MAX_ELEMENTS
) -> tuple[tuple[SdElement, ...], int]:
    """Decode STRUCTURED-DATA (RFC 5424 sec. 6.3) from text; offsets count characters.

    Returns ``(elements, end)``. See :func:`decode_sd_bytes` for the byte form.
    """
    if isinstance(text, bytes):
        return decode_sd_bytes(text, offset, max_elements=max_elements)
    raw = text.encode("utf-8")
    byte_offset = len(text[:offset].encode("utf-8"))
    elements, end = decode_sd_bytes(raw, byte_offset, max_elements=max_elements)
    return elements, len(raw[:end].decode("utf-8"))


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def encode_sd(elements: Sequence[SdElement]) -> str:
    """Encode elements as STRUCTURED-DATA (RFC 5424 sec. 6.3); no elements give ``-``."""
    if not elements:
        return "-"
    seen: set[str] = set()
    parts: list[str] = []
    for element in elements:
        _check_name(element.sd_id, "SD-ID")
        if element.sd_id in seen:
            raise SdError(f"SD-ID {element.sd_id!r} occurs more than once", 0)
        seen.add(element.sd_id)
        pieces = [element.sd_id]
        for name, value in element.params:
            _check_name(name, "PARAM-NAME")
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as error:
                raise SdError("parameter value is not encodable as UTF-8", 0) from error
            pieces.append(f'{name}="{_escape(value)}"')
        parts.append("[" + " ".join(pieces) + "]")
    return "".join(parts)
