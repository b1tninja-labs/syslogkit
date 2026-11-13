"""the 5424 message: PRI, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, STRUCTURED-DATA, MSG.

Policy decisions, each pinned by a test:

* NILVALUE fields parse to ``None``; ``format`` writes ``-`` for ``None`` and refuses a
  field whose text is literally ``-`` (it would parse back as ``None``).
* TIMESTAMP is parsed by a strict ABNF-shaped matcher, never ``datetime.fromisoformat``
  (which accepts lowercase ``t``/``z``, week dates and more). Seconds ``60`` are refused
  (sec. 6.2.3: leap seconds MUST NOT be used). Fractions are kept as microseconds; ``format``
  writes the shortest fraction that preserves them (``.003``, ``.000003``), so the number
  of digits the sender used is not preserved.
* MSG: a UTF-8 BOM followed by valid UTF-8 sets ``msg_is_utf8`` and the BOM is not kept in
  ``msg``. A BOM followed by invalid UTF-8 is kept verbatim (BOM included) with
  ``msg_is_utf8`` False, because a relay must not lose octets.
* A malformed STRUCTURED-DATA makes the whole message raise :class:`MessageError`; a
  relay that must forward it unaltered should forward the original bytes (sec. 6.3 para 5).
* A version above 1 is parsed and returned (``version`` says so); RFC 5424 defines only 1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone

from .pri import PriError, format_pri, parse_pri
from .sd import SdElement, SdError, decode_sd_bytes, encode_sd

__all__ = [
    "BOM",
    "MessageError",
    "SyslogMessage",
    "format",
    "parse",
    "parse_timestamp",
]

BOM = b"\xef\xbb\xbf"
_SP = 0x20
_TIMESTAMP = re.compile(
    rb"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    rb"(?:\.([0-9]{1,6}))?(Z|[+-][0-9]{2}:[0-9]{2})"
)
_LIMITS = {"hostname": 255, "app_name": 48, "procid": 128, "msgid": 32}


class MessageError(ValueError):
    """The bytes are not a valid RFC 5424 SYSLOG-MSG (or the message cannot be formatted)."""


@dataclass(frozen=True)
class SyslogMessage:
    """A parsed RFC 5424 message. ``None`` stands for the NILVALUE."""

    facility: int
    severity: int
    timestamp: datetime | None = None
    hostname: str | None = None
    app_name: str | None = None
    procid: str | None = None
    msgid: str | None = None
    sd: tuple[SdElement, ...] = ()
    msg: bytes = b""
    msg_is_utf8: bool = False
    version: int = field(default=1)

    @property
    def text(self) -> str:
        """MSG decoded as UTF-8, undecodable octets replaced (display only)."""
        return self.msg.decode("utf-8", errors="replace")


def parse_timestamp(field_bytes: bytes) -> datetime | None:
    """Parse a TIMESTAMP field (RFC 5424 sec. 6.2.3); ``-`` gives ``None``."""
    if field_bytes == b"-":
        return None
    match = _TIMESTAMP.fullmatch(field_bytes)
    if match is None:
        raise MessageError("TIMESTAMP does not match RFC 5424 sec. 6.2.3")
    year, month, day, hour, minute, second, frac, offset = match.groups()
    if int(second) > 59:
        raise MessageError("TIMESTAMP seconds above 59 (leap seconds MUST NOT be used)")
    if int(hour) > 23 or int(minute) > 59:
        raise MessageError("TIMESTAMP hour or minute out of range")
    if offset == b"Z":
        tz = UTC
    else:
        off_h, off_m = int(offset[1:3]), int(offset[4:6])
        if off_h > 23 or off_m > 59:
            raise MessageError("TIME-OFFSET out of range")
        delta = timedelta(hours=off_h, minutes=off_m)
        tz = timezone(-delta if offset[0:1] == b"-" else delta)
    micro = int(frac.ljust(6, b"0")) if frac else 0
    try:
        return datetime(
            int(year), int(month), int(day), int(hour), int(minute), int(second), micro, tz
        )
    except ValueError as error:
        raise MessageError(f"TIMESTAMP is not a real date: {error}") from error


def _format_timestamp(stamp: datetime | None) -> bytes:
    if stamp is None:
        return b"-"
    offset = stamp.utcoffset()
    if stamp.tzinfo is None or offset is None:
        raise MessageError("TIMESTAMP needs a timezone offset (RFC 5424 sec. 6.2.3)")
    if stamp.year < 1000:
        raise MessageError("TIMESTAMP year must have four digits")
    text = stamp.strftime("%Y-%m-%dT%H:%M:%S")
    if stamp.microsecond:
        text += "." + f"{stamp.microsecond:06d}".rstrip("0")
    total = int(offset.total_seconds())
    if total % 60:
        raise MessageError("TIME-OFFSET must be whole minutes")
    if total == 0:
        return (text + "Z").encode("ascii")
    sign = "+" if total > 0 else "-"
    hours, minutes = divmod(abs(total) // 60, 60)
    if hours > 23:
        raise MessageError("TIME-OFFSET out of range")
    return f"{text}{sign}{hours:02d}:{minutes:02d}".encode("ascii")


def _header_field(raw: bytes, name: str) -> str | None:
    if raw == b"-":
        return None
    if not raw or len(raw) > _LIMITS[name]:
        raise MessageError(f"{name} must be 1 to {_LIMITS[name]} octets")
    if any(b < 33 or b > 126 for b in raw):
        raise MessageError(f"{name} must be printable US-ASCII")
    return raw.decode("ascii")


def parse(raw: bytes) -> SyslogMessage:
    """Parse one RFC 5424 SYSLOG-MSG (RFC 5424 sec. 6, sec. 6.5)."""
    try:
        facility, severity, pos = parse_pri(raw)
    except PriError as error:
        raise MessageError(str(error)) from error
    end = pos
    while end < len(raw) and 48 <= raw[end] <= 57:
        end += 1
    digits = raw[pos:end]
    if not 1 <= len(digits) <= 3 or digits[0] == 48:
        raise MessageError("VERSION must be a nonzero digit followed by up to two digits")
    version = int(digits)
    pos = end
    values: list[bytes] = []
    for _ in range(5):
        if pos >= len(raw) or raw[pos] != _SP:
            raise MessageError("HEADER is truncated")
        pos += 1
        stop = raw.find(b" ", pos)
        if stop < 0:
            stop = len(raw)
        values.append(raw[pos:stop])
        pos = stop
    timestamp = parse_timestamp(values[0])
    if pos >= len(raw) or raw[pos] != _SP:
        raise MessageError("STRUCTURED-DATA is missing")
    try:
        elements, pos = decode_sd_bytes(raw, pos + 1)
    except SdError as error:
        raise MessageError(f"STRUCTURED-DATA: {error}") from error
    if pos == len(raw):
        body = b""
    elif raw[pos] == _SP:
        body = raw[pos + 1 :]
    else:
        raise MessageError("STRUCTURED-DATA must be followed by SP or the end of the message")
    is_utf8 = False
    if body.startswith(BOM):
        try:
            body[3:].decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            body, is_utf8 = body[3:], True
    return SyslogMessage(
        facility=facility,
        severity=severity,
        version=version,
        timestamp=timestamp,
        hostname=_header_field(values[1], "hostname"),
        app_name=_header_field(values[2], "app_name"),
        procid=_header_field(values[3], "procid"),
        msgid=_header_field(values[4], "msgid"),
        sd=elements,
        msg=body,
        msg_is_utf8=is_utf8,
    )


def _format_field(value: str | None, name: str) -> bytes:
    if value is None:
        return b"-"
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise MessageError(f"{name} must be printable US-ASCII") from error
    if raw == b"-":
        raise MessageError(f"{name} of '-' would read back as the NILVALUE; use None")
    if not raw or len(raw) > _LIMITS[name] or any(b < 33 or b > 126 for b in raw):
        raise MessageError(f"{name} must be 1 to {_LIMITS[name]} printable US-ASCII octets")
    return raw


def format(msg: SyslogMessage) -> bytes:
    """Serialise a message to RFC 5424 SYSLOG-MSG bytes (RFC 5424 sec. 6)."""
    if not 1 <= msg.version <= 999:
        raise MessageError("version must be 1 to 999")
    try:
        head = format_pri(msg.facility, msg.severity)
        structured = encode_sd(msg.sd).encode("utf-8")
    except (PriError, SdError) as error:
        raise MessageError(str(error)) from error
    if msg.msg_is_utf8:
        try:
            msg.msg.decode("utf-8")
        except UnicodeDecodeError as error:
            raise MessageError("msg_is_utf8 but msg is not valid UTF-8") from error
        body = BOM + msg.msg
    else:
        body = msg.msg
    out = b"%s%d %s %s %s %s %s %s" % (
        head,
        msg.version,
        _format_timestamp(msg.timestamp),
        _format_field(msg.hostname, "hostname"),
        _format_field(msg.app_name, "app_name"),
        _format_field(msg.procid, "procid"),
        _format_field(msg.msgid, "msgid"),
        structured,
    )
    if body:
        out += b" " + body
    return out
