"""RFC 3164 tolerance, labelled as compatibility rather than correctness.

RFC 3164 is Informational and obsolete (RFC 5424 replaced it); it describes observed
behaviour, not a grammar, and sec. 4.1 itself says any packet to port 514 is a syslog
message. :func:`parse_3164` therefore never refuses a packet: it extracts what sec. 4.1 and
sec. 4.3 describe and reports what it could not find. Dialects beyond that are a non-goal.

What is recognised:

* PRI (sec. 4.1.1): ``<`` and one to three digits and ``>``, no leading zero except the
  single priority ``0``, at most 191. Otherwise there is no PRI and, per sec. 4.3.3, the
  whole packet is CONTENT with priority 13 (facility 1, severity 5) assumed, flagged by
  ``pri_present=False``.
* TIMESTAMP (sec. 4.1.2): ``Mmm dd hh:mm:ss`` with a space-padded day (a zero-padded day
  is tolerated) followed by SP. The year and zone are not in the packet, so none is
  invented: ``LegacyTimestamp`` holds only what was sent. If there is no valid timestamp
  the rest is CONTENT (sec. 4.3.2).
* HOSTNAME: the next token, unless that token ends in ``:`` or contains ``[`` (then it is
  a TAG and there is no hostname).
* TAG (sec. 4.1.3): leading alphanumerics up to 32 characters, then an optional
  ``[pid]``, then ``:``. A message with no such terminator has no TAG.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "LegacyMessage",
    "LegacyTimestamp",
    "parse_3164",
]

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_PRI = re.compile(rb"<(0|[1-9][0-9]{0,2})>")
_TIMESTAMP = re.compile(
    rb"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([ 0-9][0-9]) "
    rb"([0-9]{2}):([0-9]{2}):([0-9]{2}) "
)
_TAG = re.compile(rb"([A-Za-z0-9]{1,32})(?:\[([^\]\s]{0,32})\])?:")
_DEFAULT_PRIORITY = 13  # RFC 3164 sec. 4.3.3
_MAX_PACKET = 1024  # RFC 3164 sec. 4.1


@dataclass(frozen=True)
class LegacyTimestamp:
    """The ``Mmm dd hh:mm:ss`` of RFC 3164 sec. 4.1.2: no year, no zone."""

    month: int
    day: int
    hour: int
    minute: int
    second: int


@dataclass(frozen=True)
class LegacyMessage:
    """What a tolerant RFC 3164 reading found. This is not an RFC 5424 message."""

    facility: int
    severity: int
    pri_present: bool
    timestamp: LegacyTimestamp | None
    hostname: str | None
    tag: str | None
    pid: str | None
    content: bytes
    oversize: bool
    raw: bytes


def parse_3164(raw: bytes) -> LegacyMessage:
    """Tolerantly parse an RFC 3164 packet (RFC 3164 sec. 4.1, sec. 4.3); never refuses."""
    pos = 0
    pri_present = False
    priority = _DEFAULT_PRIORITY
    match = _PRI.match(raw)
    if match is not None and int(match.group(1)) <= 191:
        priority = int(match.group(1))
        pri_present = True
        pos = match.end()
    timestamp = None
    hostname = None
    tag = None
    pid = None
    if pri_present:
        stamp = _TIMESTAMP.match(raw, pos)
        if stamp is not None:
            month = _MONTHS.index(stamp.group(1).decode("ascii")) + 1
            day = int(stamp.group(2))
            hour, minute, second = (int(stamp.group(i)) for i in (3, 4, 5))
            if 1 <= day <= 31 and hour <= 23 and minute <= 59 and second <= 59:
                timestamp = LegacyTimestamp(month, day, hour, minute, second)
                pos = stamp.end()
        if timestamp is not None:
            stop = raw.find(b" ", pos)
            token = raw[pos : stop if stop >= 0 else len(raw)]
            if stop >= 0 and token and not token.endswith(b":") and b"[" not in token:
                hostname = token.decode("latin-1")
                pos = stop + 1
            found = _TAG.match(raw, pos)
            if found is not None:
                tag = found.group(1).decode("ascii")
                pid = found.group(2).decode("ascii") if found.group(2) is not None else None
                pos = found.end()
                if raw[pos : pos + 1] == b" ":
                    pos += 1
    return LegacyMessage(
        facility=priority // 8,
        severity=priority % 8,
        pri_present=pri_present,
        timestamp=timestamp,
        hostname=hostname,
        tag=tag,
        pid=pid,
        content=raw[pos:],
        oversize=len(raw) > _MAX_PACKET,
        raw=raw,
    )
