"""facility and severity with the names operators expect (RFC 5424 sec. 6.2.1).

The tables are RFC 5424 section 6.2.1 Table 1 and Table 2. Facility 4 and 10 are both
"security/authorization messages" in the RFC; errata 4967 and 6647 (both reported, not
verified) are about that duplicate and the missing note. Both entries are kept, because
senders in the field use both.
"""

from __future__ import annotations

__all__ = [
    "FACILITIES",
    "SEVERITIES",
    "PriError",
    "format_pri",
    "parse_pri",
]

FACILITIES: tuple[str, ...] = (
    "kernel messages",
    "user-level messages",
    "mail system",
    "system daemons",
    "security/authorization messages",
    "messages generated internally by syslogd",
    "line printer subsystem",
    "network news subsystem",
    "UUCP subsystem",
    "clock daemon",
    "security/authorization messages",
    "FTP daemon",
    "NTP subsystem",
    "log audit",
    "log alert",
    "clock daemon",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
)

SEVERITIES: tuple[str, ...] = (
    "Emergency",
    "Alert",
    "Critical",
    "Error",
    "Warning",
    "Notice",
    "Informational",
    "Debug",
)

_MAX_PRIVAL = 191  # RFC 5424 sec. 6: PRIVAL = 1*3DIGIT ; range 0 .. 191


class PriError(ValueError):
    """The PRI field is not valid RFC 5424 sec. 6 syntax."""


def parse_pri(data: bytes) -> tuple[int, int, int]:
    """Parse ``<PRIVAL>`` at the start of ``data`` (RFC 5424 sec. 6, sec. 6.2.1).

    Returns ``(facility, severity, consumed)``. ``PRIVAL = 1*3DIGIT`` so a leading zero
    (``<034>``) is syntactically valid in RFC 5424 and accepted here; RFC 3164
    forbade it and ``syslogkit.legacy`` enforces that instead.
    """
    if not data.startswith(b"<"):
        raise PriError("PRI must start with '<'")
    end = data.find(b">", 1, 5)
    if end < 0:
        raise PriError("PRI has no '>' within three digits")
    digits = data[1:end]
    if not 1 <= len(digits) <= 3 or not all(48 <= b <= 57 for b in digits):
        raise PriError("PRIVAL must be 1 to 3 ASCII digits")
    value = int(digits)
    if value > _MAX_PRIVAL:
        raise PriError(f"PRIVAL {value} is above 191")
    return value // 8, value % 8, end + 1


def format_pri(facility: int, severity: int) -> bytes:
    """Return ``<PRIVAL>`` for a facility (0-23) and severity (0-7), RFC 5424 sec. 6.2.1."""
    if not 0 <= facility <= 23:
        raise PriError(f"facility {facility} is outside 0..23")
    if not 0 <= severity <= 7:
        raise PriError(f"severity {severity} is outside 0..7")
    return b"<%d>" % (facility * 8 + severity)
