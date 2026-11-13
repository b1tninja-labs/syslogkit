"""the mandatory transport (RFC 5426): sizes and the one-message-per-datagram rule.

Section 3.2 of RFC 5426: a message may be up to 65535 octets minus the UDP header (and,
on IPv4, minus the IP header); IPv4 receivers MUST accept 480 octets, IPv6 receivers 1180,
and all receivers SHOULD accept 2048. Senders are RECOMMENDED to stay under the smallest MTU
in use and, when it is unknown, to stay at 480 (IPv4) or 1180 (IPv6).
"""

from __future__ import annotations

import socket

__all__ = [
    "MIN_RECEIVE_IPV4",
    "MIN_RECEIVE_IPV6",
    "SAFE_SEND_IPV4",
    "SAFE_SEND_IPV6",
    "SHOULD_RECEIVE",
    "max_message_size",
]

MIN_RECEIVE_IPV4 = 480
MIN_RECEIVE_IPV6 = 1180
SHOULD_RECEIVE = 2048
SAFE_SEND_IPV4 = 480
SAFE_SEND_IPV6 = 1180

_UDP_HEADER = 8
_IPV4_HEADER = 20  # minimum; options only shrink the room


def max_message_size(family: int) -> int:
    """Largest syslog message one datagram can carry (RFC 5426 sec. 3.2)."""
    if family == socket.AF_INET:
        return 65535 - _UDP_HEADER - _IPV4_HEADER
    if family == socket.AF_INET6:
        return 65535 - _UDP_HEADER
    raise ValueError("RFC 5426 maps syslog onto IPv4 and IPv6 UDP only")
