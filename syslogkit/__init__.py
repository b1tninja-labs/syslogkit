"""syslogkit -- RFC 5424 end to end, sender and receiver.

Python's stdlib ships a 1988-era SysLogHandler and nothing else.
"""

from __future__ import annotations

from . import (
    apps,
    cli,
    dtls,
    framing,
    legacy,
    message,
    pri,
    receiver,
    sd,
    sdids,
    sender,
    tcp,
    tls,
    udp,
)
from .framing import FrameReader, frame_octet_counted, unframe
from .legacy import parse_3164
from .message import SyslogMessage, format, parse
from .receiver import listen_tcp, listen_tls, listen_udp
from .sd import SdElement, decode_sd, encode_sd
from .tls import client_context, server_context

__version__ = "0.1.0"

__all__ = [
    "FrameReader",
    "SdElement",
    "SyslogMessage",
    "__version__",
    "apps",
    "cli",
    "client_context",
    "decode_sd",
    "dtls",
    "encode_sd",
    "format",
    "frame_octet_counted",
    "framing",
    "legacy",
    "listen_tcp",
    "listen_tls",
    "listen_udp",
    "message",
    "parse",
    "parse_3164",
    "pri",
    "receiver",
    "sd",
    "sdids",
    "sender",
    "server_context",
    "tcp",
    "tls",
    "udp",
    "unframe",
]
