"""senders for the three transports (RFC 5426, RFC 6587, RFC 5425)."""

from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import Iterable

from .framing import frame_non_transparent, frame_octet_counted
from .message import SyslogMessage, format
from .udp import max_message_size

__all__ = [
    "MessageTooLarge",
    "send_tcp",
    "send_tls",
    "send_udp",
]


class MessageTooLarge(ValueError):  # noqa: N818 - reads better as a noun
    """The datagram would exceed the limit; it is refused rather than truncated or fragmented."""


def _bytes(message: bytes | SyslogMessage) -> bytes:
    return message if isinstance(message, bytes) else format(message)


def send_udp(
    message: bytes | SyslogMessage,
    host: str,
    port: int = 514,
    *,
    limit: int | None = None,
) -> int:
    """Send one message in one datagram (RFC 5426 sec. 3.1, sec. 3.2, sec. 3.3).

    Refuses (``MessageTooLarge``) a message over ``limit`` or over what one datagram can
    hold. RFC 5426 recommends 480 octets (IPv4) or 1180 (IPv6) when the path MTU is unknown;
    pass ``limit`` to enforce that. Returns the octets sent.
    """
    data = _bytes(message)
    family, _, _, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    ceiling = max_message_size(family)
    if limit is not None:
        ceiling = min(ceiling, limit)
    if len(data) > ceiling:
        raise MessageTooLarge(f"{len(data)} octets exceeds the {ceiling}-octet limit")
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        return sock.sendto(data, address)


async def _send_stream(
    host: str,
    port: int,
    messages: Iterable[bytes | SyslogMessage],
    framing: str,
    context: ssl.SSLContext | None,
    server_hostname: str | None,
) -> int:
    reader, writer = await asyncio.open_connection(
        host, port, ssl=context, server_hostname=server_hostname if context else None
    )
    del reader
    count = 0
    try:
        for message in messages:
            data = _bytes(message)
            writer.write(
                frame_octet_counted(data) if framing == "octet" else frame_non_transparent(data)
            )
            count += 1
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()
    return count


async def send_tcp(
    host: str,
    port: int,
    messages: Iterable[bytes | SyslogMessage],
    *,
    framing: str = "octet",
) -> int:
    """Send messages over plaintext TCP (RFC 6587 sec. 3.4); insecure by design.

    ``framing`` is ``"octet"`` (sec. 3.4.1) or ``"nontransparent"`` (sec. 3.4.2). Returns
    the number of messages written.
    """
    if framing not in ("octet", "nontransparent"):
        raise ValueError("framing is 'octet' or 'nontransparent'")
    return await _send_stream(host, port, messages, framing, None, None)


async def send_tls(
    host: str,
    port: int,
    messages: Iterable[bytes | SyslogMessage],
    context: ssl.SSLContext,
    *,
    server_hostname: str | None = None,
) -> int:
    """Send octet-counted messages over TLS (RFC 5425 sec. 4.3). Returns the count written.

    ``server_hostname`` defaults to ``host`` and is checked against the certificate by a
    context from :func:`syslogkit.tls.client_context`.
    """
    return await _send_stream(host, port, messages, "octet", context, server_hostname or host)
