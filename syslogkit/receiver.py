"""listener surface, drop counters, backpressure.

Listeners parse each message with :func:`syslogkit.message.parse` and call ``handler``
(sync or async) with the message and the peer address. A message that does not parse goes to
``on_malformed`` and is counted; it never stops the listener.

The peer address is **not** an identity. UDP has no sender authentication and RFC 5426
sec. 3.4 says the source address SHOULD NOT identify the originator; the HOSTNAME in the
message is the originator's claim. Only the TLS listener with a client CA authenticates the
peer.

Backpressure is not implemented: handlers run inline, so a slow handler slows the reader
(TCP applies backpressure to the sender; UDP loses datagrams in the kernel). See ROADMAP.md.
"""

from __future__ import annotations

import asyncio
import inspect
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from .framing import Accept, FrameReader, FramingError
from .message import MessageError, SyslogMessage, parse

__all__ = [
    "ListenerStats",
    "Receiver",
    "listen_tcp",
    "listen_tls",
    "listen_udp",
]

Address = tuple[str, int]
Handler = Callable[[SyslogMessage, Address], Awaitable[None] | None]
Malformed = Callable[[bytes, Address, Exception], None]


@dataclass
class ListenerStats:
    """Counters a listener keeps; nothing is dropped without one of these moving."""

    received: int = 0
    malformed: int = 0
    connections: int = 0
    framing_errors: int = 0
    dropped_octets: int = 0


class Receiver:
    """A running listener. ``address`` is the bound ``(host, port)``; call ``close``."""

    def __init__(self, stats: ListenerStats) -> None:
        self.stats = stats
        self.address: Address = ("", 0)
        self._transport: asyncio.DatagramTransport | None = None
        self._server: asyncio.Server | None = None

    async def close(self) -> None:
        """Stop listening."""
        if self._transport is not None:
            self._transport.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


async def _dispatch(
    raw: bytes,
    peer: Address,
    handler: Handler,
    on_malformed: Malformed | None,
    stats: ListenerStats,
) -> None:
    try:
        message = parse(raw)
    except MessageError as error:
        stats.malformed += 1
        if on_malformed is not None:
            on_malformed(raw, peer, error)
        return
    stats.received += 1
    outcome = handler(message, peer)
    if inspect.isawaitable(outcome):
        await outcome


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: Receiver, handler: Handler, on_malformed: Malformed | None):
        self.receiver = receiver
        self.handler = handler
        self.on_malformed = on_malformed
        self.tasks: set[asyncio.Task[None]] = set()

    def datagram_received(self, data: bytes, addr: Address) -> None:
        peer = (addr[0], addr[1])
        task = asyncio.get_running_loop().create_task(
            _dispatch(data, peer, self.handler, self.on_malformed, self.receiver.stats)
        )
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)


async def listen_udp(
    host: str,
    port: int,
    handler: Handler,
    *,
    on_malformed: Malformed | None = None,
) -> Receiver:
    """Receive one syslog message per datagram (RFC 5426 sec. 3.1, sec. 3.2).

    Bind ``127.0.0.1`` unless the caller names another host. Datagrams of any size the
    kernel delivers are parsed whole.
    """
    receiver = Receiver(ListenerStats())
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UdpProtocol(receiver, handler, on_malformed), local_addr=(host, port)
    )
    receiver._transport = transport
    sockname = transport.get_extra_info("sockname")
    receiver.address = (sockname[0], sockname[1])
    return receiver


async def _serve_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    receiver: Receiver,
    handler: Handler,
    on_malformed: Malformed | None,
    frames: FrameReader,
) -> None:
    peername = writer.get_extra_info("peername")
    peer = (peername[0], peername[1]) if peername else ("", 0)
    receiver.stats.connections += 1
    try:
        while chunk := await reader.read(65536):
            for raw in frames.feed(chunk):
                await _dispatch(raw, peer, handler, on_malformed, receiver.stats)
        frames.close()
    except FramingError:
        receiver.stats.framing_errors += 1
    except (ConnectionError, ssl.SSLError):
        pass
    finally:
        receiver.stats.dropped_octets += frames.dropped
        writer.close()


async def _start(
    host: str,
    port: int,
    handler: Handler,
    on_malformed: Malformed | None,
    context: ssl.SSLContext | None,
    make_reader: Callable[[], FrameReader],
) -> Receiver:
    receiver = Receiver(ListenerStats())

    async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _serve_stream(reader, writer, receiver, handler, on_malformed, make_reader())

    server = await asyncio.start_server(client, host, port, ssl=context)
    receiver._server = server
    sockname = server.sockets[0].getsockname()
    receiver.address = (sockname[0], sockname[1])
    return receiver


async def listen_tls(
    host: str,
    port: int,
    context: ssl.SSLContext,
    handler: Handler,
    *,
    on_malformed: Malformed | None = None,
    max_frame: int = 8192,
) -> Receiver:
    """Receive octet-counted syslog over TLS (RFC 5425 sec. 4, RFC 9662; framing is sec. 4.3).

    Only octet counting is accepted, as RFC 5425 sec. 4.3 requires. The reader handles
    messages up to ``max_frame`` (RFC 5425 sec. 4.3.1: MUST handle 2048, SHOULD handle 8192).
    A framing error closes the connection, because after a bad length the stream cannot be
    resynchronised safely.
    """
    return await _start(
        host,
        port,
        handler,
        on_malformed,
        context,
        lambda: FrameReader(max_frame=max_frame, accept="octet", on_error="raise"),
    )


async def listen_tcp(
    host: str,
    port: int,
    handler: Handler,
    *,
    on_malformed: Malformed | None = None,
    max_frame: int = 8192,
    accept: Accept = "auto",
) -> Receiver:
    """Receive syslog over plaintext TCP (RFC 6587 sec. 3.4); insecure by design.

    Nothing authenticates or protects the stream. Use :func:`listen_tls` for anything
    that leaves the host.
    """
    return await _start(
        host,
        port,
        handler,
        on_malformed,
        None,
        lambda: FrameReader(max_frame=max_frame, accept=accept, on_error="skip"),
    )
