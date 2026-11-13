"""listener surface, drop counters, backpressure.

Listeners parse each message with :func:`syslogkit.message.parse` and call ``handler``
(sync or async) with the message and the peer address. A message that does not parse goes to
``on_malformed`` and is counted; it never stops the listener.

The peer address is **not** an identity. UDP has no sender authentication and RFC 5426
sec. 3.4 says the source address SHOULD NOT identify the originator; the HOSTNAME in the
message is the originator's claim. Only the TLS listener with a client CA authenticates the
peer.

Backpressure: a parsed message is queued for its handler (``max_pending`` deep, 1024 by
default) and one worker task runs the handler for each in arrival order, so a slow handler
never slows the reader. When the queue is full the policy is **drop-oldest**: the message that
has waited longest is discarded, ``ListenerStats.dropped_messages`` counts it and the optional
``on_drop`` hook sees it. Dropping the oldest keeps the newest events, which is what a log
collector under load usually wants; the owner decided it as the default (PORTFOLIO section 9
item 15). Because the reader never waits, TCP's own flow control no longer reaches the sender
through a slow handler: the queue bound and the counter replace it.
"""

from __future__ import annotations

import asyncio
import inspect
import ssl
from collections import deque
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
Dropped = Callable[[SyslogMessage, Address], None]
DEFAULT_MAX_PENDING = 1024


@dataclass
class ListenerStats:
    """Counters a listener keeps; nothing is dropped without one of these moving."""

    received: int = 0
    malformed: int = 0
    connections: int = 0
    framing_errors: int = 0
    dropped_octets: int = 0
    dropped_messages: int = 0
    handler_errors: int = 0


class Receiver:
    """A running listener. ``address`` is the bound ``(host, port)``; call ``close``."""

    def __init__(
        self,
        stats: ListenerStats,
        *,
        max_pending: int = DEFAULT_MAX_PENDING,
        on_drop: Dropped | None = None,
    ) -> None:
        if max_pending < 1:
            raise ValueError("max_pending must be at least 1")
        self.stats = stats
        self.max_pending = max_pending
        self._on_drop = on_drop
        self._pending: deque[tuple[SyslogMessage, Address, Handler]] = deque()
        self._worker: asyncio.Task[None] | None = None
        self.address: Address = ("", 0)
        self._transport: asyncio.DatagramTransport | None = None
        self._server: asyncio.Server | None = None

    def submit(self, message: SyslogMessage, peer: Address, handler: Handler) -> None:
        """Queue a message for ``handler``; at ``max_pending`` the oldest queued one is dropped."""
        if len(self._pending) >= self.max_pending:
            old, old_peer, _ = self._pending.popleft()
            self.stats.dropped_messages += 1
            if self._on_drop is not None:
                self._on_drop(old, old_peer)
        self._pending.append((message, peer, handler))
        if self._worker is None or self._worker.done():
            self._worker = asyncio.get_running_loop().create_task(self._drain())

    async def _drain(self) -> None:
        while self._pending:
            message, peer, handler = self._pending.popleft()
            try:
                outcome = handler(message, peer)
                if inspect.isawaitable(outcome):
                    await outcome
            except Exception:  # a handler's failure must not stop later messages
                self.stats.handler_errors += 1

    async def close(self) -> None:
        """Stop listening."""
        if self._worker is not None:
            self._worker.cancel()
        if self._transport is not None:
            self._transport.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


def _dispatch(
    raw: bytes,
    peer: Address,
    handler: Handler,
    on_malformed: Malformed | None,
    receiver: Receiver,
) -> None:
    stats = receiver.stats
    try:
        message = parse(raw)
    except MessageError as error:
        stats.malformed += 1
        if on_malformed is not None:
            on_malformed(raw, peer, error)
        return
    stats.received += 1
    receiver.submit(message, peer, handler)


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: Receiver, handler: Handler, on_malformed: Malformed | None):
        self.receiver = receiver
        self.handler = handler
        self.on_malformed = on_malformed

    def datagram_received(self, data: bytes, addr: Address) -> None:
        _dispatch(data, (addr[0], addr[1]), self.handler, self.on_malformed, self.receiver)


async def listen_udp(
    host: str,
    port: int,
    handler: Handler,
    *,
    on_malformed: Malformed | None = None,
    max_pending: int = DEFAULT_MAX_PENDING,
    on_drop: Dropped | None = None,
) -> Receiver:
    """Receive one syslog message per datagram (RFC 5426 sec. 3.1, sec. 3.2).

    Bind ``127.0.0.1`` unless the caller names another host. Datagrams of any size the
    kernel delivers are parsed whole. ``max_pending`` and ``on_drop`` set the drop-oldest
    backpressure policy described in the module docstring.
    """
    receiver = Receiver(ListenerStats(), max_pending=max_pending, on_drop=on_drop)
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
                _dispatch(raw, peer, handler, on_malformed, receiver)
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
    max_pending: int,
    on_drop: Dropped | None,
) -> Receiver:
    receiver = Receiver(ListenerStats(), max_pending=max_pending, on_drop=on_drop)

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
    max_pending: int = DEFAULT_MAX_PENDING,
    on_drop: Dropped | None = None,
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
        max_pending,
        on_drop,
    )


async def listen_tcp(
    host: str,
    port: int,
    handler: Handler,
    *,
    on_malformed: Malformed | None = None,
    max_frame: int = 8192,
    max_pending: int = DEFAULT_MAX_PENDING,
    on_drop: Dropped | None = None,
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
        max_pending,
        on_drop,
    )
