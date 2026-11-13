"""octet counting, non-transparent and the resync rules (RFC 6587, RFC 5425 sec. 4.3).

RFC 6587 is Historic: it records deployed practice. Policy decisions, each pinned by a test:

* ``MSG-LEN = NONZERO-DIGIT *DIGIT`` so a leading zero (``007 abc``) and a zero length are
  malformed, and an empty message cannot be octet-counted.
* A length above ``max_frame`` is malformed; it is never allocated.
* ``on_error="skip"`` (default) discards bytes up to the next trailer and counts them in
  ``dropped``, counting one ``resyncs``; ``on_error="raise"`` raises :class:`FramingError`,
  which is the right choice on TLS where one bad length means the stream cannot be trusted.
* In ``accept="auto"`` a frame beginning with a digit is octet counted and one beginning
  with ``<`` is non-transparent (RFC 6587 sec. 3.4.1 and 3.4.2); the method may change per
  frame (sec. 3.4.3). A non-transparent frame ends at LF (a CR before it is removed) or,
  with ``trailer=b"\\0"``, at NUL.
"""

from __future__ import annotations

from typing import Literal

__all__ = [
    "FrameReader",
    "FramingError",
    "frame_non_transparent",
    "frame_octet_counted",
    "unframe",
]

Accept = Literal["octet", "nontransparent", "auto"]
OnError = Literal["skip", "raise"]


class FramingError(ValueError):
    """The stream does not follow the framing it is being read with."""


class _Bad(Exception):  # noqa: N818 - internal control flow
    pass


def frame_octet_counted(msg: bytes) -> bytes:
    """Frame one message as ``MSG-LEN SP SYSLOG-MSG`` (RFC 6587 sec. 3.4.1, RFC 5425 sec. 4.3)."""
    if not msg:
        raise ValueError("an empty message cannot be octet counted: MSG-LEN is nonzero")
    return b"%d %s" % (len(msg), msg)


def frame_non_transparent(msg: bytes, trailer: bytes = b"\n") -> bytes:
    """Frame one message with a trailer (RFC 6587 sec. 3.4.2); LF unless the application says."""
    if not 1 <= len(trailer) <= 2:
        raise ValueError("a trailer is one or two octets")
    if trailer in msg:
        raise ValueError("the message contains the trailer and would be split")
    return msg + trailer


class FrameReader:
    """Incremental deframer for a byte stream (RFC 6587 sec. 3.4, RFC 5425 sec. 4.3.1).

    ``feed`` accepts arbitrary chunks and returns the complete messages found. Memory is
    bounded: ``pending`` never exceeds about ``max_frame`` plus the length prefix.
    Counters: ``frames`` delivered, ``dropped`` octets discarded, ``resyncs`` events.
    """

    def __init__(
        self,
        *,
        max_frame: int = 8192,
        accept: Accept = "auto",
        on_error: OnError = "skip",
        trailer: bytes = b"\n",
    ) -> None:
        if max_frame < 1:
            raise ValueError("max_frame must be positive")
        if trailer not in (b"\n", b"\0"):
            raise ValueError("trailer is LF or NUL")
        self.max_frame = max_frame
        self.accept: Accept = accept
        self.on_error: OnError = on_error
        self.trailer = trailer
        self.frames = 0
        self.dropped = 0
        self.resyncs = 0
        self._buf = bytearray()
        self._skipping = False
        self._max_digits = len(str(max_frame))

    @property
    def pending(self) -> int:
        """Octets held waiting for the rest of a frame."""
        return len(self._buf)

    def feed(self, data: bytes) -> list[bytes]:
        """Add stream bytes and return every complete message now available."""
        self._buf += data
        out: list[bytes] = []
        while self._buf:
            if self._skipping:
                index = self._buf.find(self.trailer)
                if index < 0:
                    self.dropped += len(self._buf)
                    self._buf.clear()
                    break
                self.dropped += index + 1
                del self._buf[: index + 1]
                self._skipping = False
                continue
            try:
                frame = self._take()
            except _Bad as reason:
                if self.on_error == "raise":
                    raise FramingError(str(reason)) from None
                self.resyncs += 1
                self._skipping = True
                continue
            if frame is None:
                break
            self.frames += 1
            out.append(frame)
        return out

    def close(self) -> bytes | None:
        """End of stream: return and count any unfinished frame as dropped."""
        leftover = bytes(self._buf)
        self._buf.clear()
        self._skipping = False
        if leftover:
            self.dropped += len(leftover)
            return leftover
        return None

    def _method(self) -> str:
        first = self._buf[0]
        if self.accept == "octet":
            if 49 <= first <= 57:
                return "octet"
            raise _Bad("octet-counted frame must start with a nonzero digit")
        if self.accept == "nontransparent":
            return "nontransparent"
        if 49 <= first <= 57:
            return "octet"
        if first == 0x3C:
            return "nontransparent"
        raise _Bad("frame starts with neither a nonzero digit nor '<'")

    def _take(self) -> bytes | None:
        buf = self._buf
        if self._method() == "octet":
            index = 0
            while index < len(buf) and 48 <= buf[index] <= 57:
                index += 1
                if index > self._max_digits:
                    raise _Bad("MSG-LEN is longer than any frame this reader accepts")
            if index == len(buf):
                return None
            if buf[index] != 0x20:
                raise _Bad("MSG-LEN is not followed by SP")
            length = int(buf[:index])
            if length > self.max_frame:
                raise _Bad(f"MSG-LEN {length} exceeds max_frame {self.max_frame}")
            if len(buf) < index + 1 + length:
                return None
            frame = bytes(buf[index + 1 : index + 1 + length])
            del buf[: index + 1 + length]
            return frame
        index = buf.find(self.trailer)
        if index < 0:
            if len(buf) > self.max_frame:
                raise _Bad("non-transparent frame exceeds max_frame without a trailer")
            return None
        if index > self.max_frame:
            raise _Bad("non-transparent frame exceeds max_frame")
        frame = bytes(buf[:index])
        del buf[: index + 1]
        if self.trailer == b"\n" and frame.endswith(b"\r"):
            frame = frame[:-1]
        return frame


def unframe(
    buffer: bytes, *, accept: Accept = "auto", max_frame: int = 8192
) -> tuple[list[bytes], bytes]:
    """Split a complete buffer into messages (RFC 6587 sec. 3.4); also return the unfinished tail.

    A convenience over :class:`FrameReader`, which is what a socket loop should use.
    """
    reader = FrameReader(max_frame=max_frame, accept=accept, on_error="raise")
    frames = reader.feed(buffer)
    return frames, bytes(reader._buf)
