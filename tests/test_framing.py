"""RFC 6587 / RFC 5425 sec. 4.3 framing: vectors, chunking, hostile streams."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from syslogkit.framing import (
    FrameReader,
    FramingError,
    frame_non_transparent,
    frame_octet_counted,
    unframe,
)


def test_octet_counting_vectors():
    assert frame_octet_counted(b"hello world") == b"11 hello world"
    # the count is octets, not characters
    assert frame_octet_counted("é".encode()) == b"2 \xc3\xa9"
    with pytest.raises(ValueError, match="empty"):
        frame_octet_counted(b"")
    reader = FrameReader(accept="octet")
    assert reader.feed(b"11 hello world") == [b"hello world"]
    # a zero length is not MSG-LEN = NONZERO-DIGIT *DIGIT
    assert FrameReader(accept="octet", on_error="raise").feed(b"") == []
    with pytest.raises(FramingError):
        FrameReader(accept="octet", on_error="raise").feed(b"0 ")


def test_lf_inside_an_octet_counted_frame_is_data():
    assert FrameReader(accept="octet").feed(b"7 a\nb\r\nc ") == [b"a\nb\r\nc "]


def test_split_at_every_byte():
    stream = frame_octet_counted(b"<34>1 - - - - - - one") + frame_octet_counted(b"two\nlines")
    whole = FrameReader(accept="octet").feed(stream)
    reader = FrameReader(accept="octet")
    pieces: list[bytes] = []
    for index in range(len(stream)):
        pieces += reader.feed(stream[index : index + 1])
    assert pieces == whole == [b"<34>1 - - - - - - one", b"two\nlines"]
    assert reader.pending == 0 and reader.dropped == 0


def test_two_frames_in_one_chunk():
    assert FrameReader().feed(b"3 abc2 de") == [b"abc", b"de"]


def test_non_transparent_lf_and_crlf_and_nul():
    assert FrameReader().feed(b"<1>a\n<2>b\r\n<3>c\n") == [b"<1>a", b"<2>b", b"<3>c"]
    assert FrameReader(trailer=b"\0", accept="nontransparent").feed(b"<1>a\0<2>b\0") == [
        b"<1>a",
        b"<2>b",
    ]
    assert frame_non_transparent(b"<1>a") == b"<1>a\n"
    assert frame_non_transparent(b"<1>a", b"\r\n") == b"<1>a\r\n"
    with pytest.raises(ValueError, match="trailer"):
        frame_non_transparent(b"a\nb")


def test_mixed_methods_auto():
    stream = b"5 hello<34>1 x\n3 abc"
    reader = FrameReader()
    assert reader.feed(stream) == [b"hello", b"<34>1 x", b"abc"]


def test_leading_zero_len_refused():
    with pytest.raises(FramingError):
        FrameReader(accept="octet", on_error="raise").feed(b"007 abc")
    skipper = FrameReader()
    assert skipper.feed(b"007 abc\n3 xyz") == [b"xyz"]
    assert skipper.resyncs == 1 and skipper.dropped == len(b"007 abc\n")


def test_len_overflow_refused_without_allocating():
    reader = FrameReader(max_frame=8192, on_error="raise")
    with pytest.raises(FramingError):
        reader.feed(b"9" * 30 + b" x")
    assert reader.pending < 100


def test_len_larger_than_max_frame_resyncs_or_raises():
    with pytest.raises(FramingError):
        FrameReader(max_frame=10, on_error="raise").feed(b"11 hello world")
    reader = FrameReader(max_frame=10)
    assert reader.feed(b"11 hello world\n5 fine!") == [b"fine!"]
    assert reader.resyncs == 1 and reader.dropped == len(b"11 hello world\n")


def test_garbage_before_first_frame():
    reader = FrameReader()
    assert reader.feed(b"\xff\xfe junk\n3 abc") == [b"abc"]
    assert reader.dropped == len(b"\xff\xfe junk\n") and reader.resyncs == 1


def test_no_space_after_len():
    with pytest.raises(FramingError):
        FrameReader(accept="octet", on_error="raise").feed(b"12abc")


def test_truncated_final_frame_reported_on_close():
    reader = FrameReader(accept="octet")
    assert reader.feed(b"10 half") == []
    assert reader.close() == b"10 half"
    assert reader.dropped == len(b"10 half") and reader.pending == 0
    assert reader.close() is None


def test_unframe_convenience():
    assert unframe(b"3 abc2 d") == ([b"abc"], b"2 d")
    assert unframe(b"<1>x\n<2>y") == ([b"<1>x"], b"<2>y")


def test_memory_bound():
    reader = FrameReader(max_frame=8192)
    reader.feed(b"1")
    for _ in range(1000):
        reader.feed(b"9" * 100_000)
        assert reader.pending < 100
    assert reader.dropped == 100_000_001 - reader.pending  # every octet is counted
    # an overlong non-transparent frame is discarded, and counted, not buffered
    big = FrameReader(max_frame=100)
    assert big.feed(b"<1>" + b"a" * 10_000) == []
    assert big.pending == 0 and big.dropped == 10_003 and big.resyncs == 1


@given(
    st.lists(st.binary(min_size=1, max_size=40), max_size=8),
    st.lists(st.integers(1, 17), min_size=1, max_size=10),
)
def test_chunking_loses_and_invents_nothing(messages, cuts):
    stream = b"".join(frame_octet_counted(m) for m in messages)
    reader = FrameReader(accept="octet")
    out: list[bytes] = []
    position, step = 0, 0
    while position < len(stream):
        size = cuts[step % len(cuts)]
        out += reader.feed(stream[position : position + size])
        position += size
        step += 1
    assert out == messages
    assert reader.pending == 0 and reader.dropped == 0
