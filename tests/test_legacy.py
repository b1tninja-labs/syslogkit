"""RFC 3164 compatibility parser: tolerant, never refuses, says what it did not find."""

from __future__ import annotations

from syslogkit.legacy import LegacyTimestamp, parse_3164


def test_full_packet():
    # the RFC 3164 sec. 5.1 style packet
    raw = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
    m = parse_3164(raw)
    assert (m.facility, m.severity, m.pri_present) == (4, 2, True)
    assert m.timestamp == LegacyTimestamp(10, 11, 22, 14, 15)
    assert m.hostname == "mymachine"
    assert (m.tag, m.pid) == ("su", None)
    assert m.content == b"'su root' failed for lonvick on /dev/pts/8"
    assert m.raw == raw and not m.oversize


def test_space_padded_day_and_pid():
    m = parse_3164(b"<13>Aug  7 01:02:03 host sshd[1234]: Accepted")
    assert m.timestamp == LegacyTimestamp(8, 7, 1, 2, 3)
    assert (m.tag, m.pid, m.content) == ("sshd", "1234", b"Accepted")


def test_no_hostname_when_first_token_is_a_tag():
    m = parse_3164(b"<13>Aug  7 01:02:03 su: hello")
    assert m.hostname is None and m.tag == "su" and m.content == b"hello"


def test_no_pri_means_priority_13_and_all_content():
    # sec. 4.3.3
    m = parse_3164(b"just text")
    assert (m.facility, m.severity, m.pri_present) == (1, 5, False)
    assert m.content == b"just text" and m.timestamp is None


def test_unidentifiable_pri_is_content():
    # sec. 4.3.3: "<00>" is the RFC's own example of an unidentifiable PRI
    m = parse_3164(b"<00>x")
    assert not m.pri_present and m.content == b"<00>x"
    for bad in [b"<192>x", b"<>x", b"<1234>x", b"<08>x"]:
        assert not parse_3164(bad).pri_present


def test_pri_without_timestamp_keeps_remainder_as_content():
    # sec. 4.3.2
    m = parse_3164(b"<34>not a timestamp at all")
    assert m.pri_present and m.timestamp is None and m.content == b"not a timestamp at all"
    bad = parse_3164(b"<34>Foo 11 22:14:15 h x")
    assert bad.timestamp is None
    assert parse_3164(b"<34>Oct 11 25:14:15 h x").timestamp is None


def test_never_refuses_arbitrary_bytes():
    for raw in [
        b"",
        b"<",
        b"<34>",
        b"\xff\x00\xfe",
        b"<34>Oct 11 22:14:15 ",
        b"<34>Oct 11 22:14:15 h",
    ]:
        parse_3164(raw)


def test_tag_longer_than_32_is_not_a_tag():
    m = parse_3164(b"<13>Aug  7 01:02:03 host " + b"a" * 33 + b": x")
    assert m.tag is None


def test_oversize_flag():
    assert parse_3164(b"<13>" + b"x" * 1100).oversize
