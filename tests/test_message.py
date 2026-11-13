"""RFC 5424 message parse and format: sec. 6.5 examples, PRI, TIMESTAMP, limits."""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from syslogkit.message import MessageError, SyslogMessage, format, parse, parse_timestamp
from syslogkit.pri import PriError, format_pri, parse_pri
from syslogkit.sd import SdElement

BOM = b"\xef\xbb\xbf"
SD1 = b'[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]'
EX1 = (
    b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - "
    + BOM
    + b"'su root' failed for lonvick on /dev/pts/8"
)
EX2 = (
    b"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - "
    b"%% It's time to make the do-nuts."
)
EX3 = (
    b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
    + SD1
    + b" "
    + BOM
    + b"An application event log entry..."
)
EX4 = (
    b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
    + SD1
    + b'[examplePriority@32473 class="high"]'
)
UTC_MINUS_7 = timezone(timedelta(hours=-7))


def test_section_6_5_examples():
    m1 = parse(EX1)
    assert (m1.facility, m1.severity, m1.version) == (4, 2, 1)
    assert m1.timestamp == datetime(2003, 10, 11, 22, 14, 15, 3000, tzinfo=UTC)
    assert (m1.hostname, m1.app_name, m1.procid, m1.msgid) == (
        "mymachine.example.com",
        "su",
        None,
        "ID47",
    )
    assert m1.sd == ()
    assert m1.msg == b"'su root' failed for lonvick on /dev/pts/8" and m1.msg_is_utf8

    m2 = parse(EX2)
    assert (m2.facility, m2.severity) == (20, 5)
    assert m2.timestamp == datetime(2003, 8, 24, 5, 14, 15, 3, tzinfo=UTC_MINUS_7)
    assert (m2.hostname, m2.app_name, m2.procid, m2.msgid) == ("192.0.2.1", "myproc", "8710", None)
    assert m2.msg == b"%% It's time to make the do-nuts." and not m2.msg_is_utf8

    m3 = parse(EX3)
    assert len(m3.sd) == 1 and m3.sd[0].sd_id == "exampleSDID@32473"
    assert m3.sd[0].params[2] == ("eventID", "1011")
    assert m3.msg == b"An application event log entry..." and m3.msg_is_utf8

    m4 = parse(EX4)
    assert [e.sd_id for e in m4.sd] == ["exampleSDID@32473", "examplePriority@32473"]
    assert m4.msg == b"" and not m4.msg_is_utf8


@pytest.mark.parametrize("example", [EX1, EX2, EX3, EX4])
def test_format_reproduces_the_rfc_examples_byte_for_byte(example):
    assert format(parse(example)) == example


def test_pri_boundaries():
    assert parse_pri(b"<0>x") == (0, 0, 3)
    assert parse_pri(b"<191>x") == (23, 7, 5)
    assert parse_pri(b"<034>x") == (4, 2, 5)  # 1*3DIGIT admits a leading zero
    for bad in [b"<192>", b"<-1>", b"<>", b"<1234>", b"34>", b"<3", b"<a>", b""]:
        with pytest.raises(PriError):
            parse_pri(bad)
    assert format_pri(20, 5) == b"<165>"
    with pytest.raises(PriError):
        format_pri(24, 0)
    with pytest.raises(PriError):
        format_pri(0, 8)


def test_version_nonzero():
    assert parse(b"<34>1 - - - - - -").version == 1
    assert parse(b"<34>12 - - - - - -").version == 12
    for bad in [
        b"<34>0 - - - - - -",
        b"<34>1234 - - - - - -",
        b"<34> - - - - - -",
        b"<34>01 - - - - - -",
    ]:
        with pytest.raises(MessageError):
            parse(bad)


def test_timestamp_forms():
    assert parse_timestamp(b"-") is None
    utc = datetime(1985, 4, 12, 23, 20, 50, 520000, tzinfo=UTC)
    assert parse_timestamp(b"1985-04-12T23:20:50.52Z") == utc
    # sec. 6.2.3.1 examples 1 and 2 are the same instant
    assert parse_timestamp(b"1985-04-12T19:20:50.52-04:00") == utc
    plus = parse_timestamp(b"2003-01-01T00:00:00+05:30")
    assert plus is not None and plus.utcoffset() == timedelta(hours=5, minutes=30)
    frac = parse_timestamp(b"2003-01-01T00:00:00.123456Z")
    assert frac is not None and frac.microsecond == 123456
    for bad in [
        b"2003-08-24T05:14:15.000000003-07:00",  # RFC example 5: 9-digit fraction
        b"2003-08-24t05:14:15Z",
        b"2003-08-24T05:14:15z",
        b"2003-08-24 05:14:15Z",
        b"2003-08-24T24:00:00Z",
        b"2003-08-24T23:59:60Z",  # leap second
        b"2003-02-30T00:00:00Z",
        b"2003-08-24T05:14:15",  # no offset
        b"2003-08-24T05:14:15.Z",
        b"2003-08-24T05:14:15+24:00",
        b"2003-08-24T05:14:15+00:60",
        b"0000-01-01T00:00:00Z",
        b"",
    ]:
        with pytest.raises(MessageError):
            parse_timestamp(bad)


def test_field_length_caps():
    def make(host=b"h", app=b"a", pid=b"p", mid=b"m"):
        return b"<1>1 - %s %s %s %s -" % (host, app, pid, mid)

    assert parse(make(host=b"h" * 255)).hostname == "h" * 255
    assert parse(make(app=b"a" * 48)).app_name == "a" * 48
    assert parse(make(pid=b"p" * 128)).procid == "p" * 128
    assert parse(make(mid=b"m" * 32)).msgid == "m" * 32
    for bad in [
        make(host=b"h" * 256),
        make(app=b"a" * 49),
        make(pid=b"p" * 129),
        make(mid=b"m" * 33),
    ]:
        with pytest.raises(MessageError):
            parse(bad)


def test_nil_values_are_none_not_dash():
    m = parse(b"<1>1 - - - - - -")
    assert (m.timestamp, m.hostname, m.app_name, m.procid, m.msgid, m.sd) == (
        None,
        None,
        None,
        None,
        None,
        (),
    )
    assert format(m) == b"<1>1 - - - - - -"
    with pytest.raises(MessageError):
        format(SyslogMessage(1, 1, hostname="-"))


def test_msg_bom_utf8_vs_octets():
    good = parse(b"<1>1 - - - - - - " + BOM + "héllo".encode())
    assert good.msg_is_utf8 and good.msg == "héllo".encode() and good.text == "héllo"
    bad = parse(b"<1>1 - - - - - - " + BOM + b"\xff\xfe")
    assert not bad.msg_is_utf8 and bad.msg == BOM + b"\xff\xfe"  # kept verbatim, not raised
    assert format(bad) == b"<1>1 - - - - - - " + BOM + b"\xff\xfe"
    octets = parse(b"<1>1 - - - - - - \xff\x00 trailing  ")
    assert octets.msg == b"\xff\x00 trailing  "  # nothing stripped


def test_structured_data_errors_make_the_message_fail():
    for bad in [
        b"<1>1 - - - - - [ x]",
        b'<1>1 - - - - - [x k="1"',
        b"<1>1 - - - - - [x]y",
        b"<1>1 - - - - -",
        b"<1>1 - - - - - ",
    ]:
        with pytest.raises(MessageError):
            parse(bad)
    # "]SP[" ends the SD field; the rest is MSG (sec. 6.3.5 example 3)
    m = parse(b'<1>1 - - - - - [a k="1"] [b k="2"]')
    assert [e.sd_id for e in m.sd] == ["a"] and m.msg == b'[b k="2"]'


def test_truncated_everywhere():
    for cut in range(len(EX3)):
        with contextlib.suppress(MessageError):  # any other exception fails the test
            parse(EX3[:cut])


def test_format_refuses_what_parse_refuses():
    for bad in [
        SyslogMessage(1, 1, hostname="a b"),
        SyslogMessage(1, 1, hostname="é"),
        SyslogMessage(1, 1, app_name="a" * 49),
        SyslogMessage(1, 1, timestamp=datetime(2003, 1, 1)),  # naive
        SyslogMessage(1, 1, version=0),
        SyslogMessage(24, 1),
        SyslogMessage(1, 1, msg=b"\xff", msg_is_utf8=True),
        SyslogMessage(1, 1, sd=(SdElement("a"), SdElement("a"))),
    ]:
        with pytest.raises(MessageError):
            format(bad)


FIELD = st.one_of(
    st.none(),
    st.text(
        alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=1, max_size=20
    ).filter(lambda s: s != "-"),
)
STAMPS = st.one_of(
    st.none(),
    st.builds(
        datetime,
        st.integers(1000, 9999),
        st.integers(1, 12),
        st.integers(1, 28),
        st.integers(0, 23),
        st.integers(0, 59),
        st.integers(0, 59),
        st.integers(0, 999999),
        st.builds(
            lambda minutes: timezone(timedelta(minutes=minutes)), st.integers(-23 * 60, 23 * 60)
        ),
    ),
)


@given(
    facility=st.integers(0, 23),
    severity=st.integers(0, 7),
    stamp=STAMPS,
    host=FIELD,
    app=FIELD,
    pid=FIELD,
    mid=FIELD,
    msg=st.binary(max_size=30),
    utf8=st.booleans(),
)
def test_format_roundtrip(facility, severity, stamp, host, app, pid, mid, msg, utf8):
    if utf8:
        msg = msg.decode("utf-8", errors="ignore").encode()
    elif msg.startswith((BOM, b" ")):
        return
    original = SyslogMessage(
        facility,
        severity,
        stamp,
        host,
        app,
        pid,
        mid,
        (SdElement("x@1", (("k", "v]"),)),),
        msg,
        utf8,
    )
    assert parse(format(original)) == original


def test_relay_forwards_malformed_sd_unaltered():
    from syslogkit.message import parse_relay

    good = b'<34>1 2003-10-11T22:14:15.003Z h a - ID47 [x a="1"] msg'
    relayed = parse_relay(good)
    assert relayed.raw == good and relayed.message is not None and relayed.sd_error is None
    # RFC 5424 sec. 6.3: a relay MUST forward malformed SD without alteration, odd bytes and all
    bad = b'<34>1 2003-10-11T22:14:15.003Z h a - ID47 [x a="1] \xff\x00 [broken'
    with pytest.raises(MessageError):
        parse(bad)
    relayed = parse_relay(bad)
    assert relayed.raw is bad
    assert relayed.message is None and relayed.sd_error and "STRUCTURED-DATA" in relayed.sd_error
    # a bad header is not a relay case: the message is not RFC 5424 at all
    with pytest.raises(MessageError):
        parse_relay(b"not syslog")
