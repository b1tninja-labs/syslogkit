"""STRUCTURED-DATA codec: RFC 5424 sec. 6.3 examples, escaping and hostile input."""

from __future__ import annotations

import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from syslogkit.message import MessageError, format, parse, parse_relay
from syslogkit.sd import SdElement, SdError, decode_sd, decode_sd_bytes, encode_sd

BOM = b"\xef\xbb\xbf"
EX1 = '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]'
EX2 = EX1 + '[examplePriority@32473 class="high"]'
ELEM1 = SdElement(
    "exampleSDID@32473", (("iut", "3"), ("eventSource", "Application"), ("eventID", "1011"))
)
ELEM2 = SdElement("examplePriority@32473", (("class", "high"),))


def test_rfc_examples_valid_and_invalid():
    # sec. 6.3.5 Example 1 (valid)
    assert decode_sd(EX1) == ((ELEM1,), len(EX1))
    # Example 2 (valid, no SP between elements)
    assert decode_sd(EX2) == ((ELEM1, ELEM2), len(EX2))
    # Example 3 (invalid "]SP["): the field ends after the first element, the rest is MSG
    ex3 = EX1 + " " + '[examplePriority@32473 class="high"]'
    assert decode_sd(ex3) == ((ELEM1,), len(EX1))
    # Example 4 (invalid: SP right after the bracket)
    with pytest.raises(SdError):
        decode_sd("[ " + EX1[1:] + '[examplePriority@32473 class="high"]')
    # Example 5 (valid hypothetical IANA name, no '@')
    assert decode_sd('[sigSig ver="1" rsID="1234"]')[0] == (
        SdElement("sigSig", (("ver", "1"), ("rsID", "1234"))),
    )


def test_nilvalue():
    assert decode_sd("-") == ((), 1)
    assert decode_sd("- rest") == ((), 1)
    assert encode_sd([]) == "-"


def test_offset_is_honoured_in_characters():
    text = "héé " + EX1
    elements, end = decode_sd(text, 4)
    assert elements == (ELEM1,)
    assert end == len(text)


def test_escaping_roundtrip():
    for value in ['a"b', "a\\b", "a]b", "ü€😀", "", '"\\]', "x\x00y"]:
        element = SdElement("id@1", (("k", value),))
        text = encode_sd([element])
        assert decode_sd(text) == ((element,), len(text))
    assert encode_sd([SdElement("i", (("k", '"\\]'),))]) == '[i k="\\"\\\\\\]"]'


def test_invalid_escape_preserved():
    # sec. 6.3.3 para 5: backslash + other character stays a backslash and that character
    elements, _ = decode_sd('[i k="a\\nb"]')
    assert elements[0].params == (("k", "a\\nb"),)
    # the value round-trips; the *bytes* do not (the backslash is escaped on output)
    assert encode_sd(elements) == '[i k="a\\\\nb"]'


def test_unescaped_close_bracket_in_value_is_accepted():
    elements, _ = decode_sd('[i k="a]b"]')
    assert elements[0].params == (("k", "a]b"),)


def test_duplicate_sd_id_refused():
    with pytest.raises(SdError):
        decode_sd('[a k="1"][a k="2"]')
    with pytest.raises(SdError):
        encode_sd([SdElement("a"), SdElement("a")])


def test_repeated_param_name_kept_in_order():
    elements, _ = decode_sd('[a k="1" k="2"]')
    assert elements[0].params == (("k", "1"), ("k", "2"))


def test_name_length_33_refused():
    assert decode_sd("[" + "a" * 32 + "]")[0][0].sd_id == "a" * 32
    with pytest.raises(SdError):
        decode_sd("[" + "a" * 33 + "]")
    with pytest.raises(SdError):
        decode_sd("[i " + "p" * 33 + '="x"]')
    with pytest.raises(SdError):
        encode_sd([SdElement("a" * 33)])


@pytest.mark.parametrize("bad", ['[a"b]', "[a=b]", "[a\tb]", "[a\x00]", "[a\x7f]", "[]"])
def test_name_with_forbidden_characters_refused(bad):
    with pytest.raises(SdError):
        decode_sd(bad)


def test_open_bracket_inside_name_is_accepted_per_rfc_text():
    # erratum 6927 (reported, not verified) would forbid '['; the RFC text does not.
    assert decode_sd("[a[b]")[0][0].sd_id == "a[b"


def test_param_missing_quotes_refused():
    for bad in ["[a k=1]", "[a k]", '[a k="1]', "[a k=]"]:
        with pytest.raises(SdError):
            decode_sd(bad)


def test_unterminated_element():
    for bad in ["[", "[a", '[a k="1"', "[a "]:
        with pytest.raises(SdError):
            decode_sd(bad)


def test_nul_in_value_kept():
    assert decode_sd('[a k="x\x00y"]')[0][0].params == (("k", "x\x00y"),)


def test_non_ascii_in_sd_id_refused():
    with pytest.raises(SdError):
        decode_sd("[é]")
    with pytest.raises(SdError):
        encode_sd([SdElement("é")])


def test_invalid_utf8_value_refused():
    with pytest.raises(SdError):
        decode_sd_bytes(b'[a k="\xff"]')


def test_neither_nil_nor_element_refused():
    for bad in ["", "x", " [a]"]:
        with pytest.raises(SdError):
            decode_sd(bad)


def test_max_elements_cap_and_linear_time():
    many = "".join(f"[i{n}]" for n in range(1001))
    with pytest.raises(SdError):
        decode_sd(many)
    assert len(decode_sd(many, max_elements=2000)[0]) == 1001
    huge = '[a k="' + "x" * 5_000_000 + '"]'
    start = time.perf_counter()
    decode_sd(huge)
    assert time.perf_counter() - start < 5
    hostile = '[a k="' + "\\" * 2_000_000  # unterminated, many escapes
    start = time.perf_counter()
    with pytest.raises(SdError):
        decode_sd(hostile)
    assert time.perf_counter() - start < 5


NAMES = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126, exclude_characters='="]'),
    min_size=1,
    max_size=32,
)
VALUES = st.text(alphabet=st.characters(exclude_categories=["Cs"]), max_size=40)


@given(
    st.lists(
        st.tuples(NAMES, st.lists(st.tuples(NAMES, VALUES), max_size=4)),
        max_size=4,
        unique_by=lambda item: item[0],
    )
)
def test_roundtrip_property(items):
    elements = tuple(SdElement(name, tuple(params)) for name, params in items)
    text = encode_sd(elements)
    assert decode_sd(text) == (elements, len(text))


# RFC 5424 sec. 6.3.3 and sec. 6.4: UTF-8 must be in the "shortest form", and what is not must not
# be interpreted. The overlong forms below are the ones UNICODE-TR36 sec. 3.1 warns about: each is
# a longer encoding of a character that has a shorter one, and a filter that checks "/" or NUL
# before decoding would miss them.
NON_SHORTEST = {
    "NUL as two octets": b"\xc0\x80",
    "slash as two octets": b"\xc0\xaf",
    "0x7f as two octets": b"\xc1\xbf",
    "slash as three octets": b"\xe0\x80\xaf",
    "U+07FF as three octets": b"\xe0\x9f\xbf",
    "slash as four octets": b"\xf0\x80\x80\xaf",
    "U+FFFF as four octets": b"\xf0\x8f\xbf\xbf",
}
NOT_UTF8_EITHER = {
    "a surrogate half": b"\xed\xa0\x80",
    "past U+10FFFF": b"\xf4\x90\x80\x80",
    "a lone continuation octet": b"\x80",
    "a truncated sequence": b"\xe2\x82",
}
SHORTEST_BOUNDARIES = {
    "U+0080": "\u0080",
    "U+07FF": "߿",
    "U+0800": "ࠀ",
    "U+FFFF": "￿",
    "U+10000": "\U00010000",
    "U+10FFFF": "\U0010ffff",
}


def test_non_shortest_utf8_is_not_interpreted():
    for name, octets in {**NON_SHORTEST, **NOT_UTF8_EITHER}.items():
        with pytest.raises(SdError, match="UTF-8"):
            decode_sd_bytes(b'[a k="' + octets + b'"]')
        # the same octets spread through a longer value, and in the second parameter
        with pytest.raises(SdError, match="UTF-8"):
            decode_sd_bytes(b'[a j="ok" k="x' + octets + b'y"]')
        assert name  # each case is named so a failure says which


def test_shortest_form_boundaries_are_accepted():
    for name, character in SHORTEST_BOUNDARIES.items():
        elements, _ = decode_sd_bytes(b'[a k="' + character.encode("utf-8") + b'"]')
        assert elements[0].params == (("k", character),), name


def test_a_relay_forwards_a_non_shortest_value_without_interpreting_it():
    # sec. 6.3 para 5 and sec. 6.3.3: the collector refuses to read the value, the relay keeps the octets
    raw = b'<1>1 - - - - - [a k="' + NON_SHORTEST["slash as two octets"] + b'"] msg'
    with pytest.raises(MessageError, match="STRUCTURED-DATA"):
        parse(raw)
    relayed = parse_relay(raw)
    assert relayed.raw == raw
    assert relayed.message is None


def test_msg_with_a_bom_and_a_non_shortest_form_is_not_utf8():
    # sec. 6.4: "the MSG MUST NOT be interpreted as being encoded in UTF-8"; the octets are kept whole
    for name, octets in {**NON_SHORTEST, **NOT_UTF8_EITHER}.items():
        body = BOM + b"before " + octets
        message = parse(b"<1>1 - - - - - - " + body)
        assert not message.msg_is_utf8, name
        assert message.msg == body, name
        assert format(message) == b"<1>1 - - - - - - " + body, name
    # while the shortest form of the same characters is read as UTF-8, with the BOM stripped
    for name, character in SHORTEST_BOUNDARIES.items():
        message = parse(b"<1>1 - - - - - - " + BOM + character.encode("utf-8"))
        assert message.msg_is_utf8, name
        assert message.msg == character.encode("utf-8"), name
