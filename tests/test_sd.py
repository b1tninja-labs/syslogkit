"""STRUCTURED-DATA codec: RFC 5424 sec. 6.3 examples, escaping and hostile input."""

from __future__ import annotations

import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from syslogkit.sd import SdElement, SdError, decode_sd, decode_sd_bytes, encode_sd

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
