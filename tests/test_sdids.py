"""RFC 5424 sec. 7: the registered SD-IDs timeQuality, origin and meta."""

from __future__ import annotations

import pytest

from syslogkit.sd import decode_sd, encode_sd
from syslogkit.sdids import (
    MAX_SEQUENCE_ID,
    Meta,
    Origin,
    SdIdError,
    TimeQuality,
    next_sequence_id,
)


def one(text: str):
    elements, _ = decode_sd(text)
    return elements[0]


def test_registered_sd_ids():
    # the three examples of sec. 7.1.4 and the one of sec. 7.2.5, read back and written back
    assert TimeQuality.from_element(one('[timeQuality tzKnown="0" isSynced="0"]')) == TimeQuality(
        False, False
    )
    quality = TimeQuality.from_element(
        one('[timeQuality tzKnown="1" isSynced="1" syncAccuracy="60000000"]')
    )
    assert (quality.tz_known, quality.is_synced, quality.sync_accuracy) == (True, True, 60000000)
    assert encode_sd([quality.to_element()]) == (
        '[timeQuality tzKnown="1" isSynced="1" syncAccuracy="60000000"]'
    )
    origin = Origin.from_element(one('[origin ip="192.0.2.1" ip="192.0.2.129"]'))
    assert origin.ips == ("192.0.2.1", "192.0.2.129")
    assert encode_sd([origin.to_element()]) == '[origin ip="192.0.2.1" ip="192.0.2.129"]'
    meta = Meta.from_element(one('[meta sequenceId="7" sysUpTime="12" language="en-US"]'))
    assert meta == Meta(7, 12, "en-US")
    assert meta.to_element() == one('[meta sequenceId="7" sysUpTime="12" language="en-US"]')


def test_time_quality_rules():
    with pytest.raises(SdIdError, match="isSynced is 0"):
        TimeQuality(is_synced=False, sync_accuracy=5)
    with pytest.raises(SdIdError, match="0 or 1"):
        TimeQuality.from_element(one('[timeQuality tzKnown="yes"]'))
    with pytest.raises(SdIdError, match="decimal"):
        TimeQuality.from_element(one('[timeQuality syncAccuracy="-3"]'))
    # absent isSynced with an accuracy is allowed: the RFC only forbids it beside isSynced="0"
    assert TimeQuality(sync_accuracy=5).to_element().params == (("syncAccuracy", "5"),)


def test_origin_rules():
    assert Origin(enterprise_id="32473.1.2").to_element().params == (("enterpriseId", "32473.1.2"),)
    for bad in ("32473.", ".1", "a.b", ""):
        with pytest.raises(SdIdError, match="enterpriseId"):
            Origin(enterprise_id=bad)
    Origin(software="s" * 48, sw_version="v" * 32)
    with pytest.raises(SdIdError, match="48"):
        Origin(software="s" * 49)
    with pytest.raises(SdIdError, match="32"):
        Origin(sw_version="v" * 33)
    with pytest.raises(SdIdError, match="IP address"):
        Origin(ips=("not-an-ip",))
    assert Origin(ips=("2001:db8::1",)).ips == ("2001:db8::1",)


def test_meta_sequence_id_range_and_wrap():
    assert next_sequence_id(None) == 1
    assert next_sequence_id(1) == 2
    assert next_sequence_id(MAX_SEQUENCE_ID - 1) == MAX_SEQUENCE_ID
    assert next_sequence_id(MAX_SEQUENCE_ID) == 1  # sec. 7.3.1: the next one is 1
    with pytest.raises(SdIdError):
        Meta(sequence_id=0)
    with pytest.raises(SdIdError):
        Meta(sequence_id=MAX_SEQUENCE_ID + 1)
    with pytest.raises(SdIdError):
        Meta.from_element(one('[meta sequenceId="2147483648"]'))


def test_unknown_parameters_are_kept_and_duplicates_refused():
    element = one('[meta sequenceId="1" vendor="x"]')
    meta = Meta.from_element(element)
    assert meta.extra == (("vendor", "x"),)
    assert meta.to_element() == element
    with pytest.raises(SdIdError, match="more than once"):
        Meta.from_element(one('[meta sequenceId="1" sequenceId="2"]'))
    with pytest.raises(SdIdError, match="not a meta"):
        Meta.from_element(one('[origin ip="192.0.2.1"]'))
