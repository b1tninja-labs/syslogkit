"""typed helpers for the SD-IDs RFC 5424 sec. 7 registers: timeQuality, origin and meta.

Each class converts to and from an :class:`~syslogkit.sd.SdElement`. Parameters are all
OPTIONAL in the RFC, so every field may be ``None``. Reading is strict about the rules
sec. 7 states as MUST (values "0" and "1" for the flags, decimal digits, the length caps,
the sequenceId range and its wrap, ``syncAccuracy`` absent when ``isSynced`` is "0") and
raises :class:`SdIdError`; an unknown parameter name is kept in ``extra`` rather than
refused, because sec. 6.3.2 lets any SD-ID carry parameters this reader has never seen.

What is not checked: ``language`` is stored as written (a BCP 47 parser is out of scope),
and ``enterpriseId`` is checked for shape (decimal sub-identifiers separated by periods)
but not against the IANA enterprise numbers.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .sd import SdElement

__all__ = [
    "MAX_SEQUENCE_ID",
    "Meta",
    "Origin",
    "SdIdError",
    "TimeQuality",
    "next_sequence_id",
]

MAX_SEQUENCE_ID = 2147483647  # sec. 7.3.1
_DIGITS = re.compile(r"[0-9]+")
_ENTERPRISE = re.compile(r"[0-9]+(?:\.[0-9]+)*")


class SdIdError(ValueError):
    """A registered SD-ID element breaks a rule of RFC 5424 sec. 7."""


def _one(element: SdElement, name: str) -> str | None:
    values = [value for key, value in element.params if key == name]
    if len(values) > 1:
        raise SdIdError(f"{element.sd_id}: {name} given more than once")
    return values[0] if values else None


def _extra(element: SdElement, known: frozenset[str]) -> tuple[tuple[str, str], ...]:
    return tuple((k, v) for k, v in element.params if k not in known)


def _flag(value: str | None, name: str) -> bool | None:
    if value is None:
        return None
    if value not in ("0", "1"):
        raise SdIdError(f"{name} must be 0 or 1, not {value!r}")
    return value == "1"


def _number(value: str | None, name: str) -> int | None:
    if value is None:
        return None
    if not _DIGITS.fullmatch(value) or not value.isascii():
        raise SdIdError(f"{name} must be a decimal integer, not {value!r}")
    return int(value)


@dataclass(frozen=True)
class TimeQuality:
    """SD-ID ``timeQuality`` (sec. 7.1): how far the TIMESTAMP can be trusted."""

    tz_known: bool | None = None
    is_synced: bool | None = None
    sync_accuracy: int | None = None
    extra: tuple[tuple[str, str], ...] = field(default=())

    SD_ID = "timeQuality"
    _KNOWN = frozenset({"tzKnown", "isSynced", "syncAccuracy"})

    def __post_init__(self) -> None:
        if self.sync_accuracy is not None:
            if self.is_synced is False:
                raise SdIdError("syncAccuracy MUST NOT be given when isSynced is 0 (sec. 7.1.3)")
            if self.sync_accuracy < 0:
                raise SdIdError("syncAccuracy is a non-negative number of microseconds")

    @classmethod
    def from_element(cls, element: SdElement) -> TimeQuality:
        """Read a ``timeQuality`` element (RFC 5424 sec. 7.1)."""
        if element.sd_id != cls.SD_ID:
            raise SdIdError(f"not a {cls.SD_ID} element: {element.sd_id!r}")
        return cls(
            _flag(_one(element, "tzKnown"), "tzKnown"),
            _flag(_one(element, "isSynced"), "isSynced"),
            _number(_one(element, "syncAccuracy"), "syncAccuracy"),
            _extra(element, cls._KNOWN),
        )

    def to_element(self) -> SdElement:
        """The element to put in STRUCTURED-DATA."""
        params: list[tuple[str, str]] = []
        if self.tz_known is not None:
            params.append(("tzKnown", "1" if self.tz_known else "0"))
        if self.is_synced is not None:
            params.append(("isSynced", "1" if self.is_synced else "0"))
        if self.sync_accuracy is not None:
            params.append(("syncAccuracy", str(self.sync_accuracy)))
        return SdElement(self.SD_ID, (*params, *self.extra))


@dataclass(frozen=True)
class Origin:
    """SD-ID ``origin`` (sec. 7.2): where the message came from. ``ip`` may repeat."""

    ips: tuple[str, ...] = ()
    enterprise_id: str | None = None
    software: str | None = None
    sw_version: str | None = None
    extra: tuple[tuple[str, str], ...] = field(default=())

    SD_ID = "origin"
    _KNOWN = frozenset({"ip", "enterpriseId", "software", "swVersion"})

    def __post_init__(self) -> None:
        for text in self.ips:
            try:
                ipaddress.ip_address(text)
            except ValueError as error:
                raise SdIdError(f"ip is not an IP address: {text!r}") from error
        if self.enterprise_id is not None and not _ENTERPRISE.fullmatch(self.enterprise_id):
            raise SdIdError("enterpriseId is decimal numbers separated by periods (sec. 7.2.2)")
        if self.software is not None and len(self.software) > 48:
            raise SdIdError("software MUST NOT be longer than 48 characters (sec. 7.2.3)")
        if self.sw_version is not None and len(self.sw_version) > 32:
            raise SdIdError("swVersion MUST NOT be longer than 32 characters (sec. 7.2.4)")

    @classmethod
    def from_element(cls, element: SdElement) -> Origin:
        """Read an ``origin`` element (RFC 5424 sec. 7.2)."""
        if element.sd_id != cls.SD_ID:
            raise SdIdError(f"not an {cls.SD_ID} element: {element.sd_id!r}")
        return cls(
            tuple(v for k, v in element.params if k == "ip"),
            _one(element, "enterpriseId"),
            _one(element, "software"),
            _one(element, "swVersion"),
            _extra(element, cls._KNOWN),
        )

    def to_element(self) -> SdElement:
        """The element to put in STRUCTURED-DATA."""
        params: list[tuple[str, str]] = [("ip", ip) for ip in self.ips]
        if self.enterprise_id is not None:
            params.append(("enterpriseId", self.enterprise_id))
        if self.software is not None:
            params.append(("software", self.software))
        if self.sw_version is not None:
            params.append(("swVersion", self.sw_version))
        return SdElement(self.SD_ID, (*params, *self.extra))


def next_sequence_id(current: int | None) -> int:
    """The sequenceId after ``current``: 1 to start, +1 each time, back to 1 after 2147483647."""
    if current is None or current >= MAX_SEQUENCE_ID:
        return 1
    return current + 1


@dataclass(frozen=True)
class Meta:
    """SD-ID ``meta`` (sec. 7.3): sequence number, SNMP uptime and message language."""

    sequence_id: int | None = None
    sys_up_time: int | None = None
    language: str | None = None
    extra: tuple[tuple[str, str], ...] = field(default=())

    SD_ID = "meta"
    _KNOWN = frozenset({"sequenceId", "sysUpTime", "language"})

    def __post_init__(self) -> None:
        if self.sequence_id is not None and not 1 <= self.sequence_id <= MAX_SEQUENCE_ID:
            raise SdIdError(f"sequenceId must be 1 to {MAX_SEQUENCE_ID} (sec. 7.3.1)")
        if self.sys_up_time is not None and self.sys_up_time < 0:
            raise SdIdError("sysUpTime is a non-negative decimal integer (sec. 7.3.2)")
        if self.language is not None and not self.language:
            raise SdIdError("language must not be empty")

    @classmethod
    def from_element(cls, element: SdElement) -> Meta:
        """Read a ``meta`` element (RFC 5424 sec. 7.3)."""
        if element.sd_id != cls.SD_ID:
            raise SdIdError(f"not a {cls.SD_ID} element: {element.sd_id!r}")
        return cls(
            _number(_one(element, "sequenceId"), "sequenceId"),
            _number(_one(element, "sysUpTime"), "sysUpTime"),
            _one(element, "language"),
            _extra(element, cls._KNOWN),
        )

    def to_element(self) -> SdElement:
        """The element to put in STRUCTURED-DATA."""
        params: list[tuple[str, str]] = []
        if self.sequence_id is not None:
            params.append(("sequenceId", str(self.sequence_id)))
        if self.sys_up_time is not None:
            params.append(("sysUpTime", str(self.sys_up_time)))
        if self.language is not None:
            params.append(("language", self.language))
        return SdElement(self.SD_ID, (*params, *self.extra))
