# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 5424 | Proposed Standard | 2009-03 | 2026-11-05 |
| RFC 5426 | Proposed Standard | 2009-03 | 2026-11-05 |
| RFC 6587 | Historic | 2012-04 | 2026-11-05 |
| RFC 5425 | Proposed Standard | 2009-03 | 2026-11-05 |
| RFC 9662 | Proposed Standard | 2024-10 | 2026-11-05 |
| RFC 6012 | Proposed Standard, updated by RFC 8996 and RFC 9662 | 2010-10 | 2026-11-13 |
| RFC 3164 | Informational, obsolete (obsoleted by RFC 5424) | 2001-08 | 2026-11-13 |
| RFC 8996 | Best Current Practice 195, deprecates TLS 1.0, TLS 1.1, DTLS 1.0; updates RFC 6012 | 2021-03 | 2026-11-13 (via RFC 6012 record) |

## Status and errata, 2026-11-13

| Document | Errata on file | What it means here |
|---|---|---|
| RFC 5424 | 5, none verified: 2682 (held, editorial), 4967 and 6647 (reported, editorial), 5010 (reported, technical, sec. 8.1 wording), 6927 (reported, technical, SD-NAME grammar) | The RFC text stays normative. 6927: the ABNF excludes SP from a set that already excludes it and the erratum would also exclude `[`; the code follows the text and accepts `[` (pinned in `tests/test_sd.py`). |
| RFC 5425 | 2, both held for document update, editorial (1733, 1734) | No behaviour change. Updated by RFC 9662. |
| RFC 9662 | 1 verified (8135, editorial: abstract names RFC 5245 for 5425) | Updates RFC 5425 and RFC 6012. |
| RFC 5426 | none | |
| RFC 6587 | none; the document is Historic | Describes deployed practice. |
| RFC 6012 | none | Updated by RFC 8996 and RFC 9662; DTLS 1.2 is required. Not implemented (no DTLS available). |
| RFC 3164 | none; obsolete | Cited by the row `legacy.parse_3164()` as the description of observed behaviour. |

## Out of scope, listed so the choice is visible

RFC 5848 (Signed Syslog Messages), RFC 5674 (alarms), RFC 5427 (management textual conventions), RFC 9742 (YANG syslog, 2025-04), RFC 3195 (reliable delivery). None is needed for a first release. RFC 5246 and RFC 8446 are reached only through the standard library `ssl` module.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
