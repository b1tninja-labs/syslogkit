# syslogkit

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

syslogkit -- RFC 5424 end to end, sender and receiver

Python's stdlib ships a 1988-era SysLogHandler and nothing else. The maintained library in the space, aiosyslog 0.2.1 (2026-08-25), is a client. What operators actually lack is the receiving end: octet-counted and non-transparent framing, resynchronisation after a truncated message, backpressure that does not drop silently, and TLS with the cipher suite rules RFC 9662 set in October 2024. syslogkit covers the protocol and its four transport mappings on both sides.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| stdlib logging.handlers | - | - | a 3164-era UDP handler; no 5424 message, no receiver |
| aiosyslog | 0.2.1 | 2026-08-25 | async client only; no receiver, no framing, no TLS profile |
| rsyslog, syslog-ng | - | - | daemons, not importable libraries |

What this project intends to add:

- an RFC 5424 parser and emitter that preserves structured data exactly, including escaped brackets
- TCP framing on both sides with the RFC 6587 resynchronisation rules
- a receiver with bounded queues, explicit drop accounting and no silent loss
- TLS transport honouring RFC 9662 suites plus the RFC 5425 transport profiles
- DTLS for the case where UDP semantics and integrity both matter

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 5424 | Proposed Standard | 2009-03 | the protocol: HEADER, structured data, the PRI and facility model |
| RFC 5426 | Proposed Standard | 2009-03 | UDP transport, the one every implementation must have |
| RFC 6587 | Historic | 2012-04 | TCP framing: octet counting and non-transparent, plus the resync problem |
| RFC 5425 | Proposed Standard | 2009-03 | TLS transport including transport profiles and mutual auth |
| RFC 9662 | Proposed Standard | 2024-10 | refreshed cipher suite requirements for secure syslog |
| RFC 6012 | Proposed Standard | 2010-10 | DTLS transport for unreliable but secure delivery |

### Errata watch

- RFC 5424 has 5 errata on file with none verified; RFC 5425 has 2 on file, none verified. Re-check both pages before M1.
- RFC 6587 is Historic, not Standards Track: it describes deployed practice, so framing tests must include the implementations it documents.
- RFC 5424 obsoleted RFC 3164. A 3164 parser is a compatibility layer, and says so in its name.

## Module layout

| Module | Responsibility |
|---|---|
| `message` | the 5424 message: PRI, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID |
| `pri` | facility and severity with the names operators expect (RFC 5424) |
| `sd` | structured data elements, parameters and the registered SD-IDs (RFC 5424) |
| `framing` | octet counting, non-transparent and the resync rules (RFC 6587) |
| `udp` | the mandatory transport (RFC 5426) |
| `tcp` | framed TCP with keepalive and connection hygiene (RFC 6587) |
| `tls` | TLS transport, profiles and cipher suites (RFC 5425, RFC 9662) |
| `dtls` | the datagram secure transport (RFC 6012) |
| `receiver` | listener surface, drop counters, backpressure |
| `legacy` | RFC 3164 tolerance, labelled as compatibility rather than correctness |

## What it does not do

- storage, indexing or alerting: that is a logging platform, this is a protocol
- parsing every vendor's 3164 dialect; the legacy parser is documented as tolerant
- journald or Windows Event Log integration


## Install

```bash
git clone https://github.com/b1tninja/syslogkit.cd syslogkit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy syslogkit
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
