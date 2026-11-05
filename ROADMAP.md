# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation syslogkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `message.parse()` | RFC 5424 | `[ ]` | `tests/test_obligations.py::parse` |
| `message.format()` | RFC 5424 | `[ ]` | `tests/test_obligations.py::format` |
| `sd.encode_sd()` | RFC 5424 | `[ ]` | `tests/test_obligations.py::encode_sd` |
| `sd.decode_sd()` | RFC 5424 | `[ ]` | `tests/test_obligations.py::decode_sd` |
| `framing.frame_octet_counted()` | RFC 6587 | `[ ]` | `tests/test_obligations.py::frame_octet_counted` |
| `framing.unframe()` | RFC 6587 | `[ ]` | `tests/test_obligations.py::unframe` |
| `receiver.listen_tls()` | RFC 5425, RFC 9662 | `[ ]` | `tests/test_obligations.py::listen_tls` |
| `receiver.listen_udp()` | RFC 5426 | `[ ]` | `tests/test_obligations.py::listen_udp` |
| `tls.client_context()` | RFC 5425, RFC 9662 | `[ ]` | `tests/test_obligations.py::client_context` |
| `legacy.parse_3164()` | RFC 3164 | `[ ]` | `tests/test_obligations.py::parse_3164` |

## 2. Milestones

- M1 message, PRI and structured data codec, exact round trip
- M2 UDP and TCP senders plus receivers
- M3 framing with resync tests and a fuzz corpus
- M4 TLS transport honouring RFC 9662 and the RFC 5425 profiles
- M5 drop accounting, backpressure, metrics export
- M6 DTLS, then publication: 0.1.0

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 5424 has 5 errata on file with none verified; RFC 5425 has 2 on file, none verified. Re-check both pages before M1.
- RFC 6587 is Historic, not Standards Track: it describes deployed practice, so framing tests must include the implementations it documents.
- RFC 5424 obsoleted RFC 3164. A 3164 parser is a compatibility layer, and says so in its name.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| storage, indexing or alerting: that is a logging platform, this is a protocol | `[no]` | a named document requires it |
| parsing every vendor's 3164 dialect; the legacy parser is documented as tolerant | `[no]` | a named document requires it |
| journald or Windows Event Log integration | `[no]` | a named document requires it |

## 5. Open questions

- does the receiver own backpressure policy or expose a hook for the operator to

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
