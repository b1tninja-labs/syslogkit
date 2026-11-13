# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation syslogkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `message.parse()` | RFC 5424 sec. 6, sec. 6.5 | `[ok]` | `tests/test_message.py::test_section_6_5_examples` | M1 |
| `message.format()` | RFC 5424 sec. 6 | `[ok]` | `tests/test_message.py::test_format_reproduces_the_rfc_examples_byte_for_byte` | M1 |
| `message.parse_timestamp()` | RFC 5424 sec. 6.2.3 | `[ok]` | `tests/test_message.py::test_timestamp_forms` | M1 |
| `pri.parse_pri()` | RFC 5424 sec. 6, sec. 6.2.1 | `[ok]` | `tests/test_message.py::test_pri_boundaries` | M1 |
| `sd.encode_sd()` | RFC 5424 sec. 6.3 | `[ok]` | `tests/test_sd.py::test_escaping_roundtrip` | M1 |
| `sd.decode_sd()` | RFC 5424 sec. 6.3 | `[ok]` | `tests/test_sd.py::test_rfc_examples_valid_and_invalid` | M1 |
| `sd.name-grammar` (erratum 6927: SD-NAME, reported not verified; the RFC text is followed, `[` accepted) | RFC 5424 sec. 6, sec. 6.3.2 | `[ok]` | `tests/test_sd.py::test_open_bracket_inside_name_is_accepted_per_rfc_text` | M1 |
| `sd.relay-passthrough` (`message.parse_relay` returns the input octets untouched with `message=None` and the SD error when SD is malformed; a bad header still raises) | RFC 5424 sec. 6.3 para 5 | `[ok]` | `tests/test_message.py::test_relay_forwards_malformed_sd_unaltered` | M5 |
| `sd.registered-ids` (`sdids.TimeQuality`, `Origin`, `Meta`, `next_sequence_id`; sec. 7 read 2026-11-13; language is not BCP 47 checked, enterpriseId not checked against IANA PENs) | RFC 5424 sec. 7 | `[ok]` | `tests/test_sdids.py::test_registered_sd_ids` | M5 |
| `sd.shortest-form-utf8` (non-shortest UTF-8 must not be interpreted; CPython's decoder refuses it) | RFC 5424 sec. 6.3.3, sec. 8.1 | `[part]` | `tests/test_sd.py::test_invalid_utf8_value_refused` | M1 |
| `framing.frame_octet_counted()` | RFC 6587 sec. 3.4.1, RFC 5425 sec. 4.3 | `[ok]` | `tests/test_framing.py::test_octet_counting_vectors` | M3 |
| `framing.frame_non_transparent()` | RFC 6587 sec. 3.4.2 | `[ok]` | `tests/test_framing.py::test_non_transparent_lf_and_crlf_and_nul` | M3 |
| `framing.FrameReader` (streaming, resync, counters, memory bound) | RFC 6587 sec. 3.4, sec. 3.4.3 | `[ok]` | `tests/test_framing.py::test_chunking_loses_and_invents_nothing` | M3 |
| `framing.unframe()` (buffer convenience over `FrameReader`) | RFC 6587 sec. 3.4 | `[ok]` | `tests/test_framing.py::test_unframe_convenience` | M3 |
| `framing.fuzz-corpus` (17 stored hostile streams in `tests/corpus/framing/` with a manifest of expected frame counts, replayed under 8 chunkings, plus a hypothesis test over random bytes; not a stateful machine) | RFC 6587 sec. 3.4.3 | `[ok]` | `tests/test_framing.py::test_fuzz_corpus` | M3 |
| `receiver.listen_udp()` | RFC 5426 sec. 3.1, sec. 3.2 | `[ok]` | `tests/test_transports.py::test_udp_sizes_and_loopback` | M2 |
| `receiver.listen_tcp()` (plaintext, insecure by design) | RFC 6587 sec. 3.4 | `[ok]` | `tests/test_transports.py::test_tcp_framing_both_methods_and_auto_receiver` | M2 |
| `receiver.listen_tls()` | RFC 5425 sec. 4, sec. 4.3, RFC 9662 | `[ok]` | `tests/test_transports.py::test_tls_loopback_delivers_octet_counted_messages` | M4 |
| `sender.send_udp()` | RFC 5426 sec. 3.2 | `[ok]` | `tests/test_transports.py::test_udp_oversize_policy` | M2 |
| `sender.send_tcp()` | RFC 6587 sec. 3.4 | `[ok]` | `tests/test_transports.py::test_tcp_framing_both_methods_and_auto_receiver` | M2 |
| `sender.send_tls()` | RFC 5425 sec. 4.3 | `[ok]` | `tests/test_transports.py::test_tls_loopback_delivers_octet_counted_messages` | M4 |
| `tls.client_context()` | RFC 5425 sec. 4.2, sec. 5, RFC 9662 | `[ok]` | `tests/test_transports.py::test_context_defaults_verify_and_forbid_old_versions` | M4 |
| `tls.server_context()` | RFC 5425 sec. 4.2, sec. 5, RFC 9662 | `[ok]` | `tests/test_transports.py::test_context_policy` | M4 |
| `tls.fingerprint()` | RFC 5425 sec. 4.2.2 | `[ok]` | `tests/test_transports.py::test_fingerprint_format` | M4 |
| `tls.fingerprint-only-trust` (authorise a peer by pinned fingerprint alone, with a post-handshake check) | RFC 5425 sec. 4.2.1, sec. 5.1 | `[ ]` | `tests/test_transports.py::test_fingerprint_pinning_accepts_self_signed` (to be written) | M4 |
| `tls.name-matching-table` (wildcard only as the whole leftmost label, from sec. 5.2; today OpenSSL decides) | RFC 5425 sec. 5.2 | `[ ]` | `tests/test_transports.py::test_wildcard_matching_table` (to be written) | M4 |
| `tls.no-early-data` (Python's `ssl` has no switch to enable it; off by construction, not yet asserted) | RFC 9662 sec. 6 | `[ ]` | `tests/test_transports.py::test_no_early_data` (to be written) | M4 |
| `legacy.parse_3164()` | RFC 3164 sec. 4.1, sec. 4.3 | `[ok]` | `tests/test_legacy.py::test_full_packet` | M1 |
| `rx.drop-accounting` (octets dropped by framing are counted in `ListenerStats.dropped_octets`; a bounded queue with a drop policy is not built) | RFC 6587 sec. 3.4.3 | `[part]` | `tests/test_transports.py::test_tcp_garbage_is_counted_not_lost_silently` | M5 |
| `rx.backpressure-policy` (bounded queue, `max_pending` default 1024, drop-oldest default as decided, `on_drop` hook, `ListenerStats.dropped_messages`; no drop-newest or blocking policy) | - | `[ok]` | `tests/test_transports.py::test_backpressure_policy` | M5 |
| `rx.handler-isolation` (a handler exception is counted in `handler_errors` and later messages still run) | - | `[ok]` | `tests/test_transports.py::test_a_failing_handler_does_not_stop_later_messages` | M5 |
| `rx.metrics-export` | - | `[ ]` | `tests/test_transports.py::test_metrics_snapshot` (to be written) | M5 |
| `dtls.*` (RFC 6012; no DTLS in the standard library or `cryptography`; owner decision pending) | RFC 6012, RFC 8996, RFC 9662 sec. 5 | `[no]` | the decision is recorded in `syslogkit/dtls.py` and section 5 below | M6 |
| `interop.non-python` (evidence against rsyslog or syslog-ng) | RFC 5424, RFC 5425, RFC 6587 | `[ ]` | `docs/interop.md` (to be written) | M5 |

## 2. Milestones

- M1 message, PRI and structured data codec, exact round trip: done (2026-11-13), RFC 3164 tolerant parser included
- M2 UDP and TCP senders plus receivers: done on loopback
- M3 framing with resync tests and a fuzz corpus: done (2026-11-13)
- M4 TLS transport honouring RFC 9662 and the RFC 5425 profiles: CA-validated contexts and loopback done; fingerprint-only trust, name table and the early-data assertion owed
- M5 drop accounting, backpressure, metrics export, relay passthrough, registered SD-IDs, interop evidence: backpressure, relay passthrough and registered SD-IDs done (2026-11-13); metrics export and interop evidence owed
- M6 DTLS (blocked on an owner decision, see section 5), then publication: 0.1.0

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 5424 has 5 errata on file, none verified (checked 2026-11-13): 2682 (held for document update, editorial: facility 15 note), 4967 and 6647 (reported, editorial: duplicate facility 4 and 10), 5010 (reported, technical: "REQUIRING" is not an RFC 2119 keyword, sec. 8.1) and 6927 (reported, technical: SD-NAME grammar). 6927 is decided in code: the RFC text is followed and `[` is accepted in a name; the test named in the `sd.name-grammar` row pins it. Revisit if 6927 is ever verified.
- RFC 5425 has 2 errata, both held for document update and editorial (1733 wording in sec. 4.2.1, 1734 a typo in sec. 5.1); neither changes behaviour.
- RFC 9662 (updates 5425 and 6012) has verified erratum 8135 (editorial, abstract cites RFC 5245 where 5425 is meant).
- RFC 6012 is updated by RFC 8996 (no DTLS 1.0) and RFC 9662 (DTLS 1.2 MUST be used); `docs/rfc-map.md` now says so.
- RFC 5426 has no errata. RFC 3164 has none and is obsolete.
- RFC 6587 is Historic, not Standards Track: it describes deployed practice, so framing tests must include the implementations it documents.
- RFC 5424 obsoleted RFC 3164. A 3164 parser is a compatibility layer, and says so in its name.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| storage, indexing or alerting: that is a logging platform, this is a protocol | `[no]` | a named document requires it |
| parsing every vendor's 3164 dialect; the legacy parser is documented as tolerant | `[no]` | a named document requires it |
| journald or Windows Event Log integration | `[no]` | a named document requires it |

## 5. Open questions

- Backpressure ownership (decided: drop-oldest default with a counter and a hook, built 2026-11-13). Open follow-up: TCP no longer pushes back on a sender through a slow handler, so a deployment that wants lossless TCP needs a blocking policy; add one only on request.
- **Owner decision: DTLS (RFC 6012, M6).** The standard library has no DTLS (measured on Python 3.14.3 with OpenSSL 3.0: no name in `ssl` mentions it) and `cryptography` has primitives but no DTLS record or handshake layer. Writing our own is declined (PORTFOLIO section 5 "own TLS declined"). srtpkit's DTLS-SRTP needs the same layer. Options: (a) drop M6 and publish 0.1.0 without DTLS, (b) bind an external DTLS library as an optional extra, which breaks the zero-dependency rule, (c) wait for a stdlib or `cryptography` DTLS. Recommendation: (a), keep the `dtls.*` row `[no]`. Until decided the row stays `[no]` and `syslogkit/dtls.py` is an honest empty module.
- Fingerprint-only trust needs a post-handshake check on a context whose verify mode is off; decide whether the library exposes that or only CA-validated contexts.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
