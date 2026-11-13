# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

- RFC 5424 message parse and format, PRI, the strict TIMESTAMP, and STRUCTURED-DATA (sec. 6.3)
  with the sec. 6.5 and 6.3.5 examples as tests.
- RFC 6587 and RFC 5425 sec. 4.3 framing: octet counting and non-transparent, a streaming
  `FrameReader` with resynchronisation and drop counters.
- A tolerant RFC 3164 parser (`legacy.parse_3164`).
- UDP (RFC 5426), plaintext TCP and TLS (RFC 5425, RFC 9662) senders and receivers, and the
  verifying TLS contexts.
- DTLS (RFC 6012) stays unimplemented: no DTLS exists on the standard library. See ROADMAP.md.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for syslogkit.
- `syslogkit.apps` namespace reserved for composition that is not protocol behaviour.
