"""the datagram secure transport (RFC 6012): deliberately not implemented.

Owner decision pending (see ROADMAP.md, rows `dtls.*`). Python's ``ssl`` module has no
DTLS (measured on 3.14.3 with OpenSSL 3.0.x: no name in ``ssl`` mentions it), the
``cryptography`` package offers primitives but no DTLS record or handshake layer, and the
portfolio has declined to write its own TLS. RFC 6012 is updated by RFC 8996 (no DTLS 1.0)
and RFC 9662 (DTLS 1.2 MUST be used), so even a binding to an external library would need to
pin DTLS 1.2. Nothing here pretends otherwise.
"""

from __future__ import annotations

__all__: list[str] = []
