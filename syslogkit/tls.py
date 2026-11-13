"""TLS transport, profiles and cipher suites (RFC 5425, RFC 9662).

Policy, each point pinned by a test:

* Contexts verify the peer by default and trust only the CA material passed in. The system
  store and ``SSL_CERT_FILE`` are never consulted, so ambient trust cannot change the
  verdict.
* The minimum version is TLS 1.2 (RFC 9662 keeps it mandatory to implement); TLS 1.3 is
  negotiated when both ends offer it. Compression is off. The cipher list is OpenSSL's
  default, which offers ``ECDHE-RSA-AES128-GCM-SHA256``, the suite RFC 9662 says to offer.
* RFC 9662 says early data MUST NOT be used. Python's ``ssl`` exposes no switch that turns
  TLS 1.3 early data on for either end, so it is off by construction.
* No unauthenticated mode is provided for clients. A server must say it accepts anonymous
  clients (``anonymous_clients=True``) or supply a CA that clients must chain to.
* Certificate fingerprints (RFC 5425 sec. 4.2.2) are computed and compared here; making a
  fingerprint-only trust mode needs a post-handshake check and is a roadmap row.
"""

from __future__ import annotations

import hashlib
import hmac
import ssl
from collections.abc import Iterable

__all__ = [
    "TlsPolicyError",
    "client_context",
    "fingerprint",
    "fingerprint_matches",
    "server_context",
]

_LABELS = {"sha-1": "sha1", "sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512"}


class TlsPolicyError(ValueError):
    """The requested TLS configuration would break the RFC 5425 / RFC 9662 profile."""


def _base(purpose: ssl.Purpose) -> ssl.SSLContext:
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT if purpose is ssl.Purpose.SERVER_AUTH else ssl.PROTOCOL_TLS_SERVER
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    return context


def client_context(
    *, cafile: str | None = None, cadata: str | bytes | None = None
) -> ssl.SSLContext:
    """A verifying client context (RFC 5425 sec. 4, RFC 9662; sec. 4.2 and sec. 5 for trust).

    ``cafile`` or ``cadata`` is required: nothing is trusted implicitly. The server name is
    checked against the certificate, so connect with ``server_hostname`` set.
    """
    if cafile is None and cadata is None:
        raise TlsPolicyError("name the CA to trust: no ambient trust store is used")
    context = _base(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=cafile, cadata=cadata)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    return context


def server_context(
    certfile: str,
    keyfile: str | None = None,
    *,
    client_cafile: str | None = None,
    client_cadata: str | bytes | None = None,
    anonymous_clients: bool = False,
) -> ssl.SSLContext:
    """A server context (RFC 5425 sec. 4.2, sec. 5; RFC 9662); clients must authenticate.

    Pass a client CA to require and verify a client certificate, or ``anonymous_clients=True``
    to say plainly that clients are not authenticated (RFC 5425 sec. 5 does not recommend it).
    """
    have_ca = client_cafile is not None or client_cadata is not None
    if not have_ca and not anonymous_clients:
        raise TlsPolicyError("give a client CA, or set anonymous_clients=True explicitly")
    context = _base(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile, keyfile)
    if have_ca:
        context.load_verify_locations(cafile=client_cafile, cadata=client_cadata)
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def fingerprint(der: bytes, algorithm: str = "sha-1") -> str:
    """``label:HH:HH:...`` of the DER certificate, uppercase hex (RFC 5425 sec. 4.2.2).

    The label is the RFC 4572 hash textual name; a SHA-1 fingerprint is 65 characters.
    """
    try:
        name = _LABELS[algorithm.lower()]
    except KeyError:
        raise TlsPolicyError(f"unsupported fingerprint algorithm {algorithm!r}") from None
    digest = hashlib.new(name, der).hexdigest().upper()
    return algorithm.lower() + ":" + ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def fingerprint_matches(der: bytes, allowed: Iterable[str]) -> bool:
    """True if the certificate matches any ``label:HH:...`` entry (RFC 5425 sec. 4.2.2).

    Comparison is per entry's own label and case-insensitive on the hex.
    """
    for entry in allowed:
        label, _, hexpart = entry.partition(":")
        label = label.lower()
        if label not in _LABELS:
            continue
        candidate = f"{label}:{hexpart.upper()}"
        if hmac.compare_digest(fingerprint(der, label).encode(), candidate.encode()):
            return True
    return False
