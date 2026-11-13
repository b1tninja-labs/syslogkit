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
* Certificate fingerprints (RFC 5425 sec. 4.2.2) are computed and compared here.
  :func:`pinned_client_context` plus :func:`verify_pinned` give the client side of the
  fingerprint-only policy of sec. 5.1: the chain is not validated, so the handshake alone
  proves nothing, and the post-handshake pin check is the whole of the authentication. The
  server side cannot be built on the standard library: ``ssl`` cannot request a client
  certificate without also verifying it against a CA.
* :func:`name_matches` is the sec. 5.2 name rule written out (wildcard only as the whole
  left-most label, ASCII-compatible form for internationalized names) so a test table pins it.
  The live handshake still uses OpenSSL's own hostname check, which is stricter on some points.
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
    "name_matches",
    "pinned_client_context",
    "server_context",
    "verify_pinned",
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


def pinned_client_context() -> ssl.SSLContext:
    """A client context for fingerprint-only trust (RFC 5425 sec. 5.1, sec. 4.2.1).

    The certificate chain and the name are **not** checked by the handshake; the caller must
    call :func:`verify_pinned` on the connection before sending anything, which
    ``sender.send_tls(..., pinned=[...])`` does. Use :func:`client_context` unless the
    receiver's certificate is self-signed or issued by a private CA you do not hold.
    """
    context = _base(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def verify_pinned(connection: ssl.SSLObject | ssl.SSLSocket, allowed: Iterable[str]) -> None:
    """Raise :class:`TlsPolicyError` unless the peer's certificate matches a pinned fingerprint.

    RFC 5425 sec. 5 says a peer that does not meet the policy gets the handshake aborted;
    the caller closes the connection on the error.
    """
    der = connection.getpeercert(binary_form=True)
    if der is None:
        raise TlsPolicyError("the peer presented no certificate to match against the pins")
    if not fingerprint_matches(der, allowed):
        raise TlsPolicyError("the peer certificate matches none of the pinned fingerprints")


def _ace(name: str) -> str:
    name = name.rstrip(".").lower()
    try:
        return name.encode("idna").decode("ascii") if not name.isascii() else name
    except UnicodeError:
        raise TlsPolicyError(f"not a valid host name: {name!r}") from None


def name_matches(configured: str, presented: str, *, wildcards: bool = True) -> bool:
    """RFC 5425 sec. 5.2: match a locally configured host name against a certificate name.

    ``presented`` is a dNSName (or common name). A ``*`` is allowed only as the whole
    left-most label and matches exactly one label: ``*.example.com`` matches ``a.example.com``
    and not ``example.com`` or ``a.b.example.com``. ``wildcards=False`` is the option the RFC
    allows for turning wildcards off. Names are compared case-insensitively, with a trailing
    dot ignored and an internationalized name converted to its ASCII-compatible form first
    (the standard library's ``idna`` codec, which is IDNA 2003).
    """
    have, want = _ace(presented), _ace(configured)
    if not have or not want:
        return False
    labels = have.split(".")
    if "*" in have:
        if not wildcards or labels[0] != "*" or "*" in ".".join(labels[1:]) or len(labels) < 3:
            return False  # partial-label or non-leading wildcards are not wildcards here
        return want.split(".")[1:] == labels[1:] and len(want.split(".")) == len(labels)
    return have == want


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
