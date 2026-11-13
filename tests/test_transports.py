"""UDP (RFC 5426), plaintext TCP (RFC 6587) and TLS (RFC 5425) on loopback."""

from __future__ import annotations

import asyncio
import ssl
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from syslogkit import receiver, sender, tls
from syslogkit.message import SyslogMessage, format
from syslogkit.udp import max_message_size


def make(text: str) -> SyslogMessage:
    return SyslogMessage(1, 6, hostname="h", app_name="a", msg=text.encode())


async def wait_for(predicate, timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            pytest.fail("timed out waiting for the listener")
        await asyncio.sleep(0.01)


async def test_udp_sizes_and_loopback():
    got: list[SyslogMessage] = []
    listener = await receiver.listen_udp("127.0.0.1", 0, lambda m, peer: got.append(m))
    try:
        host, port = listener.address
        assert host == "127.0.0.1"
        sizes = [480, 1180, 2048, 8192, 60000]
        for size in sizes:
            sender.send_udp(make("x" * size), host, port)
        await wait_for(lambda: len(got) == len(sizes))
        assert [len(m.msg) for m in got] == sizes  # nothing truncated by a small buffer
        assert listener.stats.received == len(sizes)
    finally:
        await listener.close()


async def test_malformed_goes_to_callback_not_crash():
    bad: list[bytes] = []
    got: list[SyslogMessage] = []
    listener = await receiver.listen_udp(
        "127.0.0.1",
        0,
        lambda m, peer: got.append(m),
        on_malformed=lambda raw, p, e: bad.append(raw),
    )
    try:
        _, port = listener.address
        sender.send_udp(b"not syslog at all", "127.0.0.1", port)
        sender.send_udp(make("fine"), "127.0.0.1", port)
        await wait_for(lambda: got and bad)
        assert bad == [b"not syslog at all"] and listener.stats.malformed == 1
    finally:
        await listener.close()


async def test_async_handler_and_source_address_reported():
    seen: list[tuple[str, int]] = []

    async def handler(message: SyslogMessage, peer: tuple[str, int]) -> None:
        seen.append(peer)

    listener = await receiver.listen_udp("127.0.0.1", 0, handler)
    try:
        sender.send_udp(make("x"), "127.0.0.1", listener.address[1])
        await wait_for(lambda: seen)
        assert seen[0][0] == "127.0.0.1"
    finally:
        await listener.close()


def test_udp_oversize_policy():
    import socket

    assert max_message_size(socket.AF_INET) == 65507
    assert max_message_size(socket.AF_INET6) == 65527
    with pytest.raises(sender.MessageTooLarge):
        sender.send_udp(b"x" * 70000, "127.0.0.1", 9)
    with pytest.raises(sender.MessageTooLarge):
        sender.send_udp(b"x" * 1181, "127.0.0.1", 9, limit=1180)  # RFC 5426 sec. 3.2 safe size
    with pytest.raises(ValueError, match="IPv4 and IPv6"):
        max_message_size(socket.AF_UNSPEC)


async def test_tcp_framing_both_methods_and_auto_receiver():
    got: list[SyslogMessage] = []
    listener = await receiver.listen_tcp("127.0.0.1", 0, lambda m, peer: got.append(m))
    try:
        port = listener.address[1]
        await sender.send_tcp("127.0.0.1", port, [make("one"), make("two\nlines")], framing="octet")
        await sender.send_tcp("127.0.0.1", port, [make("three")], framing="nontransparent")
        await wait_for(lambda: len(got) == 3)
        assert [m.msg for m in got] == [b"one", b"two\nlines", b"three"]
        assert listener.stats.connections == 2
    finally:
        await listener.close()
    with pytest.raises(ValueError, match="framing"):
        await sender.send_tcp("127.0.0.1", 1, [], framing="other")


async def test_tcp_garbage_is_counted_not_lost_silently():
    got: list[SyslogMessage] = []
    listener = await receiver.listen_tcp("127.0.0.1", 0, lambda m, peer: got.append(m))
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", listener.address[1])
        payload = format(make("ok"))
        writer.write(b"\xff\xff garbage\n" + b"%d %s" % (len(payload), payload))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await wait_for(lambda: got and listener.stats.dropped_octets)
        assert listener.stats.dropped_octets == len(b"\xff\xff garbage\n")
    finally:
        await listener.close()


# ---- TLS ---------------------------------------------------------------------------------


def test_context_policy():
    # nothing is trusted implicitly, and a server cannot silently skip client authentication
    with pytest.raises(tls.TlsPolicyError):
        tls.client_context()
    with pytest.raises(tls.TlsPolicyError):
        tls.server_context("x.pem")


def test_fingerprint_format():
    der = bytes(range(256))
    text = tls.fingerprint(der)
    assert text.startswith("sha-1:") and len(text) == 65  # RFC 5425 sec. 4.2.2
    assert text == text.upper().replace("SHA-1:", "sha-1:")
    assert all(len(part) == 2 for part in text[6:].split(":"))
    assert tls.fingerprint(der, "SHA-256").startswith("sha-256:")
    assert tls.fingerprint_matches(der, ["sha-256:00", text.lower()])
    assert not tls.fingerprint_matches(der, ["sha-1:" + ":".join(["00"] * 20)])
    assert not tls.fingerprint_matches(der, ["md5:AA"])
    with pytest.raises(tls.TlsPolicyError):
        tls.fingerprint(der, "md5")


@pytest.fixture
def pki():
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def issue(name: str, issuer=None, san: str | None = None, ca: bool = False):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer[1].subject if issuer else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(days=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        )
        if san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
            )
        cert = builder.sign(issuer[0] if issuer else key, hashes.SHA256())
        return key, cert

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        ca_key, ca_cert = issue("test ca", ca=True)
        srv_key, srv_cert = issue("localhost", (ca_key, ca_cert), san="localhost")
        _, other_cert = issue("other ca", ca=True)
        paths = {}
        for label, cert in (("ca", ca_cert), ("srv", srv_cert), ("other", other_cert)):
            paths[label] = root / f"{label}.pem"
            paths[label].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        paths["srv_key"] = root / "srv.key"
        paths["srv_key"].write_bytes(
            srv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        paths["srv_der"] = srv_cert.public_bytes(serialization.Encoding.DER)
        yield paths


def test_context_defaults_verify_and_forbid_old_versions(pki):
    context = tls.client_context(cafile=str(pki["ca"]))
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.options & ssl.OP_NO_COMPRESSION
    names = {c["name"] for c in context.get_ciphers()}
    assert "ECDHE-RSA-AES128-GCM-SHA256" in names  # the RFC 9662 suite to offer


async def test_tls_loopback_delivers_octet_counted_messages(pki):
    got: list[SyslogMessage] = []
    server = tls.server_context(str(pki["srv"]), str(pki["srv_key"]), anonymous_clients=True)
    listener = await receiver.listen_tls("127.0.0.1", 0, server, lambda m, peer: got.append(m))
    try:
        client = tls.client_context(cafile=str(pki["ca"]))
        count = await sender.send_tls(
            "127.0.0.1",
            listener.address[1],
            [make("secure"), make("é" * 3000)],
            client,
            server_hostname="localhost",
        )
        assert count == 2
        await wait_for(lambda: len(got) == 2)
        assert got[0].msg == b"secure" and len(got[1].msg) == 6000
    finally:
        await listener.close()


async def test_untrusted_server_and_name_mismatch_abort_handshake(pki):
    server = tls.server_context(str(pki["srv"]), str(pki["srv_key"]), anonymous_clients=True)
    listener = await receiver.listen_tls("127.0.0.1", 0, server, lambda m, peer: None)
    try:
        port = listener.address[1]
        wrong_ca = tls.client_context(cafile=str(pki["other"]))
        with pytest.raises(ssl.SSLCertVerificationError):
            await sender.send_tls(
                "127.0.0.1", port, [make("x")], wrong_ca, server_hostname="localhost"
            )
        right_ca = tls.client_context(cafile=str(pki["ca"]))
        with pytest.raises(ssl.SSLCertVerificationError):
            await sender.send_tls(
                "127.0.0.1", port, [make("x")], right_ca, server_hostname="evil.example"
            )
    finally:
        await listener.close()


async def test_tls_framing_error_closes_the_connection(pki):
    server = tls.server_context(str(pki["srv"]), str(pki["srv_key"]), anonymous_clients=True)
    listener = await receiver.listen_tls("127.0.0.1", 0, server, lambda m, peer: None)
    try:
        client = tls.client_context(cafile=str(pki["ca"]))
        _, writer = await asyncio.open_connection(
            "127.0.0.1", listener.address[1], ssl=client, server_hostname="localhost"
        )
        writer.write(b"<34>1 - - - - - -\n")  # non-transparent is not allowed over TLS
        await writer.drain()
        await wait_for(lambda: listener.stats.framing_errors == 1)
        writer.close()
    finally:
        await listener.close()


def test_fingerprint_of_a_real_certificate_matches(pki):
    der = pki["srv_der"]
    pinned = tls.fingerprint(der)
    assert tls.fingerprint_matches(der, [pinned])
    assert not tls.fingerprint_matches(b"other", [pinned])


@pytest.mark.parametrize(
    ("configured", "presented", "expected"),
    [
        # RFC 5425 sec. 5.2 paragraph 3's own examples
        ("a.example.com", "*.example.com", True),
        ("b.example.com", "*.example.com", True),
        ("example.com", "*.example.com", False),
        ("a.b.example.com", "*.example.com", False),
        # the wildcard is the whole left-most label and nothing else
        ("ab.example.com", "a*.example.com", False),
        ("ab.example.com", "*b.example.com", False),
        ("a.example.com", "a.*.com", False),
        ("a.example.com", "a.example.*", False),
        ("a.com", "*.com", False),  # no registry-suffix knowledge: refused for lack of labels
        ("anything", "*", False),
        # exact names: case, trailing dot
        ("Host.Example.COM.", "host.example.com", True),
        ("host.example.com", "other.example.com", False),
        ("", "", False),
        # internationalized names compare in ASCII-compatible form (sec. 5.2 paragraph 5)
        ("bücher.example", "xn--bcher-kva.example", True),
        ("xn--bcher-kva.example", "*.example", False),
        ("x.bücher.example", "*.xn--bcher-kva.example", True),
    ],
)
def test_wildcard_matching_table(configured, presented, expected):
    assert tls.name_matches(configured, presented) is expected


def test_wildcards_can_be_turned_off():
    assert not tls.name_matches("a.example.com", "*.example.com", wildcards=False)
    assert tls.name_matches("a.example.com", "a.example.com", wildcards=False)


async def test_fingerprint_pinning_accepts_self_signed(pki):
    # the client does not validate the chain or the name; the pin is the authentication
    server = tls.server_context(str(pki["srv"]), str(pki["srv_key"]), anonymous_clients=True)
    got: list[bytes] = []
    listener = await receiver.listen_tls("127.0.0.1", 0, server, lambda m, peer: got.append(m.msg))
    try:
        port = listener.address[1]
        pin = tls.fingerprint(pki["srv_der"], "sha-256")
        # no CA is given and the host name does not match: only the pin lets this through
        count = await sender.send_tls(
            "127.0.0.1", port, [make("pinned")], pinned=[pin], server_hostname="wrong.example"
        )
        assert count == 1
        await wait_for(lambda: got == [b"pinned"])
        # a wrong pin is refused before anything is written
        with pytest.raises(tls.TlsPolicyError, match="pinned"):
            await sender.send_tls(
                "127.0.0.1", port, [make("refused")], pinned=[tls.fingerprint(b"other")]
            )
        await asyncio.sleep(0.05)
        assert got == [b"pinned"]
    finally:
        await listener.close()
    with pytest.raises(tls.TlsPolicyError):
        await sender.send_tls("127.0.0.1", 1, [make("x")])  # neither a context nor a pin
    with pytest.raises(tls.TlsPolicyError):
        tls.verify_pinned(_NoCertificate(), ["sha-1:00"])


class _NoCertificate:
    def getpeercert(self, binary_form=False):
        return None


def test_no_early_data(pki):
    # RFC 9662 sec. 6: early data MUST NOT be used. Python's ssl has no switch that enables
    # it; if a future version adds one this test fails and the policy needs a decision.
    assert not hasattr(ssl.SSLContext, "max_early_data")
    assert not hasattr(ssl.SSLContext, "set_max_early_data")
    contexts = (
        tls.pinned_client_context(),
        tls.client_context(cafile=str(pki["ca"])),
        tls.server_context(str(pki["srv"]), str(pki["srv_key"]), anonymous_clients=True),
    )
    for context in contexts:
        assert not getattr(context, "max_early_data", 0)
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
        assert context.options & ssl.OP_NO_COMPRESSION


async def test_metrics_snapshot():
    got: list[bytes] = []
    listener = await receiver.listen_tcp("127.0.0.1", 0, lambda m, peer: got.append(m.msg))
    try:
        before = listener.metrics()
        assert before["received"] == 0
        assert before["policy"] == "drop-oldest"
        assert before["max_pending"] == 1024
        await sender.send_tcp("127.0.0.1", listener.address[1], [make("a"), make("b")])
        await wait_for(lambda: len(got) == 2)
        after = listener.metrics()
        assert after["received"] == 2 and after["connections"] == 1
        assert set(listener.stats.snapshot()) == {
            "received",
            "malformed",
            "connections",
            "framing_errors",
            "dropped_octets",
            "dropped_messages",
            "handler_errors",
            "backpressure_waits",
        }
        assert before["received"] == 0  # a snapshot is a copy, not a live view
    finally:
        await listener.close()


async def test_backpressure_policy():
    # drop-oldest: a handler that blocks lets the queue fill, then the oldest are discarded
    gate = asyncio.Event()
    got: list[bytes] = []
    dropped: list[bytes] = []

    async def handler(message, peer):
        await gate.wait()
        got.append(message.msg)

    listener = await receiver.listen_udp(
        "127.0.0.1",
        0,
        handler,
        max_pending=2,
        on_drop=lambda message, peer: dropped.append(message.msg),
    )
    try:
        host, port = listener.address
        for index in range(6):
            sender.send_udp(make(f"m{index}"), host, port)
        await wait_for(lambda: listener.stats.received == 6)
        # m0 is in the handler, m1 and m2 queued then pushed out by m3..m5 down to two
        assert listener.stats.dropped_messages == 3
        assert dropped == [b"m1", b"m2", b"m3"]
        gate.set()
        await wait_for(lambda: len(got) == 3)
        assert got == [b"m0", b"m4", b"m5"]
        assert listener.stats.handler_errors == 0
    finally:
        await listener.close()


async def test_blocking_policy_is_lossless_over_tcp():
    # opt-in: the reader waits for queue room instead of dropping the oldest message
    gate = asyncio.Event()
    got: list[bytes] = []
    dropped: list[bytes] = []

    async def handler(message, peer):
        await gate.wait()
        got.append(message.msg)

    listener = await receiver.listen_tcp(
        "127.0.0.1",
        0,
        handler,
        max_pending=2,
        policy="block",
        on_drop=lambda message, peer: dropped.append(message.msg),
    )
    try:
        count = 200  # one burst, far more than the queue and the handler hold
        port = listener.address[1]
        await sender.send_tcp("127.0.0.1", port, [make(f"m{i}") for i in range(count)])
        # m0 is in the handler, m1 and m2 fill the queue, m3 is parsed and waiting for room:
        # the reader has stopped, so m4 onward is not even parsed
        await wait_for(lambda: listener.stats.backpressure_waits >= 1)
        await asyncio.sleep(0.05)
        assert listener.stats.received == 4
        assert listener.stats.dropped_messages == 0
        gate.set()
        await wait_for(lambda: len(got) == count)
        await listener.drain()
        assert got == [f"m{i}".encode() for i in range(count)]  # all of them, in order
        assert dropped == []
        assert listener.stats.dropped_messages == 0
        assert listener.stats.received == count
        assert listener.stats.handler_errors == 0
    finally:
        await listener.close()


async def test_default_tcp_policy_still_drops_oldest_under_the_same_burst():
    gate = asyncio.Event()
    got: list[bytes] = []

    async def handler(message, peer):
        await gate.wait()
        got.append(message.msg)

    listener = await receiver.listen_tcp("127.0.0.1", 0, handler, max_pending=2)
    try:
        assert listener.policy == "drop-oldest"
        await sender.send_tcp("127.0.0.1", listener.address[1], [make(f"m{i}") for i in range(50)])
        await wait_for(lambda: listener.stats.received == 50)
        assert listener.stats.dropped_messages == 48  # the burst lands in one read: 50 less two
        assert listener.stats.backpressure_waits == 0
        gate.set()
        await listener.drain()
        assert got == [b"m48", b"m49"]
    finally:
        await listener.close()


async def test_blocking_policy_refusals():
    with pytest.raises(ValueError, match="UDP"):
        await receiver.listen_udp("127.0.0.1", 0, lambda m, peer: None, policy="block")
    with pytest.raises(ValueError, match="policy"):
        receiver.Receiver(receiver.ListenerStats(), policy="drop-newest")


async def test_a_failing_handler_does_not_stop_later_messages():
    got: list[bytes] = []

    def handler(message, peer):
        if message.msg == b"boom":
            raise RuntimeError("handler bug")
        got.append(message.msg)

    listener = await receiver.listen_udp("127.0.0.1", 0, handler)
    try:
        host, port = listener.address
        for text in ("boom", "ok"):
            sender.send_udp(make(text), host, port)
        await wait_for(lambda: got == [b"ok"])
        assert listener.stats.handler_errors == 1
    finally:
        await listener.close()
