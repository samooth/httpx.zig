# QUIC Transport Protocol

RFC 9000 defines QUIC, a secure, general-purpose, multiplexed transport protocol operating directly on top of UDP.

## Core Features

* **Authenticated & Encrypted**: All packet headers and payloads are encrypted using TLS 1.3 (RFC 9001). Middleboxes and firewalls cannot inspect or tamper with stream headers.
* **Stream Multiplexing**: Supports arbitrary numbers of concurrent unidirectional and bidirectional streams.
* **Low Latency Handshake**: 1-RTT connection setup for new connections, and 0-RTT early-data connection resumption with pre-shared keys (PSK) and bounded anti-replay protection.
* **Congestion Control**: NewReno controller plus RTT/loss detection primitives (`loss.zig`, `cc.zig`); ACK tracking is integrated into the receive path.
* **Retry**: Integrity-tagged Retry packets (`protect.zig`) for address validation.

## QUIC Packet Types

* `Initial`: Initiates connection and carries TLS ClientHello / ServerHello.
* `Handshake`: Completes mutual authentication and exchanges application keys.
* `0-RTT Protected`: Carries early application data for resumed sessions.
* `1-RTT (Short Header)`: Carries standard application streams with minimum 1-byte header overhead.

## What is not implemented

Written down so the gaps are visible rather than discovered. None of these are
bugs in what is present; they are absent features.

### Version Negotiation (RFC 9000 §6)

The transport **rejects** a packet whose version it does not support —
`Version.isSupported` gates the header parse, and `UnsupportedVersion` is
surfaced from both `packet.zig` and `crypto.zig`. What is missing is the other
half: when a peer offers an unknown version, this implementation silently
ignores the packet rather than responding with a Version Negotiation packet
listing the versions it does support. `connection.zig:921` notes this
explicitly:

```zig
return; // Version negotiation: policy handled above this layer.
```

So the version check exists, the VN *packet* does not. A peer that offers only
a version we do not speak gets no answer at all, where RFC 9000 requires one.
This matters in practice for version-rollout interoperability, which is the
whole point of the mechanism.

### Path MTU Discovery (RFC 9000 §14)

No PMTU probing. Nothing in `src/protocols/quic/` searches for `PmtuDiscovery`
or path-challenge frames, and no DPLPMTUD frame type exists in `frames.zig`.
The transport uses a configured maximum datagram size and does not grow it.
Since QUIC is UDP, this means large responses can be black-holed by a path
that cannot carry them and gives no ICMP signal — the failure QUIC's PMTUD
specifically exists to avoid.

### Connection Migration (RFC 9000 §9)

`connectionId.zig` manages connection IDs for peer-initiated address changes,
but the transport does not perform the migration itself: there is no
`PATH_CHALLENGE`/`PATH_RESPONSE` exchange and no path validation before a new
address is used. The CID infrastructure that migration would build on is
present; the mechanism is not.

### Interoperability is untested against a third-party stack

Every test in `src/protocols/quic/` drives this implementation against itself.
That catches wire-format and state-machine regressions that stay
self-consistent, which is most of them — but it cannot catch a reading of the
RFC that is wrong in the same direction on both ends. No test runs this QUIC
stack against nghttp3, quiche, or any other QUIC implementation.

This is the same gap the TLS side closed with real `curl` and `openssl`
binaries; see [Interop Status](/reference/interop-status) for how that was
addressed there and why the equivalent is still missing here.

There is no QUIC client on this machine to test against: `curl` here is built
without HTTP/3 support, and `nghttp3` is not installed. Closing this needs an
independent implementation, not more unit tests.

## Related

* [Protocol: HTTP/3](/protocols/http-3)
* [Protocol: UDP](/protocols/udp)
* [Example: HTTP/3 QUIC](/examples/http3-quic)
