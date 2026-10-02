# QUIC Transport Protocol

RFC 9000 defines QUIC, a secure, general-purpose, multiplexed transport protocol operating directly on top of UDP.

## Core Features

* **Authenticated & Encrypted**: All packet headers and payloads are encrypted using TLS 1.3 (RFC 9001). Middleboxes and firewalls cannot inspect or tamper with stream headers.
* **Stream Multiplexing**: Supports arbitrary numbers of concurrent unidirectional and bidirectional streams.
* **Low Latency Handshake**: 1-RTT connection setup for new connections, and 0-RTT early-data connection resumption with pre-shared keys (PSK) and bounded anti-replay protection.
* **Congestion Control**: NewReno controller plus RTT/loss detection primitives (`loss.zig`, `cc.zig`); ACK tracking is integrated into the receive path.
* **Key Update**: 1-RTT keys rotate on the confidentiality limit, and the peer phase is followed. See RFC 9001 section 6.
* **Path MTU Discovery**: Sends are capped by what the peer advertised, and padded `PATH_CHALLENGE` probes raise the estimate. See RFC 9000 section 14.
* **Connection Migration**: Connection IDs are issued so a peer can migrate, and a new address is validated before it is used. See RFC 9000 section 9.
* **Version Negotiation**: Both directions. An unsupported version is answered rather than dropped, and an incoming VN is parsed, checked and acted on: the client switches to a mutually supported version and restarts its first flight. See RFC 9000 section 6 and RFC 9368.
* **Retry**: Integrity-tagged Retry packets (`protect.zig`) for address validation.

## QUIC Packet Types

* `Initial`: Initiates connection and carries TLS ClientHello / ServerHello.
* `Handshake`: Completes mutual authentication and exchanges application keys.
* `0-RTT Protected`: Carries early application data for resumed sessions.
* `1-RTT (Short Header)`: Carries standard application streams with minimum 1-byte header overhead.

## Interoperability

The transport interoperates with aioquic 1.2.0. A client sends a real HTTP/3
`GET`, this stack completes the QUIC and TLS handshakes, decodes the request,
answers it, and aioquic receives the response headers and body. The observed
event sequence is `ProtocolNegotiated`, `HandshakeCompleted`,
`ConnectionIdIssued`, `StreamDataReceived`, `HeadersReceived`,
`DataReceived`.

This matters more than the feature list above, because it is what found four
defects that no unit test could see. Each one was self-consistent: both ends
of every test are this implementation, so a wrong reading of the RFC agreed
with itself and passed. They are written up in
[Interop Status](/reference/interop-status#four-defects-only-a-third-party-stack-could-show).

Two real datagrams from aioquic are checked into
`src/protocols/quic/testdata/` and replayed by the unit suite with the
destination connection ID from the same run, so the Initial keys can be
re-derived and the packets decrypted.

The gap that remains is process rather than behaviour: the live exchange runs
from an external script, not from the opt-in `HTTPX_INTEROP=1` suite, so it
does not fail CI on a regression. The replayed captures cover the handshake;
the request/response exchange does not.

## What is not implemented

Written down so the gaps are visible rather than discovered. None of these are
bugs in what is present; they are absent features.

### Downgrade protection across the handshake (RFC 9368 section 4)

Acting on an incoming VN is implemented: `packet.parseVersionNegotiation`
parses it, and `receiveVersionNegotiation` decides whether to. A client that
survives the checks switches version, rederives Initial keys, discards the
first flight and restarts the handshake.

Two halves of the anti-downgrade mechanism are still absent:

* **`version_information` transport parameter (0x11).** RFC 9368 section 4
  requires both endpoints to exchange a Chosen Version and an Available
  Versions list during the handshake, and requires the client to close with
  `VERSION_NEGOTIATION_ERROR` if a server that reacted to a VN omits it or
  names a version the client would not have chosen. The parameter is parsed
  and echoed only in the sense that we tolerate its absence; it is not
  validated, and a server that sends a hostile Available Versions list is not
  detected. Section 8 permits a client that started on version 1 to proceed
  as though the list were `0x00000001` alone, so version 1 is unaffected --
  a negotiated version 2 connection is not authenticated this way.
* **Compatible version negotiation (section 2.3).** The server selects the
  version by switching the long header version mid-handshake. We only handle
  the incompatible form, which costs a round trip.

What is implemented is not nothing: the checks that do not need the handshake
are the ones an off-path attacker has to get past, and each is tested by
reverting it. A forged VN is rejected on the echoed connection IDs, on the
Original Version it lists, and because a second one is ignored.

### DPLPMTUD frames and ICMP feedback

Path MTU is discovered by probing, not with the dedicated frames: no
`DPLPMTUD` frame type (RFC 8899) exists in `frames.zig`, and nothing consumes
ICMP "packet too big" to shorten the estimate. Probes are `PATH_CHALLENGE`
packets padded to the target size, on a fixed interval rather than one derived
from the PTO.

### Migration initiated from this side

A peer that changes address is handled: the new address is treated as a
candidate, the validated address stays the send destination, a
`PATH_CHALLENGE` goes out, and the switch happens once the path is proven.
What this stack does not do is move its own source address, distinguish NAT
rebinding (RFC 9000 section 9.3) from a genuine migration, or act on a
`preferred_address` transport parameter (section 9.6).

`Endpoint` carries one connection, so there is no connection-ID
demultiplexing on the receive side yet.

`PATH_ABILITY` is not sent, which is correct while zero-length connection IDs
are not offered.

### Stream data coalesced with the last handshake flight

A client commonly puts its Finished and its first request in one datagram.
That datagram is processed inside the call that completes the handshake, so
`onStreamData` fires before a caller that attaches callbacks after
`serveHandshake` has attached them, and the request is dropped. `Stream`
retains the bytes, but they are not replayed when a callback appears.

Servers must install `cbs` before driving the handshake. Making this safe
would mean buffering until a consumer exists.

## Related

* [Protocol: HTTP/3](/protocols/http-3)
* [Protocol: UDP](/protocols/udp)
* [Example: HTTP/3 QUIC](/examples/http3-quic)