# HTTP/3 Protocol

> Status: live. `client.get(url, .{ .httpVersion = .http3 })` performs a
> real QUIC + TLS 1.3 handshake (ALPN `h3`, verified chain) over UDP and
> returns the response. Loss recovery and congestion control are
> implemented and integrated into the receive path (`loss.zig`,
> `cc.zig`); earlier revisions of this page claimed otherwise.
>
> Verified over loopback only. Every HTTP/3 test drives this
> implementation against itself, so no test runs it against an independent
> QUIC stack. Outside its scope it fails loudly, never silently
> downgraded. See [Interop Status](/reference/interop-status) for the
> transport-level gaps and [QUIC](/protocols/quic) for what the transport
> does not implement.

## Motivation

While HTTP/2 eliminated head-of-line blocking at the application level, TCP head-of-line blocking remained: when a single TCP packet is dropped, all interleaved HTTP/2 streams stall until the missing segment is retransmitted. HTTP/3 resolves this fundamentally by running over QUIC and UDP.

## What is not implemented

* **Server push** is refused, not ignored: a push stream is rejected with
  `frameUnexpected` under the no-push policy (RFC 9114 6.2.3). That is
  conformant -- push is optional and clients may not require it -- but
  anything relying on push will not work.
* **HTTP Datagrams** (RFC 9297) are not part of the frame set here.

The transport-level gaps that HTTP/3 inherits -- Version Negotiation, Path MTU
Discovery, connection migration -- are listed under
[QUIC](/protocols/quic#what-is-not-implemented).

## Architecture Comparison

```text
       HTTP/1.1 & HTTP/2                  HTTP/3
   +-----------------------+     +-----------------------+
   |  HTTP/1.1  |  HTTP/2  |     |        HTTP/3         |
   +-----------------------+     +-----------------------+
   |         TLS           |     |         QPACK         |
   +-----------------------+     +-----------------------+
   |         TCP           |     |     QUIC (TLS 1.3)    |
   +-----------------------+     +-----------------------+
   |          IP           |     |          UDP          |
   +-----------------------+     +-----------------------+
```

## Core Advantages

1. **Zero Transport Head-of-Line Blocking**: Each stream is delivered independently. Packet loss in stream A has zero impact on stream B.
2. **0-RTT Handshakes**: Combines transport connection setup and TLS 1.3 encryption keys into a single round trip.
3. **Connection Migration**: Mobile devices moving between Wi-Fi and Cellular networks maintain downloads seamlessly using 64-bit Connection IDs.
4. **QPACK Header Compression (RFC 9204)**: Dynamic table compression designed specifically for out-of-order packet delivery without deadlock.

## Client Usage Example

Live since the QUIC transport landing: `client.get` with
`.httpVersion = .http3` performs a real QUIC + TLS 1.3 handshake (ALPN
`h3`, verified chain) over UDP. Reliable paths (loopback/LAN) — no loss
recovery yet, so lossy networks stall to the request deadline. Runnable
end to end in `examples/http3Client.zig`:

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    var client = httpx.Client.init(allocator, io, .{});
    defer client.deinit();

    var response = try client.get("https://127.0.0.1:8443/", .{
        .httpVersion = .http3,
        .tls = .{ .verify = .caBundle, .caPem = ca_pem },
        .timeoutMs = 15_000,
    });
    defer response.deinit();

    std.debug.print("Status: {d}\n", .{response.status});
}
```

## Related

* [Protocol: QUIC](/protocols/quic)
* [Guide: HTTP/3](/guide/http3)
* [Example: HTTP/3 Client](/examples/http3-example)
