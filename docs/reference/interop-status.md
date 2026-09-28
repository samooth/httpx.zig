# Interop Status

This page records what real third-party clients do against httpx, and what
they do not. It exists because the unit suite cannot answer either question:
it drives httpx with httpx, so any regression that stays self-consistent
across both ends passes every test we have. Three defects got through that
way and were only ever caught by `curl` and `openssl s_client`.

The interop tests live in `src/interop_test.zig` and are opt-in, because they
need real binaries and loopback listeners. Run them with:

```sh
HTTPX_INTEROP=1 zig build test
```

CI runs them in a separate `interop` job on Linux and macOS so the main
three-OS matrix stays hermetic.

## Fixed

### server_name acknowledgement rejected by OpenSSL

The ServerHello carried an empty `server_name` extension. OpenSSL's
extension table lists `server_name` as valid in `SSL_EXT_CLIENT_HELLO`,
`SSL_EXT_TLS1_2_SERVER_HELLO` and `SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS`,
but not `SSL_EXT_TLS1_3_SERVER_HELLO`, so `tls_validate_all_contexts`
fails and the client aborts with `illegal_parameter` before any key
exchange.

Since every real client sends SNI, this cut off effectively all of them.
Our own client skips extensions it does not recognise, so both ends agreed
on a ServerHello no third party accepts and no unit test noticed. The
acknowledgement is now omitted: it carries nothing the client lacks, and
clients are not entitled to require it.

### Template arena never freed

Not strictly interop, but found the same way. `Renderer.render` declared
`ctx: *const Context` and then mutated the arena through it with
`@constCast`. Zig emits `readonly` on the pointee from the parameter type
and LLVM does not reconsider it because the body writes anyway, so
`Engine.render` could assume the arena's node list was still null, see the
free loop as provably empty, and fold `defer ctx.deinit()` away. Every node
pushed during a render leaked. See the `*Context` guard in `renderer.zig`.

## Open

### `h2` is advertised but not implemented

`Server.Config.alpn` defaults to `alpnMod.DEFAULT_TCP_PREFERENCE`, which
leads with `h2`. The HTTP layer has an `http2` flag but no HTTP/2
implementation behind it.

So the server negotiates `h2` with any modern client and then does not
speak it. Measured: `curl https://host/ping` fails with `curl: (56)`,
while the same request with `--http1.1` returns `HTTP/1.1 200 OK`. Every
browser and a default `curl` hit this on HTTPS.

The fix is to have `Server` pass TLS the protocol list it can actually
serve, tied to its `httpVersion` configuration, rather than changing the
default preference in place — the current default also leaves
`Config.http2 = true` asserting something untrue. Until then, use
`--http1.1` or configure `alpn` explicitly.

### X25519MLKEM768 is client-side only

The post-quantum hybrid key exchange is implemented for outgoing handshakes
only. A server's ServerHello `key_share` is hardcoded to `x25519` with a
32-byte length, so a client that offers only `X25519MLKEM768` is rejected
with `tls_parse_stoc_key_share: bad key share`. That is the default
posture of OpenSSL 3.5 and later.

The interop test that would catch this is written and disabled in
`src/interop_test.zig`, with the reason recorded inline, so it passes the
moment the server half lands.

## A note on the post-quantum test

`X25519MLKEM768` needs OpenSSL 3.5 or later, and no GitHub runner ships it:
macOS provides LibreSSL, Ubuntu 24.04 provides 3.0. The test therefore
detects the capability instead of assuming it, and the `interop` job
installs OpenSSL 3.5 on macOS so that path is actually reachable. Asserting
the group against a client that cannot speak it would prove nothing.

## A note on leak detection

`zig build test` is the only command that reliably reports allocation leaks
in optimised builds. DebugAllocator's leak check is gated on
`config.safety`, which ReleaseFast does not set, so running the test binary
directly reports nothing. The `--listen=` runner path that the build system
uses calls `detectLeaks()` explicitly and does report.
