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

### `h2` advertised through ALPN but not implemented

`Server.Config.alpn` defaulted to `alpnMod.DEFAULT_TCP_PREFERENCE`, which
leads with `h2`, while the HTTP layer has an `http2` flag with no HTTP/2
framing behind it. The server therefore negotiated `h2` with any modern
client and then did not speak it: `curl https://host/ping` failed with
`curl: (56)` while the same request with `--http1.1` returned
`HTTP/1.1 200 OK`. Every browser and a default `curl` hit this on HTTPS.

`Server.init` now derives the ALPN preference from the protocols it can
actually speak, storing the corrected list on the config so that certificate
reload — which rebuilds the TLS server from `self.cfg.tls.?.alpn` — does not
reintroduce the default. A list chosen explicitly is left alone, including a
deliberate `h2`.

`Config.http2` still exists and still defaults to `true`; it is not wired to
any framing, so it should not be read as a capability. HTTP/2 remains
unimplemented — the fix is that we no longer claim it.

### X25519MLKEM768 works in both directions

Both roles offer and accept the hybrid group. The interop test in
`src/interop_test.zig` — gated on `HTTPX_INTEROP=1` — runs
`openssl s_client -groups X25519MLKEM768 -brief` against a live harness and
requires `Negotiated TLS1.3 group: X25519MLKEM768`, so it passes exactly
while the group works and fails the moment it stops.

#### The trap: one group name, two incompatible constructions

`X25519MLKEM768` names a key-share encoding, not a shared-secret rule. Two
constructions encode it identically and still cannot interoperate:

|  | RFC 10024 `X25519MLKEM768` | X-Wing |
|---|---|---|
| client share | 1216 = 1184 ML-KEM + 32 X25519 | 1216, same layout |
| server share | 1120 = 1088 ML-KEM + 32 X25519 | 1120, same layout |
| shared secret | `ss_M ‖ ss_X`, **64 bytes** | `SHA3-256(label ‖ …)`, **32 bytes** |
| who speaks it | OpenSSL 3.5+, Chrome, Firefox | nobody over TLS |

Zig's `std.crypto.kem.hybrid.MlKem768X25519` is X-Wing, and the byte order it
uses (ML-KEM first) happens to match RFC 10024 as well — so every size check
passes and the handshake reaches the first encrypted record before failing
with `decryption failed or bad record mac`. Nothing in the error names the
construction, which is why this is worth writing down.

HTTPX implements RFC 10024: ML-KEM via `std.crypto.kem.ml_kem.MLKem768`, X25519
via `std.crypto.dh.X25519`, combined by concatenation with no hashing. The
X25519 half reuses `Engine.localKeypair`, the connection's single ephemeral,
so the hybrid needs no keypair of its own.

Two details that cost time:

- **Do not pad the secret to 64 bytes for the plain group.** HKDF-Extract is
  length-sensitive, so `sharedSecret` carries an explicit `len` rather than
  being sized to the larger of the two.
- **`fn slice(self: SharedSecret)` taking `self` by value returns a pointer
  into the parameter copy** and dies on return. Every caller then reads a
  dangling buffer; the symptom is `TlsBadRecordMac` from a peer that agrees
  on everything else. It must take `*const SharedSecret`.

The `Engine` is stack-local inside `Server.acceptBuffered`, one per
connection, so per-handshake hybrid state on it is private and needs no
synchronisation.
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
