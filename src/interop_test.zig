//! Interop tests that drive a live server with real third-party clients.
//!
//! The rest of the suite talks to httpx with httpx, so a wire-format or
//! handshake regression that stays self-consistent is invisible to it. These
//! tests close that gap: `curl` and `openssl s_client` are independent
//! implementations, so agreeing with them is real evidence.
//!
//! They are opt-in because they need real binaries and loopback listeners.
//! Set `HTTPX_INTEROP=1` to run them; the default suite skips them, which is
//! what keeps the three-OS matrix hermetic and fast.
//!
//! On capability rather than version: X25519MLKEM768 needs OpenSSL 3.5+, and
//! no GitHub runner ships it by default (macOS ships LibreSSL, Ubuntu 24.04
//! ships 3.0). So the post-quantum assertion runs only where the local
//! `openssl` actually offers ML-KEM, and the handshake is still verified
//! everywhere. Capability is detected, not assumed, so the test degrades to
//! what it can honestly prove instead of failing or quietly passing.

const std = @import("std");
const builtin = @import("builtin");
const httpx = @import("httpx.zig");
const clock = @import("common/clock.zig");

const interopCert = @embedFile("protocols/tls/testdata/localhostCert.pem");
const interopKey = @embedFile("protocols/tls/testdata/localhostKey.pem");

/// The hybrid group the post-quantum port offers. OpenSSL spells it exactly
/// this way, and it is also the name we send in the key share.
const hybridGroup = "X25519MLKEM768";

fn interopEnabled() bool {
    if (builtin.os.tag == .windows) return false;
    const v = std.process.Environ.getPosix(std.testing.environ, "HTTPX_INTEROP") orelse return false;
    return v.len > 0 and v[0] == '1';
}

fn skipUnlessInterop() bool {
    return !interopEnabled();
}

/// Whether this `openssl` can be asked for `group` at all.
///
/// X25519MLKEM768 arrived in OpenSSL 3.5, and no CI runner ships it: macOS
/// provides LibreSSL, Ubuntu 24.04 provides 3.0.13. So the question has to
/// be asked of the binary rather than of the version, because a
/// distribution backport would answer "no" to the version and "yes" here.
///
/// Asks positively -- does the group appear in the library's group list --
/// instead of reading the error text. Matching on rejection messages is a
/// guess about wording that varies by version: 3.0 rejects with
/// `group 'X25519MLKEM768' cannot be set` after
/// `SSL_CONF_cmd(-groups, ...) failed`, which matched none of the strings
/// the test used to look for, so the hybrid test failed on Ubuntu instead of
/// skipping. A positive lookup cannot miss that way.
fn opensslKnowsGroup(alloc: std.mem.Allocator, io: std.Io, group: []const u8) bool {
    const listing = runClient(alloc, io, &.{ "openssl", "list", "-kem-algorithms" }, null) catch return false;
    defer alloc.free(listing);
    return std.mem.indexOf(u8, listing, group) != null;
}

/// Runs `argv`, feeding it `input` on stdin, and returns stdout and stderr
/// concatenated. Never rejects on a non-zero exit: a failing client is a
/// result to assert on, not an error in the test.
fn runClient(alloc: std.mem.Allocator, io: std.Io, argv: []const []const u8, input: ?[]const u8) ![]u8 {
    const stdinPath = ".httpx-interop-stdin";
    var stdinFile: ?std.Io.File = null;
    if (input) |text| {
        {
            var tmp = try std.Io.Dir.cwd().createFile(io, stdinPath, .{});
            defer tmp.close(io);
            try tmp.writeStreamingAll(io, text);
        }
        stdinFile = try std.Io.Dir.cwd().openFile(io, stdinPath, .{});
    }
    defer {
        if (stdinFile) |f| f.close(io);
        std.Io.Dir.cwd().deleteFile(io, stdinPath) catch {};
    }

    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = if (stdinFile) |f| .{ .file = f } else .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var buf: [4096]u8 = undefined;
    if (child.stdout) |f| {
        var r = f.reader(io, &buf);
        try r.interface.appendRemainingUnlimited(alloc, &out);
    }
    var ebuf: [4096]u8 = undefined;
    if (child.stderr) |f| {
        var r = f.reader(io, &ebuf);
        var eout: std.ArrayList(u8) = .empty;
        defer eout.deinit(alloc);
        r.interface.appendRemainingUnlimited(alloc, &eout) catch {};
        try out.appendSlice(alloc, eout.items);
    }
    _ = child.wait(io) catch {};
    return out.toOwnedSlice(alloc);
}

fn helloHandler(_: *httpx.Context) anyerror!httpx.Response {
    return .{ .status = 200, .body = "httpx-interop-ok", .contentType = "text/plain" };
}

const Harness = struct {
    server: *httpx.Server,
    thread: std.Thread,
    port: u16,

    fn start(alloc: std.mem.Allocator, io: std.Io, use_tls: bool) !Harness {
        const server = try alloc.create(httpx.Server);
        errdefer alloc.destroy(server);
        server.* = try httpx.Server.init(alloc, io, .{
            .host = "127.0.0.1",
            .port = 0,
            .maxConnections = 4,
            .enableDocs = false,
            .logging = .{},
            .tls = if (use_tls)
                .{ .certificatePem = interopCert, .privateKeyPem = interopKey }
            else
                null,
        });
        errdefer server.deinit();
        try server.get("/ping", helloHandler);
        const port = server.localPort();

        const Run = struct {
            fn go(s: *httpx.Server) void {
                s.run();
            }
        };
        const thread = try std.Thread.spawn(.{}, Run.go, .{server});
        return .{ .server = server, .thread = thread, .port = port };
    }

    /// A server speaking HTTP/3 over QUIC, for the aioquic client.
    ///
    /// Same shape as the HTTP/1.1 harness: bind, then run on a thread so the
    /// child process has someone to answer it. `httpVersion = .http3` is what
    /// selects the QUIC transport and the `h3` ALPN; the certificate is the
    /// self-signed test pair.
    fn startHttp3(alloc: std.mem.Allocator, io: std.Io) !Harness {
        const server = try alloc.create(httpx.Server);
        errdefer alloc.destroy(server);
        server.* = try httpx.Server.init(alloc, io, .{
            .host = "127.0.0.1",
            .port = 0,
            .maxConnections = 4,
            .enableDocs = false,
            .logging = .{},
            .httpVersion = .http3,
            .tls = .{ .certificatePem = interopCert, .privateKeyPem = interopKey },
        });
        errdefer server.deinit();
        try server.get("/ping", helloHandler);
        const port = server.localPort();

        const Run = struct {
            fn go(s: *httpx.Server) void {
                s.run();
            }
        };
        const thread = try std.Thread.spawn(.{}, Run.go, .{server});
        return .{ .server = server, .thread = thread, .port = port };
    }

    fn stop(self: *Harness, alloc: std.mem.Allocator) void {
        self.server.stop();
        self.thread.join();
        self.server.deinit();
        alloc.destroy(self.server);
    }
};

test "interop: curl parses a real HTTP/1.1 response" {
    if (skipUnlessInterop()) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;

    var h = try Harness.start(a, io, false);
    defer h.stop(a);

    const url = try std.fmt.allocPrint(a, "http://127.0.0.1:{d}/ping", .{h.port});
    defer a.free(url);

    const out = try runClient(a, io, &.{ "curl", "--silent", "--show-error", "--include", "--max-time", "20", url }, null);
    defer a.free(out);

    // A real client must see a well-formed status line, our header, and the
    // exact body. If we ever emit a malformed response, curl notices here.
    try std.testing.expect(std.mem.indexOf(u8, out, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Content-Type: text/plain") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "httpx-interop-ok") != null);
}

test "interop: openssl s_client completes a TLS 1.3 handshake with us" {
    if (skipUnlessInterop()) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;

    // The test cert is self-signed, so it doubles as its own trust anchor.
    // Verifying against it is what makes "Verification: OK" mean something.
    const caPath = ".httpx-interop-ca.pem";
    {
        var f = try std.Io.Dir.cwd().createFile(io, caPath, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, interopCert);
    }
    defer std.Io.Dir.cwd().deleteFile(io, caPath) catch {};

    var h = try Harness.start(a, io, true);
    defer h.stop(a);

    const addr = try std.fmt.allocPrint(a, "127.0.0.1:{d}", .{h.port});
    defer a.free(addr);
    const out = try runClient(a, io, &.{
        "openssl",  "s_client",
        "-connect", addr,
        "-CAfile",  caPath,
        "-alpn",    "http/1.1",
        "-verify",  "1",
        "-brief",   "-no_ign_eof",
    }, "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    defer a.free(out);

    // Each of these is OpenSSL's own report of a real handshake; if the
    // server ever emits a ServerHello a strict client dislikes, we see it
    // here rather than in a user's curl.
    try std.testing.expect(std.mem.indexOf(u8, out, "Protocol version: TLSv1.3") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Ciphersuite:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Verification: OK") != null);
}

test "interop: curl over HTTPS with SNI" {
    if (skipUnlessInterop()) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;

    var h = try Harness.start(a, io, true);
    defer h.stop(a);

    // --resolve makes curl use the hostname `localhost` (so it sends SNI, as
    // every real client does) while still dialling our loopback port. Without
    // it curl would connect to an IP literal and omit SNI entirely, which is
    // exactly the case that is known to work -- so the test would pass while
    // hiding the bug.
    const addr = try std.fmt.allocPrint(a, "localhost:{d}:127.0.0.1", .{h.port});
    defer a.free(addr);
    const url = try std.fmt.allocPrint(a, "https://localhost:{d}/ping", .{h.port});
    defer a.free(url);
    const out = try runClient(a, io, &.{
        "curl",         "--silent",
        "--show-error", "--insecure",
        "--include",    "--max-time",
        "20",           "--resolve",
        addr,           url,
    }, null);
    defer a.free(out);

    std.debug.print("\n---CURL-OUT---\n{s}\n---END---\n", .{out});
    try std.testing.expect(std.mem.indexOf(u8, out, "HTTP/1.1 200") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "httpx-interop-ok") != null);
}

test "interop: OpenSSL negotiates the post-quantum hybrid group" {
    if (skipUnlessInterop()) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;

    // Asked before anything is set up: this is a property of the local
    // openssl, so there is no reason to write a certificate or bind a port
    // to find out. Where the group is missing the post-quantum path is
    // untestable rather than broken, and skipping says exactly that -- it
    // failed the run before by not being detected.
    if (!opensslKnowsGroup(a, io, hybridGroup)) {
        std.debug.print("\n---OPENSSL-HYBRID (openssl lacks {s})---\n---END---\n", .{hybridGroup});
        return error.SkipZigTest;
    }

    const caPath = ".httpx-interop-ca.pem";
    {
        var f = try std.Io.Dir.cwd().createFile(io, caPath, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, interopCert);
    }
    defer std.Io.Dir.cwd().deleteFile(io, caPath) catch {};

    var h = try Harness.start(a, io, true);
    defer h.stop(a);

    // Restricting to the hybrid is what makes this meaningful: with no
    // fallback group offered, a server that can only answer x25519 has no
    // move left, so this either negotiates the hybrid or fails loudly.
    const addr = try std.fmt.allocPrint(a, "127.0.0.1:{d}", .{h.port});
    defer a.free(addr);
    const out = try runClient(a, io, &.{
        "openssl",  "s_client",
        "-connect", addr,
        "-CAfile",  caPath,
        "-groups",  hybridGroup,
        "-brief",
    }, null);
    defer a.free(out);

    std.debug.print("\n---OPENSSL-HYBRID---\n{s}\n---END---\n", .{out});
    try std.testing.expect(std.mem.indexOf(u8, out, hybridGroup) != null);
    // `-brief` reports the result as `Verification: OK`, not the long form.
    try std.testing.expect(std.mem.indexOf(u8, out, "Verification: OK") != null);
}

/// An `openssl s_server` pinned to a single group.
///
/// Restricting the server is what turns a completed handshake into evidence.
/// With one group on offer there is nothing to fall back to, so a client that
/// gets through used that group or did not get through. This is the mirror of
/// the test above: there we are the server and OpenSSL picks the group, here
/// OpenSSL is the server and we do. The `s_client` test alone only exercises
/// the half of the key exchange we answer.
const OpenSslServer = struct {
    child: std.process.Child,
    port: u16,
    cert_path: []const u8,
    key_path: []const u8,
    out_path: []const u8,
    reaped: bool = false,

    const certFile = ".httpx-interop-sserver-cert.pem";
    const keyFile = ".httpx-interop-sserver-key.pem";
    const logFile = ".httpx-interop-sserver.log";

    fn start(alloc: std.mem.Allocator, io: std.Io, group: ?[]const u8) !OpenSslServer {
        {
            var f = try std.Io.Dir.cwd().createFile(io, certFile, .{});
            defer f.close(io);
            try f.writeStreamingAll(io, interopCert);
        }
        {
            var f = try std.Io.Dir.cwd().createFile(io, keyFile, .{});
            defer f.close(io);
            try f.writeStreamingAll(io, interopKey);
        }
        errdefer std.Io.Dir.cwd().deleteFile(io, certFile) catch {};
        errdefer std.Io.Dir.cwd().deleteFile(io, keyFile) catch {};

        // Ask the OS for a free port, then hand it to OpenSSL. A listener
        // bound to :0 is the only way to learn a port that is actually free;
        // the window between closing it and OpenSSL binding is small and the
        // readiness poll below covers a lost race.
        var probe = try httpx.tcp.Listener.bind(io, 0);
        const port = probe.localPort();
        probe.close(io);

        const accept = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{port});
        defer alloc.free(accept);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(alloc);
        try argv.append(alloc, "openssl");
        try argv.append(alloc, "s_server");
        try argv.append(alloc, "-accept");
        try argv.append(alloc, accept);
        try argv.append(alloc, "-cert");
        try argv.append(alloc, certFile);
        try argv.append(alloc, "-key");
        try argv.append(alloc, keyFile);
        if (group) |g| {
            try argv.append(alloc, "-groups");
            try argv.append(alloc, g);
        }
        // No `-naccept` cap: the readiness probe below opens a connection of
        // its own, and a one-shot server would spend its single accept on
        // that and exit before the real client arrived. Lifetime is bounded by
        // `deinit`, which kills it.
        //
        // Deliberately no `-brief`: on this build it writes nothing to a
        // redirected stream, and it also suppresses the session counters that
        // are the only usable diagnostic if the handshake fails.
        try argv.append(alloc, "-www");

        // Output goes to a file rather than a pipe. The server outlives the
        // test body and is terminated, not shut down politely, so draining a
        // pipe to EOF first would block forever and killing first would close
        // the pipe unread. A file has neither problem: read it after the kill.
        const log = try std.Io.Dir.cwd().createFile(io, logFile, .{});
        defer log.close(io);

        var child = try std.process.spawn(io, .{
            .argv = argv.items,
            .stdin = .ignore,
            .stdout = .{ .file = log },
            .stderr = .{ .file = log },
        });
        errdefer child.kill(io);

        var self: OpenSslServer = .{
            .child = child,
            .port = port,
            .cert_path = certFile,
            .key_path = keyFile,
            .out_path = logFile,
        };
        try self.waitUntilListening(io);
        return self;
    }

    /// Blocks until the server accepts connections, or gives up.
    ///
    /// `spawn` returning is not the same as the port being bound, and
    /// `-accept` is a race with our own connect: without this the client
    /// reliably wins it and reports `ConnectionRefused` for a server that
    /// works. Probing with a plain TCP connect also proves the listener is
    /// serving, not merely that the process exists.
    fn waitUntilListening(self: *OpenSslServer, io: std.Io) !void {
        // Bounded by iteration count rather than a deadline: it is the same
        // ~20s of wall clock either way, and counting retries needs no clock.
        var attempt: usize = 0;
        while (attempt < 1000) : (attempt += 1) {
            if (httpx.tcp.connect(io, "127.0.0.1", self.port)) |sock| {
                var s = sock;
                s.close();
                return;
            } else |_| {}
            clock.sleepMillis(20);
        }
        return error.OpenSslServerNeverListened;
    }

    /// Reaps the child and returns everything it printed, stdout and stderr
    /// together. Kills it first if it is still running: a failed handshake on
    /// our side can leave OpenSSL waiting, and a test must not hang on that.
    /// Terminates the server and returns everything it wrote to its log.
    ///
    /// `Child.kill` already blocks until the process is gone and reaps it, so
    /// there is no `wait` to follow: calling one would assert on a process id
    /// that no longer exists.
    fn output(self: *OpenSslServer, alloc: std.mem.Allocator, io: std.Io) ![]u8 {
        if (!self.reaped) {
            self.child.kill(io);
            self.reaped = true;
        }

        const file = try std.Io.Dir.cwd().openFile(io, self.out_path, .{});
        defer file.close(io);
        const stat = try file.stat(io);
        const len: usize = @intCast(stat.size);
        if (len == 0) return alloc.alloc(u8, 0);
        // The process is gone, so the size is final: allocate exactly that and
        // read it in one call rather than growing a buffer we cannot predict.
        const buf = try alloc.alloc(u8, len);
        errdefer alloc.free(buf);
        const n = try file.readPositionalAll(io, buf, 0);
        return buf[0..n];
    }

    fn deinit(self: *OpenSslServer, alloc: std.mem.Allocator, io: std.Io) void {
        if (!self.reaped) {
            self.child.kill(io);
            self.reaped = true;
        }
        std.Io.Dir.cwd().deleteFile(io, self.cert_path) catch {};
        std.Io.Dir.cwd().deleteFile(io, self.key_path) catch {};
        std.Io.Dir.cwd().deleteFile(io, self.out_path) catch {};
        _ = alloc;
    }
};

test "interop: our client completes a post-quantum handshake with openssl s_server" {
    if (skipUnlessInterop()) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;

    if (!opensslKnowsGroup(a, io, hybridGroup)) {
        std.debug.print("\n---OPENSSL-SSERVER-HYBRID (openssl lacks {s})---\n---END---\n", .{hybridGroup});
        return error.SkipZigTest;
    }

    var srv = try OpenSslServer.start(a, io, hybridGroup);
    defer srv.deinit(a, io);

    // The test certificate is self-signed and for 127.0.0.1, so it is its own
    // trust anchor here exactly as it is for the `s_client` test.
    var client = httpx.Client.init(a, io, .{
        .tls = .{ .verify = .selfSigned },
    });
    defer client.deinit();

    const url = try std.fmt.allocPrint(a, "https://127.0.0.1:{d}/", .{srv.port});
    defer a.free(url);

    // The status code is the whole proof, and the pinning is what makes it
    // one. OpenSSL is started with `-groups X25519MLKEM768` and nothing else,
    // so it has no group to fall back to: a request that comes back at all was
    // carried by the hybrid. A client that failed to offer it does not get a
    // weaker handshake, it gets `no suitable key share` and no response.
    //
    // Asserting the group name out of OpenSSL's own output would read better,
    // but `s_server -brief` writes nothing at all to a redirected stream --
    // measured, not assumed -- so there is nothing to read. The session stats
    // it does print are kept for diagnosis and are not the assertion.
    const respConst = try client.get(url, .{});
    var resp = respConst;
    defer resp.deinit();

    const out = try srv.output(a, io);
    defer a.free(out);
    std.debug.print("\n---OPENSSL-SSERVER-HYBRID---\n{s}\n---END---\n", .{out});

    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

/// The HTTP/3 client driven by the QUIC interop test.
///
/// Kept as a real file rather than a string literal so it stays readable and
/// can be run by hand against a listening server, which is how the QUIC
/// interop work was debugged in the first place.
const aioquicClient = @embedFile("protocols/quic/testdata/aioquic_client.py");

/// Whether a usable aioquic is importable.
///
/// Asked of the interpreter rather than assumed from a version, for the same
/// reason `opensslKnowsGroup` asks the binary: a distribution could ship the
/// package under a version this test did not anticipate, and asserting on the
/// absence of a feature we never installed is not evidence of anything.
fn aioquicAvailable(io: std.Io) bool {
    var child = std.process.spawn(io, .{
        .argv = &.{ "python3", "-c", "import aioquic, sys; sys.exit(0)" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    const term = child.wait(io) catch return false;
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

test "interop: aioquic completes an HTTP/3 request against us" {
    if (skipUnlessInterop()) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;

    // No runner ships aioquic, so this is the one interop test that may
    // legitimately skip on capability rather than version.
    if (!aioquicAvailable(io)) {
        std.debug.print("\nSKIP aioquic not importable; HTTP/3 interop not exercised\n", .{});
        return error.SkipZigTest;
    }

    var h = try Harness.startHttp3(a, io);
    defer h.stop(a);

    const scriptPath = ".httpx-interop-aioquic.py";
    {
        var f = try std.Io.Dir.cwd().createFile(io, scriptPath, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, aioquicClient);
    }
    defer std.Io.Dir.cwd().deleteFile(io, scriptPath) catch {};

    const portStr = try std.fmt.allocPrint(a, "{d}", .{h.port});
    defer a.free(portStr);

    const out = try runClient(a, io, &.{ "python3", scriptPath, portStr }, null);
    defer a.free(out);
    if (std.mem.indexOf(u8, out, "RESULT ok") == null) {
        std.debug.print("\n---AIOQUIC-OUTPUT---\n{s}\n---END---\n", .{out});
    }

    // Each of these is the client's own report. A QUIC or HTTP/3 regression
    // that we were making to ourselves would not show up here, which is the
    // whole reason this test exists.
    try std.testing.expect(std.mem.indexOf(u8, out, "HANDSHAKE completed") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "STATUS 200") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "httpx-interop-ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "RESULT ok") != null);
}
