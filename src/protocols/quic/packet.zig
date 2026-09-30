//! QUIC packet header parsing and serialization (RFC 9000 sections 17.2,
//! 17.3). Long headers: Initial(0), 0-RTT(1), Handshake(2), Retry(3).
//! Short header (1-RTT): fixed bit pattern 0b010000xx.
//!
//! Reserved-bit validation happens AFTER header-protection removal (see
//! protect.zig); the parse functions here assume unprotected input.
//! Version negotiation packets are handled separately by conn.zig.

const std = @import("std");
const varint = @import("varint.zig");

pub const Version = enum(u32) {
    version1 = 0x00000001,
    version2 = 0x6B3343CF,
    _,

    pub fn isSupported(v: u32) bool {
        return v == @intFromEnum(Version.version1) or v == @intFromEnum(Version.version2);
    }
};

pub const LongType = enum(u2) {
    initial = 0,
    zeroRtt = 1,
    handshake = 2,
    retry = 3,

    /// Wire type bits differ for QUIC v2 (RFC 9369 section 3.2).
    pub fn wireType(self: LongType, version: u32) u2 {
        if (version == 0x00000001) return @intFromEnum(self);
        // v2 mapping: Initial=1, 0-RTT=2, Handshake=3, Retry=0
        return switch (self) {
            .initial => 1,
            .zeroRtt => 2,
            .handshake => 3,
            .retry => 0,
        };
    }

    pub fn fromWire(version: u32, w: u2) LongType {
        if (version == 0x00000001) return @enumFromInt(w);
        return switch (w) {
            0 => .retry,
            1 => .initial,
            2 => .zeroRtt,
            else => .handshake,
        };
    }
};

pub const HeaderError = error{ Truncated, UnsupportedVersion, InvalidPacket, BufferTooSmall, TooLarge };

/// Parsed long header fields. Slices reference the input buffer.
pub const LongHeader = struct {
    type: LongType,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8 = "",
    /// Offset of the packet number within the buffer.
    pnOffset: usize = 0,
    /// Value of the Length varint: PN bytes + protected payload + tag.
    length: u64 = 0,
};

pub const ShortHeader = struct {
    dcid: []const u8 = "",
    keyPhase: bool = false,
    pnOffset: usize = 0,
    pnLen: usize = 0,
};

pub fn isLongHeader(firstByte: u8) bool {
    return (firstByte & 0x80) != 0;
}

pub const ParseResult = struct { header: LongHeader, payloadOffset: usize };

fn take(data: []const u8, offset: *usize, length: u64) HeaderError![]const u8 {
    const len = std.math.cast(usize, length) orelse return HeaderError.TooLarge;
    if (offset.* > data.len or len > data.len - offset.*) return HeaderError.Truncated;
    const result = data[offset.*..][0..len];
    offset.* += len;
    return result;
}

/// Parses an UNPROTECTED long header starting at data[0]. Slices point
/// into data; `payloadOffset` is where the packet number begins.
pub fn parseLongHeader(data: []const u8) HeaderError!ParseResult {
    if (data.len < 6) return HeaderError.Truncated;
    const first = data[0];
    const version = std.mem.readInt(u32, data[1..5], .big);
    if (!Version.isSupported(version)) return HeaderError.UnsupportedVersion;
    var offset: usize = 5;

    const pktType = LongType.fromWire(version, @truncate((first >> 4) & 0x3));

    var h = LongHeader{
        .type = pktType,
        .version = version,
        .dcid = "",
        .scid = "",
    };

    const dcidLen: usize = data[offset];
    offset += 1;
    if (dcidLen > 20) return HeaderError.InvalidPacket;
    h.dcid = try take(data, &offset, dcidLen);

    if (offset >= data.len) return HeaderError.Truncated;
    const scidLen: usize = data[offset];
    offset += 1;
    if (scidLen > 20) return HeaderError.InvalidPacket;
    h.scid = try take(data, &offset, scidLen);

    if (pktType == .initial) {
        const tokLenRaw = try varint.decode(data, &offset);
        h.token = try take(data, &offset, tokLenRaw);
    }

    const lengthRaw = try varint.decode(data, &offset);
    h.length = lengthRaw;

    // Packet number sits AFTER the Length varint.
    h.pnOffset = offset;

    // Retry/VN have no Length/PN; this parser handles Initial/0RTT/Handshake.
    if (pktType == .retry) return HeaderError.InvalidPacket;

    return .{ .header = h, .payloadOffset = offset };
}

/// Parses an UNPROTECTED short header (1-RTT) starting at data[0].
/// `dcidLen` is the length of the destination CID expected for this connection (0..20).
pub fn parseShortHeader(data: []const u8, dcidLen: usize) HeaderError!ShortHeader {
    if (dcidLen > 20) return HeaderError.InvalidPacket;
    if (data.len < 1 + dcidLen) return HeaderError.Truncated;
    const first = data[0];
    if ((first & 0x80) != 0) return HeaderError.InvalidPacket;
    if ((first & 0x40) == 0) return HeaderError.InvalidPacket;
    const keyPhase = (first & 0x04) != 0;
    const pnLen: usize = @as(usize, first & 0x03) + 1;
    if (data.len < 1 + dcidLen + pnLen) return HeaderError.Truncated;
    return .{
        .dcid = data[1..][0..dcidLen],
        .keyPhase = keyPhase,
        .pnOffset = 1 + dcidLen,
        .pnLen = pnLen,
    };
}

// Serialization

pub const BuildInfo = struct {
    type: LongType,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8 = "",
    pnLen: usize,
    /// Payload bytes INCLUDING the AEAD tag (Length field value minus pn).
    protectedPayloadLen: usize,
};

/// Writes the long header up to (not including) the packet number.
/// Returns the number of header bytes written; the caller appends
/// pnLen packet-number bytes then the protected payload.
/// Builds a Version Negotiation packet (RFC 9000 section 17.2.1).
///
/// The fixed bit is 0 and the version field is 0; the connection IDs are
/// echoed back swapped, and the body is every version this endpoint speaks.
/// Sent in response to a long header carrying a version we do not know,
/// which is the whole reason the packet exists: without it a peer whose
/// preferred version is unsupported gets silence instead of a negotiation
/// it can act on.
pub fn writeVersionNegotiation(buf: []u8, dcid: []const u8, scid: []const u8) HeaderError!usize {
    if (dcid.len > 20 or scid.len > 20) return HeaderError.TooLarge;
    var pos: usize = 0;
    buf[pos] = 0x80; // long header, fixed bit 0
    pos += 1;
    @memcpy(buf[pos..][0..4], &[_]u8{ 0, 0, 0, 0 }); // version 0
    pos += 4;
    buf[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(buf[pos..][0..dcid.len], dcid);
    pos += dcid.len;
    buf[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(buf[pos..][0..scid.len], scid);
    pos += scid.len;
    for ([_]u32{ @intFromEnum(Version.version1), @intFromEnum(Version.version2) }) |v| {
        if (pos + 4 > buf.len) return HeaderError.BufferTooSmall;
        std.mem.writeInt(u32, buf[pos..][0..4], v, .big);
        pos += 4;
    }
    return pos;
}

pub fn writeLongHeader(buf: []u8, info: BuildInfo) HeaderError!usize {
    if (info.dcid.len > 20 or info.scid.len > 20) return HeaderError.InvalidPacket;
    if (info.pnLen == 0 or info.pnLen > 4) return HeaderError.InvalidPacket;
    const tokenVarintLen = if (info.type == .initial) varintWidth(info.token.len) else 0;
    const lengthValue = std.math.add(usize, info.protectedPayloadLen, info.pnLen) catch return HeaderError.TooLarge;
    const needed = 5 + 1 + info.dcid.len + 1 + info.scid.len + tokenVarintLen + info.token.len + varintWidth(lengthValue);
    if (buf.len < needed) return HeaderError.BufferTooSmall;

    const wt = info.type.wireType(info.version);
    buf[0] = 0xC0 | (@as(u8, wt) << 4) | (@as(u8, @intCast(info.pnLen - 1)) & 0x03);
    std.mem.writeInt(u32, buf[1..5], info.version, .big);

    var pos: usize = 5;
    buf[pos] = @intCast(info.dcid.len);
    pos += 1;
    @memcpy(buf[pos..][0..info.dcid.len], info.dcid);
    pos += info.dcid.len;

    buf[pos] = @intCast(info.scid.len);
    pos += 1;
    if (info.scid.len > 0) {
        @memcpy(buf[pos..][0..info.scid.len], info.scid);
        pos += info.scid.len;
    }

    if (info.type == .initial) {
        const n = try varint.encode(buf[pos..], info.token.len);
        pos += n;
        if (info.token.len > 0) {
            @memcpy(buf[pos..][0..info.token.len], info.token);
            pos += info.token.len;
        }
    }

    // Length covers PN bytes + protected payload (RFC 9000 17.2).
    const n = try varint.encode(buf[pos..], lengthValue);
    pos += n;
    return pos;
}

fn varintWidth(value: usize) usize {
    if (value <= 0x3F) return 1;
    if (value <= 0x3FFF) return 2;
    if (value <= 0x3FFFFFFF) return 4;
    return 8;
}

pub const ShortBuildInfo = struct {
    keyPhase: bool = false,
    dcid: []const u8,
    pnLen: usize,
};

/// Writes the short header up to the packet number. Returns bytes written.
pub fn writeShortHeader(buf: []u8, info: ShortBuildInfo) HeaderError!usize {
    if (info.dcid.len > 20 or info.pnLen == 0 or info.pnLen > 4) return HeaderError.InvalidPacket;
    if (buf.len < 1 + info.dcid.len) return HeaderError.BufferTooSmall;
    buf[0] = 0x40 | (@as(u8, if (info.keyPhase) 1 else 0) << 2) | @as(u8, @intCast(info.pnLen - 1));
    var pos: usize = 1;
    @memcpy(buf[pos..][0..info.dcid.len], info.dcid);
    pos += info.dcid.len;
    return pos;
}

// Tests

test "long header detection" {
    try std.testing.expect(isLongHeader(0xC3));
    try std.testing.expect(!isLongHeader(0x43));
}

test "long header write/parse roundtrip with token" {
    var buf: [128]u8 = undefined;
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const scid = [_]u8{ 0x11, 0x22, 0x33 };
    const token = "some-token";

    const n = try writeLongHeader(buf[0..], .{
        .type = .initial,
        .version = 0x00000001,
        .dcid = dcid[0..],
        .scid = scid[0..],
        .token = token,
        .pnLen = 2,
        .protectedPayloadLen = 100,
    });

    const res = try parseLongHeader(buf[0..n]);
    try std.testing.expectEqual(LongType.initial, res.header.type);
    try std.testing.expectEqual(@as(u32, 1), res.header.version);
    try std.testing.expectEqualSlices(u8, dcid[0..], res.header.dcid);
    try std.testing.expectEqualSlices(u8, scid[0..], res.header.scid);
    try std.testing.expectEqualStrings(token, res.header.token);
    try std.testing.expectEqual(@as(u64, 102), res.header.length);
    try std.testing.expectEqual(@as(usize, n), res.payloadOffset);
    try std.testing.expectEqual(@as(usize, n), res.header.pnOffset);
}

test "v2 wire type remapping roundtrips" {
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 1, 2, 3, 4 };
    const n = try writeLongHeader(buf[0..], .{
        .type = .handshake,
        .version = 0x6B3343CF,
        .dcid = dcid[0..],
        .scid = "",
        .pnLen = 1,
        .protectedPayloadLen = 10,
    });
    // v2 Handshake wire type 3 -> first byte 0b1111_0000.
    try std.testing.expectEqual(@as(u8, 0xF0), buf[0]);

    const res = try parseLongHeader(buf[0..n]);
    try std.testing.expectEqual(LongType.handshake, res.header.type);
    try std.testing.expectEqual(@as(u32, 0x6B3343CF), res.header.version);
}

test "short header roundtrip" {
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF } ++ [4]u8{ 1, 2, 3, 4 };
    const n = try writeShortHeader(buf[0..], .{ .keyPhase = true, .dcid = dcid[0..], .pnLen = 3 });
    try std.testing.expectEqual(@as(u8, 0x46), buf[0]); // 0x40 | kp(0x04) | pnLen-1(2)
    try std.testing.expectEqual(@as(usize, 9), n);
    try std.testing.expectEqualSlices(u8, dcid[0..], buf[1..n]);
}

test "truncated headers rejected cleanly at every cut" {
    var buf: [128]u8 = undefined;
    const n = try writeLongHeader(buf[0..], .{
        .type = .initial,
        .version = 0x00000001,
        .dcid = &.{ 1, 2, 3 },
        .scid = &.{},
        .token = "t",
        .pnLen = 1,
        .protectedPayloadLen = 5,
    });
    for (0..n) |cut| {
        try std.testing.expectError(
            HeaderError.Truncated,
            parseLongHeader(buf[0..cut]),
        );
    }
}

test "version negotiation packet echoes ids and lists our versions" {
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const scid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    var buf: [128]u8 = undefined;

    const n = try writeVersionNegotiation(&buf, &dcid, &scid);

    // Fixed bit 0, version field 0, then the ids back the other way round.
    try std.testing.expectEqual(@as(u8, 0x80), buf[0]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, buf[1..5]);
    try std.testing.expectEqual(@as(u8, dcid.len), buf[5]);
    try std.testing.expectEqualSlices(u8, &dcid, buf[6..10]);
    try std.testing.expectEqual(@as(u8, scid.len), buf[10]);
    try std.testing.expectEqualSlices(u8, &scid, buf[11..17]);

    // The body is every version we speak, so a peer can pick one.
    const versions = n - 17;
    try std.testing.expectEqual(@as(usize, 8), versions);
    try std.testing.expectEqual(
        @as(u32, @intFromEnum(Version.version1)),
        std.mem.readInt(u32, buf[17..21], .big),
    );
    try std.testing.expectEqual(
        @as(u32, @intFromEnum(Version.version2)),
        std.mem.readInt(u32, buf[21..25], .big),
    );
}
