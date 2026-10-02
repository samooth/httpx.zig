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
/// Parsed Version Negotiation packet (RFC 9000 section 17.2.1).
///
/// This is the one packet whose Version field is zero, so it is not
/// version-specific and is recognised on receipt by that field rather
/// than by parsing it as an ordinary long header.
pub const VersionNegotiation = struct {
    /// Must equal the Source Connection ID we sent, and the Source must
    /// equal the Destination Connection ID we chose. Echoing both is the
    /// only thing distinguishing a real reply from a forged one.
    dcid: []const u8,
    scid: []const u8,
    /// The versions the peer speaks, in its own order of preference.
    /// Points into the input buffer.
    /// Raw 4-byte version entries in wire order, still inside the
    /// input buffer. Not decoded to u32 here because this runs on the
    /// receive path of a packet we did not ask for, and there is no
    /// reason to allocate in order to read it.
    versionBytes: []const u8,

    pub fn count(self: VersionNegotiation) usize {
        return self.versionBytes.len / 4;
    }

    pub fn versionAt(self: VersionNegotiation, i: usize) u32 {
        return std.mem.readInt(u32, self.versionBytes[i * 4 ..][0..4], .big);
    }
};

/// Parses a Version Negotiation packet.
///
/// RFC 9000 section 17.2.1 sets the Unused field to an arbitrary value
/// and requires clients to ignore it, so nothing here reads it beyond
/// checking that this is a long header. The version list must be a whole
/// number of 4-byte entries; a trailing partial entry makes the packet
/// malformed rather than something to skip, since it cannot have come
/// from a conforming server.
pub fn parseVersionNegotiation(data: []const u8) HeaderError!VersionNegotiation {
    if (data.len < 7) return HeaderError.Truncated;
    if ((data[0] & 0x80) == 0) return HeaderError.InvalidPacket;
    if (std.mem.readInt(u32, data[1..5], .big) != 0) return HeaderError.InvalidPacket;
    var offset: usize = 5;

    const dcidLen: usize = data[offset];
    offset += 1;
    if (dcidLen > 20) return HeaderError.InvalidPacket;
    const dcid = try take(data, &offset, dcidLen);

    if (offset >= data.len) return HeaderError.Truncated;
    const scidLen: usize = data[offset];
    offset += 1;
    if (scidLen > 20) return HeaderError.InvalidPacket;
    const scid = try take(data, &offset, scidLen);

    if (offset == data.len) return HeaderError.InvalidPacket;
    if ((data.len - offset) % 4 != 0) return HeaderError.InvalidPacket;

    return .{ .dcid = dcid, .scid = scid, .versionBytes = data[offset..] };
}
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

test "parses a real aioquic Version Negotiation packet" {
    // Captured from aioquic 1.2.0: a v2-only server replying to an Initial
    // whose version it does not speak. The first byte is 0xbd, so the Unused
    // field is 0x3d -- aioquic greases it. RFC 9000 17.2.1 says clients MUST
    // ignore that field, and a parser that looked at it would reject this.
    const bytes = @embedFile("testdata/aioquic_version_negotiation.bin");
    const vn = try parseVersionNegotiation(bytes);

    // The IDs are echoed swapped: what we sent as source is the server's
    // destination, and what we chose as destination is its source.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xc2, 0xa0, 0x87, 0xf3, 0x42, 0x51, 0x74, 0x7a }, vn.dcid);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xdf, 0xc3, 0x7c, 0x2f, 0xb6, 0x84, 0x37, 0xab }, vn.scid);

    try std.testing.expectEqual(@as(usize, 1), vn.count());
    try std.testing.expectEqual(@as(u32, 0x6B3343CF), vn.versionAt(0));
}

test "rejects Version Negotiation packets that are not Version Negotiation" {
    const vn = @embedFile("testdata/aioquic_version_negotiation.bin");

    // Version field not zero: an ordinary long header, not VN.
    var withVersion = @as([27]u8, vn[0..27].*);
    withVersion[1] = 0x01;
    try std.testing.expectError(HeaderError.InvalidPacket, parseVersionNegotiation(&withVersion));

    // Header form clear: a short header packet.
    var shortHeader = withVersion;
    shortHeader[0] = 0x40;
    try std.testing.expectError(HeaderError.InvalidPacket, parseVersionNegotiation(&shortHeader));

    // Truncated before the second connection ID length byte.
    try std.testing.expectError(HeaderError.Truncated, parseVersionNegotiation(vn[0..5]));

    // Connection ID length above the 20-byte maximum of RFC 9000 section 17.2.
    var longCid = @as([27]u8, vn[0..27].*);
    longCid[5] = 21;
    try std.testing.expectError(HeaderError.InvalidPacket, parseVersionNegotiation(&longCid));

    // A version list that is not a whole number of 4-byte entries cannot
    // have come from a conforming server, so it is malformed rather than
    // something to skip past.
    var partial: [28]u8 = undefined;
    @memcpy(partial[0..27], vn[0..27]);
    partial[27] = 0x00;
    try std.testing.expectError(HeaderError.InvalidPacket, parseVersionNegotiation(&partial));

    // No versions listed at all.
    const none: [23]u8 = vn[0..23].*;
    try std.testing.expectError(HeaderError.InvalidPacket, parseVersionNegotiation(&none));
}

test "reads every version in the list" {
    // A server offering both, as this implementation's own writer does.
    var buf: [64]u8 = undefined;
    const n = try writeVersionNegotiation(&buf, "scid1234", "dcid5678");
    const vn = try parseVersionNegotiation(buf[0..n]);
    try std.testing.expectEqual(@as(usize, 2), vn.count());
    try std.testing.expectEqual(@as(u32, 0x00000001), vn.versionAt(0));
    try std.testing.expectEqual(@as(u32, 0x6B3343CF), vn.versionAt(1));
}
