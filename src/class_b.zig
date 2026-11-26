//! Class B beacon frame and ping slots, [TS001-1.0.4] §11 and §13.
//!
//! The BCNPayload field sizes depend on the spreading factor and come from
//! [RP002-1.0.5] §5.1.3 Table 114.

const std = @import("std");
const Aes128 = std.crypto.core.aes.Aes128;

/// CRC-16 with P(x) = x^16 + x^12 + x^5 + 1, [TS001-1.0.4] §13.2.
const Crc = std.hash.crc.@"CRC-16/XMODEM";

/// BEACON_RESERVED in ms, [TS001-1.0.4] §11.1 Table 58.
pub const beacon_reserved_ms = 2120;
/// SlotLen in ms, [TS001-1.0.4] §11.2 Table 59.
pub const slot_len_ms = 30;

/// PingNb = 2^(7 - Periodicity), [TS001-1.0.4] §11.2 Table 59.
pub fn pingNb(periodicity: u3) u8 {
    return @as(u8, 1) << (7 - @as(u3, periodicity));
}

/// PingPeriod = 2^(5 + Periodicity) slots, [TS001-1.0.4] §11.2 Table 59.
pub fn pingPeriod(periodicity: u3) u13 {
    return @as(u13, 1) << (@as(u4, periodicity) + 5);
}

/// PingOffset, [TS001-1.0.4] §11.2.
///
///   Rand = aes128_encrypt(16 × 0x00, BeaconTime | DevAddr | pad16)
///   PingOffset = (Rand[0] + Rand[1] × 256) modulo PingPeriod
///
/// Multicast slots use the multicast group address as `dev_addr`.
pub fn pingOffset(beacon_time: u32, dev_addr: u32, periodicity: u3) u12 {
    var block: [16]u8 = @splat(0);
    std.mem.writeInt(u32, block[0..4], beacon_time, .little);
    std.mem.writeInt(u32, block[4..8], dev_addr, .little);
    var rand: [16]u8 = undefined;
    Aes128.initEnc(@splat(0)).encrypt(&rand, &block);
    return @intCast(std.mem.readInt(u16, rand[0..2], .little) % pingPeriod(periodicity));
}

/// Start of ping slot `n` in ms after the beacon start, for `n` below
/// `pingNb(periodicity)`, [TS001-1.0.4] §11.2 Table 60.
pub fn slotStartMs(ping_offset: u12, periodicity: u3, n: u8) u32 {
    std.debug.assert(n < pingNb(periodicity));
    return beacon_reserved_ms + (@as(u32, ping_offset) + @as(u32, n) * pingPeriod(periodicity)) * slot_len_ms;
}

/// RFU field sizes of BCNPayload, [RP002-1.0.5] §5.1.3 Table 114.
///
///   Common     | RFU | Param | Time | CRC
///   GwSpecific | InfoDesc | Info | RFU | CRC
pub const Layout = struct {
    common_rfu: u8,
    gw_rfu: u8,

    pub fn forSpreadingFactor(sf: u4) ?Layout {
        return switch (sf) {
            8 => .{ .common_rfu = 0, .gw_rfu = 3 },
            9 => .{ .common_rfu = 1, .gw_rfu = 0 },
            10 => .{ .common_rfu = 2, .gw_rfu = 1 },
            11 => .{ .common_rfu = 3, .gw_rfu = 2 },
            12 => .{ .common_rfu = 4, .gw_rfu = 3 },
            else => null,
        };
    }

    /// Network common part including its CRC.
    pub fn commonLen(l: Layout) usize {
        return l.common_rfu + 1 + 4 + 2;
    }

    /// Network common and gateway-specific parts.
    pub fn len(l: Layout) usize {
        return l.commonLen() + 1 + 6 + l.gw_rfu + 2;
    }
};

/// Gateway antenna for InfoDesc 0 to 2, [TS001-1.0.4] §13.3 Table 77.
pub const Antenna = enum(u8) { first = 0, second = 1, third = 2 };

/// GwSpecific field, [TS001-1.0.4] §13.3 Tables 76 to 79.
pub const GwSpecific = union(enum) {
    /// InfoDesc 0 to 2, Table 78.
    gps: struct {
        antenna: Antenna,
        /// −2^23 is 90° south, 2^23 would be 90° north.
        lat: i24,
        /// −2^23 is 180° west, 2^23 would be 180° east.
        lng: i24,

        pub fn latitudeDeg(self: @This()) f64 {
            return @as(f64, @floatFromInt(self.lat)) * 90.0 / (1 << 23);
        }

        pub fn longitudeDeg(self: @This()) f64 {
            return @as(f64, @floatFromInt(self.lng)) * 180.0 / (1 << 23);
        }
    },
    /// InfoDesc 3, Table 79.
    net_id: struct { net_id: u24, gateway_id: u24 },
    /// RFU or network-specific InfoDesc, Table 77.
    other: struct { info_desc: u8, info: [6]u8 },

    fn encode(self: GwSpecific) [7]u8 {
        var out: [7]u8 = undefined;
        switch (self) {
            .gps => |g| {
                out[0] = @intFromEnum(g.antenna);
                std.mem.writeInt(i24, out[1..4], g.lat, .little);
                std.mem.writeInt(i24, out[4..7], g.lng, .little);
            },
            .net_id => |n| {
                out[0] = 3;
                std.mem.writeInt(u24, out[1..4], n.net_id, .little);
                std.mem.writeInt(u24, out[4..7], n.gateway_id, .little);
            },
            .other => |o| {
                std.debug.assert(o.info_desc > 3);
                out[0] = o.info_desc;
                out[1..7].* = o.info;
            },
        }
        return out;
    }

    fn decode(bytes: *const [7]u8) GwSpecific {
        return switch (bytes[0]) {
            0...2 => .{ .gps = .{
                .antenna = @enumFromInt(bytes[0]),
                .lat = std.mem.readInt(i24, bytes[1..4], .little),
                .lng = std.mem.readInt(i24, bytes[4..7], .little),
            } },
            3 => .{ .net_id = .{
                .net_id = std.mem.readInt(u24, bytes[1..4], .little),
                .gateway_id = std.mem.readInt(u24, bytes[4..7], .little),
            } },
            else => .{ .other = .{ .info_desc = bytes[0], .info = bytes[1..7].* } },
        };
    }
};

/// BCNPayload, [TS001-1.0.4] §13.2 Tables 74 and 75.
pub const Beacon = struct {
    /// Timing precision of 10^(−6 + prec) s.
    prec: u2 = 0,
    /// Seconds since the GPS epoch, 1980-01-06 00:00:00 UTC, modulo 2^32.
    time: u32,
    /// Optional gateway-specific part, §13.3.
    gw_specific: ?GwSpecific = null,

    pub const DecodeError = error{ InvalidLength, InvalidCrc };

    /// Writes the beacon in `layout`. RFU fields are 0, [TS001-1.0.4] §13.2.
    pub fn encode(self: Beacon, layout: Layout, out: []u8) error{NoSpaceLeft}![]u8 {
        const n = if (self.gw_specific == null) layout.commonLen() else layout.len();
        if (out.len < n) return error.NoSpaceLeft;
        const common = out[0..layout.commonLen()];
        @memset(common, 0);
        common[layout.common_rfu] = self.prec;
        std.mem.writeInt(u32, common[layout.common_rfu + 1 ..][0..4], self.time, .little);
        writeCrc(common);
        if (self.gw_specific) |gw| {
            const part = out[common.len..n];
            @memset(part, 0);
            part[0..7].* = gw.encode();
            writeCrc(part);
        }
        return out[0..n];
    }

    /// Decodes a beacon in `layout`, with or without the gateway-specific
    /// part. A gateway-specific part with a wrong CRC decodes as null,
    /// [RP002-1.0.5] §5.1.3. RFU bits are ignored, [TS001-1.0.4] §13.2.
    pub fn decode(bytes: []const u8, layout: Layout) DecodeError!Beacon {
        if (bytes.len != layout.commonLen() and bytes.len != layout.len()) return error.InvalidLength;
        const common = bytes[0..layout.commonLen()];
        if (!crcOk(common)) return error.InvalidCrc;
        const part = bytes[common.len..];
        return .{
            .prec = @truncate(common[layout.common_rfu]),
            .time = std.mem.readInt(u32, common[layout.common_rfu + 1 ..][0..4], .little),
            .gw_specific = if (part.len > 0 and crcOk(part)) GwSpecific.decode(part[0..7]) else null,
        };
    }
};

/// The last two octets hold the CRC of the others, little endian.
fn writeCrc(part: []u8) void {
    const n = part.len - 2;
    std.mem.writeInt(u16, part[n..][0..2], Crc.hash(part[0..n]), .little);
}

fn crcOk(part: []const u8) bool {
    const n = part.len - 2;
    return std.mem.readInt(u16, part[n..][0..2], .little) == Crc.hash(part[0..n]);
}

const testing = std.testing;
const hex = @import("test_util.zig").hex;

test "EU868 beacon (RP002 Table 116, TS001 §13.4)" {
    const wire = hex("0000" ++ "000002CC" ++ "A27E" ++ "00" ++ "012000" ++ "008103" ++ "DE55");
    const layout = Layout.forSpreadingFactor(9).?;
    try testing.expectEqual(wire.len, layout.len());
    const beacon = try Beacon.decode(&wire, layout);
    try testing.expectEqual(Beacon{
        .prec = 0,
        .time = 0xCC020000,
        .gw_specific = .{ .gps = .{ .antenna = .first, .lat = 0x002001, .lng = 0x038100 } },
    }, beacon);
    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try beacon.encode(layout, &buf));
}

test "US915 beacon (RP002 Table 117, TS001 §13.4)" {
    // Labelled SF12, but its 2 + 1 RFU octets are the SF10 row of Table 114.
    // The 23 octet SF12 row matches the earlier US902-928 format of RP002
    // §3.5.8 footnote 9.
    const wire = hex("0000" ++ "00" ++ "000002CC" ++ "A27E" ++ "00" ++ "012000" ++ "008103" ++ "00" ++ "50D4");
    const layout = Layout.forSpreadingFactor(10).?;
    const beacon = try Beacon.decode(&wire, layout);
    try testing.expectEqual(0xCC020000, beacon.time);
    try testing.expect(beacon.gw_specific != null);
    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try beacon.encode(layout, &buf));
}

test "beacon lengths (RP002 Table 114)" {
    const lens = [_]struct { u4, usize, usize }{ .{ 8, 7, 19 }, .{ 9, 8, 17 }, .{ 10, 9, 19 }, .{ 11, 10, 21 }, .{ 12, 11, 23 } };
    for (lens) |l| {
        const layout = Layout.forSpreadingFactor(l[0]).?;
        try testing.expectEqual(l[1], layout.commonLen());
        try testing.expectEqual(l[2], layout.len());
    }
    try testing.expectEqual(null, Layout.forSpreadingFactor(7));
}

test "common part only, and a broken gateway-specific part" {
    var wire = hex("0000" ++ "000002CC" ++ "A27E" ++ "00" ++ "012000" ++ "008103" ++ "DE55");
    const layout = Layout.forSpreadingFactor(9).?;
    const common = try Beacon.decode(wire[0..8], layout);
    try testing.expectEqual(null, common.gw_specific);
    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, wire[0..8], try common.encode(layout, &buf));

    wire[10] ^= 1;
    const broken = try Beacon.decode(&wire, layout);
    try testing.expectEqual(0xCC020000, broken.time);
    try testing.expectEqual(null, broken.gw_specific);
}

test "beacon decode errors" {
    var wire = hex("0000" ++ "000002CC" ++ "A27E" ++ "00" ++ "012000" ++ "008103" ++ "DE55");
    const layout = Layout.forSpreadingFactor(9).?;
    try testing.expectError(error.InvalidLength, Beacon.decode(wire[0..9], layout));
    try testing.expectError(error.InvalidLength, Beacon.decode(&wire, Layout.forSpreadingFactor(10).?));
    wire[5] ^= 1;
    try testing.expectError(error.InvalidCrc, Beacon.decode(&wire, layout));
}

test "Param RFU bits are ignored (TS001 Table 75)" {
    const layout = Layout.forSpreadingFactor(8).?;
    var buf: [32]u8 = undefined;
    const wire = try (Beacon{ .prec = 3, .time = 1 }).encode(layout, &buf);
    try testing.expectEqual(3, wire[0]);
    wire[0] |= 0xFC;
    writeCrc(wire);
    try testing.expectEqual(3, (try Beacon.decode(wire, layout)).prec);
}

test "GwSpecific InfoDesc (TS001 Table 77)" {
    const cases = [_]GwSpecific{
        .{ .gps = .{ .antenna = .third, .lat = -1, .lng = std.math.minInt(i24) } },
        .{ .net_id = .{ .net_id = 0x000013, .gateway_id = 0xABCDEF } },
        .{ .other = .{ .info_desc = 0x80, .info = .{ 1, 2, 3, 4, 5, 6 } } },
    };
    const first_octet = [_]u8{ 2, 3, 0x80 };
    for (cases, first_octet) |gw, b| {
        const bytes = gw.encode();
        try testing.expectEqual(b, bytes[0]);
        try testing.expectEqual(gw, GwSpecific.decode(&bytes));
    }
}

test "GPS coordinates (TS001 §13.3.1)" {
    const south_west: @FieldType(GwSpecific, "gps") = .{ .antenna = .first, .lat = std.math.minInt(i24), .lng = std.math.minInt(i24) };
    try testing.expectEqual(-90.0, south_west.latitudeDeg());
    try testing.expectEqual(-180.0, south_west.longitudeDeg());
    const equator: @FieldType(GwSpecific, "gps") = .{ .antenna = .first, .lat = 0, .lng = 1 << 22 };
    try testing.expectEqual(0.0, equator.latitudeDeg());
    try testing.expectEqual(90.0, equator.longitudeDeg());
}

test "PingNb and PingPeriod (TS001 Table 59)" {
    // Periodicity 0 opens 128 slots every 32 slots (≈ 1 s), 7 one slot
    // every 4096 slots (≈ 128 s), §12.1.
    try testing.expectEqual(128, pingNb(0));
    try testing.expectEqual(32, pingPeriod(0));
    try testing.expectEqual(1, pingNb(7));
    try testing.expectEqual(4096, pingPeriod(7));
    for (0..8) |p| try testing.expectEqual(4096, @as(u32, pingNb(@intCast(p))) * pingPeriod(@intCast(p)));
}

test "PingOffset range and modulo (TS001 §11.2)" {
    // The spec has no PingOffset vector. A smaller PingPeriod divides a
    // larger one, so each offset is the periodicity 7 offset reduced.
    for ([_]u32{ 0, 128, 0xCC020000 }) |t| {
        const full = pingOffset(t, 0x26011234, 7);
        for (0..8) |p| {
            const o = pingOffset(t, 0x26011234, @intCast(p));
            try testing.expect(o < pingPeriod(@intCast(p)));
            try testing.expectEqual(full % pingPeriod(@intCast(p)), o);
        }
    }
}

test "slot start times (TS001 Table 60)" {
    try testing.expectEqual(2120, slotStartMs(0, 0, 0));
    try testing.expectEqual(2120 + (5 + 32) * 30, slotStartMs(5, 0, 1));
    // Latest slot, §11.1.
    try testing.expectEqual(124970, slotStartMs(4095, 7, 0));
}
