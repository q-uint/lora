//! Frame header (FHDR), [TS001-1.0.4] §4.3.1.
//!
//!   Size (octets) |    4    |   1   |  2   | 0..15
//!   FHDR          | DevAddr | FCtrl | FCnt | FOpts     (Table 6)
//!
//! Multi-octet fields are little endian, [TS001-1.0.4] §1.1.

const std = @import("std");
const Direction = @import("mhdr.zig").Direction;

/// FOpts holds at most 15 octets, [TS001-1.0.4] §4.3.1.6.
pub const max_fopts_len = 15;
pub const min_len = 7;
pub const max_len = min_len + max_fopts_len;

/// FCtrl for uplink frames, [TS001-1.0.4] §4.3.1 Table 8.
///
///   Bits  |  7  |     6     |  5  |   4    | [3:0]
///   FCtrl | ADR | ADRACKReq | ACK | ClassB | FOptsLen
pub const FCtrlUplink = struct {
    /// §4.3.1.1
    adr: bool = false,
    /// §4.3.1.1
    adr_ack_req: bool = false,
    /// §4.3.1.2
    ack: bool = false,
    /// §4.3.1.7
    class_b: bool = false,
};

/// FCtrl for downlink frames, [TS001-1.0.4] §4.3.1 Table 7.
///
///   Bits  |  7  |  6  |  5  |    4     | [3:0]
///   FCtrl | ADR | RFU | ACK | FPending | FOptsLen
pub const FCtrlDownlink = struct {
    /// §4.3.1.1
    adr: bool = false,
    /// §4.3.1.2
    ack: bool = false,
    /// §4.3.1.4
    fpending: bool = false,
};

pub const FCtrl = union(Direction) {
    uplink: FCtrlUplink,
    downlink: FCtrlDownlink,

    /// FOptsLen is derived from the FOpts length, so it is passed in rather than stored.
    /// The downlink RFU bit 6 SHALL be sent as 0, [TS001-1.0.4] §1.1.
    pub fn encode(self: FCtrl, fopts_len: u4) u8 {
        var b: u8 = fopts_len;
        switch (self) {
            .uplink => |f| {
                if (f.adr) b |= 0x80;
                if (f.adr_ack_req) b |= 0x40;
                if (f.ack) b |= 0x20;
                if (f.class_b) b |= 0x10;
            },
            .downlink => |f| {
                if (f.adr) b |= 0x80;
                if (f.ack) b |= 0x20;
                if (f.fpending) b |= 0x10;
            },
        }
        return b;
    }

    /// The downlink RFU bit 6 is silently ignored, [TS001-1.0.4] §1.1.
    pub fn decode(byte: u8, dir: Direction) FCtrl {
        return switch (dir) {
            .uplink => .{ .uplink = .{
                .adr = byte & 0x80 != 0,
                .adr_ack_req = byte & 0x40 != 0,
                .ack = byte & 0x20 != 0,
                .class_b = byte & 0x10 != 0,
            } },
            .downlink => .{ .downlink = .{
                .adr = byte & 0x80 != 0,
                .ack = byte & 0x20 != 0,
                .fpending = byte & 0x10 != 0,
            } },
        };
    }
};

pub const Fhdr = struct {
    dev_addr: u32,
    fctrl: FCtrl,
    /// Least-significant 16 bits of the 32-bit FCntUp or FCntDown, [TS001-1.0.4] §4.3.1.5.
    fcnt: u16,
    /// Piggybacked MAC commands, sent unencrypted, [TS001-1.0.4] §4.3.1.6 and §5.
    fopts: []const u8 = &.{},

    pub const EncodeError = error{
        /// More than 15 octets of FOpts, [TS001-1.0.4] §4.3.1.6.
        FOptsTooLong,
        /// `out` is too small.
        NoSpaceLeft,
    };
    pub const DecodeError = error{
        /// Input ends before the FHDR does.
        Truncated,
    };

    pub fn len(self: Fhdr) usize {
        return min_len + self.fopts.len;
    }

    /// Writes the FHDR to the start of `out` and returns the written slice.
    pub fn encode(self: Fhdr, out: []u8) EncodeError![]u8 {
        if (self.fopts.len > max_fopts_len) return error.FOptsTooLong;
        if (out.len < self.len()) return error.NoSpaceLeft;
        std.mem.writeInt(u32, out[0..4], self.dev_addr, .little);
        out[4] = self.fctrl.encode(@intCast(self.fopts.len));
        std.mem.writeInt(u16, out[5..7], self.fcnt, .little);
        @memcpy(out[7..][0..self.fopts.len], self.fopts);
        return out[0..self.len()];
    }

    /// Parses an FHDR from the start of `bytes`. FOpts borrows from `bytes`.
    /// The direction (from the MHDR FType) selects the FCtrl layout, Tables 7 and 8.
    pub fn decode(bytes: []const u8, dir: Direction) DecodeError!Fhdr {
        if (bytes.len < min_len) return error.Truncated;
        const fopts_len: usize = bytes[4] & 0x0F;
        if (bytes.len < min_len + fopts_len) return error.Truncated;
        return .{
            .dev_addr = std.mem.readInt(u32, bytes[0..4], .little),
            .fctrl = FCtrl.decode(bytes[4], dir),
            .fcnt = std.mem.readInt(u16, bytes[5..7], .little),
            .fopts = bytes[7..][0..fopts_len],
        };
    }
};

const testing = std.testing;

// Table 6 layout with little-endian DevAddr and FCnt (§1.1).
test "decode minimal uplink FHDR" {
    const bytes = [_]u8{ 0x44, 0x33, 0x22, 0x11, 0x00, 0x02, 0x00 };
    const h = try Fhdr.decode(&bytes, .uplink);
    try testing.expectEqual(0x11223344, h.dev_addr);
    try testing.expectEqual(FCtrl{ .uplink = .{} }, h.fctrl);
    try testing.expectEqual(2, h.fcnt);
    try testing.expectEqual(0, h.fopts.len);

    var buf: [max_len]u8 = undefined;
    try testing.expectEqualSlices(u8, &bytes, try h.encode(&buf));
}

test "FCtrl bit positions per direction (Tables 7 and 8)" {
    try testing.expectEqual(0xF0, (FCtrl{ .uplink = .{ .adr = true, .adr_ack_req = true, .ack = true, .class_b = true } }).encode(0));
    try testing.expectEqual(0xB0, (FCtrl{ .downlink = .{ .adr = true, .ack = true, .fpending = true } }).encode(0));
    // Bits 6 and 4 mean different things per direction.
    try testing.expectEqual(FCtrl{ .uplink = .{ .adr_ack_req = true, .class_b = true } }, FCtrl.decode(0x50, .uplink));
    try testing.expectEqual(FCtrl{ .downlink = .{ .fpending = true } }, FCtrl.decode(0x50, .downlink));
}

test "FOpts roundtrip and FOptsLen" {
    // LinkCheckReq (CID 0x02) piggybacked in FOpts, §5.1.
    const h = Fhdr{ .dev_addr = 0x01020304, .fctrl = .{ .uplink = .{ .adr = true } }, .fcnt = 0xBEEF, .fopts = &.{0x02} };
    var buf: [max_len]u8 = undefined;
    const enc = try h.encode(&buf);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x03, 0x02, 0x01, 0x81, 0xEF, 0xBE, 0x02 }, enc);
    const dec = try Fhdr.decode(enc, .uplink);
    try testing.expectEqualSlices(u8, h.fopts, dec.fopts);
    try testing.expectEqual(h.fcnt, dec.fcnt);
}

test "errors" {
    var buf: [max_len + 1]u8 = undefined;
    const sixteen: [16]u8 = @splat(0);
    const too_long = Fhdr{ .dev_addr = 0, .fctrl = .{ .uplink = .{} }, .fcnt = 0, .fopts = &sixteen };
    try testing.expectError(error.FOptsTooLong, too_long.encode(&buf));
    try testing.expectError(error.Truncated, Fhdr.decode(&.{ 0, 0, 0, 0, 0, 0 }, .uplink));
    // FOptsLen is 2 but only 1 FOpts octet is present.
    try testing.expectError(error.Truncated, Fhdr.decode(&.{ 0, 0, 0, 0, 0x02, 0, 0, 0x02 }, .uplink));
}
