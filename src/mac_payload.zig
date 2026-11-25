//! MAC payload of data frames (MACPayload), [TS001-1.0.4] §4.3.
//!
//!   Size (octets) | 7..22 | 0..1  |    0..N
//!   MACPayload    | FHDR  | FPort | FRMPayload     (Table 10)
//!
//! The maximum MACPayload length M is region and data rate specific and
//! defined in [RP002], so it is not enforced here, [TS001-1.0.4] §4.1.

const std = @import("std");
const Direction = @import("mhdr.zig").Direction;
const fhdr = @import("fhdr.zig");
const FHDR = fhdr.FHDR;

pub const MACPayload = struct {
    fhdr: FHDR,
    /// 0 means FRMPayload carries only MAC commands. 1..223 are application
    /// specific. 224 is the MAC layer test protocol. 224..255 are reserved
    /// by the LoRa Alliance, [TS001-1.0.4] §4.3.2.
    fport: ?u8 = null,
    /// FRMPayload as sent on air, so already encrypted, [TS001-1.0.4] §4.3.3.
    frm_payload: []const u8 = &.{},

    pub const Error = fhdr.FHDR.Error || error{
        /// FRMPayload is not empty but FPort is absent, [TS001-1.0.4] §4.3.2.
        MissingFPort,
        /// FOptsLen is not 0 and FPort is 0, so MAC commands would be in both
        /// FOpts and FRMPayload, [TS001-1.0.4] §4.3.1.6.
        MacCommandsInFOptsAndPayload,
    };

    pub fn len(self: MACPayload) usize {
        return self.fhdr.len() + @intFromBool(self.fport != null) + self.frm_payload.len;
    }

    fn validate(self: MACPayload) Error!void {
        if (self.fport == null and self.frm_payload.len != 0) return error.MissingFPort;
        if (self.fport == 0 and self.fhdr.fopts.len != 0) return error.MacCommandsInFOptsAndPayload;
    }

    /// Writes the MACPayload to the start of `out` and returns the written slice.
    pub fn encode(self: MACPayload, out: []u8) Error![]u8 {
        try self.validate();
        if (out.len < self.len()) return error.Truncated;
        var n = (try self.fhdr.encode(out)).len;
        if (self.fport) |p| {
            out[n] = p;
            n += 1;
        }
        @memcpy(out[n..][0..self.frm_payload.len], self.frm_payload);
        return out[0..self.len()];
    }

    /// Parses a MACPayload that spans all of `bytes`. FOpts and FRMPayload
    /// borrow from `bytes`. A frame with no FOpts, no FPort and no FRMPayload
    /// is valid, [TS001-1.0.4] §4.3.
    pub fn decode(bytes: []const u8, dir: Direction) Error!MACPayload {
        const h = try FHDR.decode(bytes, dir);
        const rest = bytes[h.len()..];
        const p: MACPayload = if (rest.len == 0)
            .{ .fhdr = h }
        else
            .{ .fhdr = h, .fport = rest[0], .frm_payload = rest[1..] };
        try p.validate();
        return p;
    }
};

const testing = std.testing;

// Table 10 layout built by hand: FHDR (Table 6), FPort 1, 3 octets FRMPayload.
test "encode and decode with FPort and FRMPayload" {
    const p = MACPayload{
        .fhdr = .{ .dev_addr = 0x11223344, .fctrl = .{ .uplink = .{} }, .fcnt = 1 },
        .fport = 1,
        .frm_payload = &.{ 0xAA, 0xBB, 0xCC },
    };
    var buf: [32]u8 = undefined;
    const enc = try p.encode(&buf);
    try testing.expectEqualSlices(u8, &.{ 0x44, 0x33, 0x22, 0x11, 0x00, 0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC }, enc);

    const dec = try MACPayload.decode(enc, .uplink);
    try testing.expectEqual(@as(?u8, 1), dec.fport);
    try testing.expectEqualSlices(u8, p.frm_payload, dec.frm_payload);
}

test "FHDR only is a valid frame (§4.3)" {
    const bytes = [_]u8{ 0x44, 0x33, 0x22, 0x11, 0x00, 0x01, 0x00 };
    const dec = try MACPayload.decode(&bytes, .downlink);
    try testing.expectEqual(@as(?u8, null), dec.fport);
    try testing.expectEqual(@as(usize, 0), dec.frm_payload.len);
}

test "FPort without FRMPayload is accepted" {
    const bytes = [_]u8{ 0x44, 0x33, 0x22, 0x11, 0x00, 0x01, 0x00, 0x05 };
    const dec = try MACPayload.decode(&bytes, .uplink);
    try testing.expectEqual(@as(?u8, 5), dec.fport);
    try testing.expectEqual(@as(usize, 0), dec.frm_payload.len);
}

test "FRMPayload requires FPort (§4.3.2)" {
    const p = MACPayload{
        .fhdr = .{ .dev_addr = 0, .fctrl = .{ .uplink = .{} }, .fcnt = 0 },
        .frm_payload = &.{0x01},
    };
    var buf: [32]u8 = undefined;
    try testing.expectError(error.MissingFPort, p.encode(&buf));
}

test "FPort 0 with FOpts is rejected (§4.3.1.6)" {
    const p = MACPayload{
        .fhdr = .{ .dev_addr = 0, .fctrl = .{ .uplink = .{} }, .fcnt = 0, .fopts = &.{0x02} },
        .fport = 0,
    };
    var buf: [32]u8 = undefined;
    try testing.expectError(error.MacCommandsInFOptsAndPayload, p.encode(&buf));

    // Same frame on the decode side: FOptsLen 1, FOpts 02, FPort 0.
    const bytes = [_]u8{ 0, 0, 0, 0, 0x01, 0, 0, 0x02, 0x00 };
    try testing.expectError(error.MacCommandsInFOptsAndPayload, MACPayload.decode(&bytes, .uplink));
}
