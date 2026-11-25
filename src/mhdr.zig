//! MAC header (MHDR), [TS001-1.0.4] §4.2.
//!
//!   Bits  | [7:5] | [4:2] | [1:0]
//!   MHDR  | FType |  RFU  | Major     (Table 3)

const std = @import("std");

/// Frame type, [TS001-1.0.4] §4.2.1, Table 4.
pub const FType = enum(u3) {
    join_request = 0b000,
    join_accept = 0b001,
    unconfirmed_data_up = 0b010,
    unconfirmed_data_down = 0b011,
    confirmed_data_up = 0b100,
    confirmed_data_down = 0b101,
    rfu = 0b110,
    proprietary = 0b111,

    /// Data frames carry a MACPayload (FHDR | FPort | FRMPayload), §4.2.1.2 / §4.3.
    pub fn isData(self: FType) bool {
        return switch (self) {
            .unconfirmed_data_up,
            .unconfirmed_data_down,
            .confirmed_data_up,
            .confirmed_data_down,
            => true,
            else => false,
        };
    }

    /// Direction of a data frame, or null for non-data frame types.
    pub fn direction(self: FType) ?Direction {
        return switch (self) {
            .unconfirmed_data_up, .confirmed_data_up => .uplink,
            .unconfirmed_data_down, .confirmed_data_down => .downlink,
            else => null,
        };
    }
};

/// Frame direction. The numeric value is the Dir field of the A_i and B0
/// blocks: 0 for uplink, 1 for downlink, [TS001-1.0.4] §4.3.3 Table 12, §4.4 Table 13.
pub const Direction = enum(u1) {
    uplink = 0,
    downlink = 1,
};

/// Major data frame version, [TS001-1.0.4] §4.2.2, Table 5.
/// Values 0b01..0b11 are RFU.
pub const Major = enum(u2) {
    lorawan_r1 = 0b00,
    _,
};

pub const MHDR = struct {
    ftype: FType,
    major: Major = .lorawan_r1,

    /// RFU bits SHALL be set to 0 by the transmitter, [TS001-1.0.4] §1.1.
    pub fn encode(self: MHDR) u8 {
        return @as(u8, @intFromEnum(self.ftype)) << 5 | @intFromEnum(self.major);
    }

    /// RFU bits SHALL be silently ignored by the receiver, [TS001-1.0.4] §1.1.
    pub fn decode(byte: u8) MHDR {
        return .{
            .ftype = @enumFromInt(@as(u3, @truncate(byte >> 5))),
            .major = @enumFromInt(@as(u2, @truncate(byte))),
        };
    }
};

test "encode sets FType in bits [7:5] and Major in [1:0]" {
    try std.testing.expectEqual(@as(u8, 0x40), (MHDR{ .ftype = .unconfirmed_data_up }).encode());
    try std.testing.expectEqual(@as(u8, 0x80), (MHDR{ .ftype = .confirmed_data_up }).encode());
    try std.testing.expectEqual(@as(u8, 0x60), (MHDR{ .ftype = .unconfirmed_data_down }).encode());
    try std.testing.expectEqual(@as(u8, 0xE0), (MHDR{ .ftype = .proprietary }).encode());
}

test "decode ignores RFU bits" {
    const h = MHDR.decode(0b010_111_00);
    try std.testing.expectEqual(FType.unconfirmed_data_up, h.ftype);
    try std.testing.expectEqual(Major.lorawan_r1, h.major);
}

test "roundtrip all frame types" {
    for (0..8) |v| {
        const h = MHDR{ .ftype = @enumFromInt(v) };
        try std.testing.expectEqual(h, MHDR.decode(h.encode()));
    }
}
