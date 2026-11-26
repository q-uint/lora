//! Receive window settings shared by the Join-Accept frame (§6.2.6) and
//! MAC commands (§5.4, §5.7), [TS001-1.0.4].

const std = @import("std");

/// DLSettings, [TS001-1.0.4] §6.2.6 Table 55 and §5.4 Table 27.
///
///   Bits       |  7  |     6:4     |     3:0
///   DLSettings | RFU | RX1DROffset | RX2DataRate
pub const DlSettings = struct {
    rx1_dr_offset: u3 = 0,
    rx2_data_rate: u4 = 0,

    /// RFU bit 7 SHALL be sent as 0, [TS001-1.0.4] §1.1.
    pub fn encode(self: DlSettings) u8 {
        return @as(u8, self.rx1_dr_offset) << 4 | self.rx2_data_rate;
    }

    /// RFU bit 7 is silently ignored, [TS001-1.0.4] §1.1.
    pub fn decode(byte: u8) DlSettings {
        return .{
            .rx1_dr_offset = @truncate(byte >> 4),
            .rx2_data_rate = @truncate(byte),
        };
    }
};

/// RxTimingSettings, the RXDelay field of the Join-Accept, [TS001-1.0.4]
/// §5.7 Table 44 and §6.2.6.
///
///   Bits             | 7:4 | 3:0
///   RxTimingSettings | RFU | Del
pub const RxTimingSettings = struct {
    del: u4 = 0,

    /// RFU bits 7:4 SHALL be sent as 0, [TS001-1.0.4] §1.1.
    pub fn encode(self: RxTimingSettings) u8 {
        return self.del;
    }

    /// RFU bits 7:4 are silently ignored, [TS001-1.0.4] §1.1.
    pub fn decode(byte: u8) RxTimingSettings {
        return .{ .del = @truncate(byte) };
    }

    /// Delay before RX1 in seconds. Del 0 maps to 1 s, [TS001-1.0.4] §5.7 Table 45.
    pub fn seconds(self: RxTimingSettings) u4 {
        return @max(self.del, 1);
    }
};

const testing = std.testing;

test "DLSettings bit positions (Table 55)" {
    try testing.expectEqual(0x5A, (DlSettings{ .rx1_dr_offset = 5, .rx2_data_rate = 10 }).encode());
    try testing.expectEqual(DlSettings{ .rx1_dr_offset = 5, .rx2_data_rate = 10 }, DlSettings.decode(0xDA)); // RFU bit set
}

test "RxTimingSettings and Del mapping (Tables 44, 45)" {
    try testing.expectEqual(0x0F, (RxTimingSettings{ .del = 15 }).encode());
    try testing.expectEqual(RxTimingSettings{ .del = 3 }, RxTimingSettings.decode(0xF3)); // RFU bits set
    try testing.expectEqual(1, (RxTimingSettings{ .del = 0 }).seconds());
    try testing.expectEqual(1, (RxTimingSettings{ .del = 1 }).seconds());
    try testing.expectEqual(15, (RxTimingSettings{ .del = 15 }).seconds());
}
