//! The optional CFList of the Join-Accept, [TS001-1.0.4] §6.2.6 Table 54.
//! Its layout is defined in [RP002-1.0.5] §3.3.1. That document numbers both
//! the Type 0 and the Type 1 section §3.3.1, so citations here add the title.

const std = @import("std");

pub const len = 16;

/// [RP002-1.0.5] §3.3.1 Join-Accept CFList Type 0 and Type 1.
pub const CfList = union(enum) {
    /// CFListType 0, frequencies for channels N to N + 4, where N is the
    /// number of default channels of the region. Each value is in 100 Hz
    /// steps and 0 marks an unused channel.
    ///
    ///   Octets |     3     | ... |     3     |      1
    ///   CFList | Freq Ch N | ... | Freq N+4  | CFListType
    frequencies: [5]u24,
    /// CFListType 1, ChMaskGrp0 to ChMaskGrp5. See `channelEnabled`.
    ///
    ///   Octets |     2     | ... |     2     |  3  |     1
    ///   CFList | ChMaskGrp0| ... | ChMaskGrp5| RFU | CFListType
    ch_mask: [6]u16,

    pub const DecodeError = error{UnsupportedCfListType};

    pub fn encode(self: CfList) [len]u8 {
        var out: [len]u8 = @splat(0);
        switch (self) {
            .frequencies => |freqs| {
                for (freqs, 0..) |f, i| std.mem.writeInt(u24, out[i * 3 ..][0..3], f, .little);
                out[15] = 0;
            },
            .ch_mask => |masks| {
                for (masks, 0..) |m, i| std.mem.writeInt(u16, out[i * 2 ..][0..2], m, .little);
                out[15] = 1;
            },
        }
        return out;
    }

    /// RFU octets of Type 1 are ignored, [TS001-1.0.4] §1.1.
    pub fn decode(bytes: *const [len]u8) DecodeError!CfList {
        switch (bytes[15]) {
            0 => {
                var freqs: [5]u24 = undefined;
                for (&freqs, 0..) |*f, i| f.* = std.mem.readInt(u24, bytes[i * 3 ..][0..3], .little);
                return .{ .frequencies = freqs };
            },
            1 => {
                var masks: [6]u16 = undefined;
                for (&masks, 0..) |*m, i| m.* = std.mem.readInt(u16, bytes[i * 2 ..][0..2], .little);
                return .{ .ch_mask = masks };
            },
            else => return error.UnsupportedCfListType,
        }
    }
};

/// Channel-ID = ChMask-group-number * 16 + ChMask-bit-number,
/// [RP002-1.0.5] §3.3.1 Join-Accept CFList Type 1.
pub fn channelEnabled(masks: [6]u16, channel_id: u7) bool {
    if (channel_id >= 96) return false;
    const grp = masks[channel_id / 16];
    return grp >> @intCast(channel_id % 16) & 1 == 1;
}

const testing = std.testing;
const hex = @import("test_util.zig").hex;

test "Type 1 example of RP002-1.0.5 §3.3.1" {
    // The example CFList 0x0100_A010_0000_0000_0000_0000 creates channels at
    // Channel-ID 0, 21, 23 and 28. The RFU octets and CFListType follow.
    const bytes = hex("0100A010000000000000000000000001");
    const cf = try CfList.decode(&bytes);
    var ids: [4]u7 = undefined;
    var n: usize = 0;
    for (0..96) |id| {
        if (channelEnabled(cf.ch_mask, @intCast(id))) {
            ids[n] = @intCast(id);
            n += 1;
        }
    }
    try testing.expectEqualSlices(u7, &.{ 0, 21, 23, 28 }, ids[0..n]);
    try testing.expectEqual(bytes, cf.encode());
}

test "Type 1, default EU868 channels and RFU octets" {
    // The example's note: the EU868 default channels correspond to
    // ChMaskGrp1 = 0x000E, Channel-ID 25 to 27.
    var bytes = hex("0000000E000000000000000000000001");
    const cf = try CfList.decode(&bytes);
    try testing.expect(channelEnabled(cf.ch_mask, 25));
    try testing.expect(channelEnabled(cf.ch_mask, 27));
    try testing.expect(!channelEnabled(cf.ch_mask, 24));
    try testing.expect(!channelEnabled(cf.ch_mask, 96));
    bytes[12] = 0xFF; // RFU
    try testing.expectEqual(cf, try CfList.decode(&bytes));
}

test "Type 0 layout" {
    // 867.1 MHz is 8671000 = 0x844F18, 867.3 MHz is 8673000 = 0x8456E8.
    const cf = CfList{ .frequencies = .{ 8671000, 8673000, 0, 0, 0 } };
    const bytes = cf.encode();
    try testing.expectEqual(hex("184F84E8568400000000000000000000"), bytes);
    try testing.expectEqual(cf, try CfList.decode(&bytes));
}

test "unknown CFListType" {
    var bytes: [len]u8 = @splat(0);
    bytes[15] = 2;
    try testing.expectError(error.UnsupportedCfListType, CfList.decode(&bytes));
}
