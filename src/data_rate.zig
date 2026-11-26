//! Data rate encoding per region, [RP002-1.0.5] §3.x.3 "Data Rate and
//! End-Device Output Power Encoding".

const std = @import("std");
const Direction = @import("mhdr.zig").Direction;
const Region = @import("region.zig").Region;

pub const CodingRate = enum { cr1_3, cr2_3 };

pub const Modulation = union(enum) {
    lora: struct {
        spreading_factor: u4,
        bandwidth_khz: u16,
    },
    fsk,
    lr_fhss: struct {
        coding_rate: CodingRate,
        /// Occupied bandwidth as written in the tables: 137, 336 or 1523 kHz.
        bandwidth_khz: u16,
    },
};

pub const DataRate = struct {
    modulation: Modulation,
    /// Indicative physical bit rate in bit/s.
    bit_rate: u32,
};

/// The configuration of data rate `dr`. Null for RFU values and for 15,
/// which [TS001-1.0.4] §5.2 reserves for "keep the current value".
pub fn get(region: Region, dir: Direction, dr: u4) ?DataRate {
    const t: *const Table = switch (region) {
        .eu863_870 => &eu863_870,
        .eu433 => &eu433,
        .cn470_510 => &cn470_510,
        .kr920_923 => &kr920_923,
        .in865 => &in865,
        .ru864_870 => &ru864_870,
        .as923 => &as923,
        .us902_928 => switch (dir) {
            .uplink => &us902_928_up,
            .downlink => &us902_928_down,
        },
        .au915_928 => switch (dir) {
            .uplink => &au915_928_up,
            .downlink => &au915_928_down,
        },
    };
    return t[dr];
}

const Table = [16]?DataRate;
/// RFU, or "Defined in [TS001]" for DR15.
const x: ?DataRate = null;

fn lora(sf: u4, bw_khz: u16, bit_rate: u32) ?DataRate {
    return .{ .modulation = .{ .lora = .{ .spreading_factor = sf, .bandwidth_khz = bw_khz } }, .bit_rate = bit_rate };
}

fn fsk(bit_rate: u32) ?DataRate {
    return .{ .modulation = .fsk, .bit_rate = bit_rate };
}

fn fhss(cr: CodingRate, bw_khz: u16, bit_rate: u32) ?DataRate {
    return .{ .modulation = .{ .lr_fhss = .{ .coding_rate = cr, .bandwidth_khz = bw_khz } }, .bit_rate = bit_rate };
}

/// [RP002-1.0.5] §3.4.3 Table 10.
const eu863_870 = Table{
    lora(12, 125, 250), // DR0
    lora(11, 125, 440),
    lora(10, 125, 980),
    lora(9, 125, 1760),
    lora(8, 125, 3125),
    lora(7, 125, 5470),
    lora(7, 250, 11000),
    fsk(50000),
    fhss(.cr1_3, 137, 162), // DR8
    fhss(.cr2_3, 137, 325),
    fhss(.cr1_3, 336, 162),
    fhss(.cr2_3, 336, 325),
    lora(6, 125, 9375),
    lora(5, 125, 15625),
    x,
    x, // DR15
};

/// [RP002-1.0.5] §3.7.3 Table 30.
const eu433 = Table{
    lora(12, 125, 250), // DR0
    lora(11, 125, 440),
    lora(10, 125, 980),
    lora(9, 125, 1760),
    lora(8, 125, 3125),
    lora(7, 125, 5470),
    lora(7, 250, 11000),
    fsk(50000),
    x, // DR8
    x,
    x,
    x,
    lora(6, 125, 9375),
    lora(5, 125, 15625),
    x,
    x, // DR15
};

/// [RP002-1.0.5] §3.9.3 Table 50. DR0 stays defined although devices no
/// longer use it, footnote 15.
const cn470_510 = Table{
    lora(12, 125, 250), // DR0
    lora(11, 125, 440),
    lora(10, 125, 980),
    lora(9, 125, 1760),
    lora(8, 125, 3125),
    lora(7, 125, 5470),
    lora(7, 500, 21900),
    fsk(50000),
    x, // DR8
    x,
    x,
    x,
    x,
    x,
    x,
    x, // DR15
};

/// [RP002-1.0.5] §3.10.3 Table 67.
const as923 = Table{
    lora(12, 125, 250), // DR0
    lora(11, 125, 440),
    lora(10, 125, 980),
    lora(9, 125, 1760),
    lora(8, 125, 3125),
    lora(7, 125, 5470),
    lora(7, 250, 11000),
    fsk(50000),
    x, // DR8
    x,
    x,
    x,
    lora(6, 125, 9375),
    lora(5, 125, 15625),
    x,
    x, // DR15
};

/// [RP002-1.0.5] §3.11.3 Table 80.
const kr920_923 = Table{
    lora(12, 125, 250), // DR0
    lora(11, 125, 440),
    lora(10, 125, 980),
    lora(9, 125, 1760),
    lora(8, 125, 3125),
    lora(7, 125, 5470),
    x,
    x,
    x, // DR8
    x,
    x,
    x,
    lora(6, 125, 9375),
    lora(5, 125, 15625),
    x,
    x, // DR15
};

/// [RP002-1.0.5] §3.12.3 Table 91.
const in865 = Table{
    lora(12, 125, 250), // DR0
    lora(11, 125, 440),
    lora(10, 125, 980),
    lora(9, 125, 1760),
    lora(8, 125, 3125),
    lora(7, 125, 5470),
    x,
    fsk(50000),
    x, // DR8
    x,
    x,
    x,
    lora(6, 125, 9375),
    lora(5, 125, 15625),
    x,
    x, // DR15
};

/// [RP002-1.0.5] §3.13.3 Table 102.
const ru864_870 = Table{
    lora(12, 125, 250), // DR0
    lora(11, 125, 440),
    lora(10, 125, 980),
    lora(9, 125, 1760),
    lora(8, 125, 3125),
    lora(7, 125, 5470),
    lora(7, 250, 11000),
    fsk(50000),
    x, // DR8
    x,
    x,
    x,
    lora(6, 125, 9375),
    lora(5, 125, 15625),
    x,
    x, // DR15
};

/// [RP002-1.0.5] §3.5.3 Table 19.
const us902_928_up = Table{
    lora(10, 125, 980), // DR0
    lora(9, 125, 1760),
    lora(8, 125, 3125),
    lora(7, 125, 5470),
    lora(8, 500, 12500),
    fhss(.cr1_3, 1523, 162),
    fhss(.cr2_3, 1523, 325),
    lora(6, 125, 9375),
    lora(5, 125, 15625), // DR8
    x,
    x,
    x,
    x,
    x,
    x,
    x, // DR15
};

/// [RP002-1.0.5] §3.5.3 Table 20.
const us902_928_down = Table{
    lora(5, 500, 62500), // DR0
    x,
    x,
    x,
    x,
    x,
    x,
    x,
    lora(12, 500, 980), // DR8
    lora(11, 500, 1760),
    lora(10, 500, 3900),
    lora(9, 500, 7000),
    lora(8, 500, 12500),
    lora(7, 500, 21900),
    lora(6, 500, 37500),
    x, // DR15
};

/// [RP002-1.0.5] §3.8.3 Table 39.
const au915_928_up = Table{
    lora(12, 125, 250), // DR0
    lora(11, 125, 440),
    lora(10, 125, 980),
    lora(9, 125, 1760),
    lora(8, 125, 3125),
    lora(7, 125, 5470),
    lora(8, 500, 12500),
    fhss(.cr1_3, 1523, 162),
    x, // DR8
    lora(6, 125, 9375),
    lora(5, 125, 15625),
    x,
    x,
    x,
    x,
    x, // DR15
};

/// [RP002-1.0.5] §3.8.3 Table 40.
const au915_928_down = Table{
    lora(5, 500, 62500), // DR0
    x,
    x,
    x,
    x,
    x,
    x,
    x,
    lora(12, 500, 980), // DR8
    lora(11, 500, 1760),
    lora(10, 500, 3900),
    lora(9, 500, 7000),
    lora(8, 500, 12500),
    lora(7, 500, 21900),
    lora(6, 500, 37500),
    x, // DR15
};

const testing = std.testing;

fn expectLora(region: Region, dir: Direction, dr: u4, sf: u4, bw_khz: u16, bit_rate: u32) !void {
    try testing.expectEqual(lora(sf, bw_khz, bit_rate), get(region, dir, dr));
}

test "EU863-870 Table 10" {
    try expectLora(.eu863_870, .uplink, 0, 12, 125, 250);
    try expectLora(.eu863_870, .uplink, 5, 7, 125, 5470);
    try expectLora(.eu863_870, .uplink, 6, 7, 250, 11000);
    try testing.expectEqual(fsk(50000), get(.eu863_870, .uplink, 7));
    try testing.expectEqual(fhss(.cr1_3, 137, 162), get(.eu863_870, .uplink, 8));
    try testing.expectEqual(fhss(.cr2_3, 336, 325), get(.eu863_870, .uplink, 11));
    try expectLora(.eu863_870, .uplink, 12, 6, 125, 9375);
    try expectLora(.eu863_870, .uplink, 13, 5, 125, 15625);
    try testing.expectEqual(null, get(.eu863_870, .uplink, 14));
    try testing.expectEqual(null, get(.eu863_870, .uplink, 15));
}

test "EU433 Table 30, AS923 Table 67, RU864-870 Table 102" {
    for ([_]Region{ .eu433, .as923, .ru864_870 }) |r| {
        try expectLora(r, .uplink, 6, 7, 250, 11000);
        try testing.expectEqual(fsk(50000), get(r, .downlink, 7));
        for (8..12) |dr| try testing.expectEqual(null, get(r, .uplink, @intCast(dr)));
        try expectLora(r, .uplink, 13, 5, 125, 15625);
    }
}

test "CN470-510 Table 50" {
    try expectLora(.cn470_510, .uplink, 6, 7, 500, 21900);
    try testing.expectEqual(fsk(50000), get(.cn470_510, .uplink, 7));
    for (8..16) |dr| try testing.expectEqual(null, get(.cn470_510, .uplink, @intCast(dr)));
}

test "KR920-923 Table 80 and IN865 Table 91" {
    for (6..12) |dr| try testing.expectEqual(null, get(.kr920_923, .uplink, @intCast(dr)));
    try expectLora(.kr920_923, .uplink, 12, 6, 125, 9375);
    try testing.expectEqual(null, get(.in865, .uplink, 6));
    try testing.expectEqual(fsk(50000), get(.in865, .uplink, 7));
    try expectLora(.in865, .uplink, 13, 5, 125, 15625);
}

test "US902-928 Tables 19 and 20" {
    try expectLora(.us902_928, .uplink, 0, 10, 125, 980);
    try expectLora(.us902_928, .uplink, 4, 8, 500, 12500);
    try testing.expectEqual(fhss(.cr2_3, 1523, 325), get(.us902_928, .uplink, 6));
    try expectLora(.us902_928, .uplink, 8, 5, 125, 15625);
    try testing.expectEqual(null, get(.us902_928, .uplink, 9));
    try expectLora(.us902_928, .downlink, 0, 5, 500, 62500);
    try testing.expectEqual(null, get(.us902_928, .downlink, 7));
    try expectLora(.us902_928, .downlink, 8, 12, 500, 980);
    try expectLora(.us902_928, .downlink, 14, 6, 500, 37500);
}

test "AU915-928 Tables 39 and 40" {
    try expectLora(.au915_928, .uplink, 0, 12, 125, 250);
    try expectLora(.au915_928, .uplink, 6, 8, 500, 12500);
    try testing.expectEqual(fhss(.cr1_3, 1523, 162), get(.au915_928, .uplink, 7));
    try testing.expectEqual(null, get(.au915_928, .uplink, 8));
    try expectLora(.au915_928, .uplink, 10, 5, 125, 15625);
    try expectLora(.au915_928, .downlink, 13, 7, 500, 21900);
}

test "defined data rates match the defined payload sizes" {
    // The payload tables of region.zig were transcribed separately.
    const region = @import("region.zig");
    inline for (@typeInfo(Region).@"enum".field_names) |name| {
        const r = @field(Region, name);
        for ([_]Direction{ .uplink, .downlink }) |dir| {
            for (0..16) |i| {
                const dr: u4 = @intCast(i);
                // CN470-510 DR0 has no payload size, footnote 15 of Tables
                // 50 and 54.
                if (r == .cn470_510 and dr == 0) continue;
                const has_rate = get(r, dir, dr) != null;
                const has_len = region.maxMacPayloadLen(r, dir, dr, .{}) != null;
                if (has_rate != has_len) {
                    std.debug.print("{s} {s} DR{d}: rate {} payload {}\n", .{ name, @tagName(dir), dr, has_rate, has_len });
                    return error.TestUnexpectedResult;
                }
            }
        }
    }
}
