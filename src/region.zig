//! Maximum MACPayload size M per region and data rate, [RP002-1.0.5] §3.
//!
//! [TS001-1.0.4] §4.1 defers M to the Regional Parameters and requires that a
//! frame whose MACPayload exceeds M for the data rate used SHALL NOT be sent
//! and SHALL be silently discarded on receive. This module only provides M.
//! The caller compares it with `MACPayload.len()`.
//!
//! [TS001-1.0.4] §19 cites RP002-1.0.0. RP002 applies to all LoRaWAN L2
//! versions from RP002-1.0.0 on, and this module follows RP002-1.0.5.
//!
//! The application payload N in the RP002 tables is "given for information
//! only" and always equals M - 8 (a 7-octet FHDR without FOpts plus FPort), so
//! only M is stored.

const std = @import("std");
const Direction = @import("mhdr.zig").Direction;

pub const Region = enum {
    /// EU863-870, [RP002-1.0.5] §3.4.
    eu863_870,
    /// EU433, [RP002-1.0.5] §3.7.
    eu433,
    /// CN470-510, [RP002-1.0.5] §3.9.
    cn470_510,
    /// KR920-923, [RP002-1.0.5] §3.11.
    kr920_923,
    /// IN865, [RP002-1.0.5] §3.12.
    in865,
    /// RU864-870, [RP002-1.0.5] §3.13.
    ru864_870,
    /// US902-928, [RP002-1.0.5] §3.5.
    us902_928,
    /// AU915-928, [RP002-1.0.5] §3.8.
    au915_928,
    /// AS923, all groups AS923-1 to AS923-4, [RP002-1.0.5] §3.10.
    as923,
};

pub const Options = struct {
    /// Use the repeater compatible tables. They are the default. The other
    /// tables apply only "if the end-device will never operate with a
    /// repeater", [RP002-1.0.5] §3.x.6 and §4.1. RP002 says SHALL for the
    /// other tables in EU863-870, EU433 and CN470-510, and SHOULD in
    /// KR920-923, IN865 and RU864-870.
    repeater_compatible: bool = true,
    /// UplinkDwellTime = 1 (400 ms limit). Only AS923 and AU915-928 have
    /// separate limits for it, [RP002-1.0.5] §3.10.6 and §3.8.6. Ignored elsewhere.
    uplink_dwell_time: bool = false,
    /// DownlinkDwellTime = 1 (400 ms limit). Only AS923 has separate limits
    /// for it, [RP002-1.0.5] §3.10.6. Ignored elsewhere, and for AU915-928
    /// DownlinkDwellTime SHALL be 0, [RP002-1.0.5] §3.8.6.
    ///
    /// An AS923 end-device "SHALL only enforce the maximum downlink MACPayload
    /// size defined for DownlinkDwellTime = 0 (no dwell time enforced)
    /// regardless of the actual setting", [RP002-1.0.5] §3.10.6. So an
    /// end-device checking received downlinks leaves this false.
    downlink_dwell_time: bool = false,
};

/// M per data rate DR0..DR15, null where the data rate is "Not defined" or N/A.
const Limits = [16]?u8;

const Tables = struct {
    uplink: Limits,
    downlink: Limits,
    /// Limits under a 400 ms dwell time, where the region defines them.
    uplink_dwell: ?Limits = null,
    downlink_dwell: ?Limits = null,
};

fn same(l: Limits) Tables {
    return .{ .uplink = l, .downlink = l };
}

/// Maximum MACPayload length M in octets for a frame sent in direction `dir`
/// at data rate `dr`, or null if RP002 does not define that data rate.
pub fn maxMacPayloadLen(region: Region, dir: Direction, dr: u4, opts: Options) ?u8 {
    const t = tables(region, opts);
    const l = switch (dir) {
        .uplink => if (opts.uplink_dwell_time) t.uplink_dwell orelse t.uplink else t.uplink,
        .downlink => if (opts.downlink_dwell_time) t.downlink_dwell orelse t.downlink else t.downlink,
    };
    return l[dr];
}

/// Repeater compatible and not repeater compatible tables of a region that
/// uses one table for both directions.
const Pair = struct { repeater: Limits, no_repeater: Limits };

fn pick(p: Pair, opts: Options) Tables {
    return same(if (opts.repeater_compatible) p.repeater else p.no_repeater);
}

/// Repeater compatible and not repeater compatible tables of a region with
/// per direction or dwell time limits.
const Variants = struct { repeater: Tables, no_repeater: Tables };

fn pickVariants(v: Variants, opts: Options) Tables {
    return if (opts.repeater_compatible) v.repeater else v.no_repeater;
}

fn tables(region: Region, opts: Options) Tables {
    return switch (region) {
        .eu863_870 => pick(eu863_870, opts),
        .eu433 => pick(eu433, opts),
        .cn470_510 => pick(cn470_510, opts),
        .kr920_923 => pick(kr920_923, opts),
        .in865 => pick(in865, opts),
        .ru864_870 => pick(ru864_870, opts),
        .us902_928 => pickVariants(us902_928, opts),
        .au915_928 => pickVariants(au915_928, opts),
        .as923 => pickVariants(as923, opts),
    };
}

const x: ?u8 = null; // "Not defined" in RP002

// [RP002-1.0.5] §3.4.6, EU863-870.
const eu863_870 = Pair{
    // Table 15 (repeater compatible).
    .repeater = .{
        59, 59, 59, 123, 230, 230, 230, 230, // DR0..DR7
        58, 123, 58, 123, 230, 230, x, x, // DR8..DR15
    },
    // Table 16 (not repeater compatible).
    .no_repeater = .{
        59, 59, 59, 123, 250, 250, 250, 250, // DR0..DR7
        58, 123, 58, 123, 250, 250, x, x, // DR8..DR15
    },
};

// [RP002-1.0.5] §3.7.6, EU433.
const eu433 = Pair{
    // Table 36 (repeater compatible).
    .repeater = .{
        59, 59, 59, 123, 230, 230, 230, 230, // DR0..DR7
        x, x, x, x, 230, 230, x, x, // DR8..DR15
    },
    // Table 37 (not repeater compatible).
    .no_repeater = .{
        59, 59, 59, 123, 250, 250, 250, 250, // DR0..DR7
        x, x, x, x, 250, 250, x, x, // DR8..DR15
    },
};

// [RP002-1.0.5] §3.9.6, CN470-510.
// DR0 is N/A: "As of RP002-1.0.1, DR0 is unavailable for devices implementing
// CN470-510, but remains defined to better support existing implementations"
// (footnote 15).
const cn470_510 = Pair{
    // Table 54 (repeater compatible).
    .repeater = .{
        x, 31, 94, 192, 230, 230, 230, 230, // DR0..DR7
        x, x, x, x, x, x, x, x, // DR8..DR15
    },
    // Table 55 (not repeater compatible).
    .no_repeater = .{
        x, 31, 94, 192, 250, 250, 250, 250, // DR0..DR7
        x, x, x, x, x, x, x, x, // DR8..DR15
    },
};

// [RP002-1.0.5] §3.11.6, KR920-923.
const kr920_923 = Pair{
    // Table 85 (repeater compatible).
    .repeater = .{
        59, 59, 59, 123, 230, 230, x, x, // DR0..DR7
        x, x, x, x, 230, 230, x, x, // DR8..DR15
    },
    // Table 86 (not repeater compatible).
    .no_repeater = .{
        59, 59, 59, 123, 250, 250, x, x, // DR0..DR7
        x, x, x, x, 250, 250, x, x, // DR8..DR15
    },
};

// [RP002-1.0.5] §3.12.6, IN865.
const in865 = Pair{
    // Table 96 (repeater compatible).
    .repeater = .{
        59, 59, 59, 123, 230, 230, x, 230, // DR0..DR7
        x, x, x, x, 230, 230, x, x, // DR8..DR15
    },
    // Table 97 (not repeater compatible).
    .no_repeater = .{
        59, 59, 59, 123, 250, 250, x, 250, // DR0..DR7
        x, x, x, x, 250, 250, x, x, // DR8..DR15
    },
};

// [RP002-1.0.5] §3.13.6, RU864-870.
const ru864_870 = Pair{
    // Table 107 (repeater compatible).
    .repeater = .{
        59, 59, 59, 123, 230, 230, 230, 230, // DR0..DR7
        x, x, x, x, 230, 230, x, x, // DR8..DR15
    },
    // Table 108 (not repeater compatible).
    .no_repeater = .{
        59, 59, 59, 123, 250, 250, 250, 250, // DR0..DR7
        x, x, x, x, 250, 250, x, x, // DR8..DR15
    },
};

// [RP002-1.0.5] §3.5.6, US902-928. Uplink and downlink data rates differ
// (Tables 19 and 20). Downlink DR0 is allowed since RP002-1.0.5 (§3.5.3).
const us902_928 = Variants{
    // Table 24 (repeater compatible).
    .repeater = .{
        .uplink = .{
            19, 61, 133, 230, 230, 58, 133, 230, // DR0..DR7
            230, x, x, x, x, x, x, x, // DR8..DR15
        },
        .downlink = .{
            230, x, x, x, x, x, x, x, // DR0..DR7
            61, 137, 230, 230, 230, 230, 230, x, // DR8..DR15
        },
    },
    // Table 25 (not repeater compatible).
    .no_repeater = .{
        .uplink = .{
            19, 61, 133, 250, 250, 58, 133, 250, // DR0..DR7
            250, x, x, x, x, x, x, x, // DR8..DR15
        },
        .downlink = .{
            250, x, x, x, x, x, x, x, // DR0..DR7
            61, 137, 250, 250, 250, 250, 250, x, // DR8..DR15
        },
    },
};

// [RP002-1.0.5] §3.8.6, AU915-928. Uplink has UplinkDwellTime = 0 and 1
// columns. "DownlinkDwellTime SHALL be set to 0 (no limit)", so the downlink
// has one column.
const au915_928 = Variants{
    // Table 44 (repeater compatible).
    .repeater = .{
        .uplink = .{
            59, 59, 59, 123, 230, 230, 230, 58, // DR0..DR7
            x, 230, 230, x, x, x, x, x, // DR8..DR15
        },
        .uplink_dwell = .{
            x, x, 19, 61, 133, 230, 230, 58, // DR0..DR7 (DR0, DR1 N/A)
            x, 230, 230, x, x, x, x, x, // DR8..DR15
        },
        .downlink = .{
            230, x, x, x, x, x, x, x, // DR0..DR7
            61, 137, 230, 230, 230, 230, 230, x, // DR8..DR15
        },
    },
    // Table 45 (not repeater compatible).
    .no_repeater = .{
        .uplink = .{
            59, 59, 59, 123, 250, 250, 250, 58, // DR0..DR7
            x, 250, 250, x, x, x, x, x, // DR8..DR15
        },
        .uplink_dwell = .{
            x, x, 19, 61, 133, 250, 250, 58, // DR0..DR7 (DR0, DR1 N/A)
            x, 250, 250, x, x, x, x, x, // DR8..DR15
        },
        .downlink = .{
            250, x, x, x, x, x, x, x, // DR0..DR7
            61, 137, 250, 250, 250, 250, 250, x, // DR8..DR15
        },
    },
};

// [RP002-1.0.5] §3.10.6, AS923. One table for both directions, with
// DwellTime = 0 and DwellTime = 1 columns that apply to UplinkDwellTime and
// DownlinkDwellTime alike.
fn as923Tables(no_limit: Limits, dwell: Limits) Tables {
    return .{ .uplink = no_limit, .downlink = no_limit, .uplink_dwell = dwell, .downlink_dwell = dwell };
}

const as923 = Variants{
    // Table 72 (repeater compatible).
    .repeater = as923Tables(.{
        59, 59, 123, 123, 230, 230, 230, 230, // DR0..DR7
        x, x, x, x, 230, 230, x, x, // DR8..DR15
    }, .{
        x, x, 19, 61, 133, 230, 230, 230, // DR0..DR7 (DR0, DR1 N/A)
        x, x, x, x, 230, 230, x, x, // DR8..DR15
    }),
    // Table 73 (not repeater compatible).
    .no_repeater = as923Tables(.{
        59, 59, 123, 123, 250, 250, 250, 250, // DR0..DR7
        x, x, x, x, 250, 250, x, x, // DR8..DR15
    }, .{
        x, x, 19, 61, 133, 250, 250, 250, // DR0..DR7 (DR0, DR1 N/A)
        x, x, x, x, 250, 250, x, x, // DR8..DR15
    }),
};

const testing = std.testing;

test "EU863-870 Table 15 (repeater compatible)" {
    try testing.expectEqual(59, maxMacPayloadLen(.eu863_870, .uplink, 0, .{}));
    try testing.expectEqual(123, maxMacPayloadLen(.eu863_870, .uplink, 3, .{}));
    try testing.expectEqual(230, maxMacPayloadLen(.eu863_870, .downlink, 5, .{}));
    try testing.expectEqual(58, maxMacPayloadLen(.eu863_870, .uplink, 10, .{}));
    try testing.expectEqual(230, maxMacPayloadLen(.eu863_870, .uplink, 13, .{}));
    try testing.expectEqual(null, maxMacPayloadLen(.eu863_870, .uplink, 14, .{}));
}

test "EU863-870 Table 16 (not repeater compatible)" {
    const no_rep = Options{ .repeater_compatible = false };
    try testing.expectEqual(59, maxMacPayloadLen(.eu863_870, .uplink, 2, no_rep));
    try testing.expectEqual(250, maxMacPayloadLen(.eu863_870, .uplink, 4, no_rep));
    try testing.expectEqual(250, maxMacPayloadLen(.eu863_870, .downlink, 12, no_rep));
    try testing.expectEqual(null, maxMacPayloadLen(.eu863_870, .downlink, 15, no_rep));
}

test "EU433 Tables 36 and 37" {
    try testing.expectEqual(123, maxMacPayloadLen(.eu433, .uplink, 3, .{}));
    try testing.expectEqual(null, maxMacPayloadLen(.eu433, .uplink, 8, .{}));
    try testing.expectEqual(230, maxMacPayloadLen(.eu433, .downlink, 12, .{}));
    try testing.expectEqual(250, maxMacPayloadLen(.eu433, .uplink, 7, .{ .repeater_compatible = false }));
}

test "CN470-510 Tables 54 and 55" {
    // DR0 is N/A per footnote 15.
    try testing.expectEqual(null, maxMacPayloadLen(.cn470_510, .uplink, 0, .{}));
    try testing.expectEqual(31, maxMacPayloadLen(.cn470_510, .uplink, 1, .{}));
    try testing.expectEqual(94, maxMacPayloadLen(.cn470_510, .uplink, 2, .{}));
    try testing.expectEqual(192, maxMacPayloadLen(.cn470_510, .downlink, 3, .{}));
    try testing.expectEqual(250, maxMacPayloadLen(.cn470_510, .uplink, 4, .{ .repeater_compatible = false }));
    try testing.expectEqual(null, maxMacPayloadLen(.cn470_510, .uplink, 8, .{}));
}

test "KR920-923 Tables 85 and 86" {
    try testing.expectEqual(230, maxMacPayloadLen(.kr920_923, .uplink, 5, .{}));
    try testing.expectEqual(null, maxMacPayloadLen(.kr920_923, .uplink, 6, .{}));
    try testing.expectEqual(250, maxMacPayloadLen(.kr920_923, .uplink, 13, .{ .repeater_compatible = false }));
}

test "IN865 Tables 96 and 97" {
    try testing.expectEqual(null, maxMacPayloadLen(.in865, .uplink, 6, .{}));
    try testing.expectEqual(230, maxMacPayloadLen(.in865, .uplink, 7, .{}));
    try testing.expectEqual(250, maxMacPayloadLen(.in865, .downlink, 12, .{ .repeater_compatible = false }));
}

test "RU864-870 Tables 107 and 108" {
    try testing.expectEqual(230, maxMacPayloadLen(.ru864_870, .uplink, 6, .{}));
    try testing.expectEqual(null, maxMacPayloadLen(.ru864_870, .uplink, 11, .{}));
    try testing.expectEqual(250, maxMacPayloadLen(.ru864_870, .uplink, 13, .{ .repeater_compatible = false }));
}

fn expectRepeaterRule(rep: Limits, no_rep: Limits) !void {
    for (rep, no_rep) |a, b| {
        if (b) |m| {
            try testing.expectEqual(if (m == 250) m - 20 else m, a.?);
        } else try testing.expectEqual(null, a);
    }
}

test "US902-928 Tables 24 and 25" {
    try testing.expectEqual(19, maxMacPayloadLen(.us902_928, .uplink, 0, .{}));
    try testing.expectEqual(58, maxMacPayloadLen(.us902_928, .uplink, 5, .{}));
    try testing.expectEqual(230, maxMacPayloadLen(.us902_928, .uplink, 8, .{}));
    try testing.expectEqual(null, maxMacPayloadLen(.us902_928, .uplink, 9, .{}));
    // Same DR number, different limit per direction.
    try testing.expectEqual(230, maxMacPayloadLen(.us902_928, .downlink, 0, .{}));
    try testing.expectEqual(null, maxMacPayloadLen(.us902_928, .downlink, 1, .{}));
    try testing.expectEqual(61, maxMacPayloadLen(.us902_928, .downlink, 8, .{}));
    try testing.expectEqual(137, maxMacPayloadLen(.us902_928, .downlink, 9, .{}));
    try testing.expectEqual(null, maxMacPayloadLen(.us902_928, .downlink, 15, .{}));
    try testing.expectEqual(250, maxMacPayloadLen(.us902_928, .downlink, 14, .{ .repeater_compatible = false }));
    // No dwell time columns in US902-928.
    try testing.expectEqual(19, maxMacPayloadLen(.us902_928, .uplink, 0, .{ .uplink_dwell_time = true }));
}

test "AU915-928 Tables 44 and 45" {
    try testing.expectEqual(59, maxMacPayloadLen(.au915_928, .uplink, 0, .{}));
    try testing.expectEqual(null, maxMacPayloadLen(.au915_928, .uplink, 0, .{ .uplink_dwell_time = true }));
    try testing.expectEqual(19, maxMacPayloadLen(.au915_928, .uplink, 2, .{ .uplink_dwell_time = true }));
    try testing.expectEqual(133, maxMacPayloadLen(.au915_928, .uplink, 4, .{ .uplink_dwell_time = true, .repeater_compatible = false }));
    try testing.expectEqual(null, maxMacPayloadLen(.au915_928, .uplink, 8, .{}));
    try testing.expectEqual(230, maxMacPayloadLen(.au915_928, .uplink, 10, .{}));
    try testing.expectEqual(230, maxMacPayloadLen(.au915_928, .downlink, 0, .{}));
    try testing.expectEqual(137, maxMacPayloadLen(.au915_928, .downlink, 9, .{}));
    // DownlinkDwellTime SHALL be 0 in AU915-928, so the flag has no effect.
    try testing.expectEqual(230, maxMacPayloadLen(.au915_928, .downlink, 0, .{ .downlink_dwell_time = true }));
}

test "AS923 Tables 72 and 73" {
    try testing.expectEqual(123, maxMacPayloadLen(.as923, .uplink, 2, .{}));
    try testing.expectEqual(19, maxMacPayloadLen(.as923, .uplink, 2, .{ .uplink_dwell_time = true }));
    try testing.expectEqual(null, maxMacPayloadLen(.as923, .uplink, 1, .{ .uplink_dwell_time = true }));
    try testing.expectEqual(133, maxMacPayloadLen(.as923, .uplink, 4, .{ .uplink_dwell_time = true }));
    try testing.expectEqual(null, maxMacPayloadLen(.as923, .uplink, 8, .{}));
    try testing.expectEqual(250, maxMacPayloadLen(.as923, .downlink, 13, .{ .repeater_compatible = false }));
    // DownlinkDwellTime = 1 column, for the transmitting side.
    try testing.expectEqual(61, maxMacPayloadLen(.as923, .downlink, 3, .{ .downlink_dwell_time = true }));
    // An end-device enforces the DownlinkDwellTime = 0 column (§3.10.6).
    try testing.expectEqual(123, maxMacPayloadLen(.as923, .downlink, 3, .{}));
}

fn expectRepeaterRuleTables(rep: Tables, no_rep: Tables) !void {
    try expectRepeaterRule(rep.uplink, no_rep.uplink);
    try expectRepeaterRule(rep.downlink, no_rep.downlink);
    try testing.expectEqual(rep.uplink_dwell == null, no_rep.uplink_dwell == null);
    try testing.expectEqual(rep.downlink_dwell == null, no_rep.downlink_dwell == null);
    if (rep.uplink_dwell) |l| try expectRepeaterRule(l, no_rep.uplink_dwell.?);
    if (rep.downlink_dwell) |l| try expectRepeaterRule(l, no_rep.downlink_dwell.?);
}

test "repeater tables are 20 octets smaller only where the other table has 250 (§4.1)" {
    inline for (.{ eu863_870, eu433, cn470_510, kr920_923, in865, ru864_870 }) |p| {
        try expectRepeaterRule(p.repeater, p.no_repeater);
    }
    inline for (.{ us902_928, au915_928, as923 }) |v| {
        try expectRepeaterRuleTables(v.repeater, v.no_repeater);
    }
}
