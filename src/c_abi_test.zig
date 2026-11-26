//! Checks that include/lora.h and src/c.zig agree on the ABI: struct sizes,
//! alignment, field names and offsets, and every constant. `lora_h` is the
//! header translated by `zig translate-c` in build.zig.

const std = @import("std");
const testing = std.testing;
const c = @import("c.zig");
const h = @import("lora_h");

fn expectSameLayout(comptime Z: type, comptime C: type) !void {
    const z = @typeInfo(Z).@"struct";
    const cs = @typeInfo(C).@"struct";
    try testing.expectEqual(@sizeOf(C), @sizeOf(Z));
    try testing.expectEqual(@alignOf(C), @alignOf(Z));
    try testing.expectEqual(cs.field_names.len, z.field_names.len);
    inline for (z.field_names, cs.field_names) |zn, cn| {
        try testing.expectEqualStrings(zn, cn);
        try testing.expectEqual(@offsetOf(C, cn), @offsetOf(Z, zn));
        try testing.expectEqual(@sizeOf(@FieldType(C, cn)), @sizeOf(@FieldType(Z, zn)));
    }
}

test "struct layouts match" {
    try expectSameLayout(c.FCtrl, h.lora_fctrl);
    try expectSameLayout(c.SessionKeys, h.lora_session_keys);
    try expectSameLayout(c.DataFrame, h.lora_data_frame);
    try expectSameLayout(c.ParsedFrame, h.lora_parsed_frame);
}

test "status codes match" {
    try testing.expectEqual(c.ok, h.LORA_OK);
    try testing.expectEqual(c.err_invalid_argument, h.LORA_ERR_INVALID_ARGUMENT);
    try testing.expectEqual(c.err_truncated, h.LORA_ERR_TRUNCATED);
    try testing.expectEqual(c.err_fopts_too_long, h.LORA_ERR_FOPTS_TOO_LONG);
    try testing.expectEqual(c.err_missing_fport, h.LORA_ERR_MISSING_FPORT);
    try testing.expectEqual(c.err_mac_commands_in_fopts_and_payload, h.LORA_ERR_MAC_COMMANDS_IN_FOPTS_AND_PAYLOAD);
    try testing.expectEqual(c.err_not_data_frame, h.LORA_ERR_NOT_DATA_FRAME);
    try testing.expectEqual(c.err_unsupported_major, h.LORA_ERR_UNSUPPORTED_MAJOR);
    try testing.expectEqual(c.err_fcnt_mismatch, h.LORA_ERR_FCNT_MISMATCH);
    try testing.expectEqual(c.err_too_long, h.LORA_ERR_TOO_LONG);
    try testing.expectEqual(c.err_no_space_left, h.LORA_ERR_NO_SPACE_LEFT);
    try testing.expectEqual(c.err_authentication_failed, h.LORA_ERR_AUTHENTICATION_FAILED);
}

test "enum values match the Zig enums" {
    const lora = @import("lora");
    try testing.expectEqual(@intFromEnum(lora.Direction.uplink), h.LORA_UPLINK);
    try testing.expectEqual(@intFromEnum(lora.Direction.downlink), h.LORA_DOWNLINK);

    try testing.expectEqual(@intFromEnum(lora.FType.join_request), h.LORA_FTYPE_JOIN_REQUEST);
    try testing.expectEqual(@intFromEnum(lora.FType.join_accept), h.LORA_FTYPE_JOIN_ACCEPT);
    try testing.expectEqual(@intFromEnum(lora.FType.unconfirmed_data_up), h.LORA_FTYPE_UNCONFIRMED_DATA_UP);
    try testing.expectEqual(@intFromEnum(lora.FType.unconfirmed_data_down), h.LORA_FTYPE_UNCONFIRMED_DATA_DOWN);
    try testing.expectEqual(@intFromEnum(lora.FType.confirmed_data_up), h.LORA_FTYPE_CONFIRMED_DATA_UP);
    try testing.expectEqual(@intFromEnum(lora.FType.confirmed_data_down), h.LORA_FTYPE_CONFIRMED_DATA_DOWN);
    try testing.expectEqual(@intFromEnum(lora.FType.rfu), h.LORA_FTYPE_RFU);
    try testing.expectEqual(@intFromEnum(lora.FType.proprietary), h.LORA_FTYPE_PROPRIETARY);
}

test "region values and flags match" {
    const lora = @import("lora");
    // Each header constant maps to the region of the same name.
    const cases = .{
        .{ h.LORA_REGION_EU863_870, lora.Region.eu863_870 },
        .{ h.LORA_REGION_US902_928, lora.Region.us902_928 },
        .{ h.LORA_REGION_EU433, lora.Region.eu433 },
        .{ h.LORA_REGION_AU915_928, lora.Region.au915_928 },
        .{ h.LORA_REGION_CN470_510, lora.Region.cn470_510 },
        .{ h.LORA_REGION_AS923, lora.Region.as923 },
        .{ h.LORA_REGION_KR920_923, lora.Region.kr920_923 },
        .{ h.LORA_REGION_IN865, lora.Region.in865 },
        .{ h.LORA_REGION_RU864_870, lora.Region.ru864_870 },
    };
    inline for (cases) |case| {
        try testing.expectEqual(case[1], c.region(case[0]));
    }
    try testing.expectEqual(.uplink, c.direction(h.LORA_UPLINK));
    try testing.expectEqual(.downlink, c.direction(h.LORA_DOWNLINK));

    try testing.expectEqual(c.flag_not_repeater_compatible, h.LORA_REGION_NOT_REPEATER_COMPATIBLE);
    try testing.expectEqual(c.flag_uplink_dwell_time, h.LORA_REGION_UPLINK_DWELL_TIME);
    try testing.expectEqual(c.flag_downlink_dwell_time, h.LORA_REGION_DOWNLINK_DWELL_TIME);
}
