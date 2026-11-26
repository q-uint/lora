//! C ABI for the library. The matching declarations are in include/lora.h.
//!
//! Conventions:
//!   * Functions return `lora_status` (0 on success, negative on error) unless
//!     documented otherwise.
//!   * Slices become pointer and length pairs.
//!   * Enum values crossing the boundary are validated, never cast blindly.

const std = @import("std");
const lora = @import("lora");

// Status codes, see `lora_status` in include/lora.h.
pub const ok: c_int = 0;
pub const err_invalid_argument: c_int = -1;
pub const err_truncated: c_int = -2;
pub const err_fopts_too_long: c_int = -3;
pub const err_missing_fport: c_int = -4;
pub const err_mac_commands_in_fopts_and_payload: c_int = -5;
pub const err_not_data_frame: c_int = -6;
pub const err_unsupported_major: c_int = -7;
pub const err_fcnt_mismatch: c_int = -8;
pub const err_too_long: c_int = -9;
pub const err_no_space_left: c_int = -10;
pub const err_authentication_failed: c_int = -11;

// Direction, see `lora_direction`. Values are the Dir field of A_i and B0,
// [TS001-1.0.4] §4.3.3 Table 12 and §4.4 Table 13.
pub fn direction(v: c_int) ?lora.Direction {
    return switch (v) {
        0 => .uplink,
        1 => .downlink,
        else => null,
    };
}

// Region, see `lora_region`. Explicit so the C values never depend on the
// order of the Zig enum.
pub fn region(v: c_int) ?lora.Region {
    return switch (v) {
        0 => .eu863_870,
        1 => .us902_928,
        2 => .eu433,
        3 => .au915_928,
        4 => .cn470_510,
        5 => .as923,
        6 => .kr920_923,
        7 => .in865,
        8 => .ru864_870,
        else => null,
    };
}

// Region flags, see `LORA_REGION_*` in include/lora.h. Zero means the defaults.
pub const flag_not_repeater_compatible: u32 = 1 << 0;
pub const flag_uplink_dwell_time: u32 = 1 << 1;
pub const flag_downlink_dwell_time: u32 = 1 << 2;
const flags_known = flag_not_repeater_compatible | flag_uplink_dwell_time | flag_downlink_dwell_time;

/// Maximum MACPayload length M, [RP002-1.0.5] §3.x.6.
/// Returns M (1..255), 0 if RP002 does not define the data rate (M is never
/// 0 in RP002), or `err_invalid_argument` for bad arguments.
export fn lora_max_mac_payload_len(region_v: c_int, dir_v: c_int, dr: c_uint, flags: u32) c_int {
    const r = region(region_v) orelse return err_invalid_argument;
    const d = direction(dir_v) orelse return err_invalid_argument;
    if (dr > 15 or flags & ~flags_known != 0) return err_invalid_argument;
    const m = lora.region.maxMacPayloadLen(r, d, @intCast(dr), .{
        .repeater_compatible = flags & flag_not_repeater_compatible == 0,
        .uplink_dwell_time = flags & flag_uplink_dwell_time != 0,
        .downlink_dwell_time = flags & flag_downlink_dwell_time != 0,
    });
    return if (m) |v| v else 0;
}

/// Candidate 32-bit frame counter, see `fcnt.infer` and [TS001-1.0.4] §4.3.1.5.
/// `last` is ignored when `has_last` is false. Returns true and writes `out`
/// when a candidate exists.
export fn lora_fcnt_infer(has_last: bool, last: u32, received: u16, out: ?*u32) bool {
    const o = out orelse return false;
    const v = lora.fcnt.infer(if (has_last) last else null, received) orelse return false;
    o.* = v;
    return true;
}

// Data frames, [TS001-1.0.4] §4.

/// See `lora_fctrl`. One struct for both directions. Fields of the other
/// direction must be false on encode and are false after parse,
/// [TS001-1.0.4] §4.3.1 Tables 7 and 8.
pub const FCtrl = extern struct {
    adr: bool,
    adr_ack_req: bool,
    ack: bool,
    class_b: bool,
    fpending: bool,
};

/// See `lora_session_keys`.
pub const SessionKeys = extern struct {
    nwk_s_key: [16]u8,
    app_s_key: [16]u8,
};

/// See `lora_data_frame`.
pub const DataFrame = extern struct {
    ftype: c_int,
    dev_addr: u32,
    fctrl: FCtrl,
    fcnt: u32,
    fopts: ?[*]const u8,
    fopts_len: usize,
    has_fport: bool,
    fport: u8,
    payload: ?[*]const u8,
    payload_len: usize,
};

/// See `lora_parsed_frame`.
pub const ParsedFrame = extern struct {
    ftype: c_int,
    dir: c_int,
    dev_addr: u32,
    fctrl: FCtrl,
    fcnt: u16,
    fopts_offset: usize,
    fopts_len: usize,
    has_fport: bool,
    fport: u8,
    payload_offset: usize,
    payload_len: usize,
    mic: [4]u8,
};

const AnyError = lora.phy_payload.EncodeError ||
    lora.phy_payload.ParseError ||
    lora.phy_payload.VerifyError ||
    lora.phy_payload.DecryptError;

fn status(e: AnyError) c_int {
    return switch (e) {
        error.AuthenticationFailed => err_authentication_failed,
        error.Truncated => err_truncated,
        error.NoSpaceLeft => err_no_space_left,
        error.FOptsTooLong => err_fopts_too_long,
        error.MissingFPort => err_missing_fport,
        error.MacCommandsInFOptsAndPayload => err_mac_commands_in_fopts_and_payload,
        error.NotDataFrame => err_not_data_frame,
        error.UnsupportedMajor => err_unsupported_major,
        error.FCntMismatch => err_fcnt_mismatch,
        error.TooLong => err_too_long,
    };
}

/// FType values are the bit patterns of [TS001-1.0.4] §4.2.1 Table 4.
fn ftype(v: c_int) ?lora.FType {
    if (v < 0 or v > 7) return null;
    return @enumFromInt(@as(u3, @intCast(v)));
}

fn constSlice(p: ?[*]const u8, len: usize) ?[]const u8 {
    if (len == 0) return &.{};
    const q = p orelse return null;
    return q[0..len];
}

fn mutSlice(p: ?[*]u8, len: usize) ?[]u8 {
    if (len == 0) return &.{};
    const q = p orelse return null;
    return q[0..len];
}

fn fctrlToZig(f: FCtrl, dir: lora.Direction) ?lora.FCtrl {
    return switch (dir) {
        .uplink => if (f.fpending) null else .{ .uplink = .{
            .adr = f.adr,
            .adr_ack_req = f.adr_ack_req,
            .ack = f.ack,
            .class_b = f.class_b,
        } },
        .downlink => if (f.adr_ack_req or f.class_b) null else .{ .downlink = .{
            .adr = f.adr,
            .ack = f.ack,
            .fpending = f.fpending,
        } },
    };
}

fn fctrlToC(f: lora.FCtrl) FCtrl {
    return switch (f) {
        .uplink => |u| .{ .adr = u.adr, .adr_ack_req = u.adr_ack_req, .ack = u.ack, .class_b = u.class_b, .fpending = false },
        .downlink => |d| .{ .adr = d.adr, .adr_ack_req = false, .ack = d.ack, .class_b = false, .fpending = d.fpending },
    };
}

fn keysToZig(k: *const SessionKeys) lora.SessionKeys {
    return .{ .nwk_s_key = k.nwk_s_key, .app_s_key = k.app_s_key };
}

/// Builds a data frame, see `phy_payload.encode` and [TS001-1.0.4] §4.1.
export fn lora_phy_encode(
    frame: ?*const DataFrame,
    keys: ?*const SessionKeys,
    out: ?[*]u8,
    out_cap: usize,
    out_len: ?*usize,
) c_int {
    const f = frame orelse return err_invalid_argument;
    const k = keys orelse return err_invalid_argument;
    const len_out = out_len orelse return err_invalid_argument;
    const buf = mutSlice(out, out_cap) orelse return err_invalid_argument;
    const t = ftype(f.ftype) orelse return err_invalid_argument;
    const dir = t.direction() orelse return err_not_data_frame;
    const fctrl = fctrlToZig(f.fctrl, dir) orelse return err_invalid_argument;
    const fopts = constSlice(f.fopts, f.fopts_len) orelse return err_invalid_argument;
    const payload = constSlice(f.payload, f.payload_len) orelse return err_invalid_argument;

    const zkeys = keysToZig(k);
    const written = lora.phy_payload.encode(buf, .{ .ftype = t }, .{
        .fhdr = .{
            .dev_addr = f.dev_addr,
            .fctrl = fctrl,
            // Low 16 bits of the 32-bit counter, [TS001-1.0.4] §4.3.1.5.
            .fcnt = @truncate(f.fcnt),
            .fopts = fopts,
        },
        .fport = if (f.has_fport) f.fport else null,
        .frm_payload = payload,
    }, &zkeys, f.fcnt) catch |e| return status(e);
    len_out.* = written.len;
    return ok;
}

/// Splits a data frame into its fields without cryptography, see
/// `phy_payload.parse`. Offsets index into `frame`.
export fn lora_phy_parse(frame: ?[*]const u8, len: usize, out: ?*ParsedFrame) c_int {
    const bytes = constSlice(frame, len) orelse return err_invalid_argument;
    const o = out orelse return err_invalid_argument;
    const p = lora.phy_payload.parse(bytes) catch |e| return status(e);
    const mp = p.mac_payload;
    // Offsets follow from Table 2 (MHDR is 1 octet) and Table 6 (FOpts after 7 octets).
    const fopts_offset: usize = 1 + lora.fhdr.min_len;
    const payload_offset = 1 + mp.fhdr.len() + @intFromBool(mp.fport != null);
    o.* = .{
        .ftype = @intFromEnum(p.mhdr.ftype),
        .dir = @intFromEnum(p.dir),
        .dev_addr = mp.fhdr.dev_addr,
        .fctrl = fctrlToC(mp.fhdr.fctrl),
        .fcnt = mp.fhdr.fcnt,
        .fopts_offset = fopts_offset,
        .fopts_len = mp.fhdr.fopts.len,
        .has_fport = mp.fport != null,
        .fport = mp.fport orelse 0,
        .payload_offset = payload_offset,
        .payload_len = mp.frm_payload.len,
        .mic = p.mic,
    };
    return ok;
}

/// Checks the MIC of `frame` with the full 32-bit counter, [TS001-1.0.4] §4.4.
/// Returns `ok` if it matches, `err_authentication_failed` if not. Parses
/// `frame` again rather than trusting a `lora_parsed_frame`.
export fn lora_verify_mic(
    frame: ?[*]const u8,
    len: usize,
    nwk_s_key: ?*const [16]u8,
    fcnt: u32,
) c_int {
    const bytes = constSlice(frame, len) orelse return err_invalid_argument;
    const key = nwk_s_key orelse return err_invalid_argument;
    const p = lora.phy_payload.parse(bytes) catch |e| return status(e);
    p.verifyMic(key, fcnt) catch |e| return status(e);
    return ok;
}

/// Decrypts the FRMPayload of `frame` into `out`, [TS001-1.0.4] §4.3.3.
/// Call only after lora_verify_mic returned `ok`.
export fn lora_decrypt_payload(
    frame: ?[*]const u8,
    len: usize,
    keys: ?*const SessionKeys,
    fcnt: u32,
    out: ?[*]u8,
    out_cap: usize,
    out_len: ?*usize,
) c_int {
    const bytes = constSlice(frame, len) orelse return err_invalid_argument;
    const k = keys orelse return err_invalid_argument;
    const buf = mutSlice(out, out_cap) orelse return err_invalid_argument;
    const len_out = out_len orelse return err_invalid_argument;
    const p = lora.phy_payload.parse(bytes) catch |e| return status(e);
    const zkeys = keysToZig(k);
    const plain = p.decryptPayload(&zkeys, fcnt, buf) catch |e| return status(e);
    len_out.* = plain.len;
    return ok;
}

const testing = std.testing;

test "region mapping covers every Zig region exactly once" {
    const info = @typeInfo(lora.Region).@"enum";
    var seen: [info.field_names.len]bool = @splat(false);
    var v: c_int = 0;
    while (region(v)) |r| : (v += 1) {
        const i = @intFromEnum(r);
        try testing.expect(!seen[i]);
        seen[i] = true;
    }
    for (seen) |s| try testing.expect(s);
}

const test_keys = SessionKeys{
    .nwk_s_key = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
    .app_s_key = .{ 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF },
};

test "encode, parse, verify and decrypt through the C ABI" {
    const fopts = [_]u8{0x02}; // LinkCheckReq, [TS001-1.0.4] §5.1
    const payload = "hi";
    const f = DataFrame{
        .ftype = 0b010, // unconfirmed data uplink, Table 4
        .dev_addr = 0x11223344,
        .fctrl = .{ .adr = true, .adr_ack_req = false, .ack = false, .class_b = false, .fpending = false },
        .fcnt = 0x0001_0002,
        .fopts = &fopts,
        .fopts_len = fopts.len,
        .has_fport = true,
        .fport = 1,
        .payload = payload,
        .payload_len = payload.len,
    };
    var buf: [64]u8 = undefined;
    var n: usize = 0;
    try testing.expectEqual(ok, lora_phy_encode(&f, &test_keys, &buf, buf.len, &n));
    // MHDR | FHDR (7 + 1 FOpts) | FPort | 2 octets FRMPayload | MIC, Table 2.
    try testing.expectEqual(1 + 8 + 1 + 2 + 4, n);
    // FCnt on air is the low 16 bits of 0x00010002.
    try testing.expectEqualSlices(u8, &.{ 0x40, 0x44, 0x33, 0x22, 0x11, 0x81, 0x02, 0x00, 0x02, 0x01 }, buf[0..10]);

    var p: ParsedFrame = undefined;
    try testing.expectEqual(ok, lora_phy_parse(&buf, n, &p));
    try testing.expectEqual(0b010, p.ftype);
    try testing.expectEqual(0, p.dir);
    try testing.expectEqual(2, p.fcnt);
    try testing.expect(p.fctrl.adr);
    try testing.expectEqualSlices(u8, &fopts, buf[p.fopts_offset..][0..p.fopts_len]);
    try testing.expectEqual(10, p.payload_offset);
    try testing.expectEqual(2, p.payload_len);
    try testing.expectEqualSlices(u8, buf[n - 4 .. n], &p.mic);

    try testing.expectEqual(ok, lora_verify_mic(&buf, n, &test_keys.nwk_s_key, 0x0001_0002));
    try testing.expectEqual(err_authentication_failed, lora_verify_mic(&buf, n, &test_keys.nwk_s_key, 0x0002_0002));
    try testing.expectEqual(err_fcnt_mismatch, lora_verify_mic(&buf, n, &test_keys.nwk_s_key, 0x0001_0003));

    var plain: [16]u8 = undefined;
    var plain_len: usize = 0;
    try testing.expectEqual(ok, lora_decrypt_payload(&buf, n, &test_keys, 0x0001_0002, &plain, plain.len, &plain_len));
    try testing.expectEqualSlices(u8, payload, plain[0..plain_len]);
}

test "FCtrl bits of the other direction are rejected (Tables 7 and 8)" {
    var f = std.mem.zeroes(DataFrame);
    f.ftype = 0b010; // uplink
    f.fctrl.fpending = true;
    var buf: [64]u8 = undefined;
    var n: usize = 0;
    try testing.expectEqual(err_invalid_argument, lora_phy_encode(&f, &test_keys, &buf, buf.len, &n));
    f.ftype = 0b011; // downlink
    f.fctrl = .{ .adr = false, .adr_ack_req = false, .ack = false, .class_b = true, .fpending = false };
    try testing.expectEqual(err_invalid_argument, lora_phy_encode(&f, &test_keys, &buf, buf.len, &n));
}

test "status codes and argument checks" {
    var f = std.mem.zeroes(DataFrame);
    var buf: [64]u8 = undefined;
    var n: usize = 0;
    f.ftype = 0b000; // Join-Request
    try testing.expectEqual(err_not_data_frame, lora_phy_encode(&f, &test_keys, &buf, buf.len, &n));
    f.ftype = 8;
    try testing.expectEqual(err_invalid_argument, lora_phy_encode(&f, &test_keys, &buf, buf.len, &n));
    f.ftype = 0b010;
    f.payload_len = 1; // non-zero length with a null pointer
    try testing.expectEqual(err_invalid_argument, lora_phy_encode(&f, &test_keys, &buf, buf.len, &n));
    f.payload_len = 0;
    try testing.expectEqual(err_no_space_left, lora_phy_encode(&f, &test_keys, &buf, 11, &n));
    try testing.expectEqual(err_invalid_argument, lora_phy_encode(null, &test_keys, &buf, buf.len, &n));

    var p: ParsedFrame = undefined;
    try testing.expectEqual(err_truncated, lora_phy_parse(&buf, 11, &p));
    try testing.expectEqual(err_invalid_argument, lora_phy_parse(null, 12, &p));
}

test "lora_max_mac_payload_len" {
    // EU863-870 DR5, Table 15.
    try testing.expectEqual(230, lora_max_mac_payload_len(0, 0, 5, 0));
    // Table 16.
    try testing.expectEqual(250, lora_max_mac_payload_len(0, 0, 5, flag_not_repeater_compatible));
    // AS923 DR2 with UplinkDwellTime = 1, Table 72.
    try testing.expectEqual(19, lora_max_mac_payload_len(5, 0, 2, flag_uplink_dwell_time));
    try testing.expectEqual(0, lora_max_mac_payload_len(0, 0, 14, 0));
    try testing.expectEqual(err_invalid_argument, lora_max_mac_payload_len(9, 0, 0, 0));
    try testing.expectEqual(err_invalid_argument, lora_max_mac_payload_len(0, 2, 0, 0));
    try testing.expectEqual(err_invalid_argument, lora_max_mac_payload_len(0, 0, 16, 0));
    try testing.expectEqual(err_invalid_argument, lora_max_mac_payload_len(0, 0, 0, 1 << 3));
}
