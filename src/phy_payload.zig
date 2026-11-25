//! PHY payload (PHYPayload) of data frames, [TS001-1.0.4] §4.1.
//!
//!   Size (octets) |  1   |    7..M    |  4
//!   PHYPayload    | MHDR | MACPayload | MIC     (Table 2)
//!
//! Join-Request and Join-Accept frames (§6.2) are not handled here.
//!
//! The 32-bit frame counter is passed in by the caller. Only its low 16 bits
//! travel in FCnt, so the receiver infers the upper 16 bits from traffic
//! before it can check the MIC or decrypt, [TS001-1.0.4] §4.3.1.5.

const std = @import("std");
const mhdr_mod = @import("mhdr.zig");
const MHDR = mhdr_mod.MHDR;
const Direction = mhdr_mod.Direction;
const MACPayload = @import("mac_payload.zig").MACPayload;
const fhdr = @import("fhdr.zig");
const crypto = @import("crypto.zig");
const Key = crypto.Key;
const SessionKeys = crypto.SessionKeys;
const mic = @import("mic.zig");
const Mic = mic.Mic;

/// MHDR, the smallest MACPayload (a bare FHDR, §4.3) and the MIC.
pub const min_len = 1 + fhdr.min_len + mic.len;

pub const Error = MACPayload.Error || error{
    /// FType is not one of the four data frame types, [TS001-1.0.4] §4.2.1 Table 4.
    NotDataFrame,
    /// Major is RFU, so the frame format is unknown, [TS001-1.0.4] §4.2.2 Table 5.
    UnsupportedMajor,
    /// The low 16 bits of the 32-bit counter differ from FCnt, [TS001-1.0.4] §4.3.1.5.
    FCntMismatch,
    /// len(msg) does not fit the single octet in B0, [TS001-1.0.4] §4.4 Table 13.
    TooLong,
};

fn dataDirection(h: MHDR) Error!Direction {
    if (h.major != .lorawan_r1) return error.UnsupportedMajor;
    return h.ftype.direction() orelse error.NotDataFrame;
}

/// Builds a data frame into `out` and returns the written slice.
///
/// `payload.frm_payload` is plaintext. It is encrypted with the key from
/// Table 11 before the MIC is computed over the result, [TS001-1.0.4] §4.3.3 and §4.4.
pub fn encode(
    out: []u8,
    h: MHDR,
    payload: MACPayload,
    keys: *const SessionKeys,
    fcnt: u32,
) Error![]u8 {
    const dir = try dataDirection(h);
    if (@as(u16, @truncate(fcnt)) != payload.fhdr.fcnt) return error.FCntMismatch;
    const msg_len = 1 + payload.len();
    if (msg_len > 255) return error.TooLong;
    if (out.len < msg_len + mic.len) return error.Truncated;

    out[0] = h.encode();
    _ = try payload.encode(out[1..]);

    if (payload.fport) |port| {
        const frm = out[msg_len - payload.frm_payload.len .. msg_len];
        crypto.cryptFRMPayload(keys.forFPort(port), dir, payload.fhdr.dev_addr, fcnt, frm);
    }

    out[msg_len..][0..mic.len].* = mic.compute(&keys.nwk_s_key, dir, payload.fhdr.dev_addr, fcnt, out[0..msg_len]);
    return out[0 .. msg_len + mic.len];
}

/// A received data frame, split into its fields but not yet authenticated.
/// All slices borrow from the input bytes.
pub const Parsed = struct {
    mhdr: MHDR,
    dir: Direction,
    /// FRMPayload is still encrypted.
    mac_payload: MACPayload,
    mic: Mic,
    /// MHDR | MACPayload, the input to the MIC, [TS001-1.0.4] §4.4.
    msg: []const u8,

    fn checkFCnt(self: Parsed, fcnt: u32) Error!void {
        if (@as(u16, @truncate(fcnt)) != self.mac_payload.fhdr.fcnt) return error.FCntMismatch;
    }

    /// Checks the MIC with the full 32-bit counter, [TS001-1.0.4] §4.4.
    pub fn verifyMic(self: Parsed, nwk_s_key: *const Key, fcnt: u32) Error!bool {
        try self.checkFCnt(fcnt);
        return mic.verify(nwk_s_key, self.dir, self.mac_payload.fhdr.dev_addr, fcnt, self.msg, self.mic);
    }

    /// Copies FRMPayload into `out`, decrypts it there and returns the plaintext.
    /// Call this only after `verifyMic` returned true.
    pub fn decryptPayload(self: Parsed, keys: *const SessionKeys, fcnt: u32, out: []u8) Error![]u8 {
        try self.checkFCnt(fcnt);
        const frm = self.mac_payload.frm_payload;
        if (out.len < frm.len) return error.Truncated;
        const plain = out[0..frm.len];
        @memcpy(plain, frm);
        if (self.mac_payload.fport) |port| {
            crypto.cryptFRMPayload(keys.forFPort(port), self.dir, self.mac_payload.fhdr.dev_addr, fcnt, plain);
        }
        return plain;
    }
};

/// Splits a data frame into its fields. Does no cryptography.
pub fn parse(bytes: []const u8) Error!Parsed {
    if (bytes.len < min_len) return error.Truncated;
    if (bytes.len - mic.len > 255) return error.TooLong;
    const h = MHDR.decode(bytes[0]);
    const dir = try dataDirection(h);
    const msg = bytes[0 .. bytes.len - mic.len];
    return .{
        .mhdr = h,
        .dir = dir,
        .mac_payload = try MACPayload.decode(msg[1..], dir),
        .mic = bytes[msg.len..][0..mic.len].*,
        .msg = msg,
    };
}

const testing = std.testing;

const test_keys = SessionKeys{
    .nwk_s_key = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
    .app_s_key = .{ 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF },
};

test "uplink roundtrip with application payload" {
    const fcnt: u32 = 0x0001_0002;
    var buf: [64]u8 = undefined;
    const frame = try encode(&buf, .{ .ftype = .unconfirmed_data_up }, .{
        .fhdr = .{ .dev_addr = 0x11223344, .fctrl = .{ .uplink = .{ .adr = true } }, .fcnt = 0x0002 },
        .fport = 10,
        .frm_payload = "hello",
    }, &test_keys, fcnt);

    // Table 2: MHDR (1) | MACPayload (7 + 1 + 5) | MIC (4).
    try testing.expectEqual(@as(usize, 1 + 13 + 4), frame.len);
    // Cleartext parts: MHDR (Table 3), FHDR (Table 6), FPort.
    try testing.expectEqualSlices(u8, &.{ 0x40, 0x44, 0x33, 0x22, 0x11, 0x80, 0x02, 0x00, 0x0A }, frame[0..9]);
    // FRMPayload is encrypted, §4.3.3.
    try testing.expect(!std.mem.eql(u8, "hello", frame[9..14]));

    const p = try parse(frame);
    try testing.expectEqual(Direction.uplink, p.dir);
    try testing.expect(try p.verifyMic(&test_keys.nwk_s_key, fcnt));
    var plain: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, "hello", try p.decryptPayload(&test_keys, fcnt, &plain));
}

test "the pieces compose as §4.3.3 then §4.4 describe" {
    const fcnt: u32 = 7;
    var buf: [64]u8 = undefined;
    const frame = try encode(&buf, .{ .ftype = .confirmed_data_down }, .{
        .fhdr = .{ .dev_addr = 0x01020304, .fctrl = .{ .downlink = .{ .ack = true } }, .fcnt = 7 },
        .fport = 1,
        .frm_payload = &.{ 0x01, 0x02, 0x03 },
    }, &test_keys, fcnt);

    // Encrypt with AppSKey (Table 11) using the downlink A_i blocks (Table 12).
    var frm = [_]u8{ 0x01, 0x02, 0x03 };
    crypto.cryptFRMPayload(&test_keys.app_s_key, .downlink, 0x01020304, fcnt, &frm);
    try testing.expectEqualSlices(u8, &frm, frame[9..12]);

    // MIC over everything before it with NwkSKey (Table 13).
    try testing.expectEqualSlices(u8, &mic.compute(&test_keys.nwk_s_key, .downlink, 0x01020304, fcnt, frame[0..12]), frame[12..16]);
}

test "FPort 0 encrypts with NwkSKey (Table 11)" {
    var buf: [64]u8 = undefined;
    const frame = try encode(&buf, .{ .ftype = .unconfirmed_data_down }, .{
        .fhdr = .{ .dev_addr = 0x11223344, .fctrl = .{ .downlink = .{} }, .fcnt = 0 },
        .fport = 0,
        .frm_payload = &.{0x02},
    }, &test_keys, 0);

    var frm = [_]u8{0x02};
    crypto.cryptFRMPayload(&test_keys.nwk_s_key, .downlink, 0x11223344, 0, &frm);
    try testing.expectEqual(frm[0], frame[9]);
}

test "frame without FPort or FRMPayload (§4.3)" {
    var buf: [64]u8 = undefined;
    const frame = try encode(&buf, .{ .ftype = .unconfirmed_data_up }, .{
        .fhdr = .{ .dev_addr = 0x11223344, .fctrl = .{ .uplink = .{} }, .fcnt = 3 },
    }, &test_keys, 3);
    try testing.expectEqual(min_len, frame.len);

    const p = try parse(frame);
    try testing.expectEqual(@as(?u8, null), p.mac_payload.fport);
    try testing.expect(try p.verifyMic(&test_keys.nwk_s_key, 3));
}

test "tampering and wrong counter fail the MIC" {
    var buf: [64]u8 = undefined;
    const frame = try encode(&buf, .{ .ftype = .unconfirmed_data_up }, .{
        .fhdr = .{ .dev_addr = 0x11223344, .fctrl = .{ .uplink = .{} }, .fcnt = 1 },
        .fport = 1,
        .frm_payload = "x",
    }, &test_keys, 0x0005_0001);

    try testing.expect(try (try parse(frame)).verifyMic(&test_keys.nwk_s_key, 0x0005_0001));
    // Upper 16 bits wrong, §4.3.1.5.
    try testing.expect(!try (try parse(frame)).verifyMic(&test_keys.nwk_s_key, 0x0004_0001));
    // Low 16 bits must match FCnt.
    try testing.expectError(error.FCntMismatch, (try parse(frame)).verifyMic(&test_keys.nwk_s_key, 0x0005_0002));

    frame[9] ^= 0x01;
    try testing.expect(!try (try parse(frame)).verifyMic(&test_keys.nwk_s_key, 0x0005_0001));
}

test "errors" {
    var buf: [64]u8 = undefined;
    const p = MACPayload{ .fhdr = .{ .dev_addr = 0, .fctrl = .{ .uplink = .{} }, .fcnt = 1 } };

    try testing.expectError(error.NotDataFrame, encode(&buf, .{ .ftype = .join_request }, p, &test_keys, 1));
    try testing.expectError(error.UnsupportedMajor, encode(&buf, .{ .ftype = .unconfirmed_data_up, .major = @enumFromInt(1) }, p, &test_keys, 1));
    try testing.expectError(error.FCntMismatch, encode(&buf, .{ .ftype = .unconfirmed_data_up }, p, &test_keys, 2));
    try testing.expectError(error.Truncated, encode(buf[0..11], .{ .ftype = .unconfirmed_data_up }, p, &test_keys, 1));

    try testing.expectError(error.Truncated, parse(buf[0 .. min_len - 1]));
    buf[0] = (MHDR{ .ftype = .proprietary }).encode();
    try testing.expectError(error.NotDataFrame, parse(buf[0..min_len]));
}
