//! Join procedure frames, [TS001-1.0.4] §6.2.
//!
//!   Size (octets)        |    8    |   8    |    2
//!   Join-Request payload | JoinEUI | DevEUI | DevNonce     (Table 53)
//!
//!   Size (octets)       |     3     |   3   |    4    |     1      |    1    | (16) optional
//!   Join-Accept payload | JoinNonce | NetID | DevAddr | DLSettings | RXDelay | CFList     (Table 54)
//!
//! Multi-octet fields, EUIs included, are little endian, [TS001-1.0.4] §1.1.
//! Fields here are numbers and encode/decode handle the wire order.

const std = @import("std");
const CmacAes128 = std.crypto.auth.cmac.CmacAes128;
const Aes128 = std.crypto.core.aes.Aes128;
const AuthenticationError = std.crypto.errors.AuthenticationError;
const Mhdr = @import("mhdr.zig").Mhdr;
const settings = @import("settings.zig");
const DlSettings = settings.DlSettings;
const RxTimingSettings = settings.RxTimingSettings;
const crypto = @import("crypto.zig");
const Key = crypto.Key;
const SessionKeys = crypto.SessionKeys;
const mic = @import("mic.zig");
const Mic = mic.Mic;

/// MIC of a join frame: aes128_cmac(AppKey, msg)[0..3], [TS001-1.0.4] §6.2.5 and §6.2.6.
/// Unlike data frames there is no B0 block.
fn joinMic(app_key: *const Key, msg: []const u8) Mic {
    var full: [CmacAes128.mac_length]u8 = undefined;
    CmacAes128.create(&full, msg, app_key);
    return full[0..mic.len].*;
}

pub const JoinRequest = struct {
    join_eui: u64,
    dev_eui: u64,
    /// Never reused for a given JoinEUI, [TS001-1.0.4] §6.2.5.
    dev_nonce: u16,

    pub const payload_len = 18;
    /// MHDR | Join-Request payload | MIC, [TS001-1.0.4] §4 Table 1.
    pub const frame_len = 1 + payload_len + mic.len;

    const mhdr: Mhdr = .{ .ftype = .join_request };

    pub const EncodeError = error{
        /// `out` is too small.
        NoSpaceLeft,
    };

    /// Builds MHDR | JoinEUI | DevEUI | DevNonce | MIC into `out`. The frame is
    /// not encrypted, [TS001-1.0.4] §6.2.5.
    pub fn encode(self: JoinRequest, app_key: *const Key, out: []u8) EncodeError![]u8 {
        if (out.len < frame_len) return error.NoSpaceLeft;
        const f = out[0..frame_len];
        f[0] = mhdr.encode();
        std.mem.writeInt(u64, f[1..9], self.join_eui, .little);
        std.mem.writeInt(u64, f[9..17], self.dev_eui, .little);
        std.mem.writeInt(u16, f[17..19], self.dev_nonce, .little);
        f[19..23].* = joinMic(app_key, f[0..19]);
        return f;
    }

    pub const ParseError = error{
        /// Not exactly `frame_len` octets.
        InvalidLength,
        /// FType is not Join-Request, [TS001-1.0.4] §4.2.1 Table 4.
        NotJoinRequest,
        /// Major is RFU, [TS001-1.0.4] §4.2.2 Table 5.
        UnsupportedMajor,
    };

    /// A received Join-Request, not yet authenticated.
    pub const Parsed = struct {
        request: JoinRequest,
        mic: Mic,
        /// MHDR | Join-Request payload, the input to the MIC.
        msg: []const u8,

        /// Checks the MIC with AppKey, [TS001-1.0.4] §6.2.5.
        pub fn verifyMic(self: Parsed, app_key: *const Key) AuthenticationError!void {
            if (!std.crypto.timing_safe.eql(Mic, joinMic(app_key, self.msg), self.mic)) {
                return error.AuthenticationFailed;
            }
        }
    };

    /// Splits a Join-Request frame into its fields. Does no cryptography.
    pub fn parse(bytes: []const u8) ParseError!Parsed {
        if (bytes.len != frame_len) return error.InvalidLength;
        const h = Mhdr.decode(bytes[0]);
        if (h.major != .lorawan_r1) return error.UnsupportedMajor;
        if (h.ftype != .join_request) return error.NotJoinRequest;
        return .{
            .request = .{
                .join_eui = std.mem.readInt(u64, bytes[1..9], .little),
                .dev_eui = std.mem.readInt(u64, bytes[9..17], .little),
                .dev_nonce = std.mem.readInt(u16, bytes[17..19], .little),
            },
            .mic = bytes[19..23].*,
            .msg = bytes[0..19],
        };
    }
};

pub const JoinAccept = struct {
    join_nonce: u24,
    net_id: u24,
    dev_addr: u32,
    dl_settings: DlSettings = .{},
    rx_delay: RxTimingSettings = .{},
    /// Region specific, defined in [RP002], [TS001-1.0.4] §6.2.6. Kept raw.
    cf_list: ?[16]u8 = null,

    const fields_len = 12;
    const cf_list_len = 16;
    /// MHDR | Join-Accept payload without CFList | MIC.
    pub const min_frame_len = 1 + fields_len + mic.len;
    /// MHDR | Join-Accept payload with CFList | MIC.
    pub const max_frame_len = min_frame_len + cf_list_len;

    const mhdr: Mhdr = .{ .ftype = .join_accept };

    pub fn frameLen(self: JoinAccept) usize {
        return if (self.cf_list == null) min_frame_len else max_frame_len;
    }

    pub const EncodeError = error{
        /// `out` is too small.
        NoSpaceLeft,
    };

    /// Builds an encrypted Join-Accept frame into `out` (Network side),
    /// [TS001-1.0.4] §6.2.6:
    ///
    ///   MIC = aes128_cmac(AppKey, MHDR | JoinNonce | NetID | DevAddr | DLSettings | RXDelay | CFList)[0..3]
    ///   aes128_decrypt(AppKey, JoinNonce | NetID | DevAddr | DLSettings | RXDelay | CFList | MIC)
    pub fn encode(self: JoinAccept, app_key: *const Key, out: []u8) EncodeError![]u8 {
        const n = self.frameLen();
        if (out.len < n) return error.NoSpaceLeft;
        const f = out[0..n];
        f[0] = mhdr.encode();
        std.mem.writeInt(u24, f[1..4], self.join_nonce, .little);
        std.mem.writeInt(u24, f[4..7], self.net_id, .little);
        std.mem.writeInt(u32, f[7..11], self.dev_addr, .little);
        f[11] = self.dl_settings.encode();
        f[12] = self.rx_delay.encode();
        if (self.cf_list) |cf| f[13..29].* = cf;
        f[n - mic.len ..][0..mic.len].* = joinMic(app_key, f[0 .. n - mic.len]);

        // Payload and MIC are 16 or 32 octets, so whole AES blocks.
        const ctx = Aes128.initDec(app_key.*);
        var i: usize = 1;
        while (i < n) : (i += 16) {
            const block = f[i..][0..16];
            var tmp: [16]u8 = undefined;
            ctx.decrypt(&tmp, block);
            block.* = tmp;
        }
        return f;
    }

    pub const DecryptError = AuthenticationError || error{
        /// Neither `min_frame_len` nor `max_frame_len` octets.
        InvalidLength,
        /// FType is not Join-Accept, [TS001-1.0.4] §4.2.1 Table 4.
        NotJoinAccept,
        /// Major is RFU, [TS001-1.0.4] §4.2.2 Table 5.
        UnsupportedMajor,
    };

    /// Decrypts a Join-Accept frame with AES encrypt, checks its MIC and
    /// returns the fields (end-device side), [TS001-1.0.4] §6.2.6.
    pub fn decrypt(frame: []const u8, app_key: *const Key) DecryptError!JoinAccept {
        if (frame.len != min_frame_len and frame.len != max_frame_len) return error.InvalidLength;
        const h = Mhdr.decode(frame[0]);
        if (h.major != .lorawan_r1) return error.UnsupportedMajor;
        if (h.ftype != .join_accept) return error.NotJoinAccept;

        var buf: [max_frame_len]u8 = undefined;
        const p = buf[0..frame.len];
        p[0] = frame[0];
        const ctx = Aes128.initEnc(app_key.*);
        var i: usize = 1;
        while (i < frame.len) : (i += 16) {
            ctx.encrypt(p[i..][0..16], frame[i..][0..16]);
        }

        const n = frame.len;
        const received: Mic = p[n - mic.len ..][0..mic.len].*;
        if (!std.crypto.timing_safe.eql(Mic, joinMic(app_key, p[0 .. n - mic.len]), received)) {
            return error.AuthenticationFailed;
        }
        return .{
            .join_nonce = std.mem.readInt(u24, p[1..4], .little),
            .net_id = std.mem.readInt(u24, p[4..7], .little),
            .dev_addr = std.mem.readInt(u32, p[7..11], .little),
            .dl_settings = DlSettings.decode(p[11]),
            .rx_delay = RxTimingSettings.decode(p[12]),
            .cf_list = if (n == max_frame_len) p[13..29].* else null,
        };
    }
};

/// Derives the session keys after a successful join, [TS001-1.0.4] §6.2.6:
///
///   NwkSKey = aes128_encrypt(AppKey, 0x01 | JoinNonce | NetID | DevNonce | pad16)
///   AppSKey = aes128_encrypt(AppKey, 0x02 | JoinNonce | NetID | DevNonce | pad16)
pub fn deriveSessionKeys(app_key: *const Key, join_nonce: u24, net_id: u24, dev_nonce: u16) SessionKeys {
    const ctx = Aes128.initEnc(app_key.*);
    var keys: SessionKeys = undefined;
    inline for (.{ .{ 0x01, &keys.nwk_s_key }, .{ 0x02, &keys.app_s_key } }) |k| {
        var block: [16]u8 = @splat(0);
        block[0] = k[0];
        std.mem.writeInt(u24, block[1..4], join_nonce, .little);
        std.mem.writeInt(u24, block[4..7], net_id, .little);
        std.mem.writeInt(u16, block[7..9], dev_nonce, .little);
        ctx.encrypt(k[1], &block);
    }
    return keys;
}

const testing = std.testing;

const test_app_key: Key = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

const test_request = JoinRequest{
    .join_eui = 0x0102030405060708,
    .dev_eui = 0x1112131415161718,
    .dev_nonce = 0x2122,
};

test "Join-Request layout (Table 53)" {
    var buf: [32]u8 = undefined;
    const f = try test_request.encode(&test_app_key, &buf);
    try testing.expectEqual(23, f.len);
    try testing.expectEqualSlices(u8, &.{
        0x00, // MHDR, FType 000 Join-Request (Table 4)
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // JoinEUI, little endian
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, // DevEUI, little endian
        0x22, 0x21, // DevNonce, little endian
    }, f[0..19]);
}

test "MIC is aes128_cmac(AppKey, MHDR | JoinEUI | DevEUI | DevNonce)[0..3] (§6.2.5)" {
    var buf: [32]u8 = undefined;
    const f = try test_request.encode(&test_app_key, &buf);
    var full: [16]u8 = undefined;
    CmacAes128.create(&full, f[0..19], &test_app_key);
    try testing.expectEqualSlices(u8, full[0..4], f[19..23]);
}

test "parse and verify" {
    var buf: [32]u8 = undefined;
    const f = try test_request.encode(&test_app_key, &buf);
    const p = try JoinRequest.parse(f);
    try testing.expectEqual(test_request, p.request);
    try p.verifyMic(&test_app_key);

    var wrong_key = test_app_key;
    wrong_key[0] ^= 1;
    try testing.expectError(error.AuthenticationFailed, p.verifyMic(&wrong_key));

    f[17] ^= 1; // DevNonce
    try testing.expectError(error.AuthenticationFailed, (try JoinRequest.parse(f)).verifyMic(&test_app_key));
}

test "errors" {
    var buf: [32]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, test_request.encode(&test_app_key, buf[0..22]));
    const f = try test_request.encode(&test_app_key, &buf);
    try testing.expectError(error.InvalidLength, JoinRequest.parse(f[0..22]));
    try testing.expectError(error.InvalidLength, JoinRequest.parse(buf[0..24]));
    f[0] = (Mhdr{ .ftype = .unconfirmed_data_up }).encode();
    try testing.expectError(error.NotJoinRequest, JoinRequest.parse(f));
    f[0] = (Mhdr{ .ftype = .join_request, .major = @enumFromInt(1) }).encode();
    try testing.expectError(error.UnsupportedMajor, JoinRequest.parse(f));
}

const hex = @import("test_util.zig").hex;

// [FIPS-197] Appendix B, Cipher Example, run through the inverse cipher.
test "AES-128 inverse cipher matches FIPS-197 Appendix B" {
    const ctx = Aes128.initDec(hex("2b7e151628aed2a6abf7158809cf4f3c"));
    var out: [16]u8 = undefined;
    ctx.decrypt(&out, &hex("3925841d02dc09fbdc118597196a0b32"));
    try testing.expectEqualSlices(u8, &hex("3243f6a8885a308d313198a2e0370734"), &out);
}

const test_accept = JoinAccept{
    .join_nonce = 0x010203,
    .net_id = 0x111213,
    .dev_addr = 0x21222324,
    .dl_settings = .{ .rx1_dr_offset = 2, .rx2_data_rate = 3 },
    .rx_delay = .{ .del = 5 },
};

test "Join-Accept layout (Tables 54 and 55) and encryption with AES decrypt (§6.2.6)" {
    var buf: [64]u8 = undefined;
    const f = try test_accept.encode(&test_app_key, &buf);
    try testing.expectEqual(JoinAccept.min_frame_len, f.len);
    try testing.expectEqual(0x20, f[0]); // MHDR, FType 001 Join-Accept, sent in the clear

    // Undo the network side aes128_decrypt with aes128_encrypt to see the plaintext.
    var plain: [16]u8 = undefined;
    Aes128.initEnc(test_app_key).encrypt(&plain, f[1..17]);
    try testing.expectEqualSlices(u8, &.{
        0x03, 0x02, 0x01, // JoinNonce, little endian
        0x13, 0x12, 0x11, // NetID, little endian
        0x24, 0x23, 0x22, 0x21, // DevAddr, little endian
        0x23, // DLSettings, RX1DROffset 2, RX2DataRate 3
        0x05, // RXDelay, Del 5
    }, plain[0..12]);

    // MIC over MHDR | payload, before encryption.
    var msg: [13]u8 = undefined;
    msg[0] = 0x20;
    msg[1..13].* = plain[0..12].*;
    var full: [16]u8 = undefined;
    CmacAes128.create(&full, &msg, &test_app_key);
    try testing.expectEqualSlices(u8, full[0..4], plain[12..16]);
}

test "Join-Accept roundtrip without and with CFList" {
    var buf: [64]u8 = undefined;
    try testing.expectEqual(test_accept, try JoinAccept.decrypt(try test_accept.encode(&test_app_key, &buf), &test_app_key));

    var with_cf = test_accept;
    with_cf.cf_list = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const f = try with_cf.encode(&test_app_key, &buf);
    try testing.expectEqual(JoinAccept.max_frame_len, f.len);
    try testing.expectEqual(with_cf, try JoinAccept.decrypt(f, &test_app_key));
}

test "Join-Accept errors" {
    var buf: [64]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, test_accept.encode(&test_app_key, buf[0..16]));
    const f = try test_accept.encode(&test_app_key, &buf);

    var wrong_key = test_app_key;
    wrong_key[15] ^= 1;
    try testing.expectError(error.AuthenticationFailed, JoinAccept.decrypt(f, &wrong_key));
    f[5] ^= 1;
    try testing.expectError(error.AuthenticationFailed, JoinAccept.decrypt(f, &test_app_key));
    f[5] ^= 1;

    try testing.expectError(error.InvalidLength, JoinAccept.decrypt(f[0..16], &test_app_key));
    try testing.expectError(error.InvalidLength, JoinAccept.decrypt(buf[0..18], &test_app_key));
    f[0] = (Mhdr{ .ftype = .join_request }).encode();
    try testing.expectError(error.NotJoinAccept, JoinAccept.decrypt(f, &test_app_key));
    f[0] = (Mhdr{ .ftype = .join_accept, .major = @enumFromInt(3) }).encode();
    try testing.expectError(error.UnsupportedMajor, JoinAccept.decrypt(f, &test_app_key));
}

test "session key blocks (§6.2.6)" {
    const keys = deriveSessionKeys(&test_app_key, 0x010203, 0x111213, 0x2122);
    const ctx = Aes128.initEnc(test_app_key);
    var expected: [16]u8 = undefined;

    // 0x01 | JoinNonce | NetID | DevNonce | pad16, little endian fields.
    ctx.encrypt(&expected, &.{ 0x01, 0x03, 0x02, 0x01, 0x13, 0x12, 0x11, 0x22, 0x21, 0, 0, 0, 0, 0, 0, 0 });
    try testing.expectEqualSlices(u8, &expected, &keys.nwk_s_key);
    // Same block with 0x02.
    ctx.encrypt(&expected, &.{ 0x02, 0x03, 0x02, 0x01, 0x13, 0x12, 0x11, 0x22, 0x21, 0, 0, 0, 0, 0, 0, 0 });
    try testing.expectEqualSlices(u8, &expected, &keys.app_s_key);
}

test "join then exchange a data frame" {
    const phy_payload = @import("phy_payload.zig");
    var buf: [64]u8 = undefined;

    // End-device sends a Join-Request, §6.2.5.
    const req_frame = try test_request.encode(&test_app_key, &buf);
    const req = try JoinRequest.parse(req_frame);
    try req.verifyMic(&test_app_key);

    // Network answers with a Join-Accept and derives its keys, §6.2.6.
    var accept_buf: [JoinAccept.max_frame_len]u8 = undefined;
    const accept_frame = try test_accept.encode(&test_app_key, &accept_buf);
    const net_keys = deriveSessionKeys(&test_app_key, test_accept.join_nonce, test_accept.net_id, req.request.dev_nonce);

    // End-device decrypts the Join-Accept and derives the same keys.
    const accept = try JoinAccept.decrypt(accept_frame, &test_app_key);
    const dev_keys = deriveSessionKeys(&test_app_key, accept.join_nonce, accept.net_id, test_request.dev_nonce);
    try testing.expectEqual(net_keys, dev_keys);

    // First uplink with FCntUp 0, §4.3.1.5.
    const up = try phy_payload.encode(&buf, .{ .ftype = .unconfirmed_data_up }, .{
        .fhdr = .{ .dev_addr = accept.dev_addr, .fctrl = .{ .uplink = .{} }, .fcnt = 0 },
        .fport = 1,
        .frm_payload = "joined",
    }, &dev_keys, 0);
    const p = try phy_payload.parse(up);
    try p.verifyMic(&net_keys.nwk_s_key, 0);
    var plain: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, "joined", try p.decryptPayload(&net_keys, 0, &plain));
}
