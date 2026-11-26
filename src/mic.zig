//! Message integrity code (MIC), [TS001-1.0.4] §4.4.
//!
//!   msg  = MHDR | FHDR | FPort | FRMPayload
//!   CMAC = aes128_cmac(NwkSKey, B0 | msg)
//!   MIC  = CMAC[0..3]
//!
//! AES-CMAC is defined in [RFC4493], [TS001-1.0.4] §4.4 and §19.

const std = @import("std");
const CmacAes128 = std.crypto.auth.cmac.CmacAes128;
const Direction = @import("mhdr.zig").Direction;
const Key = @import("crypto.zig").Key;

pub const len = 4;
pub const Mic = [len]u8;

/// Block B0, [TS001-1.0.4] §4.4 Table 13.
///
///   Size (octets) |  1   |    4     |  1  |    4    |      4      |  1   |    1
///   B0            | 0x49 | 4 x 0x00 | Dir | DevAddr | FCntUp/Down | 0x00 | len(msg)
///
/// FCnt is the full 32-bit counter, not the 16-bit FCnt field of the FHDR.
/// Multi-octet fields are little endian, [TS001-1.0.4] §1.1.
pub fn b0Block(dir: Direction, dev_addr: u32, fcnt: u32, msg_len: u8) [16]u8 {
    var b: [16]u8 = @splat(0);
    b[0] = 0x49;
    b[5] = @intFromEnum(dir);
    std.mem.writeInt(u32, b[6..10], dev_addr, .little);
    std.mem.writeInt(u32, b[10..14], fcnt, .little);
    b[15] = msg_len;
    return b;
}

/// Computes the MIC over `msg`, which is the whole PHYPayload without the MIC.
/// FRMPayload in `msg` must already be encrypted, [TS001-1.0.4] §4.3.3.
///
/// Asserts `msg.len <= 255`, [TS001-1.0.4] §4.4 Table 13.
pub fn compute(nwk_s_key: *const Key, dir: Direction, dev_addr: u32, fcnt: u32, msg: []const u8) Mic {
    // len(msg) is a single octet in B0.
    std.debug.assert(msg.len <= 255);
    var cmac = CmacAes128.init(nwk_s_key);
    cmac.update(&b0Block(dir, dev_addr, fcnt, @intCast(msg.len)));
    cmac.update(msg);
    var full: [CmacAes128.mac_length]u8 = undefined;
    cmac.final(&full);
    return full[0..len].*;
}

/// Checks a received MIC in constant time. Fails with
/// `error.AuthenticationFailed` like the std authenticated ciphers.
pub fn verify(
    nwk_s_key: *const Key,
    dir: Direction,
    dev_addr: u32,
    fcnt: u32,
    msg: []const u8,
    mic: Mic,
) std.crypto.errors.AuthenticationError!void {
    if (!std.crypto.timing_safe.eql(Mic, compute(nwk_s_key, dir, dev_addr, fcnt, msg), mic)) {
        return error.AuthenticationFailed;
    }
}

const testing = std.testing;

const hex = @import("test_util.zig").hex;

// [RFC4493] §4, Examples 1 to 4.
test "AES-CMAC matches RFC 4493 §4" {
    const key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    const m = hex("6bc1bee22e409f96e93d7e117393172a" ++
        "ae2d8a571e03ac9c9eb76fac45af8e51" ++
        "30c81c46a35ce411e5fbc1191a0a52ef" ++
        "f69f2445df4f9b17ad2b417be66c3710");
    const cases = .{
        .{ 0, hex("bb1d6929e95937287fa37d129b756746") },
        .{ 16, hex("070a16b46b4d4144f79bdd9dd04a287c") },
        .{ 40, hex("dfa66747de9ae63030ca32611497c827") },
        .{ 64, hex("51f0bebf7e3b9d92fc49741779363cfe") },
    };
    inline for (cases) |c| {
        var out: [16]u8 = undefined;
        CmacAes128.create(&out, m[0..c[0]], &key);
        try testing.expectEqualSlices(u8, &c[1], &out);
    }
}

// Table 13 layout built by hand.
test "B0 block layout (Table 13)" {
    try testing.expectEqualSlices(
        u8,
        &.{ 0x49, 0, 0, 0, 0, 0x00, 0x44, 0x33, 0x22, 0x11, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0C },
        &b0Block(.uplink, 0x11223344, 0x01020304, 12),
    );
}

test "MIC is the first 4 octets of CMAC over B0 | msg" {
    const key: Key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    const msg = [_]u8{ 0x40, 0x44, 0x33, 0x22, 0x11, 0x00, 0x01, 0x00, 0x01, 0xAA };

    var joined: [16 + msg.len]u8 = undefined;
    joined[0..16].* = b0Block(.uplink, 0x11223344, 1, msg.len);
    joined[16..].* = msg;
    var full: [16]u8 = undefined;
    CmacAes128.create(&full, &joined, &key);

    try testing.expectEqualSlices(u8, full[0..4], &compute(&key, .uplink, 0x11223344, 1, &msg));
}

test "verify rejects changes to msg, direction and the upper FCnt bits" {
    const key: Key = @splat(0x2B);
    const msg = [_]u8{ 0x40, 0x44, 0x33, 0x22, 0x11, 0x00, 0x01, 0x00 };
    const mic = compute(&key, .uplink, 0x11223344, 0x00010001, &msg);

    try verify(&key, .uplink, 0x11223344, 0x00010001, &msg, mic);

    var tampered = msg;
    tampered[7] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, verify(&key, .uplink, 0x11223344, 0x00010001, &tampered, mic));
    try testing.expectError(error.AuthenticationFailed, verify(&key, .downlink, 0x11223344, 0x00010001, &msg, mic));
    // Same 16-bit FCnt on air, different 32-bit counter (§4.3.1.5).
    try testing.expectError(error.AuthenticationFailed, verify(&key, .uplink, 0x11223344, 0x00000001, &msg, mic));
}
