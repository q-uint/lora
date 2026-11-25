//! FRMPayload encryption, [TS001-1.0.4] §4.3.3.
//!
//! AES-128 is defined in [FIPS-197], [TS001-1.0.4] §4.3.3 and §19.

const std = @import("std");
const Aes128 = std.crypto.core.aes.Aes128;
const Direction = @import("mhdr.zig").Direction;

pub const Key = [16]u8;

/// Session keys of an end-device.
pub const SessionKeys = struct {
    nwk_s_key: Key,
    app_s_key: Key,

    /// Key K for FRMPayload encryption, [TS001-1.0.4] §4.3.3 Table 11.
    /// FPort 0 uses NwkSKey, FPort 1..255 use AppSKey.
    pub fn forFPort(self: *const SessionKeys, fport: u8) *const Key {
        return if (fport == 0) &self.nwk_s_key else &self.app_s_key;
    }
};

/// Block A_i, [TS001-1.0.4] §4.3.3 Table 12.
///
///   Size (octets) |  1   |    4     |  1  |    4    |      4      |  1   | 1
///   A_i           | 0x01 | 4 x 0x00 | Dir | DevAddr | FCntUp/Down | 0x00 | i
///
/// FCnt is the full 32-bit counter, not the 16-bit FCnt field of the FHDR.
/// Multi-octet fields are little endian, [TS001-1.0.4] §1.1.
pub fn aBlock(dir: Direction, dev_addr: u32, fcnt: u32, i: u8) [16]u8 {
    var a: [16]u8 = @splat(0);
    a[0] = 0x01;
    a[5] = @intFromEnum(dir);
    std.mem.writeInt(u32, a[6..10], dev_addr, .little);
    std.mem.writeInt(u32, a[10..14], fcnt, .little);
    a[15] = i;
    return a;
}

/// Encrypts or decrypts FRMPayload in place, [TS001-1.0.4] §4.3.3.
///
///   S_i = aes128_encrypt(K, A_i) for i = 1..k, k = ceil(len(pld) / 16)
///   FRMPayload = (pld | pad16) xor S, truncated to len(pld)
///
/// The operation is its own inverse, so the same call decrypts.
///
/// Asserts `data.len <= 255 * 16`, [TS001-1.0.4] §4.3.3 Table 12.
pub fn cryptFrmPayload(key: *const Key, dir: Direction, dev_addr: u32, fcnt: u32, data: []u8) void {
    // i is a single octet in A_i, so at most 255 blocks.
    std.debug.assert(data.len <= 255 * 16);
    const ctx = Aes128.initEnc(key.*);
    var i: u8 = 1;
    var off: usize = 0;
    while (off < data.len) : ({
        off += 16;
        i +%= 1;
    }) {
        var s: [16]u8 = undefined;
        ctx.encrypt(&s, &aBlock(dir, dev_addr, fcnt, i));
        const chunk = data[off..@min(off + 16, data.len)];
        for (chunk, s[0..chunk.len]) |*d, k| d.* ^= k;
    }
}

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// [FIPS-197] Appendix B, Cipher Example (Nb = 4, Nk = 4).
// The output is the final state array read column by column.
test "AES-128 matches FIPS-197 Appendix B" {
    const ctx = Aes128.initEnc(hex("2b7e151628aed2a6abf7158809cf4f3c"));
    var out: [16]u8 = undefined;
    ctx.encrypt(&out, &hex("3243f6a8885a308d313198a2e0370734"));
    try testing.expectEqualSlices(u8, &hex("3925841d02dc09fbdc118597196a0b32"), &out);
}

// Table 12 layout built by hand.
test "A_i block layout (Table 12)" {
    try testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0, 0, 0, 0, 0x01, 0x44, 0x33, 0x22, 0x11, 0x04, 0x03, 0x02, 0x01, 0x00, 0x07 },
        &aBlock(.downlink, 0x11223344, 0x01020304, 7),
    );
}

test "Table 11 key selection" {
    const keys = SessionKeys{ .nwk_s_key = @splat(0xAA), .app_s_key = @splat(0xBB) };
    try testing.expectEqual(&keys.nwk_s_key, keys.forFPort(0));
    try testing.expectEqual(&keys.app_s_key, keys.forFPort(1));
    try testing.expectEqual(&keys.app_s_key, keys.forFPort(255));
}

test "keystream is S_1 | S_2 over two blocks, truncated" {
    const key: Key = hex("000102030405060708090a0b0c0d0e0f");
    const ctx = Aes128.initEnc(key);
    var s1: [16]u8 = undefined;
    var s2: [16]u8 = undefined;
    ctx.encrypt(&s1, &aBlock(.uplink, 0x11223344, 5, 1));
    ctx.encrypt(&s2, &aBlock(.uplink, 0x11223344, 5, 2));

    // 17 zero octets encrypt to the keystream itself: all of S_1 and the first octet of S_2.
    var data: [17]u8 = @splat(0);
    cryptFrmPayload(&key, .uplink, 0x11223344, 5, &data);
    try testing.expectEqualSlices(u8, &s1, data[0..16]);
    try testing.expectEqual(s2[0], data[16]);
}

test "decrypt inverts encrypt" {
    const key: Key = @splat(0x2B);
    const plain = "hello, LoRaWAN payload";
    var data = plain.*;
    cryptFrmPayload(&key, .uplink, 0x11223344, 0x00010002, &data);
    try testing.expect(!std.mem.eql(u8, plain, &data));
    cryptFrmPayload(&key, .uplink, 0x11223344, 0x00010002, &data);
    try testing.expectEqualSlices(u8, plain, &data);
}

test "empty payload is a no-op" {
    const key: Key = @splat(0);
    var data: [0]u8 = .{};
    cryptFrmPayload(&key, .uplink, 0, 0, &data);
}
