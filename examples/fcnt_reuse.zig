//! An ABP end-device resets its frame counter and sends two frames with the
//! same FCnt and keys, which [TS001-1.0.4] §4.3.1.5 and §6.3 forbid.
//!
//! The keystream depends only on the key, DevAddr, direction and FCnt
//! (§4.3.3 Table 12), so both frames are encrypted with the same keystream.
//! A listener without any key XORs the two ciphertexts and gets the XOR of
//! the two plaintexts.
//!
//! Run with `zig build fcnt-reuse`.

const std = @import("std");
const lora = @import("lora");

const keys = lora.SessionKeys{
    .nwk_s_key = @splat(0x11),
    .app_s_key = @splat(0x22),
};
const dev_addr: u32 = 0x26011234;

pub fn main() !void {
    const first = "temp=21C hum=40%";
    const second = "temp=19C hum=55%";

    // End-device, before and after a reset that lost the counter.
    var buf_a: [64]u8 = undefined;
    var buf_b: [64]u8 = undefined;
    const frame_a = try send(&buf_a, first);
    const frame_b = try send(&buf_b, second);
    show("frame before reset", frame_a);
    show("frame after reset ", frame_b);

    // Listener with no keys. Parsing needs no cryptography.
    const ca = (try lora.phy_payload.parse(frame_a)).mac_payload.frm_payload;
    const cb = (try lora.phy_payload.parse(frame_b)).mac_payload.frm_payload;

    var x: [first.len]u8 = undefined;
    for (&x, ca, cb) |*o, a, b| o.* = a ^ b;

    // 1. Knowing nothing. The keystream cancels, A ^ B is plaintext A ^ B.
    std.debug.print("\n1. Listener knows nothing\n", .{});
    show("   A ^ B", &x);
    std.debug.print("{s:<19}", .{"   00 means equal"});
    for (x) |b| std.debug.print("{s}", .{if (b == 0) "=" else "?"});
    std.debug.print("\n", .{});

    // 2. Knowing the changed characters are digits leaves a few pairs per
    //    position.
    std.debug.print("\n2. Listener knows the changed characters are digits\n", .{});
    for (x, 0..) |d, i| {
        if (d == 0) continue;
        std.debug.print("   position {d:>2}: A/B is one of", .{i});
        for ('0'..'9' + 1) |a| {
            const b = @as(u8, @intCast(a)) ^ d;
            if (b >= '0' and b <= '9') std.debug.print(" {c}/{c}", .{ @as(u8, @intCast(a)), b });
        }
        std.debug.print("\n", .{});
    }

    // 3. Knowing the first reading, for example from a public dashboard,
    //    gives the second one completely.
    var recovered: [first.len]u8 = undefined;
    for (&recovered, x, first) |*o, d, p| o.* = d ^ p;
    std.debug.print("\n3. Listener knows the first reading\n", .{});
    std.debug.print("   known     {s}\n", .{first});
    std.debug.print("   recovered {s}\n", .{recovered});
}

fn send(buf: []u8, reading: []const u8) ![]u8 {
    return lora.phy_payload.encode(buf, .{ .ftype = .unconfirmed_data_up }, .{
        .fhdr = .{ .dev_addr = dev_addr, .fctrl = .{ .uplink = .{} }, .fcnt = 0 },
        .fport = 1,
        .frm_payload = reading,
    }, &keys, 0);
}

fn show(label: []const u8, bytes: []const u8) void {
    std.debug.print("{s:<19}", .{label});
    for (bytes) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
}
