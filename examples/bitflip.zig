//! A Network Server holding only NwkSKey changes an encrypted uplink.
//!
//! FRMPayload is encrypted with AES in counter mode, [TS001-1.0.4] §4.3.3.
//! Flipping a ciphertext bit flips the same plaintext bit, and the MIC uses
//! NwkSKey, which the Network Server has (§4.4). Knowing the payload format
//! is enough to change it without AppSKey.
//!
//! Run with `zig build bitflip`.

const std = @import("std");
const lora = @import("lora");

const keys = lora.SessionKeys{
    .nwk_s_key = @splat(0x11),
    .app_s_key = @splat(0x22),
};
const dev_addr: u32 = 0x26011234;
const mic_len = 4;

pub fn main() !void {
    // 1. Knowing nothing: flipped bits still pass, the result is garbage.
    std.debug.print("1. Network Server knows nothing about the payload\n", .{});
    std.debug.print("   mask: XOR 0x01 into every byte\n", .{});
    try run("temp=21C", 42, @splat(0x01));

    // 2. Knowing the format temp=NNC: one fixed mask for every reading. Bit 0
    //    of the tens digit shifts it by 10, and 'C' ^ 'F' changes the unit.
    std.debug.print("\n2. Network Server knows the format temp=NNC, not the value\n", .{});
    std.debug.print("   mask: XOR 0x01 into the tens digit, 'C' ^ 'F' into the unit\n", .{});
    var mask: [8]u8 = @splat(0);
    mask[5] = 0x01;
    mask[7] = 'C' ^ 'F';
    try run("temp=21C", 43, mask);
    try run("temp=30C", 44, mask);
    try run("temp=17C", 45, mask);

    // 3. Knowing the format and the current value: any chosen value.
    std.debug.print("\n3. Network Server knows the format and the value 21\n", .{});
    std.debug.print("   mask: XOR \"21\" ^ \"99\" into the digits\n", .{});
    mask = @splat(0);
    mask[5] = '2' ^ '9';
    mask[6] = '1' ^ '9';
    try run("temp=21C", 46, mask);
}

/// Encodes `reading` as the device would, applies `mask` with NwkSKey only,
/// then decrypts as the application would.
fn run(reading: *const [8]u8, fcnt: u32, mask: [8]u8) !void {
    var frame_buf: [64]u8 = undefined;
    const frame = try lora.phy_payload.encode(&frame_buf, .{ .ftype = .unconfirmed_data_up }, .{
        .fhdr = .{ .dev_addr = dev_addr, .fctrl = .{ .uplink = .{} }, .fcnt = @truncate(fcnt) },
        .fport = 1,
        .frm_payload = reading,
    }, &keys, fcnt);

    // Network Server: XOR into the ciphertext, recompute the MIC.
    const frm = frame[frame.len - mic_len - reading.len .. frame.len - mic_len];
    for (frm, mask) |*c, m| c.* ^= m;
    const msg = frame[0 .. frame.len - mic_len];
    frame[frame.len - mic_len ..][0..mic_len].* = lora.mic.compute(&keys.nwk_s_key, .uplink, dev_addr, fcnt, msg);

    // Application: the MIC checks out and AppSKey decrypts the change.
    const p = try lora.phy_payload.parse(frame);
    try p.verifyMic(&keys.nwk_s_key, fcnt);
    var plain: [16]u8 = undefined;
    const received = try p.decryptPayload(&keys, fcnt, &plain);
    std.debug.print("   sent {s}  received {s}  (MIC valid)\n", .{ reading, received });
}
