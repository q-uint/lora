//! Helpers shared by tests.

const std = @import("std");

/// Hex string to bytes at comptime, for test vectors.
pub fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
