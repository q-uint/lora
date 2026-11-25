//! Inferring the 32-bit frame counter from the 16-bit FCnt field.
//!
//! Only the low 16 bits of FCntUp or FCntDown travel in FCnt, and "the server
//! must infer the 16 most-significant bits of the frame counter by observing
//! the traffic", [TS001-1.0.4] §4.3.1.5 (note, informative per §1.1).
//! TS001-1.0.4 gives no algorithm and removed MAX_FCNT_GAP (§17.5), so the
//! strategy here is a choice of this library, not a requirement of the spec.
//!
//! Nothing in this library calls `infer` on its own. `phy_payload.Parsed`
//! takes the full counter as a plain u32, so an implementer can use `infer`
//! or bring any other strategy (a maximum gap, several candidates tried
//! against the MIC, counters from persistent storage, and so on).
//!
//! What the spec does require, [TS001-1.0.4] §4.3.1.5:
//!   * the received counter has been incremented compared to the current one,
//!   * the MIC matches, computed with that counter,
//!   * a first frame with counter 0 after a Join (or for ABP) is accepted.

const std = @import("std");

/// Smallest 32-bit counter that is greater than `last` and whose low 16 bits
/// equal `received`. `last` is the last accepted counter, or null if no frame
/// has been accepted yet, in which case the upper 16 bits are taken as 0.
///
/// Returns null if no such counter fits in 32 bits.
///
/// The result is a candidate only. Accept it after the MIC verifies with it.
///
/// A repeat of the last FCnt (retransmission, see NbTrans in §4.3.1.5) maps to
/// `last + 0x10000` and will normally fail the MIC. Callers that want to treat
/// retransmissions separately compare `received` with the low bits of `last` first.
pub fn infer(last: ?u32, received: u16) ?u32 {
    const prev = last orelse return received;
    const candidate = (prev & 0xFFFF_0000) | received;
    if (candidate > prev) return candidate;
    return std.math.add(u32, candidate, 0x1_0000) catch null;
}

const testing = std.testing;

test "first frame takes upper bits 0" {
    try testing.expectEqual(0, infer(null, 0));
    try testing.expectEqual(5, infer(null, 5));
}

test "increment within the same upper half" {
    try testing.expectEqual(0x0003_0011, infer(0x0003_0010, 0x0011));
    try testing.expectEqual(0x0003_F000, infer(0x0003_0010, 0xF000));
}

test "low 16 bits wrap" {
    try testing.expectEqual(0x0004_0000, infer(0x0003_FFFF, 0x0000));
    try testing.expectEqual(0x0004_0005, infer(0x0003_FFF0, 0x0005));
}

test "repeat of the last FCnt moves to the next upper value" {
    try testing.expectEqual(0x0004_0010, infer(0x0003_0010, 0x0010));
}

test "no candidate above the 32-bit range" {
    try testing.expectEqual(null, infer(0xFFFF_FFFF, 0xFFFF));
    try testing.expectEqual(null, infer(0xFFFF_0010, 0x0005));
}
