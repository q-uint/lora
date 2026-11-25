//! LoRaWAN frame encoding/decoding.
//!
//! References:
//!   [TS001-1.0.4] LoRa Alliance, LoRaWAN L2 1.0.4 Specification, October 2020.
//!   [FIPS-197]    NIST, Advanced Encryption Standard (AES), FIPS 197.
//!   [RFC4493]     Song, Poovendran, Lee, Iwata, The AES-CMAC Algorithm, June 2006.
//!   [RP002]       LoRa Alliance, LoRaWAN Regional Parameters (cited, not implemented).

pub const mhdr = @import("mhdr.zig");
pub const MHDR = mhdr.MHDR;
pub const FType = mhdr.FType;
pub const Major = mhdr.Major;
pub const Direction = mhdr.Direction;

pub const fhdr = @import("fhdr.zig");
pub const FHDR = fhdr.FHDR;
pub const FCtrl = fhdr.FCtrl;

pub const mac_payload = @import("mac_payload.zig");
pub const MACPayload = mac_payload.MACPayload;

pub const crypto = @import("crypto.zig");
pub const Key = crypto.Key;
pub const SessionKeys = crypto.SessionKeys;

pub const mic = @import("mic.zig");
pub const Mic = mic.Mic;

pub const phy_payload = @import("phy_payload.zig");

pub const fcnt = @import("fcnt.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
