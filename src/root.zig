//! LoRaWAN frame encoding/decoding.
//!
//! References:
//!   [TS001-1.0.4] LoRa Alliance, LoRaWAN L2 1.0.4 Specification, October 2020.
//!   [FIPS-197]    NIST, Advanced Encryption Standard (AES), FIPS 197.
//!   [RFC4493]     Song, Poovendran, Lee, Iwata, The AES-CMAC Algorithm, June 2006.
//!   [RP002-1.0.5] LoRa Alliance, LoRaWAN Regional Parameters RP002-1.0.5.
//!                 TS001-1.0.4 cites RP002-1.0.0, see region.zig.

pub const mhdr = @import("mhdr.zig");
pub const Mhdr = mhdr.Mhdr;
pub const FType = mhdr.FType;
pub const Major = mhdr.Major;
pub const Direction = mhdr.Direction;

pub const fhdr = @import("fhdr.zig");
pub const Fhdr = fhdr.Fhdr;
pub const FCtrl = fhdr.FCtrl;

pub const mac_payload = @import("mac_payload.zig");
pub const MacPayload = mac_payload.MacPayload;

pub const mac_command = @import("mac_command.zig");

pub const crypto = @import("crypto.zig");
pub const Key = crypto.Key;
pub const SessionKeys = crypto.SessionKeys;

pub const mic = @import("mic.zig");
pub const Mic = mic.Mic;

pub const phy_payload = @import("phy_payload.zig");

pub const join = @import("join.zig");
pub const JoinRequest = join.JoinRequest;
pub const JoinAccept = join.JoinAccept;
pub const deriveSessionKeys = join.deriveSessionKeys;

pub const cf_list = @import("cf_list.zig");
pub const CfList = cf_list.CfList;

pub const settings = @import("settings.zig");
pub const DlSettings = settings.DlSettings;
pub const RxTimingSettings = settings.RxTimingSettings;

pub const fcnt = @import("fcnt.zig");

pub const region = @import("region.zig");
pub const Region = region.Region;

pub const data_rate = @import("data_rate.zig");
pub const DataRate = data_rate.DataRate;

test {
    @import("std").testing.refAllDecls(@This());
}
