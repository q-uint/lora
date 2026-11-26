//! MAC commands, [TS001-1.0.4] §5.
//!
//! A command is a 1 octet CID followed by a payload whose length depends on
//! the CID and the direction. Commands are carried in FOpts or, with FPort 0,
//! in FRMPayload (§5).

const std = @import("std");
const Direction = @import("mhdr.zig").Direction;
const settings = @import("settings.zig");
const DlSettings = settings.DlSettings;
const RxTimingSettings = settings.RxTimingSettings;

/// Command identifiers, [TS001-1.0.4] §5 Table 14 and §12 Table 61.
pub const Cid = enum(u8) {
    link_check = 0x02,
    link_adr = 0x03,
    duty_cycle = 0x04,
    rx_param_setup = 0x05,
    dev_status = 0x06,
    new_channel = 0x07,
    rx_timing_setup = 0x08,
    tx_param_setup = 0x09,
    dl_channel = 0x0A,
    device_time = 0x0D,
    ping_slot_info = 0x10,
    ping_slot_channel = 0x11,
    beacon_freq = 0x13,
    _,

    /// Payload length in octets, excluding the CID. Null for CIDs without a
    /// definition in [TS001-1.0.4] (RFU, deprecated BeaconTiming, Class C,
    /// proprietary).
    pub fn payloadLen(cid: Cid, dir: Direction) ?u8 {
        return switch (dir) {
            .uplink => lenIn(Uplink, cid),
            .downlink => lenIn(Downlink, cid),
        };
    }
};

fn lenIn(comptime U: type, cid: Cid) ?u8 {
    inline for (@typeInfo(Cid).@"enum".field_names) |name| {
        if (cid == @field(Cid, name)) return lenOf(@FieldType(U, name));
    }
    return null;
}

fn lenOf(comptime T: type) u8 {
    return if (T == void) 0 else T.len;
}

/// Commands sent by the end-device, [TS001-1.0.4] Tables 14 and 61.
pub const Uplink = union(enum) {
    /// LinkCheckReq, no payload, §5.1.
    link_check,
    link_adr: LinkAdrAns,
    /// DutyCycleAns, no payload, §5.3.
    duty_cycle,
    rx_param_setup: RxParamSetupAns,
    dev_status: DevStatusAns,
    new_channel: NewChannelAns,
    /// RXTimingSetupAns, no payload, §5.7.
    rx_timing_setup,
    /// TXParamSetupAns, no payload, §5.8.
    tx_param_setup,
    dl_channel: DlChannelAns,
    /// DeviceTimeReq, no payload, §5.9.
    device_time,
    ping_slot_info: PingSlotInfoReq,
    ping_slot_channel: PingSlotChannelAns,
    beacon_freq: BeaconFreqAns,

    pub fn decode(cmd: Command) DecodeError!Uplink {
        return decodeAs(Uplink, cmd);
    }

    /// Writes the CID and payload to `out`.
    pub fn encode(self: Uplink, out: []u8) EncodeError![]u8 {
        return encodeAs(self, out);
    }
};

/// Commands sent by the Network Server, [TS001-1.0.4] Tables 14 and 61.
pub const Downlink = union(enum) {
    link_check: LinkCheckAns,
    link_adr: LinkAdrReq,
    duty_cycle: DutyCycleReq,
    rx_param_setup: RxParamSetupReq,
    /// DevStatusReq, no payload, §5.5.
    dev_status,
    new_channel: NewChannelReq,
    rx_timing_setup: RxTimingSetupReq,
    tx_param_setup: TxParamSetupReq,
    dl_channel: DlChannelReq,
    device_time: DeviceTimeAns,
    /// PingSlotInfoAns, no payload, §12.1.
    ping_slot_info,
    ping_slot_channel: PingSlotChannelReq,
    beacon_freq: BeaconFreqReq,

    pub fn decode(cmd: Command) DecodeError!Downlink {
        return decodeAs(Downlink, cmd);
    }

    /// Writes the CID and payload to `out`.
    pub fn encode(self: Downlink, out: []u8) EncodeError![]u8 {
        return encodeAs(self, out);
    }
};

pub const DecodeError = error{ UnknownCommand, InvalidLength };
pub const EncodeError = error{NoSpaceLeft};

fn decodeAs(comptime U: type, cmd: Command) DecodeError!U {
    inline for (@typeInfo(Cid).@"enum".field_names) |name| {
        if (cmd.cid == @field(Cid, name)) {
            const T = @FieldType(U, name);
            if (cmd.payload.len != lenOf(T)) return error.InvalidLength;
            if (T == void) return @unionInit(U, name, {});
            return @unionInit(U, name, T.decode(cmd.payload[0..T.len]));
        }
    }
    return error.UnknownCommand;
}

fn encodeAs(u: anytype, out: []u8) EncodeError![]u8 {
    switch (u) {
        inline else => |v, tag| {
            const T = @TypeOf(v);
            const payload: [lenOf(T)]u8 = if (T == void) .{} else v.encode();
            if (out.len < 1 + payload.len) return error.NoSpaceLeft;
            out[0] = @intFromEnum(@field(Cid, @tagName(tag)));
            @memcpy(out[1..][0..payload.len], &payload);
            return out[0 .. 1 + payload.len];
        },
    }
}

/// LinkCheckAns, [TS001-1.0.4] §5.1 Table 16.
pub const LinkCheckAns = struct {
    /// Link margin in dB above the demodulation floor, 0 to 254. 255 is
    /// reserved.
    margin: u8,
    /// Number of gateways that received the LinkCheckReq.
    gw_cnt: u8,

    pub const len = 2;

    pub fn encode(self: LinkCheckAns) [len]u8 {
        return .{ self.margin, self.gw_cnt };
    }

    pub fn decode(bytes: *const [len]u8) LinkCheckAns {
        return .{ .margin = bytes[0], .gw_cnt = bytes[1] };
    }
};

/// LinkADRReq, [TS001-1.0.4] §5.2 Tables 17 to 20.
///
///   Octets     |        1         |   2    |     1
///   LinkADRReq | DataRate_TXPower | ChMask | Redundancy
///
///   Bits             |   7:4    |   3:0
///   DataRate_TXPower | DataRate | TXPower
///
///   Bits       |  7  |    6:4     |   3:0
///   Redundancy | RFU | ChMaskCntl | NbTrans
pub const LinkAdrReq = struct {
    /// Region specific [RP002-1.0.5]. 15 keeps the current value.
    data_rate: u4,
    /// Region specific [RP002-1.0.5]. 15 keeps the current value.
    tx_power: u4,
    /// Bit n enables channel n + 1 of the block selected by ChMaskCntl,
    /// Table 19.
    ch_mask: u16,
    /// Region specific [RP002-1.0.5].
    ch_mask_cntl: u3,
    /// Transmissions per uplink frame. 0 selects the default of 1.
    nb_trans: u4,

    pub const len = 4;

    pub fn encode(self: LinkAdrReq) [len]u8 {
        var out: [len]u8 = undefined;
        out[0] = @as(u8, self.data_rate) << 4 | self.tx_power;
        std.mem.writeInt(u16, out[1..3], self.ch_mask, .little);
        out[3] = @as(u8, self.ch_mask_cntl) << 4 | self.nb_trans;
        return out;
    }

    pub fn decode(bytes: *const [len]u8) LinkAdrReq {
        return .{
            .data_rate = @truncate(bytes[0] >> 4),
            .tx_power = @truncate(bytes[0]),
            .ch_mask = std.mem.readInt(u16, bytes[1..3], .little),
            .ch_mask_cntl = @truncate(bytes[3] >> 4),
            .nb_trans = @truncate(bytes[3]),
        };
    }
};

/// LinkADRAns, [TS001-1.0.4] §5.2 Tables 21 to 23.
///
///   Bits   | 7:3 |    2     |      1      |       0
///   Status | RFU | PowerACK | DataRateACK | ChannelMaskACK
pub const LinkAdrAns = struct {
    channel_mask_ack: bool,
    data_rate_ack: bool,
    power_ack: bool,

    pub const len = 1;

    /// All three bits set, [TS001-1.0.4] §5.2.
    pub fn accepted(self: LinkAdrAns) bool {
        return self.channel_mask_ack and self.data_rate_ack and self.power_ack;
    }

    pub fn encode(self: LinkAdrAns) [len]u8 {
        return .{statusBits(.{ self.channel_mask_ack, self.data_rate_ack, self.power_ack })};
    }

    pub fn decode(bytes: *const [len]u8) LinkAdrAns {
        const b = bytes[0];
        return .{ .channel_mask_ack = bit(b, 0), .data_rate_ack = bit(b, 1), .power_ack = bit(b, 2) };
    }
};

/// DutyCycleReq, [TS001-1.0.4] §5.3 Tables 24 and 25.
///
///   Bits        | 7:4 |     3:0
///   DutyCyclePL | RFU | MaxDutyCycle
pub const DutyCycleReq = struct {
    /// Aggregated duty cycle of 1 / 2^max_duty_cycle. 0 means no limit
    /// beyond the regional one.
    max_duty_cycle: u4,

    pub const len = 1;

    pub fn encode(self: DutyCycleReq) [len]u8 {
        return .{self.max_duty_cycle};
    }

    pub fn decode(bytes: *const [len]u8) DutyCycleReq {
        return .{ .max_duty_cycle = @truncate(bytes[0]) };
    }
};

/// RXParamSetupReq, [TS001-1.0.4] §5.4 Tables 26 and 27.
///
///   Octets          |     1      |     3
///   RXParamSetupReq | DLSettings | Frequency
pub const RxParamSetupReq = struct {
    dl_settings: DlSettings,
    /// RX2 frequency in 100 Hz steps, §5.6.
    frequency: u24,

    pub const len = 4;

    pub fn encode(self: RxParamSetupReq) [len]u8 {
        var out: [len]u8 = undefined;
        out[0] = self.dl_settings.encode();
        std.mem.writeInt(u24, out[1..4], self.frequency, .little);
        return out;
    }

    pub fn decode(bytes: *const [len]u8) RxParamSetupReq {
        return .{
            .dl_settings = DlSettings.decode(bytes[0]),
            .frequency = std.mem.readInt(u24, bytes[1..4], .little),
        };
    }
};

/// RXParamSetupAns, [TS001-1.0.4] §5.4 Tables 28 to 30.
///
///   Bits   | 7:3 |       2        |       1        |     0
///   Status | RFU | RX1DROffsetACK | RX2DataRateACK | ChannelACK
pub const RxParamSetupAns = struct {
    channel_ack: bool,
    rx2_data_rate_ack: bool,
    rx1_dr_offset_ack: bool,

    pub const len = 1;

    /// All three bits set, [TS001-1.0.4] §5.4.
    pub fn accepted(self: RxParamSetupAns) bool {
        return self.channel_ack and self.rx2_data_rate_ack and self.rx1_dr_offset_ack;
    }

    pub fn encode(self: RxParamSetupAns) [len]u8 {
        return .{statusBits(.{ self.channel_ack, self.rx2_data_rate_ack, self.rx1_dr_offset_ack })};
    }

    pub fn decode(bytes: *const [len]u8) RxParamSetupAns {
        const b = bytes[0];
        return .{ .channel_ack = bit(b, 0), .rx2_data_rate_ack = bit(b, 1), .rx1_dr_offset_ack = bit(b, 2) };
    }
};

/// DevStatusAns, [TS001-1.0.4] §5.5 Tables 31 to 33.
///
///   Octets       |    1    |      1
///   DevStatusAns | Battery | RadioStatus
///
///   Bits        | 7:6 | 5:0
///   RadioStatus | RFU | SNR
pub const DevStatusAns = struct {
    /// 1 (minimum) to 254 (maximum), or one of the values below, Table 32.
    battery: u8,
    /// SNR in dB of the last DevStatusReq.
    snr: i6,

    pub const battery_external_power: u8 = 0;
    pub const battery_unknown: u8 = 255;

    pub const len = 2;

    pub fn encode(self: DevStatusAns) [len]u8 {
        return .{ self.battery, @as(u6, @bitCast(self.snr)) };
    }

    pub fn decode(bytes: *const [len]u8) DevStatusAns {
        return .{ .battery = bytes[0], .snr = @bitCast(@as(u6, @truncate(bytes[1]))) };
    }
};

/// NewChannelReq, [TS001-1.0.4] §5.6 Tables 34 and 35.
///
///   Octets        |    1    |     3     |    1
///   NewChannelReq | ChIndex | Frequency | DRRange
///
///   Bits    |  7:4  |  3:0
///   DRRange | MaxDR | MinDR
pub const NewChannelReq = struct {
    ch_index: u8,
    /// Frequency in 100 Hz steps. 0 disables the channel.
    frequency: u24,
    min_dr: u4,
    max_dr: u4,

    pub const len = 5;

    pub fn encode(self: NewChannelReq) [len]u8 {
        var out: [len]u8 = undefined;
        out[0] = self.ch_index;
        std.mem.writeInt(u24, out[1..4], self.frequency, .little);
        out[4] = @as(u8, self.max_dr) << 4 | self.min_dr;
        return out;
    }

    pub fn decode(bytes: *const [len]u8) NewChannelReq {
        return .{
            .ch_index = bytes[0],
            .frequency = std.mem.readInt(u24, bytes[1..4], .little),
            .min_dr = @truncate(bytes[4]),
            .max_dr = @truncate(bytes[4] >> 4),
        };
    }
};

/// NewChannelAns, [TS001-1.0.4] §5.6 Tables 36 to 38.
///
///   Bits   | 7:2 |         1          |          0
///   Status | RFU | Data-rate range ok | Channel frequency ok
pub const NewChannelAns = struct {
    channel_frequency_ok: bool,
    data_rate_range_ok: bool,

    pub const len = 1;

    /// Both bits set, [TS001-1.0.4] §5.6.
    pub fn accepted(self: NewChannelAns) bool {
        return self.channel_frequency_ok and self.data_rate_range_ok;
    }

    pub fn encode(self: NewChannelAns) [len]u8 {
        return .{statusBits(.{ self.channel_frequency_ok, self.data_rate_range_ok })};
    }

    pub fn decode(bytes: *const [len]u8) NewChannelAns {
        return .{ .channel_frequency_ok = bit(bytes[0], 0), .data_rate_range_ok = bit(bytes[0], 1) };
    }
};

/// DlChannelReq, [TS001-1.0.4] §5.6 Table 39.
///
///   Octets       |    1    |     3
///   DlChannelReq | ChIndex | Frequency
pub const DlChannelReq = struct {
    ch_index: u8,
    /// RX1 downlink frequency in 100 Hz steps.
    frequency: u24,

    pub const len = 4;

    pub fn encode(self: DlChannelReq) [len]u8 {
        var out: [len]u8 = undefined;
        out[0] = self.ch_index;
        std.mem.writeInt(u24, out[1..4], self.frequency, .little);
        return out;
    }

    pub fn decode(bytes: *const [len]u8) DlChannelReq {
        return .{ .ch_index = bytes[0], .frequency = std.mem.readInt(u24, bytes[1..4], .little) };
    }
};

/// DlChannelAns, [TS001-1.0.4] §5.6 Tables 40 to 42.
///
///   Bits   | 7:2 |            1            |          0
///   Status | RFU | Uplink frequency exists | Channel frequency ok
pub const DlChannelAns = struct {
    channel_frequency_ok: bool,
    uplink_frequency_exists: bool,

    pub const len = 1;

    /// Both bits set, [TS001-1.0.4] §5.6.
    pub fn accepted(self: DlChannelAns) bool {
        return self.channel_frequency_ok and self.uplink_frequency_exists;
    }

    pub fn encode(self: DlChannelAns) [len]u8 {
        return .{statusBits(.{ self.channel_frequency_ok, self.uplink_frequency_exists })};
    }

    pub fn decode(bytes: *const [len]u8) DlChannelAns {
        return .{ .channel_frequency_ok = bit(bytes[0], 0), .uplink_frequency_exists = bit(bytes[0], 1) };
    }
};

/// RXTimingSetupReq, [TS001-1.0.4] §5.7 Tables 43 to 45.
pub const RxTimingSetupReq = struct {
    settings: RxTimingSettings,

    pub const len = 1;

    pub fn encode(self: RxTimingSetupReq) [len]u8 {
        return .{self.settings.encode()};
    }

    pub fn decode(bytes: *const [len]u8) RxTimingSetupReq {
        return .{ .settings = RxTimingSettings.decode(bytes[0]) };
    }
};

/// TXParamSetupReq, [TS001-1.0.4] §5.8 Tables 46 to 49.
///
///   Bits            | 7:6 |         5         |        4         |   3:0
///   EIRP_DwellTime  | RFU | DownlinkDwellTime | UplinkDwellTime  | MaxEIRP
pub const TxParamSetupReq = struct {
    /// Index into Table 48, see `maxEirpDbm`.
    max_eirp: u4,
    /// True limits the dwell time to 400 ms, false means no limit, Table 49.
    uplink_dwell_time: bool,
    downlink_dwell_time: bool,

    pub const len = 1;

    /// [TS001-1.0.4] §5.8 Table 48.
    const eirp_dbm = [16]u8{ 8, 10, 12, 13, 14, 16, 18, 20, 21, 24, 26, 27, 29, 30, 33, 36 };

    pub fn maxEirpDbm(self: TxParamSetupReq) u8 {
        return eirp_dbm[self.max_eirp];
    }

    pub fn encode(self: TxParamSetupReq) [len]u8 {
        return .{@as(u8, @intFromBool(self.downlink_dwell_time)) << 5 |
            @as(u8, @intFromBool(self.uplink_dwell_time)) << 4 |
            self.max_eirp};
    }

    pub fn decode(bytes: *const [len]u8) TxParamSetupReq {
        const b = bytes[0];
        return .{ .max_eirp = @truncate(b), .uplink_dwell_time = bit(b, 4), .downlink_dwell_time = bit(b, 5) };
    }
};

/// DeviceTimeAns, [TS001-1.0.4] §5.9 Table 50.
///
///   Octets        |    4    |     1
///   DeviceTimeAns | Seconds | Fraction
pub const DeviceTimeAns = struct {
    /// Seconds since the GPS epoch, 1980-01-06 00:00:00 UTC.
    seconds: u32,
    /// Fractional second in 1/256 s steps.
    fraction: u8,

    pub const len = 5;

    pub fn encode(self: DeviceTimeAns) [len]u8 {
        var out: [len]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.seconds, .little);
        out[4] = self.fraction;
        return out;
    }

    pub fn decode(bytes: *const [len]u8) DeviceTimeAns {
        return .{ .seconds = std.mem.readInt(u32, bytes[0..4], .little), .fraction = bytes[4] };
    }
};

/// PingSlotInfoReq, [TS001-1.0.4] §12.1 Tables 62 and 63.
///
///   Bits          | 7:3 |     2:0
///   PingSlotParam | RFU | Periodicity
pub const PingSlotInfoReq = struct {
    /// Ping slot every 0.96 × 2^periodicity s.
    periodicity: u3,

    pub const len = 1;

    pub fn encode(self: PingSlotInfoReq) [len]u8 {
        return .{self.periodicity};
    }

    pub fn decode(bytes: *const [len]u8) PingSlotInfoReq {
        return .{ .periodicity = @truncate(bytes[0]) };
    }
};

/// BeaconFreqReq, [TS001-1.0.4] §12.2 Table 64.
pub const BeaconFreqReq = struct {
    /// Beacon frequency in 100 Hz steps. 0 selects the default plan.
    frequency: u24,

    pub const len = 3;

    pub fn encode(self: BeaconFreqReq) [len]u8 {
        var out: [len]u8 = undefined;
        std.mem.writeInt(u24, &out, self.frequency, .little);
        return out;
    }

    pub fn decode(bytes: *const [len]u8) BeaconFreqReq {
        return .{ .frequency = std.mem.readInt(u24, bytes, .little) };
    }
};

/// BeaconFreqAns, [TS001-1.0.4] §12.2 Tables 65 to 67.
///
///   Bits   | 7:1 |          0
///   Status | RFU | Beacon frequency ok
pub const BeaconFreqAns = struct {
    beacon_frequency_ok: bool,

    pub const len = 1;

    pub fn encode(self: BeaconFreqAns) [len]u8 {
        return .{statusBits(.{self.beacon_frequency_ok})};
    }

    pub fn decode(bytes: *const [len]u8) BeaconFreqAns {
        return .{ .beacon_frequency_ok = bit(bytes[0], 0) };
    }
};

/// PingSlotChannelReq, [TS001-1.0.4] §12.3 Tables 68 and 69.
///
///   Octets             |     3     |  1
///   PingSlotChannelReq | Frequency | DR
///
///   Bits | 7:4 |   3:0
///   DR   | RFU | DataRate
pub const PingSlotChannelReq = struct {
    /// Ping slot frequency in 100 Hz steps. 0 selects the default plan.
    frequency: u24,
    /// Region specific [RP002-1.0.5].
    data_rate: u4,

    pub const len = 4;

    pub fn encode(self: PingSlotChannelReq) [len]u8 {
        var out: [len]u8 = undefined;
        std.mem.writeInt(u24, out[0..3], self.frequency, .little);
        out[3] = self.data_rate;
        return out;
    }

    pub fn decode(bytes: *const [len]u8) PingSlotChannelReq {
        return .{ .frequency = std.mem.readInt(u24, bytes[0..3], .little), .data_rate = @truncate(bytes[3]) };
    }
};

/// PingSlotChannelAns, [TS001-1.0.4] §12.3 Tables 70 to 72.
///
///   Bits   | 7:2 |      1       |          0
///   Status | RFU | Data rate ok | Channel frequency ok
pub const PingSlotChannelAns = struct {
    channel_frequency_ok: bool,
    data_rate_ok: bool,

    pub const len = 1;

    /// Both bits set, [TS001-1.0.4] §12.3.
    pub fn accepted(self: PingSlotChannelAns) bool {
        return self.channel_frequency_ok and self.data_rate_ok;
    }

    pub fn encode(self: PingSlotChannelAns) [len]u8 {
        return .{statusBits(.{ self.channel_frequency_ok, self.data_rate_ok })};
    }

    pub fn decode(bytes: *const [len]u8) PingSlotChannelAns {
        return .{ .channel_frequency_ok = bit(bytes[0], 0), .data_rate_ok = bit(bytes[0], 1) };
    }
};

/// RFU bits are sent as 0, [TS001-1.0.4] §1.1.
fn statusBits(bits: anytype) u8 {
    var b: u8 = 0;
    inline for (bits, 0..) |set, i| b |= @as(u8, @intFromBool(set)) << i;
    return b;
}

fn bit(b: u8, comptime i: u3) bool {
    return b >> i & 1 == 1;
}

/// One command with its payload borrowed from the input.
pub const Command = struct {
    cid: Cid,
    payload: []const u8,
};

pub const Error = error{
    /// The length of an unknown command is not known, so it ends the
    /// sequence, [TS001-1.0.4] §5.
    UnknownCommand,
    Truncated,
};

/// Walks a sequence of commands. After an error, `bytes[index..]` starts at
/// the command that failed.
pub const Iterator = struct {
    bytes: []const u8,
    dir: Direction,
    index: usize = 0,

    pub fn next(it: *Iterator) Error!?Command {
        if (it.index == it.bytes.len) return null;
        const cid: Cid = @enumFromInt(it.bytes[it.index]);
        const len = cid.payloadLen(it.dir) orelse return error.UnknownCommand;
        const start = it.index + 1;
        if (it.bytes.len - start < len) return error.Truncated;
        it.index = start + len;
        return .{ .cid = cid, .payload = it.bytes[start..it.index] };
    }
};

/// Commands in `bytes`, sent in direction `dir`. Uplink commands are those an
/// end-device transmits, [TS001-1.0.4] §5 Table 14.
pub fn iterate(bytes: []const u8, dir: Direction) Iterator {
    return .{ .bytes = bytes, .dir = dir };
}

const testing = std.testing;

test Iterator {
    // A proprietary command (0x80 to 0xFF, [TS001-1.0.4] §5 Table 14) after
    // the standard ones. Its format is defined by the application, here a
    // CID 0x80 with a 2 octet payload.
    const fopts = [_]u8{ 0x02, 0x80, 0xAB, 0xCD };
    var it = iterate(&fopts, .uplink);
    const proprietary = while (true) {
        const cmd = it.next() catch |err| switch (err) {
            error.UnknownCommand => break it.bytes[it.index..],
            error.Truncated => return err,
        } orelse break &.{};
        try testing.expectEqual(.link_check, cmd.cid);
    };
    try testing.expectEqualSlices(u8, &.{ 0x80, 0xAB, 0xCD }, proprietary);
}

test "payload lengths (Table 14)" {
    // Uplink then downlink, from the payload format tables of §5.1 to §5.9.
    const cases = .{
        .{ Cid.link_check, 0, 2 },
        .{ Cid.link_adr, 1, 4 },
        .{ Cid.duty_cycle, 0, 1 },
        .{ Cid.rx_param_setup, 1, 4 },
        .{ Cid.dev_status, 2, 0 },
        .{ Cid.new_channel, 1, 5 },
        .{ Cid.rx_timing_setup, 0, 1 },
        .{ Cid.tx_param_setup, 0, 1 },
        .{ Cid.dl_channel, 1, 4 },
        .{ Cid.device_time, 0, 5 },
        // Tables 62 to 70.
        .{ Cid.ping_slot_info, 1, 0 },
        .{ Cid.ping_slot_channel, 1, 4 },
        .{ Cid.beacon_freq, 1, 3 },
    };
    inline for (cases) |c| {
        try testing.expectEqual(c[1], c[0].payloadLen(.uplink));
        try testing.expectEqual(c[2], c[0].payloadLen(.downlink));
    }
    // Not in Table 14 (0x00, 0x01), RFU, deprecated BeaconTiming (§12.4),
    // undefined Class B, Class C, RFU and proprietary.
    for ([_]u8{ 0x00, 0x01, 0x0B, 0x0C, 0x0E, 0x0F, 0x12, 0x14, 0x1F, 0x20, 0x30, 0x7F, 0x80, 0xFF }) |b| {
        const cid: Cid = @enumFromInt(b);
        try testing.expectEqual(null, cid.payloadLen(.uplink));
        try testing.expectEqual(null, cid.payloadLen(.downlink));
    }
}

test "iterate an uplink sequence" {
    // LinkCheckReq, LinkADRAns, DevStatusAns, DeviceTimeReq.
    const bytes = [_]u8{ 0x02, 0x03, 0x07, 0x06, 0xFF, 0x20, 0x0D };
    var it = iterate(&bytes, .uplink);
    const expected = [_]struct { Cid, []const u8 }{
        .{ .link_check, &.{} },
        .{ .link_adr, &.{0x07} },
        .{ .dev_status, &.{ 0xFF, 0x20 } },
        .{ .device_time, &.{} },
    };
    for (expected) |e| {
        const cmd = (try it.next()).?;
        try testing.expectEqual(e[0], cmd.cid);
        try testing.expectEqualSlices(u8, e[1], cmd.payload);
    }
    try testing.expectEqual(null, try it.next());
}

test "iterate a downlink sequence" {
    // LinkADRReq, DutyCycleReq, DeviceTimeAns.
    const bytes = [_]u8{ 0x03, 0x51, 0xFF, 0x00, 0x01, 0x04, 0x02, 0x0D, 1, 2, 3, 4, 5 };
    var it = iterate(&bytes, .downlink);
    try testing.expectEqualSlices(u8, &.{ 0x51, 0xFF, 0x00, 0x01 }, (try it.next()).?.payload);
    try testing.expectEqualSlices(u8, &.{0x02}, (try it.next()).?.payload);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, (try it.next()).?.payload);
    try testing.expectEqual(null, try it.next());
}

test "unknown command stops the sequence" {
    // DutyCycleAns, then the deprecated BeaconTimingReq (0x12, §12.4), then
    // LinkCheckReq.
    const bytes = [_]u8{ 0x04, 0x12, 0x02 };
    var it = iterate(&bytes, .uplink);
    _ = (try it.next()).?;
    try testing.expectError(error.UnknownCommand, it.next());
    try testing.expectEqualSlices(u8, &.{ 0x12, 0x02 }, it.bytes[it.index..]);
}

test "truncated payload" {
    var it = iterate(&.{ 0x03, 0x51, 0xFF }, .downlink);
    try testing.expectError(error.Truncated, it.next());
    try testing.expectEqual(0, it.index);
}

test "empty sequence" {
    var it = iterate(&.{}, .uplink);
    try testing.expectEqual(null, try it.next());
}

fn expectDownlink(cmd: Downlink, wire: []const u8) !void {
    var buf: [6]u8 = undefined;
    try testing.expectEqualSlices(u8, wire, try cmd.encode(&buf));
    try testing.expectEqual(cmd, try Downlink.decode(.{ .cid = @enumFromInt(wire[0]), .payload = wire[1..] }));
}

fn expectUplink(cmd: Uplink, wire: []const u8) !void {
    var buf: [3]u8 = undefined;
    try testing.expectEqualSlices(u8, wire, try cmd.encode(&buf));
    try testing.expectEqual(cmd, try Uplink.decode(.{ .cid = @enumFromInt(wire[0]), .payload = wire[1..] }));
}

test "downlink commands, bit positions from §5" {
    // Table 16.
    try expectDownlink(.{ .link_check = .{ .margin = 20, .gw_cnt = 3 } }, &.{ 0x02, 20, 3 });
    // Tables 17, 18 and 20, ChMask little endian.
    try expectDownlink(.{ .link_adr = .{
        .data_rate = 5,
        .tx_power = 1,
        .ch_mask = 0x00FF,
        .ch_mask_cntl = 6,
        .nb_trans = 1,
    } }, &.{ 0x03, 0x51, 0xFF, 0x00, 0x61 });
    // Table 25.
    try expectDownlink(.{ .duty_cycle = .{ .max_duty_cycle = 7 } }, &.{ 0x04, 0x07 });
    // Tables 26 and 27, 869.525 MHz is 8695250 = 0x84ADD2.
    try expectDownlink(.{ .rx_param_setup = .{
        .dl_settings = .{ .rx1_dr_offset = 2, .rx2_data_rate = 3 },
        .frequency = 8695250,
    } }, &.{ 0x05, 0x23, 0xD2, 0xAD, 0x84 });
    try expectDownlink(.dev_status, &.{0x06});
    // Tables 34 and 35, 867.1 MHz is 8671000 = 0x844F18.
    try expectDownlink(.{ .new_channel = .{
        .ch_index = 3,
        .frequency = 8671000,
        .min_dr = 0,
        .max_dr = 5,
    } }, &.{ 0x07, 3, 0x18, 0x4F, 0x84, 0x50 });
    // Tables 43 and 44.
    try expectDownlink(.{ .rx_timing_setup = .{ .settings = .{ .del = 5 } } }, &.{ 0x08, 0x05 });
    // Table 47.
    try expectDownlink(.{ .tx_param_setup = .{
        .max_eirp = 13,
        .uplink_dwell_time = true,
        .downlink_dwell_time = false,
    } }, &.{ 0x09, 0x1D });
    // Table 39.
    try expectDownlink(.{ .dl_channel = .{ .ch_index = 3, .frequency = 8695250 } }, &.{ 0x0A, 3, 0xD2, 0xAD, 0x84 });
    // Table 50, the §5.9 example 1139322288 s = 0x43E8ADB0.
    try expectDownlink(.{ .device_time = .{ .seconds = 1139322288, .fraction = 128 } }, &.{ 0x0D, 0xB0, 0xAD, 0xE8, 0x43, 128 });
    try expectDownlink(.ping_slot_info, &.{0x10});
    // Tables 68 and 69.
    try expectDownlink(.{ .ping_slot_channel = .{ .frequency = 8695250, .data_rate = 3 } }, &.{ 0x11, 0xD2, 0xAD, 0x84, 0x03 });
    // Table 64.
    try expectDownlink(.{ .beacon_freq = .{ .frequency = 8695250 } }, &.{ 0x13, 0xD2, 0xAD, 0x84 });
}

test "uplink commands, bit positions from §5" {
    try expectUplink(.link_check, &.{0x02});
    // Table 22.
    try expectUplink(.{ .link_adr = .{ .channel_mask_ack = true, .data_rate_ack = false, .power_ack = true } }, &.{ 0x03, 0x05 });
    try expectUplink(.duty_cycle, &.{0x04});
    // Table 29.
    try expectUplink(.{ .rx_param_setup = .{ .channel_ack = false, .rx2_data_rate_ack = true, .rx1_dr_offset_ack = true } }, &.{ 0x05, 0x06 });
    // Tables 31 and 33, SNR -1 is 0x3F in 6 bits.
    try expectUplink(.{ .dev_status = .{ .battery = 254, .snr = -1 } }, &.{ 0x06, 254, 0x3F });
    // Table 37.
    try expectUplink(.{ .new_channel = .{ .channel_frequency_ok = true, .data_rate_range_ok = false } }, &.{ 0x07, 0x01 });
    try expectUplink(.rx_timing_setup, &.{0x08});
    try expectUplink(.tx_param_setup, &.{0x09});
    // Table 41.
    try expectUplink(.{ .dl_channel = .{ .channel_frequency_ok = false, .uplink_frequency_exists = true } }, &.{ 0x0A, 0x02 });
    try expectUplink(.device_time, &.{0x0D});
    // Table 63.
    try expectUplink(.{ .ping_slot_info = .{ .periodicity = 7 } }, &.{ 0x10, 0x07 });
    // Table 71.
    try expectUplink(.{ .ping_slot_channel = .{ .channel_frequency_ok = false, .data_rate_ok = true } }, &.{ 0x11, 0x02 });
    // Table 66.
    try expectUplink(.{ .beacon_freq = .{ .beacon_frequency_ok = true } }, &.{ 0x13, 0x01 });
}

test "RFU bits are ignored on decode (§1.1)" {
    const ans = LinkAdrAns.decode(&.{0xF8});
    try testing.expect(!ans.channel_mask_ack and !ans.data_rate_ack and !ans.power_ack);
    try testing.expectEqual(31, DevStatusAns.decode(&.{ 0, 0xDF }).snr);
    try testing.expectEqual(DutyCycleReq{ .max_duty_cycle = 2 }, DutyCycleReq.decode(&.{0xF2}));
    try testing.expectEqual(0, (LinkAdrReq.decode(&.{ 0, 0, 0, 0x80 })).ch_mask_cntl);
    const tx = TxParamSetupReq.decode(&.{0xC0});
    try testing.expect(!tx.uplink_dwell_time and !tx.downlink_dwell_time);
    try testing.expectEqual(3, PingSlotInfoReq.decode(&.{0xFB}).periodicity);
    try testing.expectEqual(3, PingSlotChannelReq.decode(&.{ 0, 0, 0, 0xF3 }).data_rate);
    try testing.expect(!BeaconFreqAns.decode(&.{0xFE}).beacon_frequency_ok);
}

test "accepted needs every status bit" {
    try testing.expect((LinkAdrAns{ .channel_mask_ack = true, .data_rate_ack = true, .power_ack = true }).accepted());
    try testing.expect(!(LinkAdrAns{ .channel_mask_ack = true, .data_rate_ack = true, .power_ack = false }).accepted());
    try testing.expect(!(RxParamSetupAns{ .channel_ack = true, .rx2_data_rate_ack = false, .rx1_dr_offset_ack = true }).accepted());
    try testing.expect((NewChannelAns{ .channel_frequency_ok = true, .data_rate_range_ok = true }).accepted());
    try testing.expect(!(DlChannelAns{ .channel_frequency_ok = true, .uplink_frequency_exists = false }).accepted());
    try testing.expect(!(PingSlotChannelAns{ .channel_frequency_ok = false, .data_rate_ok = true }).accepted());
}

test "MaxEIRP encoding (Table 48)" {
    try testing.expectEqual(8, (TxParamSetupReq{ .max_eirp = 0, .uplink_dwell_time = false, .downlink_dwell_time = false }).maxEirpDbm());
    try testing.expectEqual(16, (TxParamSetupReq{ .max_eirp = 5, .uplink_dwell_time = false, .downlink_dwell_time = false }).maxEirpDbm());
    try testing.expectEqual(36, (TxParamSetupReq{ .max_eirp = 15, .uplink_dwell_time = false, .downlink_dwell_time = false }).maxEirpDbm());
}

test "decode errors" {
    try testing.expectError(error.UnknownCommand, Uplink.decode(.{ .cid = @enumFromInt(0x80), .payload = &.{} }));
    try testing.expectError(error.InvalidLength, Downlink.decode(.{ .cid = .link_adr, .payload = &.{0x51} }));
    // An uplink LinkADRAns read as a downlink command.
    try testing.expectError(error.InvalidLength, Downlink.decode(.{ .cid = .link_adr, .payload = &.{0x07} }));
}

test "encode into a short buffer" {
    var buf: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, (Downlink{ .device_time = .{ .seconds = 0, .fraction = 0 } }).encode(&buf));
    try testing.expectError(error.NoSpaceLeft, (Uplink{ .link_check = {} }).encode(buf[0..0]));
}

test "iterate and decode a downlink" {
    var buf: [16]u8 = undefined;
    var n: usize = 0;
    n += (try (Downlink{ .link_check = .{ .margin = 7, .gw_cnt = 2 } }).encode(buf[n..])).len;
    n += (try (Downlink{ .dev_status = {} }).encode(buf[n..])).len;
    n += (try (Downlink{ .duty_cycle = .{ .max_duty_cycle = 4 } }).encode(buf[n..])).len;
    var it = iterate(buf[0..n], .downlink);
    try testing.expectEqual(Downlink{ .link_check = .{ .margin = 7, .gw_cnt = 2 } }, try Downlink.decode((try it.next()).?));
    try testing.expectEqual(Downlink{ .dev_status = {} }, try Downlink.decode((try it.next()).?));
    try testing.expectEqual(Downlink{ .duty_cycle = .{ .max_duty_cycle = 4 } }, try Downlink.decode((try it.next()).?));
    try testing.expectEqual(null, try it.next());
}
