/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Quint Daenen
 *
 * LoRaWAN frame encoding and decoding, C API.
 *
 * References:
 *   [TS001-1.0.4] LoRa Alliance, LoRaWAN L2 1.0.4 Specification, October 2020.
 *   [RP002-1.0.5] LoRa Alliance, LoRaWAN Regional Parameters RP002-1.0.5.
 *
 * Implemented in src/c.zig.
 */
#ifndef LORA_H
#define LORA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. 0 on success, negative on error. */
typedef enum lora_status {
    LORA_OK = 0,
    LORA_ERR_INVALID_ARGUMENT = -1,
    /* Input frame ends early. */
    LORA_ERR_TRUNCATED = -2,
    /* FOpts longer than 15 octets, [TS001-1.0.4] §4.3.1.6. */
    LORA_ERR_FOPTS_TOO_LONG = -3,
    /* FRMPayload without FPort, [TS001-1.0.4] §4.3.2. */
    LORA_ERR_MISSING_FPORT = -4,
    /* FPort 0 with non-empty FOpts, [TS001-1.0.4] §4.3.1.6. */
    LORA_ERR_MAC_COMMANDS_IN_FOPTS_AND_PAYLOAD = -5,
    /* FType is not a data frame, [TS001-1.0.4] §4.2.1 Table 4. */
    LORA_ERR_NOT_DATA_FRAME = -6,
    /* Major is RFU, [TS001-1.0.4] §4.2.2 Table 5. */
    LORA_ERR_UNSUPPORTED_MAJOR = -7,
    /* Low 16 bits of the counter differ from FCnt, [TS001-1.0.4] §4.3.1.5. */
    LORA_ERR_FCNT_MISMATCH = -8,
    /* len(msg) does not fit B0, [TS001-1.0.4] §4.4 Table 13. */
    LORA_ERR_TOO_LONG = -9,
    /* Output buffer too small. */
    LORA_ERR_NO_SPACE_LEFT = -10,
    /* MIC does not match, [TS001-1.0.4] §4.4. */
    LORA_ERR_AUTHENTICATION_FAILED = -11
} lora_status;

/* Frame direction. The value is the Dir field of the A_i and B0 blocks,
 * [TS001-1.0.4] §4.3.3 Table 12 and §4.4 Table 13. */
typedef enum lora_direction {
    LORA_UPLINK = 0,
    LORA_DOWNLINK = 1
} lora_direction;

/* Regional plans of [RP002-1.0.5] §3. CN779-787 is deprecated (§3.6). */
typedef enum lora_region {
    LORA_REGION_EU863_870 = 0, /* §3.4 */
    LORA_REGION_US902_928 = 1, /* §3.5 */
    LORA_REGION_EU433 = 2,     /* §3.7 */
    LORA_REGION_AU915_928 = 3, /* §3.8 */
    LORA_REGION_CN470_510 = 4, /* §3.9 */
    LORA_REGION_AS923 = 5,     /* §3.10, groups AS923-1 to AS923-4 */
    LORA_REGION_KR920_923 = 6, /* §3.11 */
    LORA_REGION_IN865 = 7,     /* §3.12 */
    LORA_REGION_RU864_870 = 8  /* §3.13 */
} lora_region;

/* Flags for lora_max_mac_payload_len. 0 selects the defaults. */
/* Use the "not repeater compatible" tables, [RP002-1.0.5] §4.1. */
#define LORA_REGION_NOT_REPEATER_COMPATIBLE (1u << 0)
/* UplinkDwellTime = 1 (400 ms). AS923 and AU915-928 only. */
#define LORA_REGION_UPLINK_DWELL_TIME (1u << 1)
/* DownlinkDwellTime = 1 (400 ms). AS923 only. An AS923 end-device checking
 * received downlinks SHALL leave this unset, [RP002-1.0.5] §3.10.6. */
#define LORA_REGION_DOWNLINK_DWELL_TIME (1u << 2)

/*
 * Maximum MACPayload length M, [RP002-1.0.5] §3.x.6. A frame whose
 * MACPayload exceeds M SHALL NOT be sent and SHALL be silently discarded on
 * receive, [TS001-1.0.4] §4.1.
 *
 * Returns M (1..255), 0 if the data rate is not defined for this region,
 * direction and flags, or LORA_ERR_INVALID_ARGUMENT.
 */
int lora_max_mac_payload_len(lora_region region, lora_direction dir, unsigned dr, uint32_t flags);

/*
 * Smallest 32-bit frame counter above `last` whose low 16 bits equal
 * `received`. With has_last false the upper 16 bits are taken as 0.
 * The result is a candidate only. Accept it after the MIC verifies.
 * This strategy is a choice of this library, TS001-1.0.4 gives none,
 * [TS001-1.0.4] §4.3.1.5 (note) and §17.5.
 *
 * Returns true and writes *out if a candidate fits in 32 bits.
 */
bool lora_fcnt_infer(bool has_last, uint32_t last, uint16_t received, uint32_t *out);

/*
 * Data frames, [TS001-1.0.4] §4.
 *
 * Pointers paired with a length may be NULL when the length is 0.
 * Join-Request and Join-Accept frames (§6.2) are not handled.
 */

/* Frame type, values as in [TS001-1.0.4] §4.2.1 Table 4. */
typedef enum lora_ftype {
    LORA_FTYPE_JOIN_REQUEST = 0,
    LORA_FTYPE_JOIN_ACCEPT = 1,
    LORA_FTYPE_UNCONFIRMED_DATA_UP = 2,
    LORA_FTYPE_UNCONFIRMED_DATA_DOWN = 3,
    LORA_FTYPE_CONFIRMED_DATA_UP = 4,
    LORA_FTYPE_CONFIRMED_DATA_DOWN = 5,
    LORA_FTYPE_RFU = 6,
    LORA_FTYPE_PROPRIETARY = 7
} lora_ftype;

/* Frame control, [TS001-1.0.4] §4.3.1 Table 7 (downlink) and Table 8
 * (uplink). Fields of the other direction SHALL be false on encode
 * (LORA_ERR_INVALID_ARGUMENT otherwise) and are false after parse.
 * FOptsLen is derived from fopts_len. */
typedef struct lora_fctrl {
    bool adr;         /* §4.3.1.1 */
    bool adr_ack_req; /* §4.3.1.1, uplink only */
    bool ack;         /* §4.3.1.2 */
    bool class_b;     /* §4.3.1.7, uplink only */
    bool fpending;    /* §4.3.1.4, downlink only */
} lora_fctrl;

typedef struct lora_session_keys {
    uint8_t nwk_s_key[16];
    uint8_t app_s_key[16];
} lora_session_keys;

/* Input to lora_phy_encode. */
typedef struct lora_data_frame {
    lora_ftype ftype;   /* one of the four data frame types */
    uint32_t dev_addr;
    lora_fctrl fctrl;
    /* Full 32-bit FCntUp or FCntDown. Its low 16 bits are sent in FCnt and
     * all 32 bits enter A_i and B0, [TS001-1.0.4] §4.3.1.5. */
    uint32_t fcnt;
    const uint8_t *fopts; /* 0..15 octets, sent unencrypted, §4.3.1.6 */
    size_t fopts_len;
    bool has_fport;       /* SHALL be true if payload_len > 0, §4.3.2 */
    uint8_t fport;
    const uint8_t *payload; /* plaintext FRMPayload, encrypted per §4.3.3 */
    size_t payload_len;
} lora_data_frame;

/* Output of lora_phy_parse. Offsets index into the parsed frame buffer. */
typedef struct lora_parsed_frame {
    lora_ftype ftype;
    lora_direction dir;
    uint32_t dev_addr;
    lora_fctrl fctrl;
    uint16_t fcnt;          /* low 16 bits only, §4.3.1.5 */
    size_t fopts_offset;
    size_t fopts_len;
    bool has_fport;
    uint8_t fport;
    size_t payload_offset;  /* FRMPayload, still encrypted */
    size_t payload_len;
    uint8_t mic[4];
} lora_parsed_frame;

/*
 * Builds MHDR | MACPayload | MIC, [TS001-1.0.4] §4.1 Table 2. Encrypts the
 * payload with NwkSKey (FPort 0) or AppSKey (FPort 1..255), Table 11, then
 * computes the MIC with NwkSKey, §4.4. Writes the frame length to *out_len.
 */
lora_status lora_phy_encode(const lora_data_frame *frame, const lora_session_keys *keys,
                            uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * Splits a data frame into its fields. Does no cryptography, so the result
 * is not authenticated until lora_verify_mic succeeds.
 */
lora_status lora_phy_parse(const uint8_t *frame, size_t len, lora_parsed_frame *out);

/*
 * Checks the MIC with the full 32-bit counter, [TS001-1.0.4] §4.4. Returns
 * LORA_OK if it matches and LORA_ERR_AUTHENTICATION_FAILED if not. The
 * counter's low 16 bits SHALL equal FCnt (LORA_ERR_FCNT_MISMATCH otherwise).
 * Parses `frame` itself.
 */
lora_status lora_verify_mic(const uint8_t *frame, size_t len, const uint8_t nwk_s_key[16],
                            uint32_t fcnt);

/*
 * Decrypts FRMPayload into `out`, [TS001-1.0.4] §4.3.3. Call only after
 * lora_verify_mic returned LORA_OK. Writes the length to *out_len.
 */
lora_status lora_decrypt_payload(const uint8_t *frame, size_t len, const lora_session_keys *keys,
                                 uint32_t fcnt, uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* LORA_H */
