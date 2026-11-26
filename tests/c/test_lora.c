/* Exercises include/lora.h against the built library. */
#include <stdio.h>

#include "lora.h"

static int failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                   \
        }                                                                 \
    } while (0)

static void test_max_mac_payload_len(void) {
    /* [RP002-1.0.5] §3.4.6 Table 15 and Table 16. */
    CHECK(lora_max_mac_payload_len(LORA_REGION_EU863_870, LORA_UPLINK, 5, 0) == 230);
    CHECK(lora_max_mac_payload_len(LORA_REGION_EU863_870, LORA_UPLINK, 5, LORA_REGION_NOT_REPEATER_COMPATIBLE) == 250);
    CHECK(lora_max_mac_payload_len(LORA_REGION_EU863_870, LORA_UPLINK, 14, 0) == 0);
    /* [RP002-1.0.5] §3.5.6 Table 24, downlink DR0. */
    CHECK(lora_max_mac_payload_len(LORA_REGION_US902_928, LORA_DOWNLINK, 0, 0) == 230);
    /* [RP002-1.0.5] §3.10.6 Table 72, DwellTime = 1. */
    CHECK(lora_max_mac_payload_len(LORA_REGION_AS923, LORA_UPLINK, 2, LORA_REGION_UPLINK_DWELL_TIME) == 19);
    /* Every region value in the header is accepted. */
    for (int r = LORA_REGION_EU863_870; r <= LORA_REGION_RU864_870; r++) {
        CHECK(lora_max_mac_payload_len((lora_region)r, LORA_UPLINK, 0, 0) >= 0);
    }
    CHECK(lora_max_mac_payload_len((lora_region)9, LORA_UPLINK, 0, 0) == LORA_ERR_INVALID_ARGUMENT);
    CHECK(lora_max_mac_payload_len(LORA_REGION_EU863_870, LORA_UPLINK, 16, 0) == LORA_ERR_INVALID_ARGUMENT);
}

static void test_fcnt_infer(void) {
    uint32_t v = 0;
    CHECK(lora_fcnt_infer(false, 0, 5, &v) && v == 5);
    CHECK(lora_fcnt_infer(true, 0x0003FFFFu, 0x0000, &v) && v == 0x00040000u);
    CHECK(!lora_fcnt_infer(true, 0xFFFFFFFFu, 0xFFFF, &v));
    CHECK(!lora_fcnt_infer(false, 0, 0, NULL));
}

static const lora_session_keys keys = {
    .nwk_s_key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    .app_s_key = {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF},
};

static void test_frame_roundtrip(void) {
    const uint8_t payload[] = {'h', 'e', 'l', 'l', 'o'};
    lora_data_frame f = {
        .ftype = LORA_FTYPE_CONFIRMED_DATA_DOWN,
        .dev_addr = 0x01020304u,
        .fctrl = {.ack = true, .fpending = true},
        .fcnt = 0x00050007u,
        .has_fport = true,
        .fport = 42,
        .payload = payload,
        .payload_len = sizeof payload,
    };
    uint8_t buf[64];
    size_t n = 0;
    CHECK(lora_phy_encode(&f, &keys, buf, sizeof buf, &n) == LORA_OK);
    /* Table 2: MHDR (1) | FHDR (7) | FPort (1) | FRMPayload (5) | MIC (4). */
    CHECK(n == 18);
    /* MHDR 0xA0 (Table 3, FType 101), DevAddr little endian, FCtrl ACK and
     * FPending (Table 7), FCnt 0x0007, FPort 42. */
    const uint8_t clear[] = {0xA0, 0x04, 0x03, 0x02, 0x01, 0x30, 0x07, 0x00, 42};
    for (size_t i = 0; i < sizeof clear; i++) CHECK(buf[i] == clear[i]);

    lora_parsed_frame p;
    CHECK(lora_phy_parse(buf, n, &p) == LORA_OK);
    CHECK(p.ftype == LORA_FTYPE_CONFIRMED_DATA_DOWN);
    CHECK(p.dir == LORA_DOWNLINK);
    CHECK(p.dev_addr == 0x01020304u);
    CHECK(p.fctrl.ack && p.fctrl.fpending && !p.fctrl.adr && !p.fctrl.class_b);
    CHECK(p.fcnt == 0x0007);
    CHECK(p.fopts_len == 0);
    CHECK(p.has_fport && p.fport == 42);
    CHECK(p.payload_offset == 9 && p.payload_len == 5);
    for (int i = 0; i < 4; i++) CHECK(p.mic[i] == buf[n - 4 + (size_t)i]);

    CHECK(lora_verify_mic(buf, n, keys.nwk_s_key, 0x00050007u) == LORA_OK);
    CHECK(lora_verify_mic(buf, n, keys.nwk_s_key, 0x00040007u) == LORA_ERR_AUTHENTICATION_FAILED);
    CHECK(lora_verify_mic(buf, n, keys.nwk_s_key, 0x00050008u) == LORA_ERR_FCNT_MISMATCH);

    uint8_t plain[16];
    size_t plain_len = 0;
    CHECK(lora_decrypt_payload(buf, n, &keys, 0x00050007u, plain, sizeof plain, &plain_len) == LORA_OK);
    CHECK(plain_len == sizeof payload);
    for (size_t i = 0; i < sizeof payload; i++) CHECK(plain[i] == payload[i]);

    buf[9] ^= 0x01; /* tamper with FRMPayload */
    CHECK(lora_verify_mic(buf, n, keys.nwk_s_key, 0x00050007u) == LORA_ERR_AUTHENTICATION_FAILED);
}

static void test_frame_errors(void) {
    uint8_t buf[64];
    size_t n = 0;
    lora_data_frame f = {.ftype = LORA_FTYPE_UNCONFIRMED_DATA_UP, .fctrl = {.fpending = true}};
    CHECK(lora_phy_encode(&f, &keys, buf, sizeof buf, &n) == LORA_ERR_INVALID_ARGUMENT);
    f.fctrl.fpending = false;
    f.ftype = LORA_FTYPE_JOIN_REQUEST;
    CHECK(lora_phy_encode(&f, &keys, buf, sizeof buf, &n) == LORA_ERR_NOT_DATA_FRAME);
    f.ftype = LORA_FTYPE_UNCONFIRMED_DATA_UP;
    const uint8_t one = 1;
    f.payload = &one;
    f.payload_len = 1;
    CHECK(lora_phy_encode(&f, &keys, buf, sizeof buf, &n) == LORA_ERR_MISSING_FPORT);
    f.payload_len = 0;
    f.fopts = &one;
    f.fopts_len = 1;
    f.has_fport = true;
    f.fport = 0;
    CHECK(lora_phy_encode(&f, &keys, buf, sizeof buf, &n) == LORA_ERR_MAC_COMMANDS_IN_FOPTS_AND_PAYLOAD);
    const uint8_t sixteen[16] = {0};
    f.fopts = sixteen;
    f.fopts_len = sizeof sixteen;
    f.fport = 1;
    CHECK(lora_phy_encode(&f, &keys, buf, sizeof buf, &n) == LORA_ERR_FOPTS_TOO_LONG);
    f.fopts = NULL;
    f.fopts_len = 0;
    CHECK(lora_phy_encode(&f, &keys, buf, 11, &n) == LORA_ERR_NO_SPACE_LEFT);
    lora_parsed_frame p;
    CHECK(lora_phy_parse(buf, 11, &p) == LORA_ERR_TRUNCATED);
}

static void test_join(void) {
    const uint8_t app_key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t buf[64];
    size_t n = 0;

    /* Join-Request, [TS001-1.0.4] §6.2.5 Table 53. */
    const lora_join_request req = {.join_eui = 0x0102030405060708u, .dev_eui = 0x1112131415161718u, .dev_nonce = 0x2122};
    CHECK(lora_join_request_encode(&req, app_key, buf, sizeof buf, &n) == LORA_OK);
    CHECK(n == LORA_JOIN_REQUEST_LEN);
    CHECK(buf[0] == 0x00 && buf[1] == 0x08 && buf[8] == 0x01 && buf[17] == 0x22 && buf[18] == 0x21);
    lora_join_request req_out;
    CHECK(lora_join_request_parse(buf, n, &req_out) == LORA_OK);
    CHECK(req_out.join_eui == req.join_eui && req_out.dev_eui == req.dev_eui && req_out.dev_nonce == req.dev_nonce);
    CHECK(lora_join_request_verify_mic(buf, n, app_key) == LORA_OK);
    buf[18] ^= 1;
    CHECK(lora_join_request_verify_mic(buf, n, app_key) == LORA_ERR_AUTHENTICATION_FAILED);
    CHECK(lora_join_request_parse(buf, n - 1, &req_out) == LORA_ERR_INVALID_LENGTH);

    /* Join-Accept, [TS001-1.0.4] §6.2.6 Table 54. */
    const lora_join_accept acc = {
        .join_nonce = 0x010203u,
        .net_id = 0x111213u,
        .dev_addr = 0x21222324u,
        .rx1_dr_offset = 2,
        .rx2_data_rate = 3,
        .rx_delay = 5,
    };
    CHECK(lora_join_accept_encode(&acc, app_key, buf, sizeof buf, &n) == LORA_OK);
    CHECK(n == LORA_JOIN_ACCEPT_MIN_LEN);
    CHECK(buf[0] == 0x20);
    lora_join_accept acc_out;
    CHECK(lora_join_accept_decrypt(buf, n, app_key, &acc_out) == LORA_OK);
    CHECK(acc_out.join_nonce == acc.join_nonce && acc_out.net_id == acc.net_id && acc_out.dev_addr == acc.dev_addr);
    CHECK(acc_out.rx1_dr_offset == 2 && acc_out.rx2_data_rate == 3 && acc_out.rx_delay == 5 && !acc_out.has_cf_list);
    buf[3] ^= 1;
    CHECK(lora_join_accept_decrypt(buf, n, app_key, &acc_out) == LORA_ERR_AUTHENTICATION_FAILED);
    lora_join_accept bad = acc;
    bad.net_id = 1u << 24;
    CHECK(lora_join_accept_encode(&bad, app_key, buf, sizeof buf, &n) == LORA_ERR_INVALID_ARGUMENT);

    /* Session keys, then a first uplink with them, [TS001-1.0.4] §6.2.6. */
    lora_session_keys keys;
    CHECK(lora_derive_session_keys(app_key, acc.join_nonce, acc.net_id, req.dev_nonce, &keys) == LORA_OK);
    const uint8_t payload[] = {'o', 'k'};
    lora_data_frame f = {
        .ftype = LORA_FTYPE_UNCONFIRMED_DATA_UP,
        .dev_addr = acc.dev_addr,
        .has_fport = true,
        .fport = 1,
        .payload = payload,
        .payload_len = sizeof payload,
    };
    CHECK(lora_phy_encode(&f, &keys, buf, sizeof buf, &n) == LORA_OK);
    CHECK(lora_verify_mic(buf, n, keys.nwk_s_key, 0) == LORA_OK);
    CHECK(lora_derive_session_keys(app_key, 1u << 24, 0, 0, &keys) == LORA_ERR_INVALID_ARGUMENT);
}

int main(void) {
    test_max_mac_payload_len();
    test_fcnt_infer();
    test_frame_roundtrip();
    test_frame_errors();
    test_join();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
