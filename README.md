# LoRaWAN® library for Zig and C

A small Zig library for encoding and decoding LoRaWAN® 1.0.4 data frames, with a C API.

It builds and parses the PHYPayload of data frames (MHDR, FHDR, FPort, FRMPayload and MIC) as defined in TS001-1.0.4 §4. It encrypts FRMPayload with AES-128 (§4.3.3) and computes and checks the MIC with AES-CMAC (§4.4). Parsing does no cryptography and allocates nothing. The decoded fields borrow from the input buffer, and MIC verification and decryption are separate steps that run once the receiver knows the full 32-bit frame counter. Over-the-air activation is covered as well: Join-Request and Join-Accept frames and session key derivation (§6.2). MAC command parsing (§5) is not implemented yet.

Two helpers sit next to the frame code and are never called by it. `fcnt.infer` reconstructs the 32-bit frame counter from the 16-bit FCnt field. TS001-1.0.4 leaves that algorithm open (§4.3.1.5), so it is a default you can replace with your own. `region.maxMacPayloadLen` returns the maximum MACPayload size M for every regional plan in RP002-1.0.5, including the repeater compatible and dwell time variants, so callers can apply the length rule of TS001-1.0.4 §4.1.

The C API in `include/lora.h` covers the same frame level workflow: `lora_phy_encode`, `lora_phy_parse`, `lora_verify_mic`, `lora_decrypt_payload`, `lora_fcnt_infer` and `lora_max_mac_payload_len`. Functions return a `lora_status` code, buffers are passed as pointer and length, and parsed fields are reported as offsets into the caller's buffer. A test checks that the header and the Zig implementation agree on every struct layout and constant. The C library was added mostly because Zig makes it easy. I only use the Zig library myself, so the C API gets less real-world testing.

Code comments cite the section, table or appendix each rule comes from. Test vectors for the crypto primitives come from the specifications themselves (FIPS-197 Appendix B, RFC 4493 §4), and frame layout tests are built from the TS001-1.0.4 tables.

## Building

The development shell provides Zig 0.17.1.

```sh
nix develop
zig build test   # Zig tests, C ABI checks and a C test program
zig build        # liblora (static and shared) and include/lora.h in zig-out/
```

From Zig, import the `lora` module and start at `phy_payload.encode` and `phy_payload.parse`.

## References

- [TS001-1.0.4] LoRa Alliance, *LoRaWAN L2 1.0.4 Specification*, October 2020. https://resources.lora-alliance.org/home/ts001-1-0-4-lorawan-l2-1-0-4-specification
- [Errata-L2-1.0.4-D2D] LoRa Alliance, *ERRATA Allow Downlink Transmissions*, Revision 1, 2022-10-17. https://resources.lora-alliance.org/home/errata-l2-1-0-4-d2d
- [RP002-1.0.5] LoRa Alliance, *LoRaWAN Regional Parameters RP002-1.0.5*. https://resources.lora-alliance.org/home/rp002-1-0-5-lorawan-regional-parameters
- [RFC4493] Song, JH., Poovendran, R., Lee, J., and T. Iwata, *The AES-CMAC Algorithm*, RFC 4493, June 2006. https://www.rfc-editor.org/rfc/rfc4493
- [FIPS-197] NIST, *Advanced Encryption Standard (AES)*, FIPS 197, updated May 9, 2023. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

## License

MIT, see [LICENSE](LICENSE). The built libraries also contain compiled code from the Zig standard library, which is MIT licensed by its authors.

LoRa® and LoRaWAN® are registered trademarks or service marks of Semtech Corporation or its affiliates. This project is not affiliated with or certified by Semtech or the LoRa Alliance.
