# eMRTD Reader — Development Tracking

## Status: Working on Device

## Completed

- [x] Project scaffolding (go.mod, Makefile, directory structure)
- [x] IPP protocol layer (copied from stamper — protocol.go, transport.go, reader.go)
- [x] BAC authentication (internal/bac/bac.go)
  - MRZ parsing (TD3 format, handles 88-char concatenated and 2-line formats)
  - Key derivation (SHA-1 + DES parity adjust)
  - Mutual authentication (GET CHALLENGE + EXTERNAL AUTHENTICATE)
  - Session key derivation (KSenc, KSmac, SSC)
- [x] Secure Messaging (internal/sm/sm.go)
  - APDU wrapping (DO87 encrypted data + DO97 Le + DO8E MAC)
  - RAPDU unwrapping (MAC verification + decryption)
  - 3DES-CBC with zero IV (BAC-specific, NOT SSC-derived IV which is for PACE)
  - ISO 9797-1 Algorithm 3 MAC (retail MAC)
  - SSC management with IncrementSSC for empty responses
- [x] eMRTD operations (internal/emrtd/)
  - SELECT eMRTD AID (A0000002471001)
  - Chunked file reading with secure messaging
  - DG1 parsing — MRZ field extraction
  - DG2 parsing — JPEG/JP2 face image extraction
  - Uses param_7=0x05 for SM APDUs (tells cVEND to forward response data)
- [x] Display (internal/display/)
  - Framebuffer rendering (800x480 BGRA)
  - Screens: booting, waiting for MRZ, waiting for card, authenticating, result, error
  - Passport data layout: surname first, given names, masked PII fields
  - JPEG face image decoded and rendered on right side of screen
- [x] Main entry point (cmd/emrtd/main.go)
  - CLI flags: -mrz, -port, -barcode
  - Barcode scanner input (serial read with timeout-based completion detection)
  - Watchdog + keepalive goroutines
  - Card detection loop with post-detect delay
  - 4-tone ascending startup beep
- [x] Cross-compilation verified (GOOS=linux GOARCH=arm GOARM=7)
- [x] Tested on device with real passport — DG1 + DG2 read successfully

## Key Discoveries During Development

- **SM encryption IV**: BAC uses zero IV, not E(KSenc, SSC) — the SSC-derived IV is only for PACE/AES
- **param_7=0x05**: SM APDUs must use param_7=0x05 (not 0x04) to tell the cVEND to forward SM response data (DO99+DO8E). Without bit 0 set, the cVEND drops response data.
- **SSC sync**: When SM response data is missing (e.g., SELECT EF with cVEND Le handling), must still increment SSC to stay in sync with passport
- **Le through proxy**: Non-zero Le values (e.g., 256) cause cVEND proxy error 50. Use Le=0 for all SM commands.

## To Test Further

- [ ] Barcode scanner MRZ QR code input
- [x] Display rendering quality check
- [x] Face image rendering on framebuffer
- [ ] Error handling: wrong MRZ, card removed mid-read
- [ ] Long-running stability

## Known Limitations

- BAC only (no PACE support)
- No TD1/TD2 MRZ format support (only TD3 passport)
- Face image may be JPEG2000 (not decodable by Go stdlib)
- Chunk size (224 bytes) is conservative
