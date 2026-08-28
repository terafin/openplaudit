# PLAUD Note NB100 BLE Protocol Notes (verified on firmware 2.2)

These are the byte-level findings that make `plaude sync` work. They were
reverse-engineered live against a PLAUD Note model **NB100** (serial
`88831807738023788B`, firmware 2.2) and verified end-to-end: auth, file list,
download to WAV, `afinfo`/`afplay`.

## Connection & auth (portVersion >= 20, project 888)

1. **Service/characteristics**
   - Service: `0x1910`
   - RX (host → device): `0x2BB1` (write)
   - TX (device → host): `0x2BB0` (notify)

2. **RSA pre-handshake** — required before the main handshake:
   - Send SN signature in chunks: opcode `0xFE20`, frame
     `[opcode:2][count:1][index:1][chunk:100B]`.
   - Wait for `0xFE11` confirm (`11 fe 00`).
   - Send user RSA public key in chunks: opcode `0xFE12` (same framing).
   - Device returns `3x 0xFE12` chunks: `[fe 12][count:1][index:1][data...]`.
     Strip the 4-byte header per chunk, concatenate, and RSA-PKCS1v15-decrypt
     with the user private key. Result: `[key:32][nonce:12][ad:12][ChaCha20
     ciphertext]`. Decrypt the ciphertext with those key/nonce/ad and verify it
     is `b"PLAUD.AI"`.

3. **ChaCha20-Poly1305 (IETF) session**:
   - `send_counter` starts at 1 and is incremented BEFORE each encryption, so
     the first encrypted packet uses counter=2.
   - Plaintext = `[counter LE:4] + command_frame`. Counter is INSIDE the
     encryption.
   - On receive: decrypt, then strip the first 4 bytes (the counter).

4. **Main handshake** (encrypted): `[0x01][cmd 0x01 LE] + MTU_INDICATOR
   (02 00) + portVersion byte (20) + bindToken (32 bytes, zero-padded)`.
   - Response status is at **frame[3]** (payload[0]); portVersion at frame[4:6].
   - status 0 = SUCCESS.

5. **Two-handshake (v20+)**: after the main handshake, the device pushes its
   SSN as cmd `0x02` (null-terminated string at frame[3]). The host replies
   with the same handshake frame plus the 8-byte zero-padded SSN.

## Commands

| cmd | name | payload |
|-----|------|---------|
| 0x01 | HANDSHAKE | token/SSN |
| 0x02 | GET_SSN | — |
| 0x03 | GET_STATE | — (resp: state=payload[0], 1=idle 3=recording) |
| 0x04 | TIME_SYNC | `[unix:4]` |
| 0x05 | RECORD_SWITCH | `[0/1]` |
| 0x1A | GET_REC_SESSIONS | `[ts:4][ts:4][flag:1]` |
| 0x1C | SYNC_FILE_HEAD | `[sessionId:4][startPos:4][fileSize:4]` |
| 0x1D | SYNC_FILE_TAIL | (device pushes as EOF signal) |
| 0x1E | SYNC_FILE_STOP | `[sessionId:4]` |

> **cmd 0x14 is the RECORD command** (`[1][scene]` start / `[0][1]` stop). It is
> NEVER used for file sync. There is NO "prepare" command — do not send 0x14
> during a download or the device starts recording (red light).

## File listing (GET_REC_SESSIONS 0x1A)

Request `[ts:4][ts:4][flag:1]`. Response:
`[type:1][cmd:2][ts:4][total:2 LE][entries...]` where entries (portVersion>=20)
are **10 bytes each**: `[session_id:4][file_size:4][file_type:1][file_index:1]`,
starting at frame offset 11 (payload offset 8).

The device returns no response (or total=0) **while recording** (state=3); it
answers when idle (state=1). Session IDs are unix timestamps.

## File download

```
-> cmd 0x1C SYNC_FILE_HEAD [sessionId:4][startPos:4][fileSize:4]
<- cmd 0x1C response   (confirm)
<- data packets  (type 0x02) until EOF
<- cmd 0x1D SYNC_FILE_TAIL  (EOF)
-> cmd 0x1E SYNC_FILE_STOP [sessionId:4]
```

Data packet layout: `[type:1][session_id:4][offset:4][chunk_len:1][data:chunk_len]`.
- **chunk_len is a single byte** (0x50 = 80 bytes). Reading it as 2 bytes
  mis-slices data and produces "offset mismatch: expected N, got N+79".
- The offset advances by exactly `chunk_len` each packet. There is **no**
  length-16 field.
- EOF is signalled by `SYNC_FILE_TAIL` (cmd 0x1D) or a data packet with offset
  `0xFFFFFFFF`.

`startPos` is honored: sending a nonzero startPosition resumes from a previous
offset (useful after a BLE drop).

## Device behavior notes

- The device sleeps aggressively; it must be woken (single tap on the Record
  button) before it advertises, and it drops connections mid-large-transfer.
- Resume: reconnect → handshake → re-issue SYNC_FILE_HEAD with the last offset.
- `plaude sync` writes partials to the raw path so a killed run is resumable.
- There is **no BLE delete-file command** in the SDK (checked: cmd 120/123/124
  are not per-file deletes). Deletion is done in the official app.
