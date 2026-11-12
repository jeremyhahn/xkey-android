# Co-signing architecture

> **Status: REFERENCE** · Last verified: 2026-11-12
> As-built description of the co-sign message extension and the co-sign flows in xKey.

## Message Types

### Co-Sign Extension

| Method | Description | Parameters |
|--------|-------------|------------|
| `cosign.request` | Request co-signature from connected device | `hash` (hex), `hashAlgorithm` (default `SHA-256`), `keyId` (optional), `from` |
| `cosign.response` | Return co-signature to initiator | `signature` (base64), `keyFingerprint`, `signerName`, `algorithm` |

### Handling `cosign.request` on the phone

`cosign.request` is in the shared dispatch map, so every transport reaches the
same handler (`RequestHandler.handleCosignRequest`). It signs only after these
checks, in this order:

1. **Confirmed peer.** The session must have a confirmed peer identity; an
   anonymous session cannot ask the owner to vouch for anything.
2. **Whole digest.** `hashAlgorithm` must be `SHA-256`, `SHA-384` or
   `SHA-512`, and `hash` must decode to exactly its digest length (32, 48 or
   64 bytes). A truncated or padded value is refused, never signed as
   whatever it decodes to.
3. **Signing keys only.** A named `keyId` must be a `signing` key; any other
   type, a FIDO2 credential included, is refused. Without `keyId` the phone
   takes the first stored `signing` key and never falls back to a FIDO2 key.
4. **Owner approval.** The phone shows a biometric prompt (with a
   notification when the screen is locked) whose subtitle names the first 8
   hex characters of the hash. It signs only when the owner approves; every
   co-signature prompts, with no session cache.

The success result is unchanged: `signature` (base64), `keyFingerprint`,
`algorithm` and `signerName`.

| Condition | Error |
|-----------|-------|
| No params, or empty `hash` | `INVALID_PARAMS` |
| No confirmed peer for the session | `OPERATION_DENIED` |
| Unknown `hashAlgorithm`, `hash` not hex, or wrong digest length | `INVALID_PARAMS` |
| Named `keyId` not found, or no stored signing key | `KEY_NOT_FOUND` |
| Named `keyId` is not a `signing` key (FIDO2 included) | `OPERATION_DENIED` |
| No approval prompt available, owner cancels, or authentication fails | `BIOMETRIC_FAILED` |
| Keystore signing fails after approval | `SIGNING_FAILED` |

## Data Flow: Co-Sign via BLE

```mermaid
graph LR
    A[CoSignActivity] -->|cosign.request| B[GattServer]
    B -->|Noise encrypt| C[NoiseSession]
    C -->|Fragment| D[BLE Transport]
    D -->|To desktop| E[Paired Device]
    E -->|cosign.response| D
    D -->|Reassemble| F[FragmentReassembler]
    F -->|Noise decrypt| C
    C -->|Response| B
    B -->|Signature| A
    A -->|Append| G[XmpMetadataHelper]
```

## Co-Sign a Photo via QR

Two people are at the same location. The photo owner wants the witness to
co-sign the photo to attest they were both present.

```mermaid
sequenceDiagram
    actor Owner
    participant OApp as Owner's xKey
    participant QR1 as Owner's QR Display
    participant WCam as Witness Camera
    participant WApp as Witness's xKey
    participant QR2 as Witness's QR Display
    participant OCam as Owner Camera

    Owner->>OApp: Open CoSignActivity, select signed photo
    OApp->>OApp: Read ContentAuthenticityData from EXIF
    OApp->>OApp: Extract content hash

    OApp->>QR1: Display QR code
    Note over QR1: {"v":1,"hash":"e3b0c4...",<br/>"alg":"SHA-256","from":"a1b2c3..."}

    actor Witness
    Witness->>WCam: Scan Owner's QR
    WCam->>WApp: Decoded QR payload

    WApp-->>Witness: "Sign content hash e3b0c4...?"
    Witness->>WApp: Approve

    WApp->>WApp: Sign hash with local key
    WApp->>QR2: Display response QR
    Note over QR2: {"v":1,"sig":"MEUCIQDx...",<br/>"fp":"f5e6d7...","name":"Bob","alg":"ES256"}

    Owner->>OCam: Scan Witness's QR
    OCam->>OApp: Decoded response QR

    OApp->>OApp: Build SignatureEntry (role=ATTESTOR)
    OApp->>OApp: Append to ContentAuthenticityData
    OApp->>OApp: Write updated data to EXIF

    OApp-->>Owner: "Co-signature from Bob added"
    Note over Owner: Photo now has 2 signatures:<br/>Creator (Owner) + Attestor (Bob)
```
