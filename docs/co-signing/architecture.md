# Co-signing architecture

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of the co-sign message extension and the co-sign flows in xKey.

## Message Types

### Co-Sign Extension

| Method | Description | Parameters |
|--------|-------------|------------|
| `cosign.request` | Request co-signature from connected device | `hash`, `hashAlgorithm`, `initiatorFingerprint` |
| `cosign.response` | Return co-signature to initiator | `signature` (base64), `keyFingerprint`, `signerName`, `algorithm` |

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
