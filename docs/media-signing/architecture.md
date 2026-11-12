# Media signing architecture

> **Status: REFERENCE** · Last verified: 2026-11-12
> As-built description of how `MediaSigningService` fits into xKey and the auto-sign flow.

## Service Layer

### MediaSigningService

Foreground service that monitors `MediaStore` via `ContentObserver` for new
photos and videos. When new media is detected, it computes a SHA-256 hash,
signs it with the configured key via `KeystoreManager.signWithAlgorithm()`,
and embeds the signature in the file using `XmpMetadataHelper`: EXIF
`UserComment` for JPEG, an XMP box or chunk for MP4/MOV, PNG and WebP
(`XmpContainers`). HEIC, MKV, unknown types, a file the embed refuses and one
above the embed bound (`XmpMetadataHelper.maxEmbedBytes`, hashed by streaming)
get a `<name>.xkeysig` sidecar, and readers fall back to a sidecar, so files
signed before embedding still verify. Embedded writes go through a unique,
exclusively created staging file, serialized per path. See
[engineering.md](engineering.md#mp4--mov-png-webp-embedded-xmp).

- Foreground service type: `dataSync`
- Notification channel: `media_signing_channel`
- Controlled by `MediaSigningSettings.autoSignEnabled`

## Activity to Service Communication

### SettingsActivity to MediaSigningService

| Mechanism | Direction | Purpose |
|-----------|-----------|---------|
| `startForegroundService()` | Activity -> Service | Start auto-signing |
| `stopService()` | Activity -> Service | Stop auto-signing |
| `MediaSigningSettingsRepository` | Shared | Settings read by both |

## MediaSigningService to ContentObserver

```mermaid
sequenceDiagram
    participant Camera
    participant MS as MediaStore
    participant CO as ContentObserver
    participant Svc as MediaSigningService
    participant KM as KeystoreManager
    participant XMP as XmpMetadataHelper

    Camera->>MS: Insert new photo
    MS->>CO: onChange(uri)
    CO->>Svc: handleNewMedia(uri, "image")
    Note over Svc: delay(500ms) for file write completion
    Svc->>MS: Query file path from URI
    Svc->>Svc: Hash content via MediaHasher
    Svc->>KM: signWithAlgorithm(keyId, hash, alg)
    KM-->>Svc: Signature bytes
    Svc->>XMP: writeSignature(filePath, data)
```

## Data Flow: Auto-Sign Media

```mermaid
graph LR
    A[Camera] -->|New photo| B[MediaStore]
    B -->|onChange| C[ContentObserver]
    C -->|URI| D[MediaSigningService]
    D -->|Hash| E[MediaHasher]
    E -->|Hash bytes| F[KeystoreManager]
    F -->|In hardware| G[Android Keystore]
    G -->|Signature| F
    F -->|Signature| D
    D -->|Write EXIF/XMP| H[XmpMetadataHelper]
    D -->|Log| I[AuditLogger]
```

## Auto-Sign a Photo

The user takes a photo with the system camera. The `MediaSigningService`
detects the new media and automatically signs it in the background.

```mermaid
sequenceDiagram
    actor User
    participant Camera as Camera App
    participant MS as MediaStore
    participant Svc as MediaSigningService
    participant MH as MediaHasher
    participant KM as KeystoreManager
    participant HW as TEE / StrongBox
    participant XMP as XmpMetadataHelper

    Note over User,Svc: Precondition: Auto-sign enabled in Settings

    User->>Camera: Take photo
    Camera->>MS: Save JPEG to MediaStore

    MS->>Svc: ContentObserver.onChange(uri)
    Note over Svc: Debounce: wait 500ms

    Svc->>Svc: Check settings (autoSignEnabled = true)
    Svc->>Svc: Check media type (signPhotos = true)
    Svc->>Svc: Get signingKeyId from settings

    Svc->>MH: hashUri(contentResolver, uri)
    Note over MH: Streaming SHA-256
    MH-->>Svc: Content hash

    Svc->>KM: signWithAlgorithm(keyId, hashBytes, algorithm)
    KM->>HW: Sign in hardware (no biometric -- key has authDuration < 0)
    HW-->>KM: Signature bytes
    KM-->>Svc: Signature

    Svc->>Svc: Build SignatureEntry (role=CREATOR)
    Svc->>Svc: Build ContentAuthenticityData

    Svc->>MS: Query file path from URI
    Svc->>XMP: writeSignature(filePath, data)
    Note over XMP: JPEG: EXIF TAG_USER_COMMENT<br/>MP4/MOV, PNG, WebP: XMP box or chunk

    Note over User: User opens photo later in Verified Viewer<br/>and sees green verification badge
```
