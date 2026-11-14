# Media Auto-Signing

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of `MediaSigningService`.

This document describes the `MediaSigningService`, which automatically signs
photos and videos as they are captured, embedding cryptographic signatures in
the file metadata for later verification.

## Service Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Stopped: Service not running

    Stopped --> Starting: Settings toggle ON
    Starting --> Observing: onStartCommand()
    Note right of Observing: ContentObservers registered<br/>Wake lock acquired<br/>Foreground notification shown

    Observing --> Signing: New media detected
    Signing --> Observing: Signature embedded
    Signing --> Observing: Error (logged, continues)

    Observing --> Stopped: Settings toggle OFF / onDestroy()
    Note right of Stopped: Observers unregistered<br/>Wake lock released
```

## Architecture

`MediaSigningService` is a foreground service that follows the same pattern as
`XKeyGattService`: foreground notification, wake lock, `START_STICKY` restart
policy, and `CoroutineScope(SupervisorJob() + Dispatchers.IO)` for async work.

### Components

| Component | Role |
|-----------|------|
| `MediaSigningService` | Foreground service lifecycle, ContentObserver registration |
| `ContentObserver` (image) | Observes `MediaStore.Images.Media.EXTERNAL_CONTENT_URI` |
| `ContentObserver` (video) | Observes `MediaStore.Video.Media.EXTERNAL_CONTENT_URI` |
| `MediaHasher` | Streaming SHA-256 hash of media content |
| `KeystoreManager` | Hardware-backed signing via `signWithAlgorithm()` |
| `XmpMetadataHelper` | Signature embedding in EXIF/XMP or sidecar file |
| `MediaSigningSettingsRepository` | DataStore-backed settings |
| `AuditLogger` | Logs `MEDIA_AUTO_SIGNED` events |

## ContentObserver Flow

```mermaid
sequenceDiagram
    participant Camera as Camera App
    participant MS as MediaStore
    participant Obs as ContentObserver
    participant Svc as MediaSigningService
    participant MH as MediaHasher
    participant KM as KeystoreManager
    participant XMP as XmpMetadataHelper
    participant AL as AuditLogger

    Camera->>MS: Write new photo/video
    MS->>Obs: onChange(selfChange, uri)
    Obs->>Svc: handleNewMedia(uri, mediaType)

    Note over Svc: Check if URI already processed

    Svc->>Svc: delay(500ms)
    Note over Svc: Wait for file to be fully written

    Svc->>Svc: Check settings (autoSignEnabled, signPhotos/Videos)
    Svc->>Svc: Get signing key ID from settings

    Svc->>MH: hashUri(contentResolver, uri)
    Note over MH: Streaming SHA-256 via DigestInputStream<br/>Handles large files without loading to memory
    MH-->>Svc: Hex hash string

    Svc->>KM: signWithAlgorithm(keyId, hashBytes, algorithm)
    Note over KM: Sign in Keystore hardware (TEE/StrongBox)
    KM-->>Svc: Signature bytes

    Svc->>KM: getPublicKeyDER(keyId)
    KM-->>Svc: Public key DER bytes
    Note over Svc: Compute key fingerprint = SHA-256(publicKeyDER)

    Svc->>Svc: Build SignatureEntry (role=CREATOR)
    Svc->>Svc: Build ContentAuthenticityData

    Svc->>Svc: getFilePathFromUri(uri)
    alt File path available
        Svc->>XMP: writeSignature(filePath, data)
    end

    Svc->>Svc: Add URI to processedUris set

    Svc->>AL: logMediaAutoSigned(keyId, label, uri)
```

### Deduplication

The service maintains an in-memory `Set<String>` of processed URIs to prevent
re-signing when `ContentObserver` fires multiple times for the same file.
The set is bounded to 1000 entries; when full, the oldest 500 are evicted.

### Debounce

A 500ms delay is applied after receiving a `ContentObserver` callback to ensure
the media file is fully written to disk before hashing. Without this delay,
the hash could be computed on an incomplete file.

## EXIF/XMP Embedding Strategy

Signature data is stored differently depending on the media format:

### JPEG

```
Method:  ExifInterface.setAttribute(TAG_USER_COMMENT, jsonString)
Format:  "XKEY_SIG:" + JSON-encoded ContentAuthenticityData
API:     ExifInterface (API 28+, reliable for TAG_USER_COMMENT)
```

The `TAG_USER_COMMENT` field supports arbitrary string data. A compact JSON
signature is approximately 500 bytes for a single signer and 5KB for 10
co-signers, well within EXIF limits.

The `XKEY_SIG:` prefix allows xKey to identify its own metadata and distinguish
it from other applications that may use the same EXIF field.

### MP4 / MOV, PNG, WebP: embedded XMP

The same JSON is embedded as an XMP packet (`XmpContainers`, pure byte-level
edits): one `rdf:Description` declaring
`xmlns:xkey="http://ns.automatethethings.com/xkey/media/1.0/"`, whose
`xkey:signature` element holds the XML-escaped JSON. A packet is xKey's when
it declares that namespace.

| Type | Where the packet goes |
|------|-----------------------|
| MP4, MOV (ISO BMFF) | Top-level `uuid` box, usertype `BE7ACFCB-97A9-42E8-9C71-999491E3AFAC`, appended after the last box so no `stco`/`co64` offset moves |
| PNG | Uncompressed `iTXt` chunk, keyword `XML:com.adobe.xmp`, just before `IEND`, with its CRC |
| WebP | RIFF `XMP ` chunk at the end, VP8X XMP flag (0x04) set, RIFF size updated; a simple (VP8/VP8L-only) file gets a VP8X with only that flag and the canvas size from the bitstream |

Rewriting replaces xKey's box or chunk; it never adds a second. The new bytes
go to a staging file beside the media, created exclusively under a unique
name for that write (`.<name>.<random>.xkeytmp`), which then replaces the
media by rename. Every write and append to one path is serialized, so two
signing jobs for the same capture never share or delete each other's staging
file, and the result is one job's complete output.

The canonical hash (`MediaHasher.canonicalContent`) leaves out exactly that
box or chunk and undoes what embedding changed (WebP: the XMP flag, a VP8X
whose flags are then 0, the RIFF size), so it is the file's hash as it was
before signing and survives every re-embed. A file without xKey's packet is
hashed whole, as before. In MP4/MOV only a trailing run of xKey boxes is left
out, the only place the writer puts one: sample offsets are absolute, so an
xKey box before any other box would shift the media they address. Such a file
is hashed whole, so its signature never verifies.

The automatic signer (`AutoSignHash.contentHashUri`) hashes these types in the
same canonical domain, so media that already carries an embedded signature (an
import, or a capture notified again after a restart) verifies once
`writeSignature` replaces the packet.

### Large media

An MP4/MOV, PNG or WebP with no XMP packet is embedded streaming
(`XmpContainers.embedFile`): only box and chunk headers are read into memory,
and the output is byte for byte what the in-memory `XmpContainers.embed`
returns, so a camera video of any size carries its signature in XMP, never a
sidecar. It is hashed whole by streaming; unsigned, its canonical hash is its
plain hash. Replacing a packet a file already carries is done in memory, about
three times over, so it is bounded by `XmpMetadataHelper.maxEmbedBytes` (128 MiB,
or a sixth of the heap when that is less); a larger file that already carries
an embedded signature is refused, keeping that signature.

### Sidecar fallback

```
Method:  Sidecar file (.xkeysig)
Format:  JSON file alongside the media file
Path:    <original_path>.xkeysig
```

A sidecar is written for HEIC, MKV and unknown types, and for an MP4/MOV, PNG
or WebP the embed refuses: bytes that do not parse, a foreign XMP packet
(never overwritten), an MP4 whose last box runs to the end of the file (size
0), a WebP whose VP8X has no flags, or a file above the embed bound (see Large
media). Files signed before embedding keep
their sidecar: it still reads, and `appendSignature` adds a co-signer to the
sidecar rather than moving the signature into the file.

### Read Priority

When reading signatures, `XmpMetadataHelper.readSignature()` checks in order:

1. EXIF `TAG_USER_COMMENT` (JPEG) or the embedded XMP packet (MP4/MOV, PNG,
   WebP)
2. Sidecar `.xkeysig` file (fallback for all formats)

`readSignatureFromUri()` reads the embedded form only (a URI has no sidecar
beside it); for MP4/MOV, PNG and WebP it walks the box or chunk headers and
skips every payload but the XMP one, so a video is never loaded whole.

## ContentAuthenticityData Schema

```json
{
    "version": 1,
    "contentHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "hashAlgorithm": "SHA-256",
    "signatures": [
        {
            "keyFingerprint": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
            "signerName": "My Photo Signing Key",
            "algorithm": "ES256",
            "value": "MEUCIQDxE9vVU3r7KnYm+B8r8r5w...",
            "timestamp": "2025-07-15T14:30:00.000Z",
            "role": "CREATOR"
        }
    ]
}
```

### Example: Multi-Signer (after co-signing)

```json
{
    "version": 1,
    "contentHash": "e3b0c44298fc1c149afbf4c8996fb924...",
    "hashAlgorithm": "SHA-256",
    "signatures": [
        {
            "keyFingerprint": "a1b2c3d4...",
            "signerName": "Alice (Camera Owner)",
            "algorithm": "ES256",
            "value": "MEUCIQD...",
            "timestamp": "2025-07-15T14:30:00.000Z",
            "role": "CREATOR"
        },
        {
            "keyFingerprint": "f5e6d7c8...",
            "signerName": "Bob",
            "algorithm": "ES384",
            "value": "MGQCMAE...",
            "timestamp": "2025-07-15T14:31:15.000Z",
            "role": "WITNESS"
        },
        {
            "keyFingerprint": "1a2b3c4d...",
            "signerName": null,
            "algorithm": "ES256",
            "value": "MEUCIBn...",
            "timestamp": "2025-07-15T15:00:00.000Z",
            "role": "ATTESTOR"
        }
    ]
}
```

## Settings Integration

`MediaSigningSettings` is managed via a DataStore repository following the
same pattern as `UsbHsmSettingsRepository`.

```kotlin
data class MediaSigningSettingsData(
    val autoSignEnabled: Boolean = false,
    val signingKeyId: String? = null,
    val signPhotos: Boolean = true,
    val signVideos: Boolean = true
)
```

### SettingsActivity Integration

The media signing section is built programmatically in `buildMediaSigningSection()`
within `SettingsActivity`, positioned between the Device Trust and Connectivity
sections. It includes:

- **Auto-sign toggle** (MaterialSwitch): Starts/stops `MediaSigningService`
- **Signing key selector** (Spinner): Populated from `KeyDao`, filtered to signing keys
- **Sign photos toggle**: Enable/disable photo auto-signing
- **Sign videos toggle**: Enable/disable video auto-signing

## Permissions

```xml
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"
    android:maxSdkVersion="32" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
```

## Service Declaration

```xml
<service android:name=".media.MediaSigningService"
    android:foregroundServiceType="dataSync"
    android:exported="false" />
```

## Notification

The service shows a persistent low-priority notification:

| Property | Value |
|----------|-------|
| Channel ID | `media_signing_channel` |
| Channel name | "xKey Media Signing" |
| Title | "xKey Media Signing" |
| Text | "Auto-signing active" |
| Priority | Low |
| Ongoing | Yes |
