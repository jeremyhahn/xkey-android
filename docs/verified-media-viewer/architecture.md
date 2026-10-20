# Verified media viewer architecture

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of the verified media viewing flow in xKey.

## View Verified Media

A user opens a signed image to verify its authenticity and see who signed it.

```mermaid
sequenceDiagram
    actor User
    participant Gallery as Gallery / File Manager
    participant VMA as VerifiedMediaViewerActivity
    participant XMP as XmpMetadataHelper
    participant MH as MediaHasher
    participant KD as KeyDao
    participant CD as ContactDao

    User->>Gallery: Tap on image, select "Open with xKey"
    Gallery->>VMA: ACTION_VIEW with image URI

    VMA->>VMA: Display image (BitmapFactory with inSampleSize)

    VMA->>XMP: readSignatureFromUri(uri, "image/jpeg")
    XMP-->>VMA: ContentAuthenticityData (2 signatures)

    VMA->>MH: hashStream(image content)
    MH-->>VMA: Content hash

    Note over VMA: Process Signature 1 (Creator)
    VMA->>KD: getByPublicKeyFingerprint("a1b2c3...")
    KD-->>VMA: KeyEntity (own key "My Photo Key")
    VMA->>VMA: Verify signature against hash
    Note over VMA: Valid -- GREEN badge "My Photo Key (Creator)"

    Note over VMA: Process Signature 2 (Attestor)
    VMA->>KD: getByPublicKeyFingerprint("f5e6d7...")
    KD-->>VMA: null (not a local key)
    VMA->>CD: getByFingerprint("f5e6d7...")
    CD-->>VMA: ContactEntity (name="Bob")
    VMA->>VMA: Verify signature against hash
    Note over VMA: Valid -- GREEN badge "Bob (Attestor)"

    VMA-->>User: Image displayed with verification overlay
    Note over User: Two green badges showing:<br/>1. My Photo Key (Creator)<br/>2. Bob (Attestor)
```
