# User Flows

This document provides end-to-end user flow diagrams for the major operations
in xKey, from user intent through system interaction to final result.

## Sign a File via Share Sheet

A user shares a document from any app (e.g., a file manager, email client,
or browser) and signs it with their xKey key.

```mermaid
sequenceDiagram
    actor User
    participant App as Any App
    participant Share as Android Share Sheet
    participant FOA as FileOperationActivity
    participant KS as Key Selector
    participant MH as MediaHasher
    participant KM as KeystoreManager
    participant HW as TEE / StrongBox
    participant XMP as XmpMetadataHelper
    participant SAF as System File Picker

    User->>App: Long-press file, tap Share
    App->>Share: ACTION_SEND with file URI
    Share-->>User: Show share targets
    User->>Share: Select "xKey"
    Share->>FOA: Launch with EXTRA_STREAM URI

    FOA-->>User: Show file info + operation selector
    User->>FOA: Select "Sign"
    FOA-->>User: Show key selector
    User->>KS: Choose signing key

    User->>FOA: Tap "Process"
    FOA->>MH: hashStream(file content)
    MH-->>FOA: SHA-256 hex hash

    FOA->>KM: signWithAlgorithm(keyId, hashBytes, "ES256")
    KM->>HW: Sign in hardware
    HW-->>KM: Signature bytes
    KM-->>FOA: DER-encoded signature

    alt Image or video file
        FOA->>XMP: writeSignature(filePath, data)
        XMP-->>FOA: Signature embedded in EXIF
        FOA-->>User: "File signed successfully"
    else Other file type
        FOA->>SAF: ACTION_CREATE_DOCUMENT (.xkeysig)
        SAF-->>User: Choose save location
        User->>SAF: Confirm save
        FOA-->>User: "Signature saved as .xkeysig"
    end
```

## Encrypt a File for a Recipient

A user encrypts a file so that only a specific recipient (whose public key
is stored as a contact) can decrypt it.

```mermaid
sequenceDiagram
    actor User
    participant App as Any App
    participant FOA as FileOperationActivity
    participant CD as Contact Selector
    participant FE as FileEncryptor
    participant KS as Android Keystore
    participant SAF as System File Picker

    User->>App: Share file to xKey
    App->>FOA: ACTION_SEND with file URI

    FOA-->>User: Show file info + operation selector
    User->>FOA: Select "Encrypt"
    FOA-->>User: Show recipient selector
    User->>CD: Choose recipient (from contacts)
    CD-->>FOA: ContactEntity with publicKeyDer

    User->>FOA: Tap "Process"

    FOA->>FE: encryptForRecipient(recipientPubKey, plaintext, output)

    Note over FE,KS: Generate ephemeral EC key in Keystore
    FE->>KS: KeyPairGenerator(P-256, PURPOSE_AGREE_KEY)
    KS-->>FE: Ephemeral key pair

    Note over FE,KS: ECDH in hardware
    FE->>KS: KeyAgreement(ephemeral, recipientPubKey)
    KS-->>FE: Shared secret

    Note over FE: HKDF-SHA256 -> AES-256 key
    Note over FE: AES-256-GCM streaming encrypt
    Note over FE: Delete ephemeral key

    FE-->>FOA: Encryption complete

    FOA->>SAF: ACTION_CREATE_DOCUMENT (.xkeyenc)
    SAF-->>User: Choose save location
    User->>SAF: Confirm save
    FOA-->>User: "File encrypted for [recipient name]"
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
    Note over XMP: Write to EXIF TAG_USER_COMMENT

    Note over User: User opens photo later in Verified Viewer<br/>and sees green verification badge
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

## Import a Contact via QR

A user scans another person's QR code to import their public key as a contact,
enabling file encryption and signature verification for that person.

```mermaid
sequenceDiagram
    actor User
    actor Other as Other Person
    participant OApp as Other's xKey
    participant QR as QR Code Display
    participant CMA as ContactManagementActivity
    participant Cam as QR Scanner (CameraX + ML Kit)
    participant DB as ContactDao

    Other->>OApp: Open Contact Management, tap "Export Key"
    OApp->>OApp: Select key to export
    OApp->>OApp: Get public key DER from KeystoreManager
    OApp->>QR: Display QR code
    Note over QR: {"v":1,"type":"xkey-pubkey",<br/>"name":"Other's Key",<br/>"alg":"ES256",<br/>"key":"MFkwEwYH..."}

    User->>CMA: Open Contact Management, tap FAB
    CMA-->>User: Import options bottom sheet
    User->>CMA: Select "Scan QR Code"
    CMA->>Cam: Open camera preview

    User->>Cam: Point at QR code
    Cam->>CMA: Decoded JSON string

    CMA->>CMA: Parse QR payload
    CMA->>CMA: Base64-decode public key
    CMA->>CMA: Compute SHA-256 fingerprint
    CMA-->>User: "Import 'Other's Key' (ES256)?"
    User->>CMA: Confirm import

    CMA->>DB: insert(ContactEntity)
    Note over DB: Unique index on fingerprint<br/>prevents duplicates

    CMA-->>User: "Contact imported successfully"

    Note over User: Can now encrypt files for this contact<br/>and verify their signatures
```

## Decrypt a File

A user receives an encrypted `.xkeyenc` file and decrypts it using their
encryption key.

```mermaid
sequenceDiagram
    actor User
    participant App as File Manager
    participant FOA as FileOperationActivity
    participant KS as Key Selector
    participant FE as FileEncryptor
    participant KM as KeystoreManager
    participant HW as TEE / StrongBox
    participant SAF as System File Picker

    User->>App: Share .xkeyenc file to xKey
    App->>FOA: ACTION_SEND with .xkeyenc URI

    FOA-->>User: Show file info
    FOA->>FOA: Detect .xkeyenc extension, pre-select "Decrypt"
    FOA-->>User: Show encryption key selector
    User->>KS: Choose decryption key (EC key with PURPOSE_AGREE_KEY)

    User->>FOA: Tap "Process"

    FOA->>FE: decryptWithKey(localKeyId, inputStream, outputStream)
    FE->>FE: Read header (version, ephemeral pubkey, salt, IV)
    FE->>KM: performECDH(localKeyId, ephemeralPubKeyDer)
    KM->>HW: ECDH key agreement in hardware
    HW-->>KM: Shared secret
    KM-->>FE: Shared secret
    FE->>FE: HKDF-SHA256 -> AES-256 key
    FE->>FE: AES-256-GCM streaming decrypt

    FE-->>FOA: Decryption complete

    FOA->>SAF: ACTION_CREATE_DOCUMENT (original filename)
    SAF-->>User: Choose save location
    User->>SAF: Confirm save
    FOA-->>User: "File decrypted successfully"
```
