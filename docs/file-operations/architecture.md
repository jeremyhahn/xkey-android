# File operations architecture

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of xKey's file encryption (ECIES) and the file sign, encrypt and decrypt flows.

## File Encryption (ECIES) Flow

xKey uses an Elliptic Curve Integrated Encryption Scheme where the ECDH key
agreement happens entirely in hardware. The derived AES key is used in software
because Android Keystore does not support importing arbitrary derived keys.

### Encryption

```mermaid
sequenceDiagram
    participant App as FileOperationActivity
    participant FE as FileEncryptor
    participant KM as KeystoreManager
    participant KS as Android Keystore

    App->>FE: encryptForRecipient(recipientPubKey, plaintext, output)

    Note over FE: Generate ephemeral key ID
    FE->>KS: KeyPairGenerator(EC P-256, PURPOSE_AGREE_KEY)
    KS-->>FE: Ephemeral key pair created in hardware

    FE->>KM: getPublicKeyDER(ephemeralKeyId)
    KM-->>FE: Ephemeral public key (DER)

    FE->>KM: performECDH(ephemeralKeyId, recipientPubKey)
    KM->>KS: KeyAgreement.doPhase(recipientPubKey)
    Note over KS: ECDH in hardware -- private key never leaves TEE
    KS-->>KM: Shared secret bytes
    KM-->>FE: Shared secret

    Note over FE: Generate random 32-byte salt
    FE->>FE: HKDF-SHA256(sharedSecret, salt) --> AES-256 key
    Note over FE: Generate random 12-byte IV

    FE->>FE: Write .xkeyenc header
    FE->>FE: AES-256-GCM encrypt (streaming via CipherOutputStream)

    FE->>KM: deleteKey(ephemeralKeyId)
    Note over KM: Ephemeral key destroyed

    FE-->>App: Encrypted file written
```

### Decryption

```mermaid
sequenceDiagram
    participant App as FileOperationActivity
    participant FE as FileEncryptor
    participant KM as KeystoreManager
    participant KS as Android Keystore

    App->>FE: decryptWithKey(localKeyId, input, output)

    FE->>FE: Read .xkeyenc header (version, ephemeral pubkey, salt, IV)

    FE->>KM: performECDH(localKeyId, ephemeralPubKeyDer)
    KM->>KS: KeyAgreement.doPhase(ephemeralPubKey)
    Note over KS: ECDH in hardware
    KS-->>KM: Shared secret bytes
    KM-->>FE: Shared secret

    FE->>FE: HKDF-SHA256(sharedSecret, salt) --> AES-256 key
    FE->>FE: AES-256-GCM decrypt (streaming via CipherInputStream)

    FE-->>App: Decrypted file written
```

## Data Flow: Sign a File

```mermaid
graph LR
    A[Share Sheet] -->|URI| B[FileOperationActivity]
    B -->|InputStream| C[MediaHasher]
    C -->|Hash bytes| D[KeystoreManager]
    D -->|In hardware| E[Android Keystore]
    E -->|Signature| D
    D -->|Signature bytes| B
    B -->|ContentAuthenticityData| F[XmpMetadataHelper]
    F -->|Write EXIF| G[File System]
    B -->|Log event| H[AuditLogger]
    H -->|Insert| I[(audit_logs)]
```

## Data Flow: Encrypt a File

```mermaid
graph LR
    A[Share Sheet] -->|URI| B[FileOperationActivity]
    B -->|Recipient key| C[ContactDao]
    C -->|PublicKeyDer| B
    B -->|Plaintext stream| D[FileEncryptor]
    D -->|Generate ephemeral| E[Android Keystore]
    D -->|ECDH in hardware| E
    E -->|Shared secret| D
    D -->|HKDF derive| F[AES-256 key]
    D -->|AES-GCM stream| G[.xkeyenc file]
    D -->|Delete ephemeral| E
    B -->|Log event| H[AuditLogger]
```

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
