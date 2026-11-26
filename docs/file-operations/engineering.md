# File operations

> **Status: REFERENCE** · Last verified: 2026-11-23
> Engineering reference for `FileOperationActivity`: the share-sheet entry, the screen, key selection, the `.xkeyenc` and `.xkeysig` formats, and audit events.

The flows themselves, with sequence diagrams, are in
[architecture.md](architecture.md).

## Share sheet entry

`FileOperationActivity` handles `ACTION_SEND` and `ACTION_SEND_MULTIPLE` for
any MIME type, so xKey shows up in the share sheet for every file:

```xml
<activity
    android:name=".ui.FileOperationActivity"
    android:exported="true"
    android:label="@string/file_operation_title">
    <intent-filter>
        <action android:name="android.intent.action.SEND" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="*/*" />
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.SEND_MULTIPLE" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="*/*" />
    </intent-filter>
</activity>
```

`extractFileUris` reads `EXTRA_STREAM` (one URI for `SEND`, a list for
`SEND_MULTIPLE`). The operations use only the first URI.

The screen is built in code (no layout XML) from these cards:

1. File info: name and size of every shared file, from `ContentResolver`.
2. Operation: Sign, Verify, Encrypt, Decrypt.
3. Key: shown for Sign and Decrypt, hidden for Verify and Encrypt.
4. Recipient: shown for Encrypt only, filled from `ContactDao.getAll()`.
5. Process button, progress indicator and a result card. The result text is
   in the danger colour when the operation failed and the verified colour
   otherwise.

## Key selection

`loadKeysAndContacts` reads every row from `KeyDao` and splits them:

| Operation | Choices |
|-----------|---------|
| Sign | Keys whose `keyType` is `signing`, `fido2`, `ca` or `attestation`, or whose algorithm starts with `ES` or `RS`, or is `Ed25519` |
| Verify | No key choice. The public key comes from a contact or a local key (see below) |
| Encrypt | No key choice. The user picks a recipient contact |
| Decrypt | Keys whose `keyType` is `encryption`, or whose algorithm starts with `ES` and whose `keyType` is not `fido2` |

`KeystoreManager.signWithAlgorithm` accepts ES256, ES384, ES512, RS256, RS384
and RS512. An `Ed25519` key appears in the Sign list but signing with it
throws a `SigningException`. A Decrypt key must have been generated with
`PURPOSE_AGREE_KEY` on Android 12 or later; any other EC key in the list fails
at the ECDH step.

After a successful sign or decrypt the activity calls `keyDao.recordUsage`
for the key.

## Sign

1. `MediaHasher.hashCanonicalUri` hashes the file. For JPEG it skips the
   `APPn` and `COM` segments; anything else is hashed whole.
2. `KeystoreManager.signWithAlgorithm(keyId, hashBytes, key.algorithm)` signs
   the 32 hash bytes. The JCA algorithm hashes its input again with the
   key algorithm's own digest: SHA-256 for ES256 and RS256 (`SHA256withECDSA`,
   `SHA256withRSA`), SHA-384 for ES384 and RS384, SHA-512 for ES512 and RS512.
   An Ed25519 key shows in the picker but signing with it fails, since
   `KeystoreManager.jcaSignatureAlgorithm` has no mapping for it.
   Verification (`SignatureVerifier`) uses the same mapping.
3. The activity builds a `ContentAuthenticityData` with one `SignatureEntry`
   whose role is `CREATOR`. `keyFingerprint` is the SHA-256 of the key's
   public key DER, or the key ID when the row has no public key.
4. A JPEG gets the block in its EXIF `UserComment` and is written back over
   the shared URI. Anything else gets a `.xkeysig` file through the save
   picker.

## Verify

1. For a JPEG, `XmpMetadataHelper.readSignatureFromUri` looks for an EXIF
   `UserComment` that starts with `XKEY_SIG:`. Other types never have an
   embedded block.
2. With no embedded block the activity opens the system picker
   (`OpenDocument`, filtered to `application/json` and `*/*`) for a
   `.xkeysig` file.
3. `MediaHasher.contentHashMatchesUri` compares the stored `contentHash` with
   the file. An embedded block must match the canonical hash. A `.xkeysig`
   file may match the canonical hash or the SHA-256 of the whole file.
4. For each entry the activity looks up a contact with
   `ContactDao.getByFingerprint(keyFingerprint)`. If there is none, it passes
   every local key to `SignerVerification.verify`, which matches one whose
   public key DER hashes to the fingerprint.

The result card has one line per signer, `<name>: Verified`,
`<name>: Unknown signer` or `<name>: Failed`, under a header:

| Header | When |
|--------|------|
| Signature verified | Every signer verified |
| Signature verification failed | Any signer failed, or the content hash did not match |
| Verification complete | No failures, but at least one unknown signer |

The name is the matched contact's name or local key's label. With no match it
is the `signerName` from the file, or the first 16 characters of the
fingerprint.

## Encrypt and decrypt

`FileEncryptor` does the work; see [architecture.md](architecture.md) for the
sequence. The activity encrypts into a staging file named after
`<file>.xkeyenc`, then asks where to save it. Decrypt does the same with the
`.xkeyenc` suffix removed from the name.

## `.xkeyenc` binary format

```
Offset  Size  Field             Description
0       1     version           Format version, 0x01
1       2     ephemeral_len     Length of the ephemeral public key, big-endian
3       var   ephemeral_pubkey  DER (SubjectPublicKeyInfo) ephemeral P-256 public key
var     32    salt              HKDF salt
var+32  12    iv                AES-GCM nonce
var+44  var   ciphertext        AES-256-GCM ciphertext
tail    16    tag               GCM authentication tag, appended by the cipher
```

| Field | Size | Notes |
|-------|------|-------|
| Version | 1 byte | Always `0x01`. Decrypt rejects any other value |
| Ephemeral key length | 2 bytes | Big-endian unsigned 16-bit |
| Ephemeral public key | 91 bytes for P-256 | SubjectPublicKeyInfo DER |
| Salt | 32 bytes | Random |
| IV | 12 bytes | Random |
| Header total | 138 bytes for P-256 | Before the ciphertext |
| Tag | 16 bytes | 128-bit GCM tag |

Key derivation is HKDF-SHA256 (Bouncy Castle `HKDFBytesGenerator`) over the
ECDH shared secret, with the salt from the header and the info string
`xkey-file-encryption-v1`, giving a 32-byte AES key. Data is streamed through
the cipher in 8 KiB buffers, so file size is not limited by memory.

What the format gives you:

- AES-256-GCM with a random IV per file, and a 128-bit tag over the
  ciphertext.
- The ephemeral private key is deleted after each file, so the sender's
  device holds nothing that can decrypt the file later.
- The recipient's key is long-lived. Anyone who can use it can decrypt every
  file sent to it; there is no forward secrecy on the recipient side.
- ECDH runs in Keystore on both sides. The recipient's key may be in
  StrongBox; the ephemeral key is in the TEE.

## `.xkeysig` JSON format

A `.xkeysig` file is the JSON form of `ContentAuthenticityData`
(`media/SignatureFormat.kt`). The same JSON, prefixed with `XKEY_SIG:`, is
what a JPEG carries in its EXIF `UserComment`.

```json
{
    "version": 1,
    "contentHash": "a1b2c3d4e5f6...64 hex characters",
    "hashAlgorithm": "SHA-256",
    "signatures": [
        {
            "keyFingerprint": "f1e2d3c4b5a6...64 hex characters",
            "signerName": "My Signing Key",
            "algorithm": "ES256",
            "value": "MEUCIQDx...base64",
            "timestamp": "2025-07-15T10:30:00Z",
            "role": "CREATOR"
        }
    ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | Format version, `1`. Read as `1` when missing |
| `contentHash` | string | Hex SHA-256 of the content. Signing writes the canonical hash, which for a non-JPEG file is the whole-file hash |
| `hashAlgorithm` | string | `SHA-256` |
| `signatures` | array | `SignatureEntry` objects |
| `signatures[].keyFingerprint` | string | Hex SHA-256 of the signer's DER public key |
| `signatures[].signerName` | string | Signer's label. Left out when null |
| `signatures[].algorithm` | string | `ES256`, `ES384`, `ES512`, `RS256`, `RS384` or `RS512` |
| `signatures[].value` | string | Base64 (no line wrap) signature: DER for EC, PKCS#1 for RSA |
| `signatures[].timestamp` | string | ISO 8601 instant |
| `signatures[].role` | string | `CREATOR`, `WITNESS` or `ATTESTOR`. A missing or unknown value reads as `CREATOR` |

## Saving output

Output goes through the Storage Access Framework, so the app needs no storage
permission. The activity registers these launchers:

| Launcher | Contract | Used for |
|----------|----------|----------|
| `createSignatureFileLauncher` | `CreateDocument("application/json")` | `.xkeysig` from Sign |
| `createEncryptedFileLauncher` | `CreateDocument("application/octet-stream")` | `.xkeyenc` from Encrypt |
| `createDecryptedFileLauncher` | `CreateDocument("*/*")` | Plaintext from Decrypt |
| `pickSidecarLauncher` | `OpenDocument()` | Choosing a `.xkeysig` file to verify against |

Encrypt and decrypt hand their staging file to a `PendingStagedSave`, which
copies it to the chosen URI and deletes it, or deletes it when the user
cancels.

## Audit events

| Operation | Call | When |
|-----------|------|------|
| Sign | `AuditLogger.logFileSigned(keyId, label, fileName)` | After signing, before the `.xkeysig` save picker opens |
| Verify | `AuditLogger.logFileVerified(fileName, signerCount, verified)` | After the result is computed. `verified` is false if any line failed |
| Encrypt | `AuditLogger.logFileEncrypted(recipientFingerprint, fileName)` | After the staging file is written |
| Decrypt | `AuditLogger.logFileDecrypted(keyId, fileName)` | After the staging file is written |
