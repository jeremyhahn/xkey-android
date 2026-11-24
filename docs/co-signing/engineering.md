# Co-signing payloads

> **Status: REFERENCE** · Last verified: 2026-11-23
> Engineering reference for co-signing: roles, the QR payloads and their checks, how signatures are stored, and how they are verified.

The flows and the `cosign.request` handler are in
[architecture.md](architecture.md).

## Roles

| Role | Written by |
|------|------------|
| `CREATOR` | Sign in `FileOperationActivity` and the media signing service |
| `ATTESTOR` | The owner's phone when it appends a witness's QR response (`CoSignResponse.toAttestorEntry`) |
| `WITNESS` | Defined in `SignerRole`; no code on main writes it |

The role is a label. Verification treats every entry the same way.

## QR request

The owner's phone shows this. `CoSignRequest` (`media/CoSignPayload.kt`)
builds and parses it.

```json
{
    "v": 1,
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "alg": "SHA-256",
    "from": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"
}
```

| Field | Rule on parse |
|-------|---------------|
| `v` | Must be `1` |
| `hash` | Lowercase hex, exactly the digest length of `alg`: 64 characters for SHA-256, 96 for SHA-384, 128 for SHA-512 |
| `alg` | `SHA-256`, `SHA-384` or `SHA-512` |
| `from` | Non-blank. The owner's key fingerprint, shown to the witness in the approval dialog |

## QR response

The witness's phone shows this. `CoSignResponse` builds and parses it.

```json
{
    "v": 1,
    "sig": "MEUCIQDxE9vVU3r7KnYm+B8r8r5w...",
    "fp": "f5e6d7c8b9a01234567890abcdef1234567890abcdef1234567890abcdef1234",
    "name": "Witness key",
    "alg": "ES256"
}
```

| Field | Rule on parse |
|-------|---------------|
| `v` | Must be `1` |
| `sig` | Non-blank base64 |
| `fp` | Non-blank. Hex SHA-256 of the witness's public key DER |
| `name` | Non-blank. The witness key's label |
| `alg` | Non-blank. The signature algorithm, such as `ES256` |

A payload that fails to parse is reported by type: `NotJson`,
`UnsupportedVersion`, `MissingField`, `UnsupportedHashAlgorithm`,
`InvalidHash` or `InvalidSignature`.

The witness signs the hash bytes with the JCA algorithm for its key
(`KeystoreManager.jcaSignatureAlgorithm`), which hashes them again with the
key algorithm's own digest: SHA-256 for ES256 and RS256, SHA-384 for ES384 and
RS384, SHA-512 for ES512 and RS512. That digest follows the key, not the
request's `alg`. This matches how Sign in file operations signs and how
`SignatureVerifier` checks.

## Storing co-signatures

All signatures live in the `signatures` array of the one
`ContentAuthenticityData` block in the JPEG's EXIF `UserComment`
(`XKEY_SIG:` followed by JSON). `appendAttestor` adds the new entry with
role `ATTESTOR` and the current time, and refuses it when an entry with the
same fingerprint (compared without case) is already there.
`XmpMetadataHelper.appendSignature` then writes the block back.

Every signer signs the same content hash. It is the canonical JPEG hash,
which skips the `APPn` and `COM` segments, so rewriting the EXIF block to add
a signature does not change the hash the earlier signatures cover.

## Verifying co-signed media

Co-signed files are checked like any signed file, by
`SignerVerification.verify` (`media/`), from both the
[verified-media viewer](../verified-media-viewer/architecture.md) and Verify
in [file operations](../file-operations/architecture.md):

1. The stored content hash must match the file. If it does not, every signer
   fails.
2. For each entry, a contact whose fingerprint equals `keyFingerprint` gives
   the public key. With no contact, a local key whose public key DER hashes
   to the fingerprint does.
3. With a public key, the signature is checked: verified or failed. With
   none, the signer is unknown.

## Audit events

| Call | When |
|------|------|
| `AuditLogger.logCoSignInitiated(contentHash)` | The owner's phone shows a request QR |
| `AuditLogger.logCoSignReceived(contentHash, signerFingerprint)` | The witness's phone shows its response QR, the owner's phone appends a co-signature, or the handler answers `cosign.request` |

## Limits

- The witness signs the hash it is shown and never sees the photo. A witness
  who wants to check the content has to compare it some other way.
- QR payloads are shown on screen and not stored.
- `cosign.response` received over the protocol is acknowledged and dropped.
  Only the QR path adds signatures to a file.
