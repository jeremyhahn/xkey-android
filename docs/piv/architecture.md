# PIV architecture

> **Status: REFERENCE** · Last verified: 2026-11-23
> As-built description of the phone's PIV slots: the `local.piv*` wire family, the Keystore keys behind each slot, the `piv_slots` table, and the `remote.piv*` calls that show the paired desktop's slots.

## Summary

The phone emulates PIV smart-card slots. Each slot (`PivSlot`: the primary
slots 9A, 9C, 9D, 9E, F9 and the retired slots 82 to 95) can hold one
Android Keystore key pair under the alias `xkey_piv_<hexId>`, plus an optional
imported X.509 certificate. Metadata (algorithm, public key DER, certificate,
created / last-used time, use count) lives in the Room table `piv_slots`
(`PivSlotEntity`, `PivSlotDao`). Keys are ECDSA P-256, ECDSA P-384, RSA 2048, RSA 3072 or RSA 4096
(`PivAlgorithm`). PIV keys never ask for StrongBox, so every size is made in
the TEE.

### PIV algorithms

| `PivAlgorithm` | Key | PIV algorithm id | Wire names accepted |
|---|---|---|---|
| `ES256` | ECDSA P-256 | `0x11` | `ES256`, `ECCP256`, `ECC-P256`, `ECDSA-P256`, `EC-P256`, `P256` |
| `ES384` | ECDSA P-384 | `0x14` | `ES384`, `ECCP384`, `ECC-P384`, `ECDSA-P384`, `EC-P384`, `P384` |
| `RS2048` | RSA 2048 | `0x07` | `RS2048`, `RSA2048`, `RSA-2048` |
| `RS3072` | RSA 3072 | `0x05` | `RS3072`, `RSA3072`, `RSA-3072` |
| `RS4096` | RSA 4096 | `0x16` | `RS4096`, `RSA4096`, `RSA-4096` |
| `ML_DSA_44` | ML-DSA-44 (FIPS 204) | none | `ML-DSA-44`, `MLDSA44`, `ML_DSA_44` |
| `ML_DSA_65` | ML-DSA-65 (FIPS 204) | none | `ML-DSA-65`, `MLDSA65`, `ML_DSA_65` |
| `ML_DSA_87` | ML-DSA-87 (FIPS 204) | none | `ML-DSA-87`, `MLDSA87`, `ML_DSA_87` |

The ids for P-256, P-384, RSA 2048 and RSA 3072 are the NIST SP 800-78
values; `0x16` for RSA 4096 is the YubiKey extension the desktop uses. SP
800-78 assigns no ML-DSA id, so `pivAlgorithmId` is null for the ML-DSA
entries and peers name them only by wire name.
`PivAlgorithm.fromWireName` matches names case-insensitively and treats `_`
as `-`; any other name, including RSA 1024, P-521 and other post-quantum
names such as SLH-DSA, is answered with `INVALID_ALGORITHM`.

An ML-DSA slot key is held in software (`PqcSoftwareKeyStore`, under the
slot's alias) or in the Android Keystore through `PqcHardware.backend`.
`local.pivGenerateKey` takes an optional `keyBacking` (`hardware` or
`software`; absent picks hardware when the device makes the set); `hardware`
the device does not make is `FEATURE_UNAVAILABLE`, and `keyBacking` on an EC
or RSA slot key is `INVALID_PARAMS`. Sign, public key export and delete reach
either backing. See [../pqc-keys/architecture.md](../pqc-keys/architecture.md).

The desktop drives the slots through `local.piv*`. All transports share the
one `RequestHandler` built in `XKeyGattService` with
`PivKeyManager(XKeyDatabase.getInstance(this).pivSlotDao())`, used by the BLE
(`GattServer`), TCP (`TcpHsmServer`) and USB (`UsbAccessoryServer`) servers.
On the phone, `PivActivity` and `PivSlotDetailActivity` use their own
`PivKeyManager`.

The PIV screens also show the paired desktop's slots while a desktop is
connected. `PivActivity` lists them in a separate read-only section from
`remote.pivListSlots`. Opening one shows `PivSlotDetailActivity` in desktop
mode: the certificate comes from `remote.pivGetCert` and the "sign test"
action sends `remote.pivSign`. That view has no delete or export. A desktop
slot id is sent back exactly as the desktop gave it and is never mapped onto
the phone's own slots. When no desktop is connected, or the desktop errors,
the list shows only the phone's slots and no error.

## Components

| Component | File | Role |
|-----------|------|------|
| `RequestHandler` (`handlePivListSlots`, `handlePivGenerateKey`, `handlePivImportCert`, `handlePivSign`, `handlePivGetCert`, `pivSlotId`, `pivAlgorithmOf`) | `app/src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt` | Wire handlers; accept go-xkms field and algorithm spellings alongside the older Android ones |
| `PivKeyManager`, `PivSlotInfo` | `app/src/main/kotlin/com/automatethethings/xkey/piv/PivKeyManager.kt` | `generateKey`, `importCertificate`, `listSlots`, `sign`, `getCertificate`, `getPublicKey`, `deleteKey`; audit via `AuditLogger.logKeyCreated`, `AuditLogger.logSigningRequest` and, after a stored import, `AuditLogger.logPivCertImported` (slot and subject) |
| `PivSlot`, `PivAlgorithm` | `app/src/main/kotlin/com/automatethethings/xkey/piv/PivSlot.kt` | Slot ids, labels, `keystoreAlias`, `isPrimarySlot`, `fromHexId` (case-insensitive); algorithms `ES256`, `ES384`, `RS2048`, `RS3072`, `RS4096` with `pivAlgorithmId`; `PivAlgorithm.fromWireName` parses wire names |
| `PivSlotEntity`, `PivSlotDao` | `app/src/main/kotlin/com/automatethethings/xkey/piv/PivSlotEntity.kt`, `PivSlotDao.kt` | Room table `piv_slots`; `upsert`, `getBySlotId`, `getAll`, `recordUsage`, `deleteBySlotId`, observers for the UI |
| `PivActivity`, `PivSlotDetailActivity` | `app/src/main/kotlin/com/automatethethings/xkey/ui/` | On-phone slot list and slot detail screens, for the phone's slots and the desktop's |
| `DesktopPivSlots`, `desktopPivSlots`, `desktopSessions` | `app/src/main/kotlin/com/automatethethings/xkey/ui/PivActivity.kt` | Load the desktop's slots for each desktop session; any failure gives an empty list |
| `DesktopPivSlotActions`, `desktopPivSlotDetail` | `app/src/main/kotlin/com/automatethethings/xkey/ui/PivSlotDetailActivity.kt` | The desktop slot's certificate (none on `PIV_SLOT_NOT_FOUND`) and the test sign |
| `RemoteKeyClient` (`pivListSlots`, `pivGetCert`, `pivSign`), `RemotePivSlot`, `RemotePivCertificate`, `RemotePivSignature` | `app/src/main/kotlin/com/automatethethings/xkey/remote/RemoteKeyClient.kt` | Sends `remote.piv*`; an off-shape reply is a `ProtocolException` with `PARSE_ERROR` |

## Wire methods served

| Method | Constant | Params | Result |
|--------|----------|--------|--------|
| `local.pivListSlots` | `MethodNames.LOCAL_PIV_LIST_SLOTS` | none | `slots[]`: `slot`/`slotId`, `label`, `description`, `has_key`/`hasKey`, `has_certificate`/`hasCertificate`, `algorithm`, `public_key_der`/`publicKey`, `createdAt`, `lastUsedAt`, `useCount`. Only slots with a `piv_slots` row are listed |
| `local.pivGenerateKey` | `LOCAL_PIV_GENERATE_KEY` | `slot` (or `slotId`), `algorithm` (default `ES256`) | `slot`, `algorithm`, `has_key`, `public_key_der` (SPKI, base64). Overwrites a key already in the slot |
| `local.pivImportCert` | `LOCAL_PIV_IMPORT_CERT` | `slot`, `certificate_der` (or `certificate`), base64 | `success: true`. The bytes must be exactly one DER X.509 certificate whose SubjectPublicKeyInfo equals the slot key's public key; a refusal stores nothing and an earlier certificate stays |
| `local.pivSign` | `LOCAL_PIV_SIGN` | `slot`, `data` (base64), `algorithm` (default `ES256`) | `signature` (base64). `ES256` signs with `SHA256withECDSA`, `ES384` with `SHA384withECDSA`, `RS2048` with `SHA256withRSA`; the signature algorithm comes from the request, not from the slot's stored algorithm |
| `local.pivGetCert` | `LOCAL_PIV_GET_CERT` | `slot` | `certificate_der`/`certificate`: the imported certificate, else the Keystore's self-signed certificate for the alias |

Accepted algorithm names: the enum names (`ES256`, `ES384`, `RS2048`) and
`ECDSA-P256`, `EC-P256`, `P256`, `ECDSA-P384`, `EC-P384`, `P384`, `RSA-2048`,
`RSA2048` (case and `_`/`-` folded).

Each result also carries the older Android spellings (`slotId`, `hasKey`,
`hasCertificate`, `publicKey`, `certificate`) next to the go-xkms names.

## Wire methods sent

| Method | Constant | Params | Result read |
|--------|----------|--------|-------------|
| `remote.pivListSlots` | `REMOTE_PIV_LIST_SLOTS` | none, or `backend` | `slots[]`: `slot`, `has_key`, `has_certificate` required; `label`, `algorithm`, `cert_subject`, `cert_expiry` optional. A `null` `slots` means no slots |
| `remote.pivGetCert` | `REMOTE_PIV_GET_CERT` | `slot`, optional `backend` | `certificate_der` (must parse as X.509); `subject`, `issuer`, `expiry` optional |
| `remote.pivSign` | `REMOTE_PIV_SIGN` | `slot`, `data` (base64), optional `algorithm` and `backend` | `signature`, `algorithm` |

The shapes follow go-xkms `protocol_piv.go`. The client refuses a blank slot
or empty data before sending.

## Main flow

```mermaid
sequenceDiagram
    participant D as Desktop
    participant H as RequestHandler
    participant P as PivKeyManager
    participant KS as Android Keystore
    participant DB as PivSlotDao (piv_slots)

    D->>H: local.pivGenerateKey {slot 9A, algorithm ECDSA-P256}
    H->>H: PivSlot.fromHexId, pivAlgorithmOf
    H->>P: generateKey(AUTHENTICATION, ES256)
    P->>KS: KeyPairGenerator alias xkey_piv_9A (SIGN/VERIFY)
    P->>DB: upsert(PivSlotEntity hasKey, publicKeyDer)
    H-->>D: {slot, algorithm, public_key_der}

    D->>H: local.pivImportCert {slot 9A, certificate_der}
    H->>P: importCertificate
    P->>DB: getBySlotId
    P->>P: parse X.509 DER, SPKI == slot publicKeyDer
    P->>DB: upsert(certificateDer)
    H-->>D: {success: true}

    D->>H: local.pivSign {slot 9A, data, algorithm}
    H->>P: sign(slot, data, ES256)
    P->>KS: getKey(xkey_piv_9A), Signature SHA256withECDSA
    P->>DB: recordUsage
    H-->>D: {signature}
```

## Errors and refusals

| Condition | Error code |
|-----------|------------|
| Handler built without a `PivKeyManager` | `FEATURE_UNAVAILABLE` ("PIV support is not available on this transport") |
| Missing params, missing certificate or data | `INVALID_PARAMS` |
| Unknown slot id | `PIV_INVALID_SLOT` |
| Unknown algorithm name | `INVALID_ALGORITHM` |
| Key generation throws | `KEY_GENERATION_FAILED` |
| Signing throws (including no key in the slot) | `PIV_SIGN_FAILED` |
| `local.pivGetCert` on a slot with no certificate | `PIV_SLOT_NOT_FOUND` |
| `local.pivImportCert`: certificate not base64, not one DER certificate, or for another key | `INVALID_PARAMS` (nothing stored) |
| `local.pivImportCert` into a slot with no key | `PIV_SLOT_NOT_FOUND` |
| Any other import failure, list or get-cert failure | `INTERNAL_ERROR` |

The `local.piv*` handlers and `PivKeyManager` do not check a PIN or prompt the
user.

## Tests

- Unit (`app/src/test`): `PivKeyManagerTest`, `PivSlotTest`, `PivSlotEntityTest`, `PivHandlerTest`, `ProtocolConstantsTest`, `KeystoreManagerPivAliasTest`, `RemoteKeyClientPivTest`, `DesktopPivSlotsTest`, `DesktopPivSessionTest`.
- Instrumented (`app/src/androidTest`): `PivSlotDaoTest`, `PivActivityUiTest`, `PivFlowTest`, `PivSlotDetailActivityUiTest`, `PivSlotDetailFlowTest`.

## Related features

- [PIN](../pin/architecture.md): the other smart-card style family on the same handler.
- [Hardware-backed keys](../hardware-backed-keys/architecture.md): the general Keystore key path.
- [Remote key access](../remote-key-access/architecture.md): the `remote.*` client and router.
- [Certificate authority](../certificate-authority/)
- [Audit log](../audit-log/architecture.md)
