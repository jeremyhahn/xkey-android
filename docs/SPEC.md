# xkey-android specification

> **Status: NORMATIVE** · Owner: xkey-android (parked; maintained by the Software Department) · Last verified: 2026-10-13
> The requirements contract for this project: what it is and every feature, with its requirements and status. [ROADMAP.md](../ROADMAP.md) agrees with the feature table below.

A feature listed here, in any status, is never deleted (not its docs, code or issues); removing or re-scoping one needs the owner's change to this file.

## Purpose

xkey-android is the Android phone-as-HSM companion to go-xkms: a Kotlin app that keeps its keys in Android Keystore, StrongBox when available.
It is a Layer 6 application (handbook `software/docs/00-ownership-and-sdk-boundary.md`). Its consumers are the `xkey` desktop CLI (`xkey device pair`, `xkey fido2 --backend phone`) and xkmsd, which uses the paired phone as a key backend (`BackendType "phone"`).
It couples to go-xkms only by wire compatibility with `go-xkms/xkey/pkg/pairing`, not by a Go import: handbook `software/docs/12-xkey-android-wire-contract.md`.
On the phone itself it also signs, encrypts and verifies files and media, and serves passkeys through the Android credential manager.
The xkey application can dispatch webauthn to the phone for hardware backed keys and biometric login & user presence.
Provides passkey ability to android OS

## Boundaries

Owns:
- The Android side of the pairing protocol: the Noise responder, the BLE, USB and TCP transports, the `local.*` handlers and the `remote.*` initiators.
- Keystore-held keys, user verification, and the on-phone stores and screens listed under Features.
- Handles user logins via webauthn

Never does:
- Defines the wire contract. The two sides are kept compatible by hand; a change made on one side but not the other is a defect (docs/12).
- Server-side pairing, key management or attestation verification; those belong to go-xkms.
- Exports private key material. Hardware keys share their public half only; software keys share material only if `exportable` and `shareable`.
- Cloud backup of app data.

## Features

| Feature | Status | Requirements | Detail |
|---|---|---|---|
| Noise pairing | shipped | Noise responder for `Noise_XX_25519_ChaChaPoly_SHA256` after the pre-handshake identity exchange, with the docs/12 prologue and counter nonces; static key in `EncryptedSharedPreferences`; JSON-RPC 2.0 base methods `ping`, `getInfo`, `generateKey`, `sign`, `loadKey`, `deleteKey`, `pairing.confirm`; the user approves each pairing; paired-device list and detail screens | `docs/architecture/BLE_PROTOCOL.md` |
| BLE transport | shipped | GATT peripheral advertising the xkey service; 7-byte fragment header (flags, sequence, total, length), MTU-aware; a foreground service keeps it advertising | `docs/architecture/BLE_PROTOCOL.md` |
| USB transport | shipped | USB accessory (AOA) with a 2-byte big-endian length prefix; shares the `StreamPairingSession` responder with TCP | none |
| TCP pairing | shipped | Loopback server on `:8444` behind the Settings toggle "TCP Pairing (ADB)", same framing as USB; enables the emulator and ADB end-to-end suites | none |
| Device attestation | shipped | Protocol version 2 of docs/12 (NORMATIVE there): a persistent Device Attestation Key attested once to an Android hardware root, a live ECDSA-P256 signature over the transcript, and a `DeviceFingerprint` that hashes the DAK's SPKI | none |
| Hardware-backed keys | shipped | `local.*` crypto: generate, sign, decrypt, symmetric encrypt and decrypt, ECDH, HMAC, public key, list, info, delete, key policy, key attestation, capabilities; StrongBox preferred, TEE fallback; `generateKey` returns `publicKeyDer` and `securityLevel`; EC keys carry `PURPOSE_AGREE_KEY` | `docs/architecture/CRYPTO.md` |
| Exportable symmetric keys | shipped | `local.generateKey` with `exportable` makes a software-backed symmetric key whose material may be shared or synced; exportable asymmetric keys are refused | handbook `software/docs/12-xkey-android-wire-contract.md` |
| Key sharing | shipped | `local.sharePublicKey`, `local.shareSymmetric`, `local.importSharedKey`; per-key, per-peer sharing policies managed from the key detail screen | `docs/architecture/DATA_MODEL.md` |
| User verification | shipped | Biometric auth mode, UV policy and session duration in Settings; a disabled mode for devices with no enrolled biometric, which auth-bound keys require; the user confirms the biometric prompt on the phone | none |
| PIN | shipped | The `local.pin*` family (set, verify, change, status, reset lockout), served over every transport | none |
| PIV | shipped | The `local.piv*` family (list slots, generate key, sign, import and get certificate), served over every transport; `remote.piv*` to the desktop | none |
| OATH | shipped | `local.oathAdd`, `oathGenerate`, `oathList`, `oathRemove`; TOTP codes match the desktop's | none |
| Passkey provider | shipped | Android Credential Provider service handling create and get credential requests from the system credential manager, with an enable setting; real ceremonies pass against the go-xkms relying party | none |
| FIDO2 phone backend | shipped | CTAP2 over BLE so `xkey fido2 --backend phone` authenticates with keys on the phone after a biometric prompt there | none |
| Store sync | shipped | One `SyncEngine` gathers and merges the trust store, OATH and passwords, inbound through `local.sync*` and outbound through `remote.sync*` and `RemoteSyncClient` | none |
| Desktop backup store | shipped | `local.createBackup` and `local.restoreBackup` hold a paired desktop's backups; backups round-trip | none |
| Remote key access | shipped | `remote.*` from phone to desktop reaches xkmsd backends through the desktop `Bridge`: key operations, sync and PIV; a router sends `remote.*` to the desktop and `local.*` to the phone | `docs/processes/COMPONENT_COMMUNICATION.md` |
| Trust store and CA bootstrap | shipped | Fetches the platform CA bundle by the configured bootstrap methods from `/v1/ca/bootstrap` or `/acme/ca-bundle`; verifies IDevID certificates; trusted-CA screen | none |
| Certificate authority | shipped | A local CA issues X.509 certificates by profile and tracks their lifecycle; certificate management screens | `docs/architecture/DATA_MODEL.md` |
| Password vault | shipped | The phone's password store, synced with the desktop through `syncPasswords` | none |
| Contacts | shipped | Recipient public keys for encryption and signature verification, with import and export | `docs/engineering/CONTACTS.md` |
| File operations | shipped | Sign, verify, encrypt and decrypt files received through the Android Share sheet | `docs/engineering/FILE_OPERATIONS.md` |
| Media signing | shipped | A foreground service watches MediaStore, hashes new photos and videos, signs them and embeds the signature in EXIF or XMP; auto-sign toggle and key choice | `docs/engineering/MEDIA_SIGNING.md` |
| Co-signing | shipped | Multi-party signing of media by QR or BLE exchange (`cosign.request`, `cosign.response`); Android-only, not part of the desktop contract | `docs/engineering/COSIGN_PROTOCOL.md` |
| Verified media viewer | shipped | Shows media with signature verification badges | `docs/engineering/VERIFIED_VIEWER.md` |
| Audit log | shipped | Records security events in Room; audit screen and recent activity on the home screen | `docs/architecture/DATA_MODEL.md` |
| Release signing | shipped | `assembleRelease` and `bundleRelease` sign with credentials outside version control and fail with a message when they are missing | none |
| Remote backup password | planned | Send the required `password` on `remote.createBackup` and `remote.restoreBackup` (go-xkms#690) | none |
| Password vault RPCs | planned | Answer the `Password*` and `SealStore*` methods the desktop sends over USB (go-xkms#692), including the per-user vault's new unlock body | none |
| Phone-initiated pairing | planned | Answer `local.attestDevice` on sessions the phone opens and display the pairing SAS (go-xkms#1306) | none |
| Request generation echo | planned | Echo a per-request `generation` in every pairing response, the phone half of the go-xkms#128 flag day | none |
| FIDO2 built-in UV | planned | A biometric-gated, verifiable "verify user" RPC so the desktop authenticator can issue a pinUvAuthToken through UV | none |
| Protected memory | planned | An owner ruling on the protected-memory mandate for Android, applied to the Noise static and session keys | none |
| Attestation-challenge keys | planned | A decision on `KeystoreManager.generateKeyWithAttestationChallenge`, which has no production caller; removing it is a change to this file | none |
| Trusted-computing enrollment | future | Android initiators for `remote.getTCGCSRIDevID`, `remote.activateCredential` and `remote.getAttestationQuote` (needs a Kotlin TPM2 credential-activation flow), and the `local.*` IDevID and TCG family, dormant on both sides | none |

## Interfaces

- Pairing wire protocol: the base, `local.*`, `remote.*` and `cosign.*` families over BLE, USB and TCP; handbook `software/docs/12-xkey-android-wire-contract.md`.
- Android CredentialManager: the Passkey provider.
- Android Share sheet (`ACTION_SEND`): File operations.
- Android MediaStore: Media signing.
- Build and test: the `make` targets in [README.md](../README.md#available-targets).
- Wire-compatibility harnesses: `ProtocolIntegrationTest` here and `go-xkms/xkey/cmd/e2eprobe`.

## Release criteria

The Release candidate milestone (#23) follows handbook `release-versioning.md` §1a (candidate, then staging, then production). It closes when:
- the owner resumes the project, which is parked;
- every milestone issue is closed, including the `docs/` spec-review scrub (#26);
- the `CI Gate` is green on `main`;
- `make integration-test` and the e2eprobe and WebAuthn suites pass on a device against the go-xkms candidate.
