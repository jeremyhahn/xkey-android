# xKey documentation

> **Status: REFERENCE** · Last verified: 2026-11-23
> Index of the folders in `docs/`.

[SPEC.md](SPEC.md) is the requirements contract: every feature, its status and
its folder. Each folder below is named after a SPEC feature. `architecture.md`
describes the design, components and data flow; `engineering.md`, where a
folder has one, is the implementation contract. `plans/` holds one plan per
issue, written by the branch that worked on it.

## Pairing and transports

- [noise-pairing](noise-pairing/architecture.md): the identity exchange, the Noise_XX handshake, the JSON-RPC base methods and the pairing approval flow.
- [device-attestation](device-attestation/architecture.md): protocol version 2, the Device Attestation Key and the device fingerprint.
- [phone-initiated-pairing](phone-initiated-pairing/architecture.md): sessions the phone opens, `local.attestDevice` and the pairing SAS.
- [request-generation-echo](request-generation-echo/architecture.md): the per-request `generation` echoed in every response.
- [protected-memory](protected-memory/architecture.md): how `NoiseSession` zeroes key material, and the limits of that on Android.
- [ble-transport](ble-transport/architecture.md): the GATT service, the fragment protocol and the foreground service.
- [usb-transport](usb-transport/architecture.md): the USB accessory (AOA) transport and its length-prefixed framing.
- [tcp-pairing](tcp-pairing/architecture.md): the loopback TCP server on port 8444 for emulators and ADB.

## Keys and verification

- [hardware-backed-keys](hardware-backed-keys/architecture.md): the `local.*` crypto methods, the key hierarchy, algorithms and signing flows. It also has the app overview and component map; its Room schema section predates the current database version (13).
- [exportable-symmetric-keys](exportable-symmetric-keys/architecture.md): software-backed symmetric keys the desktop may share or sync.
- [key-sharing](key-sharing/architecture.md): `local.sharePublicKey`, `local.shareSymmetric`, `local.importSharedKey` and the per-key sharing policies.
- [user-verification](user-verification/architecture.md): authentication modes, the UV policy and the biometric prompt from the background service.
- [fido2-built-in-uv](fido2-built-in-uv/architecture.md): `local.verifyUser`, the biometric-gated user verification the desktop authenticator uses.
- [pin](pin/architecture.md): the `local.pin*` methods and the PIN Management screen.
- [piv](piv/architecture.md): PIV slots, `local.piv*` and `remote.piv*`.

## Passkeys and FIDO2

- [passkey-provider](passkey-provider/architecture.md): the Android Credential Provider service for create and get requests.
- [fido2-phone-backend](fido2-phone-backend/architecture.md): passkeys for `xkey fido2 --backend phone`, over the paired session and CTAP2 over BLE.

## Stores and sync

- [oath](oath/architecture.md): TOTP and HOTP accounts, the `local.oath*` methods and QR import.
- [password-vault](password-vault/architecture.md): the password store, its screen and its sync.
- [password-vault-rpcs](password-vault-rpcs/engineering.md): the `Password*` methods the desktop sends over USB.
- [store-sync](store-sync/architecture.md): `SyncEngine`, `local.sync*` and `remote.sync*`.
- [desktop-backup-store](desktop-backup-store/architecture.md): `local.createBackup` and `local.restoreBackup`.
- [remote-backup-password](remote-backup-password/architecture.md): the `password` on `remote.createBackup` and `remote.restoreBackup`.
- [remote-key-access](remote-key-access/architecture.md): `remote.*` calls from the phone to the desktop and the message router.
- [audit-log](audit-log/architecture.md): audited events, their storage, the Audit Log screen and export.

## Certificates and trust

- [certificate-authority](certificate-authority/): [architecture](certificate-authority/architecture.md) (the local CA, profiles and lifecycle), [engineering](certificate-authority/engineering.md).
- [trust-store-bootstrap](trust-store-bootstrap/architecture.md): fetching the platform CA bundle and verifying IDevID certificates.

## Files and media

- [contacts](contacts/): [architecture](contacts/architecture.md) (the contact table and QR import), [engineering](contacts/engineering.md) (recipient key management).
- [file-operations](file-operations/): [architecture](file-operations/architecture.md) (ECIES and the sign, encrypt and decrypt flows), [engineering](file-operations/engineering.md) (Share sheet operations and file formats).
- [media-signing](media-signing/): [architecture](media-signing/architecture.md) (service wiring and the auto-sign flow), [engineering](media-signing/engineering.md) (`MediaSigningService`).
- [co-signing](co-signing/): [architecture](co-signing/architecture.md) (co-sign messages and flows), [engineering](co-signing/engineering.md) (the multi-party attestation protocol).
- [verified-media-viewer](verified-media-viewer/): [architecture](verified-media-viewer/architecture.md) (the viewing flow), [engineering](verified-media-viewer/engineering.md) (`VerifiedMediaViewerActivity`).

## Build

- [release-signing](release-signing/architecture.md): release signing credentials and the guard that refuses an unsigned release.
