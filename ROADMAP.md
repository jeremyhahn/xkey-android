# xkey-android roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-13
> Changes are proposed by docs-only PR. Every item names its feature in [docs/SPEC.md](docs/SPEC.md), and the two agree.

## Mission

Android phone-as-HSM companion to go-xkms: a Kotlin app whose keys stay in Android Keystore, StrongBox when available.
Serves as the xkmsd `phone` key backend behind `xkey device pair` and `xkey fido2 --backend phone`.
Wire-coupled to go-xkms through the pairing contract (Noise-XX + JSON-RPC), not a Go import.

The project is parked by the owner: no work is scheduled until the owner resumes it.

## Milestones

- [Release candidate](../../milestone/23) — target kind RC — no date while parked
- [#26](../../issues/26) `docs/` scrubbed for spec review — milestone work, not a feature — blocked: waits for its slot in [dept-software#126](../../../dept-software/issues/126)

## Complete

- **Noise pairing** — Noise-XX responder with identity exchange and JSON-RPC base methods — [BLE_PROTOCOL.md](docs/architecture/BLE_PROTOCOL.md) — shipped (as built; no release tag)
- **BLE transport** — GATT peripheral with 7-byte fragment framing — [BLE_PROTOCOL.md](docs/architecture/BLE_PROTOCOL.md) — shipped (as built)
- **USB transport** — USB accessory with 2-byte length framing — [BLE_PROTOCOL.md](docs/architecture/BLE_PROTOCOL.md) — shipped (as built)
- **TCP pairing** — loopback `:8444` server behind the Settings toggle — [README.md](README.md#live-e2e-conformance-probe) — shipped (as built)
- **Device attestation** — pairing fingerprint bound to the attested key's SPKI — [#2](../../issues/2) — shipped
- **Device attestation** — DAK rotation surface decided — [#4](../../issues/4) — shipped
- **Hardware-backed keys** — `local.*` crypto in Keystore, StrongBox preferred — [CRYPTO.md](docs/architecture/CRYPTO.md) — shipped (as built)
- **Exportable symmetric keys** — software-backed shareable symmetric keys — handbook `software/docs/12-xkey-android-wire-contract.md` — shipped (as built)
- **Key sharing** — per-key, per-peer sharing policies — [DATA_MODEL.md](docs/architecture/DATA_MODEL.md) — shipped (as built)
- **User verification** — biometric auth mode, UV policy and session duration — [OVERVIEW.md](docs/architecture/OVERVIEW.md) — shipped (as built)
- **PIN** — `local.pin*` over every transport — [README.md](README.md#wire-protocol-integration-suite) — shipped (as built)
- **PIV** — `local.piv*` and `remote.piv*` — [README.md](README.md#wire-protocol-integration-suite) — shipped (as built)
- **OATH** — `local.oath*` with TOTP matching the desktop — [README.md](README.md#live-e2e-conformance-probe) — shipped (as built)
- **Passkey provider** — Credential Provider service, proven against the go-xkms RP — [README.md](README.md#webauthn-against-the-go-xkms-relying-party) — shipped (as built)
- **FIDO2 phone backend** — `xkey fido2 --backend phone` over BLE — [README.md](README.md#usage) — shipped (as built)
- **Store sync** — one `SyncEngine` for trust store, OATH and passwords — [README.md](README.md#wire-protocol-integration-suite) — shipped (as built)
- **Desktop backup store** — `local.createBackup` and `local.restoreBackup` round-trip — [README.md](README.md#live-e2e-conformance-probe) — shipped (as built)
- **Remote key access** — `remote.*` to xkmsd backends through the desktop bridge — [COMPONENT_COMMUNICATION.md](docs/processes/COMPONENT_COMMUNICATION.md) — shipped (as built)
- **Trust store and CA bootstrap** — CA bundle fetch and IDevID verification — [OVERVIEW.md](docs/architecture/OVERVIEW.md) — shipped (as built)
- **Certificate authority** — local X.509 CA by profile — [DATA_MODEL.md](docs/architecture/DATA_MODEL.md) — shipped (as built)
- **Password vault** — phone password store synced through `syncPasswords` — [README.md](README.md#wire-protocol-integration-suite) — shipped (as built)
- **Contacts** — recipient public keys — [CONTACTS.md](docs/engineering/CONTACTS.md) — shipped (as built)
- **File operations** — Share-sheet sign, verify, encrypt, decrypt — [FILE_OPERATIONS.md](docs/engineering/FILE_OPERATIONS.md) — shipped (as built)
- **Media signing** — automatic signing of new photos and videos — [MEDIA_SIGNING.md](docs/engineering/MEDIA_SIGNING.md) — shipped (as built)
- **Co-signing** — multi-party media signing by QR or BLE — [COSIGN_PROTOCOL.md](docs/engineering/COSIGN_PROTOCOL.md) — shipped (as built)
- **Verified media viewer** — media with verification badges — [VERIFIED_VIEWER.md](docs/engineering/VERIFIED_VIEWER.md) — shipped (as built)
- **Audit log** — security events in Room with an audit screen — [DATA_MODEL.md](docs/architecture/DATA_MODEL.md) — shipped (as built)
- **Release signing** — release builds signed from credentials outside version control — [README.md](README.md#release-signing) — shipped (as built)

## Now

None: the project is parked.

## Next

None: the project is parked.

## Later

- **Remote backup password** — password sent on remote backup create and restore ([go-xkms#690](../../../go-xkms/issues/690)) — [#11](../../issues/11) — blocked: needs a JDK 17 + Android SDK 34 worker image
- **Password vault RPCs** — password store and seal store RPCs handled — [#12](../../issues/12) — blocked: needs a JDK 17 + Android SDK 34 worker image
- **Password vault RPCs** — USB transport supports the per-user password vault — [#15](../../issues/15) — blocked: needs a JDK 17 + Android SDK 34 worker image
- **Phone-initiated pairing** — phone-initiated attestation and pairing SAS display ([go-xkms#1306](../../../go-xkms/issues/1306)) — [#14](../../issues/14) — blocked: needs a JDK 17 + Android SDK 34 worker image
- **Request generation echo** — pairing responses echo per-request generation — [#10](../../issues/10) — blocked: [go-xkms#128](../../../go-xkms/issues/128)
- **FIDO2 built-in UV** — biometric-gated verify-user RPC for FIDO2 built-in UV — [#13](../../issues/13) — blocked: `verifyUser` undefined in go-xkms
- **Protected memory** — Noise static and session keys under an Android protected-memory clause — [#6](../../issues/6) — blocked: needs a JDK 17 + Android SDK 34 worker image
- **Attestation-challenge keys** — attestation-challenge key generation wired or its removal ruled — [#5](../../issues/5) — blocked: needs a JDK 17 + Android SDK 34 worker image

## Future

- **Trusted-computing enrollment** — Android initiators for the TCG IDevID, credential-activation and quote methods — handbook `software/docs/12-xkey-android-wire-contract.md` §The contract — not scheduled: dormant on both sides

## Dependencies

- Up: none pinned (not a Go module); wire contract with go-xkms per the handbook's xkey-android wire contract (software docs/12).
- Up: [go-xkms#128](../../../go-xkms/issues/128) per-request generation, needed by #10.
- Up: go-xkms defines the `verifyUser` RPC, needed by #13.
- Up: a JDK 17 + Android SDK 34 worker image, needed by #5, #6, #11, #12, #14 and #15.
- Down: go-xkms xkmsd `phone` key backend, `xkey device *` pairing and `xkey fido2 --backend phone`.
