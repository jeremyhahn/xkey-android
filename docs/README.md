# xKey Documentation

> **Status: REFERENCE** · Last verified: 2026-10-20
> Index of the project documents in `docs/`.

[SPEC.md](SPEC.md) is the requirements contract: every feature, with its status. A feature that needs more than its SPEC row has a folder named after it, holding `architecture.md` (design, boundaries, data flow) and `engineering.md` (implementation contract) where each has content.

## Feature folders

- [noise-pairing](noise-pairing/architecture.md): Noise_XX handshake, JSON-RPC messages, pairing flow.
- [ble-transport](ble-transport/architecture.md): transport stack, fragment protocol, GATT service states.
- [hardware-backed-keys](hardware-backed-keys/architecture.md): key hierarchy, algorithms, signing flows; also the application overview, component map and Room schema (stale past v7).
- [key-sharing](key-sharing/architecture.md): sharing policy table.
- [user-verification](user-verification/architecture.md): biometric prompt from the BLE service.
- [passkey-provider](passkey-provider/architecture.md): Credential Provider service and its legacy table.
- [remote-key-access](remote-key-access/architecture.md): `remote.*` methods and routing to the desktop.
- [certificate-authority](certificate-authority/architecture.md): certificate table.
- [contacts](contacts/): [architecture](contacts/architecture.md) (contact table, QR import flow), [engineering](contacts/engineering.md) (recipient key management).
- [file-operations](file-operations/): [architecture](file-operations/architecture.md) (ECIES, sign, encrypt and decrypt flows), [engineering](file-operations/engineering.md) (Share sheet operations, file formats).
- [media-signing](media-signing/): [architecture](media-signing/architecture.md) (service wiring, auto-sign flow), [engineering](media-signing/engineering.md) (`MediaSigningService`).
- [co-signing](co-signing/): [architecture](co-signing/architecture.md) (co-sign messages and flows), [engineering](co-signing/engineering.md) (multi-party attestation protocol).
- [verified-media-viewer](verified-media-viewer/): [architecture](verified-media-viewer/architecture.md) (viewing flow), [engineering](verified-media-viewer/engineering.md) (`VerifiedMediaViewerActivity`).
- [audit-log](audit-log/architecture.md): audit log table.
- [password-vault-rpcs](password-vault-rpcs/engineering.md): USB `Password*` methods, tenant, scope, sharing and expiry.
