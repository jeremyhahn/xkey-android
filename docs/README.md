# xKey Documentation

> **Status: REFERENCE** · Last verified: 2026-10-09
> Index of the project documents in `docs/`.

## Architecture

- [OVERVIEW](architecture/OVERVIEW.md): high-level application architecture.
- [BLE_PROTOCOL](architecture/BLE_PROTOCOL.md): BLE transport between xKey and desktop clients.
- [CRYPTO](architecture/CRYPTO.md): key hierarchy, algorithms, signing flows, file encryption.
- [DATA_MODEL](architecture/DATA_MODEL.md): Room schema and DataStore repositories (stale past v7).

## Engineering

- [CONTACTS](engineering/CONTACTS.md): contact/recipient key management.
- [COSIGN_PROTOCOL](engineering/COSIGN_PROTOCOL.md): multi-party attestation of media.
- [FILE_OPERATIONS](engineering/FILE_OPERATIONS.md): file sign, verify, encrypt, decrypt from the Share sheet.
- [MEDIA_SIGNING](engineering/MEDIA_SIGNING.md): automatic signing of captured media.
- [VERIFIED_VIEWER](engineering/VERIFIED_VIEWER.md): media viewer with signature verification badges.

## Processes

- [COMPONENT_COMMUNICATION](processes/COMPONENT_COMMUNICATION.md): how components talk to each other.
- [USER_FLOWS](processes/USER_FLOWS.md): end-to-end user flows.
