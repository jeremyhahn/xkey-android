# Store sync architecture

> **Status: REFERENCE** · Last verified: 2026-11-12
> As-built description of how xKey synchronizes its trust store, OATH credentials and passwords with a paired desktop.

## Summary

One class, `SyncEngine`, gathers (exports) and merges (imports) the three
synced stores: the trust store, OATH credentials and passwords. Both
directions use it:

- **Inbound** (`local.sync*`, desktop to phone): `RequestHandler` merges the
  desktop's items, then returns the phone's items in a `remote` array.
- **Outbound** (`remote.sync*`, phone to desktop): `RemoteSyncClient` sends the
  phone's items, then merges the desktop's reply, which comes back in a `local`
  array.

The DTO field names follow the go-xkms pairing contract
(`pkg/pairingproto/protocol_sync.go` at tag `xkey/v0.64.2-alpha`:
`SyncCertificate`, `SyncOATHCredential`, `SyncPassword`,
`RemoteSyncStatusResult`).

## Components

| Class | File | Role |
|-------|------|------|
| `SyncEngine` | `app/src/main/kotlin/com/automatethethings/xkey/sync/SyncEngine.kt` | Gather and merge for each store (`gatherCertificates`, `mergeCertificates`, `gatherOath`, `mergeOath`, `gatherPasswords`, `mergePasswords`), plus status (`deviceId`, `storeChecksums`, `lastSyncRfc3339`, `markSynced`) |
| `PasswordSync` | `app/src/main/kotlin/com/automatethethings/xkey/sync/PasswordSync.kt` | Password gather and merge, behind the password vault's lock (see [password-vault](../password-vault/architecture.md)) |
| `RemoteSyncClient` | `app/src/main/kotlin/com/automatethethings/xkey/remote/RemoteSyncClient.kt` | Phone-initiated sync: `syncAll`, `syncTrustStore`, `syncOath`, `syncPasswords`; the desktop's status: `syncStatus` (`DesktopSyncStatus`) |
| `RequestHandler` | `app/src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt` | Inbound handlers `handleSyncTrustStore`, `handleSyncOATH`, `handleSyncPasswords`, `handleSyncStatus` |
| `XKeyGattService` | `app/src/main/kotlin/com/automatethethings/xkey/ble/XKeyGattService.kt` | `syncNow()` builds the client from `connectedDesktop()` (BLE, then TCP, then USB; the sender is bound to that desktop's session) and runs `RemoteSyncClient.syncAll()`; `desktopSyncStatus()` runs `RemoteSyncClient.syncStatus()` |
| `MainActivity` | `app/src/main/kotlin/com/automatethethings/xkey/ui/MainActivity.kt` | Calls `syncNow()`, then `desktopSyncStatus()`, from the Sync with Desktop card |
| `SyncStatusText` | `app/src/main/kotlin/com/automatethethings/xkey/ui/SyncStatusText.kt` | The result line about the desktop's status: its last sync time in the phone's zone, never synced, or unavailable |
| `SyncCodec` | `app/src/main/kotlin/com/automatethethings/xkey/crypto/SyncCodec.kt` | PEM/DER conversion, RFC 3339 times, store checksums |
| `SyncStateRepository` | `app/src/main/kotlin/com/automatethethings/xkey/settings/SyncStateRepository.kt` | Stores the last successful sync time |
| `TrustStoreRepository` | `app/src/main/kotlin/com/automatethethings/xkey/truststore/TrustStoreRepository.kt` | The trust store read and written by the certificate leg |
| `OathRepository`, `OathSecretManager` | `app/src/main/kotlin/com/automatethethings/xkey/oath/` | The OATH store; secrets are decrypted for export and re-imported through an `otpauth://` URI |

## Wire methods

Method names are constants in `MethodNames` (`protocol/Messages.kt`).

| Method | Direction | Params | Result |
|--------|-----------|--------|--------|
| `local.syncTrustStore` | desktop to phone | `certificates` | `added`, `skipped`, `remote` |
| `local.syncOATH` | desktop to phone | `credentials` | `added`, `updated`, `skipped`, `remote` |
| `local.syncPasswords` | desktop to phone | `passwords` | `added`, `updated`, `skipped`, `remote` |
| `local.syncStatus` | desktop to phone | none | `last_sync`, `device_id`, `store_checksums` (`oath`, `passwords`, `trust_store`) |
| `remote.syncTrustStore` | phone to desktop | `certificates` | `local`, `added`, `updated` |
| `remote.syncOATH` | phone to desktop | `credentials` | `local`, `added`, `updated` |
| `remote.syncPasswords` | phone to desktop | `passwords` | `local`, `added`, `updated` |
| `remote.syncStatus` | phone to desktop | none (`{}`) | `last_sync` (RFC 3339, omitted when never synced), `device_id` (required), `store_checksums` (map of strings; `null` read as empty) |

`RemoteSyncClient.syncAll()` runs the three `remote.sync*` legs in turn.

### Why `remote.syncAll` is not sent

`MethodNames` defines `REMOTE_SYNC_ALL` (`remote.syncAll`), and the desktop
serves it, but the phone never sends it. go-xkms `RemoteSyncAllParams` carries
only the include flags (`include_trust_store`, `include_oath`,
`include_passwords`) and none of the phone's items, so the desktop could not
merge the phone's stores from it: it would be a pull, not a sync. Each
per-store `remote.sync*` call pushes the phone's items and pulls the desktop's
in one round trip, and lets the password leg be skipped on its own when the
vault is locked.

## Merge rules

- **Certificates:** skipped when the fingerprint is already in the trust store
  or the PEM does not decode; otherwise imported with the `purpose` field as its
  label (`sync` when blank).
- **OATH:** an entry without an id (or name), secret or `account_name` is
  skipped; the rest are imported through `OathRepository.importStructured`, counted
  as updated when the id already existed.
- **Passwords:** `PasswordSync.merge` patches an existing entry in place or adds
  a new personal, non-expiring entry in the default tenant. `PasswordSync.gather`
  leaves out entries with a non-default tenant, sharing or an expiry, because
  `SyncPassword` cannot carry them.
- **Status:** `storeChecksums` hashes OATH ids with counters, password ids with
  update times (read without decrypting a password) and trust-store
  fingerprints. It is not behind the password vault's lock.

## Main flow

```mermaid
sequenceDiagram
    actor User
    participant UI as MainActivity
    participant Svc as XKeyGattService
    participant RSC as RemoteSyncClient
    participant Eng as SyncEngine
    participant Desk as Desktop

    User->>UI: Sync now
    UI->>Svc: syncNow()
    Svc->>Svc: connectedDesktop()
    Svc->>RSC: syncAll()
    RSC->>Eng: gatherCertificates()
    RSC->>Desk: remote.syncTrustStore {certificates}
    Desk-->>RSC: {local, added, updated}
    RSC->>Eng: mergeCertificates(local)
    RSC->>Eng: gatherOath()
    RSC->>Desk: remote.syncOATH {credentials}
    Desk-->>RSC: {local, added, updated}
    RSC->>Eng: mergeOath(local)
    RSC->>Eng: gatherPasswords()
    Note over Eng: refused if the password vault is locked
    RSC->>Desk: remote.syncPasswords {passwords}
    Desk-->>RSC: {local, added, updated}
    RSC->>Eng: mergePasswords(local)
    RSC->>Eng: markSynced()
    RSC-->>UI: SyncResult (pushed / pulled per store)
    UI->>Svc: desktopSyncStatus()
    Svc->>RSC: syncStatus()
    RSC->>Desk: remote.syncStatus {}
    Desk-->>RSC: {last_sync, device_id, store_checksums}
    RSC-->>UI: DesktopSyncStatus
    UI->>User: sent / received, and the desktop's last sync time
```

The status request runs after the store legs and touches no phone store. A
failure there, including an unreadable reply (a missing `device_id` or a
wrongly typed field), is turned into no status by `SyncStatusText.fetch`: the
completed sync is still reported, with the desktop's status shown as unavailable. The
phone does not compare `store_checksums` with its own digests: the two sides'
digest inputs are not pinned to match.

The inbound flow is the mirror image: `RequestHandler` builds a `SyncEngine`,
calls the store's merge, then its gather, then `markSynced()`, and answers with
the counts and the `remote` array.

## Errors and refusals

- `syncNow()` throws `IllegalStateException` when no desktop is connected.
- `RemoteSyncClient` throws `ProtocolException` when the desktop returns an
  error, or with `ErrorCodes.INTERNAL_ERROR` when no reply arrives within
  `requestTimeoutMs` (30 s by default) or a `remote.syncStatus` reply is
  malformed.
- Request ids come from one counter shared by every `RemoteSyncClient`, so a
  status request from `desktopSyncStatus()` never reuses the id of a store leg
  still pending on the same router.
- A locked password vault throws `PasswordStoreLockedException` before anything
  is read or written. `syncAll()` catches it, logs it and still syncs the other
  stores. `handleSyncPasswords` answers `ErrorCodes.PASSWORD_STORE_LOCKED`
  (-32040).
- Any other failure in an inbound sync handler answers
  `ErrorCodes.INTERNAL_ERROR` with the method name in the message.
- `markSynced()` logs and ignores a failure to record the sync time.

## Audit

Every OATH and password sync, in either direction, records one audit entry,
success or failure (see [audit-log](../audit-log/architecture.md#sync-events)):

| Leg | Recorded by | Operation type | Device |
|-----|-------------|----------------|--------|
| `local.syncOATH` | `handleSyncOATH` | `OATH_SYNC_PERFORMED`, `direction` `inbound` | the peer of the connection the request arrived on (none when it authenticated no peer; the served peer only for a request that names no connection) and its paired name |
| `local.syncPasswords` | `handleSyncPasswords` | `PASSWORD_SYNC_PERFORMED`, `direction` `inbound` | as above |
| `remote.syncOATH` | `RemoteSyncClient.syncOath` | `OATH_SYNC_PERFORMED`, `direction` `outbound` | the client's `peerDeviceId` / `peerDeviceName` (null when the caller passes none; `XKeyGattService.syncNow` passes none yet) |
| `remote.syncPasswords` | `RemoteSyncClient.syncPasswords` | `PASSWORD_SYNC_PERFORMED`, `direction` `outbound` | as above |

A locked vault is recorded as a failed password entry, inbound and outbound
(`syncAll()` still syncs the other stores). Entries hold counts only, never a
secret, password, site or user name. Trust-store syncs record no entry yet.

## Tests

| Test class | Covers |
|------------|--------|
| `RemoteSyncClientTest` (`app/src/test/.../remote/`) | Outbound legs and push counts; `remote.syncStatus` params, result parsing and malformed replies; distinct ids for a status request beside a store leg; one outbound audit entry per OATH and password leg |
| `SyncAuditTest` (`app/src/test/.../protocol/`) | One inbound audit entry per `local.syncOATH` / `local.syncPasswords`, failures and a locked vault included; no password data in the entry |
| `RemoteClientInteropTest` (`app/src/test/.../remote/`) | Outbound client wire interop |
| `SyncEngineStatusTest`, `SyncEngineTrustStoreTest`, `PasswordSyncTest` (`app/src/test/.../sync/`) | Status checksums, certificate merge, password gather and merge |
| `SyncCodecTest` (`app/src/test/.../crypto/`) | Codec helpers |
| `SyncStatusTextTest` (`app/src/test/.../ui/`) | The desktop status line and its failure handling |
| `SyncEngineTest` (`app/src/androidTest/.../sync/`) | Engine on a device database |
| `SyncStateRepositoryTest` (`app/src/androidTest/.../settings/`) | Last-sync time |
| `BleSyncLoopbackTest` (`app/src/androidTest/.../ble/`) | `local.sync*` over the BLE loopback |
| `ProtocolIntegrationTest` (`app/src/androidTest/.../e2e/`) | `local.sync*` end to end |
| `RequestHandlerErrorPathTest` (`app/src/androidTest/.../protocol/`) | Sync handler error paths |

## Related features

- [password-vault](../password-vault/architecture.md): the lock that guards the password leg
- [trust-store-bootstrap](../trust-store-bootstrap/architecture.md): the trust store the certificate leg syncs
- [desktop-backup-store](../desktop-backup-store/architecture.md): backups over the same paired transports
- [noise-pairing](../noise-pairing/architecture.md): the paired session sync runs on
