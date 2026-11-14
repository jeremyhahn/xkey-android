# Audit log architecture

> **Status: REFERENCE** · Last verified: 2026-11-12
> As-built description of the `audit_logs` table in the xKey Room database
> (`XKeyDatabase`, schema version 12).

## Entity Details

### AuditLogEntity (`audit_logs`)

Security event log with 59 operation types (`AuditOperationType`) covering key
lifecycle, cryptographic operations, FIDO2 events, pairing and connection
events, configuration, certificate operations, file/media operations, contact
management, OATH, co-signing, PIN and PIV.

Key attestation is among the recorded events: every `local.attestKey` the
phone answers writes one `KEY_ATTESTED` entry with the key id, label, type,
the attestation security level and the duration, and a keystore that returns
no certificate chain writes one failed `KEY_ATTESTED` entry before the
`ATTESTATION_FAILED` reply. A request refused before the keystore is asked
(missing parameters, a stale device attestation, a refused user-presence
check) records none.

Key-use requests write one entry per successful operation, naming the key,
the requesting device and the duration; the output and the inputs (data,
MAC, shared secret, peer key) are never logged:

| Request | Operation type | Writer |
|---------|----------------|--------|
| `local.sign` | `SIGNING_REQUEST` | `AuditLogger.logSigningRequest` |
| `local.hmac` (Keystore and software keys) | `HMAC_REQUEST` | `AuditLogger.logHmacRequest` |
| `local.ecdh` | `KEY_DERIVATION_REQUEST` | `AuditLogger.logKeyDerivationRequest` |

The entry's `keyType` is the type the key is stored with, never the
operation: the operation type already names the operation, and the audit
screen filters by `keyType`. An ECDH on an EC key stored as `signing` is
recorded as `signing`; an HMAC as its key's stored type (the key row's,
else the software key's). A key with no stored metadata is recorded as
`unknown`. `RequestHandler.auditKeyType` is the one source of this value
for sign, decrypt, encrypt, HMAC and ECDH entries.

The entry's `algorithm` (in `details`) is the algorithm the operation ran,
never the key's stored metadata, which is not validated: the sign
request's algorithm (`signWithAlgorithm` refuses any other), the Keystore
HMAC's own MAC (`computeHMACWithAlgorithm`), the software HMAC's mapping
(`SoftwareKeyOps.hmacAlgorithm`: `HMAC-SHA512` or `HMAC-SHA256`), and
the RSA decrypt's OAEP parameters, named from the one explicit spec its
cipher is initialised with (`KeystoreManager.rsaOaepSpec`: SHA-256 OAEP
with SHA-1 MGF1, passed explicitly because the MGF1 default differs by
provider, so the entry reads `RSA-OAEP-SHA-256-MGF1-SHA-1`; JOSE
`RSA-OAEP-256` would mean SHA-256 for both), and `AES-GCM` and `ECDH` for the fixed transformations.
`RequestHandler.logKeyUse` writes every key-use entry;
`AuditKeyTypeChokePointTest` fails on a writer outside it.

The entry's `deviceId` and `deviceName` name the desktop that sent the
request: each key-use handler captures it once with
`RequestHandler.auditCaller` (the peer of the session the request arrived
on) before any prompt or crypto call, and `logKeyUse` takes the device from
that capture alone. The handler-wide connected device is never used: a
second desktop confirming over another transport overwrites it while the
first request is still running. The same scan test fails on a call that
passes its own device or captures the caller late.

### Key-sharing transfers

Each transfer between the phone and a paired desktop records one entry with
`device_id` (the peer's static key, hex) and `device_name` (its pairing name).
No entry carries key material.

| Method | Operation type | Details |
|--------|----------------|---------|
| `local.importSharedKey` (a key leaves the phone) | `KEY_EXPORTED` | `format`: `raw` (software material), `metadata` (software key, no material), `public` (hardware key, public key only). A sharing-policy refusal records `success = false`. Granted or refused, `keyType` is the key's stored type (`RequestHandler.auditKeyType`), never the format. An unknown key records nothing. |
| `local.shareSymmetric` (material arrives) | `KEY_CREATED` | `algorithm`, `strongBox = false`, `source = shared`. A refused duplicate id records nothing. |
| `local.sharePublicKey` (a public key arrives) | `CONTACT_IMPORTED` | `name`, `fingerprint`, `source = shared`. A key already in contacts records nothing. |

An arriving key's write and its entry run together, outside cancellation
(`persistAudited` in `RequestHandler`). If the connection drops mid-write,
the stored key still gets its entry. A request cancelled before the write,
or already cancelled when it reaches it, stores and records nothing. The
device name comes from `auditPeerName`, which every audit record uses: when
the paired-device store cannot be read the entry still lands, with a null
`device_name`.

### Sync events

Operation types are stored by name (the type converter in `XKeyDatabase.kt`),
so a new type needs no migration.

| Operation type | Logger | Recorded when | Details |
|----------------|--------|---------------|---------|
| `OATH_SYNC_PERFORMED` | `AuditLogger.logOathSyncPerformed` | each `local.syncOATH` (`RequestHandler.handleSyncOATH`) and `remote.syncOATH` (`RemoteSyncClient.syncOath`) | `direction` (`inbound` / `outbound`), `credentialCount` (sent to the peer), `added`, `updated`, `skipped` |
| `PASSWORD_SYNC_PERFORMED` | `AuditLogger.logPasswordSyncPerformed` | each `local.syncPasswords` (`RequestHandler.handleSyncPasswords`) and `remote.syncPasswords` (`RemoteSyncClient.syncPasswords`) | `direction`, `passwordCount` (sent to the peer), `added`, `updated`, `skipped`; never a password, site or user name |

A failed sync, a locked password vault included, records one entry with
`success = false` and `error_message` set, and zero merge counts. Its count is
0 when nothing reached the peer; an outbound sync whose local merge fails after
the desktop answered keeps the count the desktop acknowledged. `device_id` and `device_name` name
the desktop. Both inbound handlers audit through one path
(`RequestHandler.auditedInboundSync`): the id is the peer of the request's own
connection, never the phone's last served desktop, so two desktops syncing at
once each get their own entry; and `device_name` is null when the paired-device store cannot be read, so the
sync still runs and is audited. See [store-sync](../store-sync/architecture.md#audit).

## Index Strategy

### audit_logs

| Index | Columns | Unique | Purpose |
|-------|---------|--------|---------|
| `index_audit_logs_timestamp` | `timestamp` | No | Chronological queries and recent activity |
| `index_audit_logs_operation_type` | `operation_type` | No | Filter by operation category |
| `index_audit_logs_key_id` | `key_id` | No | Audit trail for specific key |
| `index_audit_logs_key_type` | `key_type` | No | Aggregate by key type |
| `index_audit_logs_device_id` | `device_id` | No | Device-specific audit trail |
| `index_audit_logs_success` | `success` | No | Filter failures for alerting |

## Views

### Audit screen (`AuditLogActivity`)

The full log: search, operation and key-type filters, date range, export to
JSON or CSV, and deletion.

### Recent activity on the home screen (`MainActivity`)

The Audit Log card on the home screen carries a Recent Activity section
(`layoutRecentActivity`). `MainActivity.observeRecentActivity` collects
`AuditLogDao.observeRecent(RecentActivityRows.DEFAULT_LIMIT)` (5 entries,
uses `index_audit_logs_timestamp`) while the activity is started and
redraws the section on every change. Tapping the card opens the audit
screen.

`RecentActivityRows.build` (pure, JVM-tested in `RecentActivityRowsTest`)
maps the entries to rows, newest first, at most the limit:

- the operation label, from `AuditOperationLabels`, the same mapping the
  audit screen uses for its badges and filter chips;
- the key's label: the stored key's label for the entry's key id, else
  the logged label. Every candidate passes one filter inside
  `RecentActivityRows` that drops a blank value or a raw key id (the
  entry's own or any stored key's; keys created without a label and
  discovered general keys store their id as the label), falling back to
  no key text. `MainActivity` renders only the row's `keyLabel`. Never
  the key id or the `details` JSON;
- the outcome (succeeded or failed; a failure is drawn in the error colour);
- how long ago, against an injected `java.time.Clock`: just now, minutes,
  hours or days.

No entries give a single "No recent activity" row.

## Retention

### Retention policy

`AuditLogger` applies two limits:

| Limit | Constant | Value | DAO call |
|-------|----------|-------|----------|
| Age | `AuditLogger.DEFAULT_RETENTION_MS` | 90 days | `deleteOlderThan(now - 90 days)` |
| Count | `AuditLogger.MAX_ENTRIES` | 10,000 entries | `deleteExceedingCount(10_000)` |

The policy runs once per process, when `AuditLogger.initialize` first sets up
the logger at application start. It runs in the background on
`Dispatchers.IO`; a failure is logged and does not stop logging. The age limit
runs first, then the count limit, so the count applies to what is left.

- `deleteOlderThan(cutoff)` deletes entries with `timestamp < cutoff`
  (an entry exactly at the cutoff stays) and returns the number deleted.
- `deleteExceedingCount(n)` keeps the `n` newest entries by `timestamp` and
  deletes the rest, returning the number deleted. When entries tie on the
  timestamp at the limit, exactly `n` stay; which of the tied entries stay is
  not specified.

Neither limit is configurable.

### The audit screen's purge

The audit log screen (`AuditLogActivity`) has its own "delete older" action.
After a confirmation dialog it calls `deleteOlderThan(now - 30 days)` and
shows the number deleted. This is a manual purge, separate from the 90-day
policy, and it does not change the policy's limits. The screen's "clear all"
action calls `deleteAll()`.

### Tests

- `AuditRetentionConstantsTest` (JVM) pins the two constants above.
- `AuditRetentionTest` and `AuditLogDaoTest` (instrumented, in-memory
  `XKeyDatabase`) cover both DAO calls, tied timestamps, and the policy's two
  calls with the constants.
