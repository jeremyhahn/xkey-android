# Audit log architecture

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

## Entity Details

### AuditLogEntity (`audit_logs`)

Comprehensive security event log with 35+ operation types covering key lifecycle,
cryptographic operations, FIDO2 events, connection events, certificate operations,
file/media operations, contact management, and co-signing.

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
the desktop. See [store-sync](../store-sync/architecture.md#audit).

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
