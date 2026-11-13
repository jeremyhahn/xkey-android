# Audit log architecture

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

## Entity Details

### AuditLogEntity (`audit_logs`)

Comprehensive security event log with 35+ operation types covering key lifecycle,
cryptographic operations, FIDO2 events, connection events, certificate operations,
file/media operations, contact management, and co-signing.

### Key-sharing transfers

Each transfer between the phone and a paired desktop records one entry with
`device_id` (the peer's static key, hex) and `device_name` (its pairing name).
No entry carries key material.

| Method | Operation type | Details |
|--------|----------------|---------|
| `local.importSharedKey` (a key leaves the phone) | `KEY_EXPORTED` | `format`: `raw` (software material), `metadata` (software key, no material), `public` (hardware key, public key only). A sharing-policy refusal records `success = false`. An unknown key records nothing. |
| `local.shareSymmetric` (material arrives) | `KEY_CREATED` | `algorithm`, `strongBox = false`, `source = shared`. A refused duplicate id records nothing. |
| `local.sharePublicKey` (a public key arrives) | `CONTACT_IMPORTED` | `name`, `fingerprint`, `source = shared`. A key already in contacts records nothing. |

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
