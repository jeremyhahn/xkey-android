# Audit log architecture

> **Status: REFERENCE** · Last verified: 2026-11-12
> As-built description of the `audit_logs` table in the xKey Room database
> (`XKeyDatabase`, schema version 12).

## Entity Details

### AuditLogEntity (`audit_logs`)

Security event log with 58 operation types (`AuditOperationType`) covering key
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
