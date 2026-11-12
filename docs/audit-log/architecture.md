# Audit log architecture

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

## Entity Details

### AuditLogEntity (`audit_logs`)

Comprehensive security event log with 35+ operation types covering key lifecycle,
cryptographic operations, FIDO2 events, connection events, certificate operations,
file/media operations, contact management, and co-signing.

Key attestation is among the recorded events: every `local.attestKey` the
phone answers writes one `KEY_ATTESTED` entry with the key id, label, type,
the attestation security level and the duration, and a keystore that returns
no certificate chain writes one failed `KEY_ATTESTED` entry before the
`ATTESTATION_FAILED` reply. A request refused before the keystore is asked
(missing parameters, a stale device attestation, a refused user-presence
check) records none.

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
