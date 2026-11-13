# Audit log architecture

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

## Entity Details

### AuditLogEntity (`audit_logs`)

Comprehensive security event log with 35+ operation types covering key lifecycle,
cryptographic operations, FIDO2 events, connection events, certificate operations,
file/media operations, contact management, and co-signing.

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
