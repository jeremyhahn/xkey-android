# Audit log architecture

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

## Entity Details

### AuditLogEntity (`audit_logs`)

Comprehensive security event log with 35+ operation types covering key lifecycle,
cryptographic operations, FIDO2 events, connection events, certificate operations,
file/media operations, contact management, and co-signing.

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
