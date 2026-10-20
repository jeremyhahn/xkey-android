# Certificate authority architecture

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

## Entity Details

### CertificateEntity (`certificates`)

X.509 certificates issued by the local Android CA. Tracks certificate lifecycle
including issuance, revocation, and expiration.

## Index Strategy

### certificates

| Index | Columns | Unique | Purpose |
|-------|---------|--------|---------|
| `index_certificates_serial_number` | `serial_number` | Yes | Unique certificate lookup |
| `index_certificates_profile` | `profile` | No | Filter by certificate profile |
| `index_certificates_key_id` | `key_id` | No | Find certificates for a key |
| `index_certificates_revoked` | `revoked` | No | Filter active vs revoked |
| `index_certificates_not_after` | `not_after` | No | Expiration monitoring |
| `index_certificates_is_ca` | `is_ca` | No | Find CA certificates |
| `index_certificates_fingerprint` | `fingerprint` | No | Certificate fingerprint lookup |
