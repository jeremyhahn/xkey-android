# Certificate authority architecture

> **Status: REFERENCE** · Last verified: 2026-11-12
> As-built description of the certificate table in the xKey Room schema (`XKeyDatabase.kt`, version 12; the table was added in v6). The full schema and migration history are in [hardware-backed-keys](../hardware-backed-keys/architecture.md#migration-history).

## Entity Details

### CertificateEntity (`certificates`)

X.509 certificates issued by the local Android CA. Tracks certificate lifecycle
including issuance, revocation, and expiration.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key, auto-generated |
| `serial_number` | TEXT | Unique |
| `subject_dn` | TEXT | |
| `issuer_dn` | TEXT | |
| `not_before` | INTEGER | Epoch milliseconds |
| `not_after` | INTEGER | Epoch milliseconds |
| `profile` | TEXT | Certificate profile |
| `fingerprint` | TEXT | |
| `certificate_pem` | TEXT | |
| `chain_pem` | TEXT | Nullable |
| `key_id` | TEXT | Nullable; the `keys.key_id` of the certified key |
| `device_id` | TEXT | Nullable |
| `revoked` | INTEGER (boolean) | Default false |
| `revoked_at` | INTEGER | Nullable |
| `revoked_reason` | INTEGER | Nullable |
| `is_ca` | INTEGER (boolean) | Default false |
| `created_at` | INTEGER | Epoch milliseconds |

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
