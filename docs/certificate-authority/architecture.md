# Certificate authority architecture

> Status: reference. Last checked against main on 2026-11-23.
> This page describes the phone's local X.509 certificate authority: its keys,
> what it issues, where certificates are stored, and the screens that drive it.
> Validity and revocation rules are in [engineering.md](engineering.md).

## Overview

`AndroidCA` (`app/src/main/kotlin/com/automatethethings/xkey/ca/AndroidCA.kt`)
is a two-level CA that runs on the phone. The root signs one intermediate, and
the intermediate signs every issued certificate.

| Level | Keystore alias | Key | Validity | Subject CN |
|-------|----------------|-----|----------|------------|
| Root | `xkey_root_ca` | EC P-256, SHA256withECDSA | 10 years, self-signed | `xKey Root CA` |
| Intermediate | `xkey_intermediate_ca` | EC P-256, SHA256withECDSA | 5 years, signed by the root | `xKey Intermediate CA` |

Both keys are generated in the Android Keystore with `PURPOSE_SIGN` and
`PURPOSE_VERIFY` and no user authentication. `generateCAKey` asks for
StrongBox first. If that fails it deletes any half-created entry and
generates the key in the TEE. The CA certificates are kept as DER in the
SharedPreferences file `xkey_ca`, and each is also written to the
`certificates` table with profile `ca-root` or `ca-intermediate`.

`reset()` deletes both Keystore entries and the stored CA certificates. Rows
in the `certificates` table stay.

## Who uses it

- Settings (`ui/SettingsActivity.kt`) generates the root (`generateRootCA`)
  and then the intermediate (`generateIntermediateCA`), imports each into the
  trust store, shows their details, and resets the CA.
- Certificate management (`ui/CertificateManagementActivity.kt`) creates a CSR
  for a Keystore key (`createCSR`) and issues a certificate for it under a
  chosen profile (`issueCertificate`). It needs an initialised CA.
- Certificate detail (`ui/CertificateDetailActivity.kt`) shows a certificate,
  builds its chain from the CA certificates, and revokes it through
  `CertificateDao.revoke`. The management screen can revoke from its list
  the same way.
- The trust store screen (`ui/TrustStoreActivity.kt`) lists the CA
  certificates.
- Post-pairing enrollment in `ble/GattServer.kt` issues IAK and IDevID
  certificates to a paired desktop through `issueForPublicKey` with the
  `idevid` profile, and returns them with `getCABundle()` as the chain over
  `remote.storeEnrollmentCerts`. It runs only when trusted computing is
  enabled and the certificate authority setting
  (`CertificateAuthoritySource` in `settings/TrustedComputingSettings.kt`) is
  `THIS_DEVICE`. With `XKMS` the desktop enrolls against that server, and
  with `NONE` nothing is issued. `XKeyGattService` builds the `AndroidCA`
  for this with the certificate DAO attached.

Every issuance path (`issueCertificate`, `issueIDevIDCertificate`, `signCSR`,
`issueCertificateWithProfile`) goes through `issueForPublicKey`.

## Profiles

`CertificateProfile` (`ca/CertificateProfile.kt`) sets key usage, extended key
usage and default validity.

| Profile | `profileName` | Default validity (days) |
|---------|---------------|-------------------------|
| `IDevID` | `idevid` | 365 |
| `TLSServer` | `tls-server` | 365 |
| `TLSClient` | `tls-client` | 365 |
| `CodeSigning` | `code-signing` | 365 |
| `Email` | `email` | 365 |
| `OCSPResponder` | `ocsp-responder` | 90 |
| `Timestamping` | `timestamping` | 365 |
| `SubordinateCA` | `subordinate-ca` | 1825 |

No certificate outlives the intermediate that signs it (see
[engineering.md](engineering.md#certificate-validity)).

## Wire methods

`MethodNames` in `protocol/Messages.kt` defines `local.getCABundle`,
`local.getIDevIDCertificate` and `local.requestIDevIDIssuance`, with
parameter and result types, but `RequestHandler` does not route them. A
request for any of them gets `ErrorCodes.METHOD_NOT_FOUND`. The CA is
reached only through the screens and the enrollment flow above.

## SSH certificates

`ca/SSHCertificateAuthority.kt` builds OpenSSH user and host certificates. No
screen, RPC or service calls it on main.

## Storage

### CertificateEntity (`certificates`)

Certificates issued by the local CA and the CA's own certificates. The entity
lives in `ca/CertificateEntity.kt` and the DAO in `ca/CertificateDao.kt`. The
table was added in database version 6. The full schema and migration history
are in
[hardware-backed keys](../hardware-backed-keys/architecture.md#migration-history).

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key, auto-generated |
| `serial_number` | TEXT | Hex serial, unique |
| `subject_dn` | TEXT | |
| `issuer_dn` | TEXT | |
| `not_before` | INTEGER | Epoch milliseconds |
| `not_after` | INTEGER | Epoch milliseconds |
| `profile` | TEXT | Profile name, or `ca-root` / `ca-intermediate` |
| `fingerprint` | TEXT | SHA-256, hex |
| `certificate_pem` | TEXT | |
| `chain_pem` | TEXT | Nullable |
| `key_id` | TEXT | Nullable; the `keys.key_id` of the certified key |
| `device_id` | TEXT | Nullable |
| `revoked` | INTEGER (boolean) | Default false |
| `revoked_at` | INTEGER | Nullable |
| `revoked_reason` | INTEGER | Nullable; RFC 5280 CRLReason code |
| `is_ca` | INTEGER (boolean) | Default false |
| `created_at` | INTEGER | Epoch milliseconds |

| Index | Columns | Unique | Purpose |
|-------|---------|--------|---------|
| `index_certificates_serial_number` | `serial_number` | Yes | Lookup by serial |
| `index_certificates_profile` | `profile` | No | Filter by profile |
| `index_certificates_key_id` | `key_id` | No | Certificates for a key |
| `index_certificates_revoked` | `revoked` | No | Active or revoked |
| `index_certificates_not_after` | `not_after` | No | Expiry checks |
| `index_certificates_is_ca` | `is_ca` | No | CA certificates |
| `index_certificates_fingerprint` | `fingerprint` | No | Lookup by fingerprint |

## Tests

Unit tests in `app/src/test/kotlin/com/automatethethings/xkey/ca/`, among
them `CertificateValidityTest`, `AndroidCAIssuanceValidityTest`,
`AndroidCARevocationTest`, `AndroidCACertificateStoreTest` and
`CertificateProfileTest`.
