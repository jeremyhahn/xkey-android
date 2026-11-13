# Passkey provider architecture

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of xKey's Android Credential Provider service.

## Service Layer

### XKeyCredentialService

Android Credential Provider service for FIDO2/WebAuthn passkey operations.
Handles `CreateCredentialRequest` and `GetCredentialRequest` from the system
credential manager.

### The enable switch

Settings > Passkey provider stores one value, `credential_provider_enabled`,
in the `credential_provider_settings` DataStore
(`CredentialProviderSettingsRepository`). It is **off** when nothing is
stored: the user turns it on in xKey, then selects xKey in the system
credential provider settings.

The service reads the switch before every begin request, through
`CredentialProviderEnableGate`. While it is off, `onBeginCreateCredentialRequest`
answers an empty `BeginCreateCredentialResponse` (no create entries) and
`onBeginGetCredentialRequest` an empty `BeginGetCredentialResponse` (no
credential entries, even for a relying party with stored passkeys); the
handlers are not called, so nothing is looked up and no PendingIntent is
built. The system picker then shows no xKey entry, and with no entry offered
the final create and get calls cannot be reached. Turning the switch back on
takes effect on the next request; stored passkeys are kept either way.

Instrumented tests that drive the service through the system picker
(`WebAuthnE2ETest`) turn the switch on in their setup and restore it after.

## Entity Details

> **Status: REFERENCE** · Last verified: 2026-11-12
> As-built description of the passkey tables in the xKey Room schema (`XKeyDatabase.kt`, version 12). The full schema and migration history are in [hardware-backed-keys](../hardware-backed-keys/architecture.md#migration-history).

### CredentialMetadataEntity (`credential_metadata`)

Legacy FIDO2 credential table retained for backward compatibility with the
Credential Provider service. New FIDO2 credentials are also stored in `keys`.
Data was migrated from this table in MIGRATION_1_2.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key, auto-generated |
| `credential_id` | TEXT | Unique |
| `rp_id` | TEXT | Relying party ID |
| `rp_name` | TEXT | Relying party name |
| `user_id` | TEXT | |
| `user_name` | TEXT | |
| `user_display_name` | TEXT | |
| `public_key_cose` | BLOB | COSE-encoded public key |
| `sign_count` | INTEGER | Entity default `0` |
| `created_at` | INTEGER | Epoch milliseconds |
| `last_used_at` | INTEGER | Epoch milliseconds |
| `is_discoverable` | INTEGER (boolean) | Entity default true |

Every `credential_metadata` column is NOT NULL. The defaults are those of the
Kotlin entity; the v12 schema sets no SQL default on these columns.

### Passkey columns in `keys` (`KeyEntity`)

The FIDO2 rows in `keys` (`key_type = 'fido2'`) carry the same relying party
and user columns:

| Column | Type | Null | Notes |
|--------|------|------|-------|
| `rp_id` | TEXT | Nullable | Relying party ID; null for non-FIDO2 keys |
| `rp_name` | TEXT | Nullable | Relying party name |
| `user_id` | TEXT | Nullable | |
| `user_name` | TEXT | Nullable | |
| `user_display_name` | TEXT | Nullable | |
| `is_discoverable` | INTEGER (boolean) | NOT NULL | Entity default false |
| `sign_count` | INTEGER | NOT NULL | Entity default `0` |

As in `credential_metadata`, the defaults are the Kotlin entity's; the v12
schema sets no SQL default on `is_discoverable` or `sign_count`.

## Index Strategy

### credential_metadata

| Index | Columns | Unique | Purpose |
|-------|---------|--------|---------|
| `index_credential_metadata_credential_id` | `credential_id` | Yes | Credential lookup by ID |
| `index_credential_metadata_rp_id` | `rp_id` | No | Credentials for a relying party |
| `index_credential_metadata_user_id_rp_id` | `user_id`, `rp_id` | No | A user's credentials at a relying party |
