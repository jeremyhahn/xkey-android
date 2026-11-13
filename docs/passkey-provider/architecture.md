# Passkey provider architecture

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of xKey's Android Credential Provider service.

## Service Layer

### XKeyCredentialService

Android Credential Provider service for FIDO2/WebAuthn passkey operations.
Handles `CreateCredentialRequest` and `GetCredentialRequest` from the system
credential manager.

### Signature counter

`GetCredentialHandler.handleGetCredential` takes the assertion's signature
counter from `PasskeySignCounter.next(credentialId)` before it builds
authenticator data. The phone backend (`local.signFido2Assertion`) serves the
same passkeys and takes its counter from the same place, so the relying
party sees one counter that rises whichever path signed. `next` holds a
per-credential mutex shared across the process. It reads
`credential_metadata.sign_count` and `keys.sign_count` and writes max + 1 to
both before it returns. The counter advances before signing, so a failed
signature leaves a gap but never reuses a value. The handler no longer
writes `sign_count` itself.

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

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

### CredentialMetadataEntity (`credential_metadata`)

Legacy FIDO2 credential table retained for backward compatibility with the
Credential Provider service. New FIDO2 credentials are also stored in `keys`.
Data was migrated from this table in MIGRATION_1_2.
