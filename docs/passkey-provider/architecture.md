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

## Entity Details

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

### CredentialMetadataEntity (`credential_metadata`)

Legacy FIDO2 credential table retained for backward compatibility with the
Credential Provider service. New FIDO2 credentials are also stored in `keys`.
Data was migrated from this table in MIGRATION_1_2.
