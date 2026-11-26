# Passkey provider architecture

> **Status: REFERENCE** · Last verified: 2026-11-24
> As-built description of xKey's Android Credential Provider service.

## Summary

`XKeyCredentialService` is an Android 14 (API 34) `CredentialProviderService`.
It lets xKey create and use passkeys for browsers and apps, which helps on
devices without a platform passkey provider, such as GrapheneOS.
`res/xml/credential_provider_meta.xml` declares one capability,
`androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL`. Every class here is
`@RequiresApi(34)`.

Passkeys are ES256 keys in the Android Keystore. Their metadata is kept in
the `credential_metadata` table and copied to the `keys` table as a `fido2`
row, so the phone backend (`local.signFido2Assertion`) and the Passkeys screen
see the same passkeys.

## Components

All paths are under `app/src/main/kotlin/com/automatethethings/xkey/credential/`.

| Component | File | Role |
|-----------|------|------|
| `XKeyCredentialService` | `XKeyCredentialService.kt` | Answers the begin create and begin get calls through the enable gate; `onClearCredentialStateRequest` does nothing |
| `CreateCredentialHandler` | `handler/CreateCredentialHandler.kt` | Begin phase: one `CreateEntry`. Final phase: makes the key, stores metadata, builds the attestation response |
| `GetCredentialHandler` | `handler/GetCredentialHandler.kt` | Begin phase: matching `PublicKeyCredentialEntry` items. Final phase: signs the assertion |
| `CredentialPendingIntentHelper` | `handler/CredentialPendingIntentHelper.kt` | Builds the PendingIntents that open `CredentialSelectorActivity` |
| `BrowserAllowlist` | `handler/BrowserAllowlist.kt` | Privileged browser list passed to `CallingAppInfo.getOrigin` |
| `CredentialSelectorActivity` | `ui/CredentialSelectorActivity.kt` | Runs the final phase, the user verification prompt and the result intent |
| `UvRequirement`, `UserVerificationCompliance` | `UserVerificationCompliance.kt` | Parses `userVerification`, refuses or allows an unverified ceremony, and builds the flag byte |
| `RelyingPartyOrigin` | `RelyingPartyOrigin.kt` | Checks that the RP ID fits the caller's verified origin |
| `PasskeySignCounter` | `PasskeySignCounter.kt` | The one signature counter shared with the phone backend |
| `CredentialProviderSettingsRepository`, `CredentialProviderEnableGate` | `CredentialProviderSettings.kt` | The enable switch |
| `CredentialProviderException` and subclasses | `Errors.kt` | `InvalidRequestException`, `NoCredentialsFoundException`, `CredentialCreationException`, `CredentialAssertionException` and others |

## Create flow

1. `onBeginCreateCredentialRequest` accepts only a
   `BeginCreatePublicKeyCredentialRequest`. It answers one `CreateEntry` named
   after the user's display name, described "Create passkey for <rp name>".
2. When the user picks it, `CredentialSelectorActivity` prompts for user
   verification (title "Create xKey Credential"), then calls
   `handleCreateCredential` with whether the user was verified.
3. The handler reads `rp`, `user` and `pubKeyCredParams`; a missing member is
   an `InvalidRequestException`. The request must offer ES256 (COSE -7).
4. If the caller gave no `clientDataHash`, the handler writes
   `clientDataJSON` itself (see Origin checks).
5. It applies the user verification rule (below). A credential in
   `excludeCredentials` that is stored for the same RP ID fails the request.
6. It makes a 32-byte random credential id and a Keystore key with
   `generateKeyWithAuthDuration`. The auth duration follows
   `userVerification`: `required` needs authentication for every use,
   `preferred` allows 5 seconds, `discouraged` binds no authentication. With no
   strong biometric or device credential enrolled the key is never auth-bound.
   StrongBox is not required for this key.
7. It inserts the `credential_metadata` row (if that fails, the key is
   deleted) and a `keys` row with `key_type` `fido2`, `biometricRequired` true
   only when the key really is auth-bound, `exportable` and `shareable` false.
   A failed `keys` insert is logged and ignored.
8. It audits the registration (`AuditLogger.logFido2Registration`) and answers
   a `none` attestation: a zero AAGUID, the flags UP, AT and UV (UV only when
   verified), counter 0, the COSE key, the SPKI public key, and `transports`
   `["internal"]`. The key is discoverable when `residentKey` is `required` or
   `preferred` (the default).

## Get flow

1. `onBeginGetCredentialRequest` looks at each
   `BeginGetPublicKeyCredentialOption`. With a non-empty `allowCredentials` it
   offers the RP's credentials in that list. Otherwise it offers the RP's
   discoverable credentials.
2. When the user picks one, `CredentialSelectorActivity` calls
   `handleGetCredential` straight away. Any prompt comes from the handler.
3. The handler loads the credential (`NoCredentialsFoundException` if gone)
   and refuses a request whose `rpId` differs from the stored one.
4. It builds `clientDataJSON` itself when the caller gave no hash, as on create.
5. It decides user verification before building authenticator data, because
   the UV bit is signed. Verification happens when the key is auth-bound, or
   when the RP asks `required` or `preferred` and a biometric is available.
6. A verified assertion runs in one turn of the prompt queue
   (`BiometricHelper.inOneTurn`). For a key that is not auth-bound it first
   shows an explicit prompt, so UV=1 is never claimed for a silent signature.
   An unverified assertion uses `signWithoutBiometric`; if the key turns out
   to be auth-bound the assertion fails instead of signing.
7. The counter comes from `PasskeySignCounter.next` inside the signing step.
   The signature covers `authenticatorData || clientDataHash`.
8. It records use in `keys`, audits the sign-in
   (`AuditLogger.logFido2Authentication`) and answers `authenticatorData`,
   `signature`, `userHandle` and, when it built one, `clientDataJSON`.

The activity reports any failure as `CreateCredentialUnknownException` or
`GetCredentialUnknownException` with the exception's message, and a
dismissed prompt as `CreateCredentialInterruptedException` or
`GetCredentialInterruptedException`.

## User verification

The selector prompt accepts `BIOMETRIC_STRONG` or `DEVICE_CREDENTIAL`. With
neither enrolled, the ceremony goes on unverified. `UvRequirement.fromJson`
reads `required` and `discouraged`; anything else is `preferred`.

`UserVerificationCompliance.enforce` fails a ceremony whose RP required
verification when none took place, while "strict user verification"
(`BiometricSettingsRepository`) is on. With it off the ceremony goes on with
UV=0 and a warning in the log. The UV flag always reports what happened.

## Origin checks

When the caller supplies `clientDataHash`, the browser has written
`clientDataJSON` and the handler signs over that hash. When it does not, the
handler builds `clientDataJSON` (`type`, `challenge`, `origin`,
`crossOrigin` false). The origin must come from
`CallingAppInfo.getOrigin(BrowserAllowlist.PRIVILEGED_BROWSERS)`; a caller with
no verified origin is refused. `RelyingPartyOrigin.isRpIdValidForOrigin` then
requires the RP ID to equal the origin's host or be a suffix of it. Only
`https` origins, and `http://localhost`, qualify.

`BrowserAllowlist` lists Chrome (stable, beta, dev, canary), Firefox (release,
beta, Fenix nightly), Samsung Internet, Microsoft Edge and Vanadium, each with
its SHA-256 signing certificate fingerprint.

## Signature counter

`PasskeySignCounter.next(credentialId)` holds a per-credential mutex shared
across the process. It reads `credential_metadata.sign_count` and
`keys.sign_count`, writes max + 1 to both and returns it. The phone backend
uses the same counter, so the relying party sees one count that rises
whichever path signed. The counter advances before signing, so a failed
signature leaves a gap but never reuses a value. If the count cannot be
stored, the assertion fails before anything is signed.

## The enable switch

Settings > Passkey provider stores `credential_provider_enabled` in the
`credential_provider_settings` DataStore
(`CredentialProviderSettingsRepository`). It is off when nothing is stored.
The user turns it on in xKey, then selects xKey in the system credential
provider settings.

The service reads the switch before every begin request through
`CredentialProviderEnableGate`. While it is off, both begin calls answer an
empty response and the handlers are not called, so the system picker shows no
xKey entry and the final phase cannot be reached. Turning it back on takes
effect on the next request. Stored passkeys are kept either way.

## Tables

The passkey tables are in the Room schema of `XKeyDatabase.kt`, version 13.
The full schema and migration history are in
[hardware-backed-keys](../hardware-backed-keys/architecture.md#migration-history).

### `credential_metadata` (`CredentialMetadataEntity`)

The table the provider reads. New passkeys are also written to `keys`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key, auto-generated |
| `credential_id` | TEXT | Unique; base64url |
| `rp_id` | TEXT | Relying party ID |
| `rp_name` | TEXT | Relying party name |
| `user_id` | TEXT | |
| `user_name` | TEXT | |
| `user_display_name` | TEXT | |
| `public_key_cose` | BLOB | COSE-encoded public key |
| `sign_count` | INTEGER | Entity default 0 |
| `created_at` | INTEGER | Epoch milliseconds |
| `last_used_at` | INTEGER | Epoch milliseconds |
| `is_discoverable` | INTEGER (boolean) | Entity default true |

Every column is NOT NULL. The defaults are those of the Kotlin entity.

| Index | Columns | Unique |
|-------|---------|--------|
| `index_credential_metadata_credential_id` | `credential_id` | Yes |
| `index_credential_metadata_rp_id` | `rp_id` | No |
| `index_credential_metadata_user_id_rp_id` | `user_id`, `rp_id` | No |

### Passkey columns in `keys` (`KeyEntity`)

The `fido2` rows in `keys` carry the same relying party and user columns:
`rp_id`, `rp_name`, `user_id`, `user_name` and `user_display_name` (all
nullable), plus `is_discoverable` and `sign_count` (NOT NULL, entity defaults
false and 0).

## Tests

- Unit (`app/src/test`): `CredentialProviderEnableGateTest`, `CredentialProviderErrorsTest`, `CredentialsLibraryUpgradeTest`, `CredentialSelectorRotationTest`, `PasskeySignCounterTest`, `PasskeySignCounterHandlerTest`, `CredentialMetadataEntityTest`.
- Instrumented (`app/src/androidTest`): `CreateCredentialHandlerTest`, `GetCredentialHandlerTest`, `CredentialHandlerResidueTest`, `CredentialProviderSettingsRepositoryTest`, `CredentialSelectorActivityTest`, `WebAuthnE2ETest` (drives the system picker and turns the switch on in its setup).
