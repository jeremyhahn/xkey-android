# Password vault RPCs

> **Status: REFERENCE** · Last verified: 2026-11-24
> As-built contract of the `Password*` and `SealStore*` methods the desktop sends over USB.

`usb/PasswordStoreMethods.kt` and `usb/SealStoreMethods.kt` answer the
password-store and seal-store methods go-xkms proxies over the USB accessory
link. Their request and response shapes are those of go-xkms
`pkg/api/transport/types.go`; Go `[]byte` fields travel as standard base64.

`XKeyGattService` builds both, with one `PasswordVault`, each time a USB
accessory attaches while "Native USB Mode" is on. Neither is served over BLE
or TCP. Each response must fit one USB frame (`FrameBudget.RESULT_BUDGET`).

## Password methods

| Method | Needs the store unlocked | Request | Result |
|---|---|---|---|
| `PasswordAdd` | yes | `name` and `password` required; `title`, `username`, `url`, `notes`, `folder_path`, `expires_at`, `shared`, `tenant_id` | `id` (a new UUID), `name`, `created_at` |
| `PasswordGet` | yes | `id`, `tenant_id` | The entry, password included |
| `PasswordList` | yes | `folder_path`, `scope`, `tenant_id`, `page`, `page_size`, `sort_field`, `sort_order` | `passwords[]` without passwords, plus the page fields |
| `PasswordUpdate` | yes | `id`, `tenant_id`; any of `name`, `title`, `username`, `password`, `url`, `notes`, `folder_path`, `expires_at` | `{}` |
| `PasswordDelete` | yes | `id`, `tenant_id` | `{}` |
| `PasswordStoreUnlock` | no | A vault credential (below) | `{}` |
| `PasswordStoreLock` | no | none | `{}` |
| `PasswordStoreStatus` | no | none | `access_mode` `"local"`, `is_locked`, `barrier_sealed` and `auto_unsealed` (always false), `password_count` (0 while locked) |
| `PasswordGenerate` | no | `length`, `charset`, `upper`, `lower`, `digits`, `symbols` | `password` |

Passwords are encrypted at rest by `PasswordRepository`. Only a `PasswordGet`
response holds a plaintext password; a listing never decrypts one.

`sort_field` is one of `title`, `username`, `url`, `folder_path`,
`created_at` and `updated_at`; anything else sorts by `name`. `sort_order` 1
sorts descending.

### Lock and unlock

Once a factor is enrolled, every entry method answers `PASSWORD_STORE_LOCKED`
until `PasswordStoreUnlock` succeeds. Before any enrollment the store is open.
Each USB attach starts with a new `PasswordVault`, so a new connection starts
locked. `routingContext()` adds the session's vault to every request on that
link, so `local.syncPasswords` on the same link uses the same lock. See
[password-vault](../password-vault/architecture.md) for the lock check.

The `PasswordStoreUnlock` body is one factor's credential
(`PasswordVaultCredential`, go-xkms `transport.PasswordVaultCredential`):

- `{"factor":"passphrase","passphrase":"..."}`
- `{"factor":"passkey","credential_id":"<b64>","secret":"<b64>"}`, where
  `secret` is the 32-byte hmac-secret output; `prf_salt` is optional
- `{"factor":"piv"|"certificate"|"tpm","key_fingerprint":"...","secret":"<b64>"}`

The older `{"user_pin":...}` body is refused with `INVALID_PARAMS`: the device
PIN no longer unlocks the password store. Only a passphrase factor can match
today. Passkey and key credentials parse but are always rejected, because the
phone cannot enroll those factors yet. Nothing on main calls
`enrollPassphrase`, so no factor can be enrolled over any transport.

Failed unlocks are counted under the PIN settings
(`PinSettingsVaultUnlockAttemptStore`) and locked out by the same `PinLockout`
rule as the PINs, with the PIN's `maxPinAttempts` and
`lockoutDurationSeconds`. A successful unlock clears the count.

### Generate

`length` counts Unicode code points. Absent or 0 means 24; the most is 256.
With `charset`, every character comes from it, and a charset holding an
unpaired surrogate is refused. Without it, the characters come from the
selected classes (upper, lower, digits, symbols), all four when none is
selected, with at least one from each. A length shorter than the number of
classes is refused. The result is shuffled with `SecureRandom`.

## Policy fields

| Field | Requests | Stored as | Answered |
|---|---|---|---|
| `tenant_id` | Add, Get, List, Update, Delete | `passwords.tenant_id`, as sent; absent, null and `""` are the default tenant `""` | never |
| `shared` | Add | `passwords.shared`; absent, null and `false` are a personal entry | `true` only, omitted when false |
| `expires_at` | Add, Update | `passwords.expires_at`, normalized (below); absent, null and `""` on Add store none | when set |
| `scope` | List | not stored: a filter | never |

### Tenants

Every request reaches only its own tenant's entries. Get, Update and Delete of
an entry in another tenant answer `KEY_NOT_FOUND` "password not found", the
same as an unknown id, so a caller cannot tell another tenant's id exists.
An entry's tenant is fixed at Add; Update never moves it.

### Scope

`personal` lists entries with `shared` false, `shared` those with it true,
and `all`, absent, null or `""` lists both. Any other value, case included,
is `INVALID_PARAMS` "scope must be one of personal, shared, all".

The tenant, scope and `folder_path` are filtered in the query
(`PasswordDao.getForListing`), before sorting and `FrameBudget.page`, so every
page is cut from matching entries only and `total` counts matches.

### Expiry

`expires_at` is an RFC 3339 date-time (`OffsetDateTime.parse`). It is stored
normalized to the UTC instant it names, in `Instant.toString` form, which is
RFC 3339 too: `2027-01-02T05:04:05+02:00` is stored and answered as
`2027-01-02T03:04:05Z`, and a fraction of a second is kept. A value that does
not parse, lacks an offset, or falls outside the years 0000 to 9999 in UTC is
`INVALID_PARAMS` "expires_at must be an RFC 3339 date-time", and nothing is
written.

On Update, `expires_at` is a `*string`: absent or null keeps the expiry, `""`
clears it, and any other value replaces it. The phone stores the expiry and
answers it; it does not enforce it, so an expired entry is still answered.

## Seal store methods

`SealStore` (`storage/SealStore.kt`) keeps named secrets that go-xkms seals to
the phone. Each secret is encrypted with a Keystore AES-GCM key (alias
`xkey_seal_store_key`) and kept under `filesDir/seal_store` as
`<sha256 of name>.sealed` beside `<sha256 of name>.name`. Writes go through a
temporary file and a rename, the name file first, so a readable secret is
always listed. The seal store has no lock.

| Method | Request | Result |
|---|---|---|
| `SealStorePut` | `name` (at most 1024 UTF-8 bytes), `secret` (base64) | `{}`; replaces a secret of the same name |
| `SealStoreGet` | `name` | `name`, `secret` |
| `SealStoreDelete` | `name` | `{}` |
| `SealStoreList` | `page`, `page_size` | `names[]` (sorted) and the page fields |
| `SealStoreReseal` | `name` | `{}`; encrypts the secret again under a fresh IV |
| `SealStoreStatus` | none | `available` true, `sealer_id` `"android-keystore"`, `secret_count`, `secret_names` |

`SealStorePut` refuses a secret whose `SealStoreGet` response would not fit a
frame. Decrypted secrets are zeroed once the response is built.
`secret_count` is exact. `secret_names` is cut to what fits the frame, and
nothing in the response says it was cut.

## Paging

`PasswordList` and `SealStoreList` page with `FrameBudget.page`. `page` is
1-based, and 0 (the default) asks for everything. `page_size` defaults to 25.
Page 0 answers the longest prefix that fits a frame and sets `has_more` when
items were left out. An explicit page that does not fit is refused with
`INVALID_PARAMS`, and the message names the largest `page_size` that would.

## Errors

| Condition | Error code |
|---|---|
| Missing or mistyped field, bad scope, bad expiry, bad page, bad credential body, `user_pin` body | `INVALID_PARAMS` |
| A password entry that would not fit a `PasswordGet` frame (`PasswordEntryTooLargeException`), or a sealed secret that would not fit `SealStoreGet` | `INVALID_PARAMS` (nothing written) |
| Unknown id or name, or an entry in another tenant | `KEY_NOT_FOUND` |
| Entry method while the store is locked | `PASSWORD_STORE_LOCKED` (-32040) |
| Unlock or lock with no factor enrolled | `VAULT_NOT_INITIALIZED` (-32038) |
| No enrolled factor matched | `VAULT_CREDENTIAL_REJECTED` (-32039); the failure is counted |
| Too many failed unlocks | `PIN_LOCKED` (-32034), with no lockout end or count |
| A stored entry or secret from before the size limits that no longer fits | `INTERNAL_ERROR` |
| Any other failure | `INTERNAL_ERROR`, with a fixed message that never echoes the cause |

## Storage

Room schema v12 (`XKeyDatabase.MIGRATION_11_12`) adds the three policy
columns: `expires_at TEXT`, `shared INTEGER NOT NULL DEFAULT 0` and
`tenant_id TEXT NOT NULL DEFAULT ''`, so every entry stored before v12 is a
personal entry with no expiry in the default tenant.

Every password write is held to `PasswordEntryLimit.MAX_ENTRY_SIZE`, so each
entry can be read back in one `PasswordGet` frame.

`PasswordRepository.updateFields` applies the patch with
`PasswordDao.updateFieldsIfUnchanged`, which guards on every column it read,
the policy columns included, and retries a lost race. A writer that does not
name a policy field therefore keeps the value stored at the write.

## Other writers

- Sync (`sync/PasswordSync.kt`): `SyncPassword` carries no policy field.
  Merging a remote copy into an existing entry, in whichever tenant holds its
  id, patches its descriptive fields with `updateFields` and keeps its tenant,
  sharing and expiry; one that keeps changing locally during the merge is
  skipped. A new remote entry is a personal one with no expiry in the default
  tenant. Gather sends no policy field.
- UI (`ui/PasswordManagementActivity.kt`): adds personal entries in the
  default tenant and deletes by id in any tenant.

## Tests

- Unit (`app/src/test`): `PasswordStoreMethodsTest`, `SealStoreMethodsTest`, `FrameBudgetTest`, `UsbWireContractTest`, `PasswordVaultTest`, `PasswordVaultCredentialTest`, `WebAuthnPrfTest`, `PinSettingsVaultUnlockAttemptStoreTest`.
- Instrumented (`app/src/androidTest`): `SealStoreFrameBudgetTest`, `PasswordDaoTest`.
