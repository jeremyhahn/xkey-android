# Password Vault RPCs

> **Status: REFERENCE** · Last verified: 2026-10-21
> As-built contract of the `Password*` methods the desktop sends over USB.

`usb/PasswordStoreMethods.kt` answers go-xkms' `PasswordAdd`, `PasswordGet`,
`PasswordList`, `PasswordUpdate` and `PasswordDelete` against the phone's
`PasswordRepository`. Wire names and shapes are go-xkms'
`xkey/pkg/pairing` password types; every field below is `omitempty` there.

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

`expires_at` is an RFC 3339 date-time (`OffsetDateTime.parse`, `T` and `Z`
in either case). It is stored normalized to the UTC instant it names, in
`Instant.toString` form, which is RFC 3339 too:
`2027-01-02T05:04:05+02:00` is stored and answered as `2027-01-02T03:04:05Z`,
and a fraction of a second is kept. A value that does not parse, lacks an
offset, or falls outside the years 0000 to 9999 in UTC is `INVALID_PARAMS`
"expires_at must be an RFC 3339 date-time", and nothing is written.

On Update, `expires_at` is a `*string`: absent or null keeps the expiry, `""`
clears it, and any other value replaces it. The phone stores the expiry and
answers it; it does not enforce it, so an expired entry is still answered.

## Storage

Room schema v12 (`XKeyDatabase.MIGRATION_11_12`) adds the three columns:
`expires_at TEXT`, `shared INTEGER NOT NULL DEFAULT 0` and
`tenant_id TEXT NOT NULL DEFAULT ''`, so every entry stored before v12 is a
personal entry with no expiry in the default tenant.

`PasswordRepository.updateFields` applies the patch with
`PasswordDao.updateFieldsIfUnchanged`, which guards on every column it read,
the policy columns included, and retries a lost race. A writer that does not
name a policy field therefore keeps the value stored at the write.

## Other writers

- **Sync** (`sync/PasswordSync.kt`): `SyncPassword` carries no policy field.
  Merging a remote copy into an existing entry, in whichever tenant holds its
  id, patches its descriptive fields with `updateFields` and keeps its tenant,
  sharing and expiry; one that keeps changing locally during the merge is
  skipped. A new remote entry is a personal one with no expiry in the default
  tenant. Gather sends no policy field.
- **UI** (`ui/PasswordManagementActivity.kt`): adds personal entries in the
  default tenant and deletes by id in any tenant.
- **BLE** (`ble/XKeyGattService.kt`): constructs the repository only.
