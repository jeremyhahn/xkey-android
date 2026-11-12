# Plan: local.oathAdd encodes the label and returns the stored id

Follow-up of #133, which fixed the same `otpauth://` encoding in
`SyncEngine` only.

## Defects

1. `RequestHandler.handleOathAdd` builds the `otpauth://` URI by hand. An
   issuer or account name with a space, `:`, `&`, `?`, `#` or `/` gives a URI
   that `OathRepository.importFromUri` parses wrongly: a wrong account, a
   truncated issuer or a dropped secret.
2. It returns `credential_id = credential.name`. The phone stores the
   credential under the id `importFromUri` returns, and `local.oathList`
   (`name`), `local.oathGenerate` and `local.oathRemove` key on that id, so
   a desktop cannot generate or remove the credential it just added.

## Tests

`OathAddHandlerTest` (JVM, protocol package) drives `local.oathAdd` through
`handleRawRequest` with the real `OathRepository.importFromUri` (a JVM
stand-in for `android.net.Uri` that decodes as Android does) and a mocked
DAO:

- an issuer and account with space, `&`, `?`, `#`, `/` and `:` (in the
  account) are stored exactly as sent;
- `credential_id` is the stored id, and `local.oathList` reports it as
  `name`;
- a HOTP add stores its counter; a TOTP add stores none.

The test commit comes first and fails on main.

## Fix

`handleOathAdd` builds the URI with `sync.otpauthUri(...)` (counter only for
HOTP) and returns the id `importFromUri` returned as `credential_id`. No
other handler, wire field or `SyncEngine` behaviour changes.
`docs/oath/architecture.md` records both.
