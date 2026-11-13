# Plan: backup store ids and latest-backup order

Row: desktop-backup-store (SPEC line 49), hardening. Refs #11.

## Problem

- `local.createBackup` sends no id, so `BackupStore.store("", bytes)` names
  every backup `backup-<currentTimeMillis>`. Two backups stored in the same
  millisecond get the same id; the second overwrites the first.
- `latestId()` orders by file `lastModified()`, which can have one-second
  granularity, so the latest backup is undefined when two land close together.
- No JVM test pins the `local.*` backup wire shapes against the go-xkms
  structs in `pkg/pairingproto/protocol_backup.go` (`xkey/v0.64.2-alpha`).

## Steps

1. `BackupStoreIdTest` (JVM, mocked Context over a temporary folder): distinct
   generated ids, `latestId()` with equal mtimes, older records still load.
   Failing test commit first.
2. `BackupStore.kt`: generated ids get a unique suffix after the `backup-`
   prefix; a new `XKB2` record header carries a store sequence number and the
   creation time; `latestId()` orders by sequence, then creation time. `XKB1`
   records and bare legacy blobs are still read.
3. `BackupHandlerWireTest` (JVM): `local.createBackup` / `local.restoreBackup`
   params and results as Go encodes them (standard padded base64 for
   `[]byte`, RFC 3339 `created_at`, INVALID_PARAMS on bad input). Handler
   changes only where a case fails, test commit first.
4. `docs/desktop-backup-store/architecture.md`: id scheme, latest order and
   record format as built.
