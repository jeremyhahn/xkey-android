# SPEC rows

One SPEC row = one row issue = one branch `row/<issue>-<row>` = one lane session = one PR (handbook `software/conventions/sdlc.md` §2b). Every open issue sits under its row issue or is listed below. Rows are in [docs/SPEC.md](../docs/SPEC.md) order.

| Row | Row issue | Status | Folded issues | Open PRs |
|---|---|---|---|---|
| usb-transport | #257 | shipped | 1 | #165 |
| hardware-backed-keys | #254 | shipped | 1 | #206 |
| key-sharing | #255 | shipped | 1 | #211, #215 |
| remote-key-access | #256 | shipped | 1 | #159, #170 |
| media-signing | #258 | shipped | 1 | #212 |
| co-signing | #259 | shipped | 1 | #179 |
| audit-log | #253 | shipped | 6 | #243, #239, #238, #234, #226, #204 |
| password-vault-rpcs | #55 | planned | 0 | none |

Rows with no open work: `noise-pairing`, `ble-transport`, `tcp-pairing`, `device-attestation`, `exportable-symmetric-keys`, `user-verification`, `pin`, `piv`, `oath`, `passkey-provider`, `fido2-phone-backend`, `store-sync`, `desktop-backup-store`, `trust-store-bootstrap`, `certificate-authority`, `password-vault`, `contacts`, `file-operations`, `verified-media-viewer`, `release-signing`, `remote-backup-password`, `phone-initiated-pairing`, `request-generation-echo`, `fido2-built-in-uv`, `protected-memory`, `trusted-computing-enrollment`.

## Open items outside the rows

- #252 GattServerCccdOrderTest flake: CI fix, kept as is.
- #136 SPEC rows whose wording the code contradicts (PR #176): a SPEC change, kept for the owner.
- #129 CI signature check (ci-template v1.35): CI configuration, not a SPEC row; left to land on its own.
