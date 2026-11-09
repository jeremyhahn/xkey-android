# xkey-android roadmap

> **Status: REFERENCE** · Owner: xkey-android maintainers · Last verified: 2026-11-09
> Changes are proposed by docs-only PR. Every item names its feature in [docs/SPEC.md](docs/SPEC.md), and the two agree.

## Mission

Android phone-as-HSM companion to go-xkms: a Kotlin app whose keys stay in Android Keystore, StrongBox when available.
Serves as the xkmsd `phone` key backend behind `xkey device pair` and `xkey fido2 --backend phone`.
Wire-coupled to go-xkms through the pairing contract (Noise-XX + JSON-RPC), not a Go import.

## Milestones

- [Dev complete](../../milestone/23) — target kind RC — due 2026-11-16

## Complete

- **noise-pairing** — Noise-XX responder with identity exchange and JSON-RPC base methods — as built, no closing issue — done
- **ble-transport** — GATT peripheral with 7-byte fragment framing — as built, no closing issue — done
- **usb-transport** — USB accessory with 2-byte length framing — as built, no closing issue — done
- **tcp-pairing** — loopback `:8444` server behind the Settings toggle — as built, no closing issue — done
- **device-attestation** — pairing fingerprint bound to the attested key's SPKI — [#2](../../issues/2) — done
- **device-attestation** — DAK rotation surface decided — [#4](../../issues/4) — done
- **device-attestation** — unused `generateKeyWithAttestationChallenge` removed — [#5](../../issues/5) — done
- **hardware-backed-keys** — `local.*` crypto in Keystore, StrongBox preferred — as built, no closing issue — done
- **exportable-symmetric-keys** — software-backed shareable symmetric keys — as built, no closing issue — done
- **key-sharing** — per-key, per-peer sharing policies — as built, no closing issue — done
- **user-verification** — biometric auth mode, UV policy and session duration — as built, no closing issue — done
- **pin** — `local.pin*` over every transport — as built, no closing issue — done
- **piv** — `local.piv*` and `remote.piv*` — as built, no closing issue — done
- **oath** — `local.oath*` with TOTP matching the desktop — as built, no closing issue — done
- **passkey-provider** — Credential Provider service, proven against the go-xkms RP — as built, no closing issue — done
- **fido2-phone-backend** — `xkey fido2 --backend phone` over BLE — as built, no closing issue — done
- **store-sync** — one `SyncEngine` for trust store, OATH and passwords — as built, no closing issue — done
- **desktop-backup-store** — `local.createBackup` and `local.restoreBackup` round-trip — as built, no closing issue — done
- **remote-key-access** — `remote.*` to xkmsd backends through the desktop bridge — as built, no closing issue — done
- **trust-store-bootstrap** — CA bundle fetch and IDevID verification — as built, no closing issue — done
- **certificate-authority** — local X.509 CA by profile — as built, no closing issue — done
- **password-vault** — phone password store synced through `syncPasswords` — as built, no closing issue — done
- **contacts** — recipient public keys — as built, no closing issue — done
- **file-operations** — Share-sheet sign, verify, encrypt, decrypt — as built, no closing issue — done
- **media-signing** — automatic signing of new photos and videos — as built, no closing issue — done
- **co-signing** — multi-party media signing by QR or BLE — as built, no closing issue — done
- **verified-media-viewer** — media with verification badges — as built, no closing issue — done
- **audit-log** — security events in Room with an audit screen — as built, no closing issue — done
- **release-signing** — release builds signed from credentials outside version control — as built, no closing issue — done
- **phone-initiated-pairing** — phone-initiated attestation and pairing SAS display ([go-xkms#1306](../../../go-xkms/issues/1306)) — [#14](../../issues/14), PR #42 — done
- **request-generation-echo** — pairing responses echo per-request generation — [#10](../../issues/10), PR #42 — done
- **remote-backup-password** — password sent on remote backup create and restore ([go-xkms#690](../../../go-xkms/issues/690)) — [#11](../../issues/11), PR #61 — done
- **fido2-built-in-uv** — biometric-gated verify-user RPC for FIDO2 built-in UV ([go-xkms#1716](../../../go-xkms/pulls/1716)) — [#13](../../issues/13) — done
- **protected-memory** — Noise static, ephemeral and session keys zeroed with `fill(0)`, documented as best-effort hygiene on the managed heap — [#6](../../issues/6), PR #46 — done

Release-readiness checklist for [Dev complete](../../milestone/23), done; none of these is a SPEC.md feature:

- [x] `docs/` scrubbed for spec review — [#26](../../issues/26) — done
- [x] SPEC.md feature names in kebab-case — [#32](../../issues/32) — done
- [x] ROADMAP.md items in one item form — [#33](../../issues/33) — done
- [x] `docs/` files moved into feature folders — [#34](../../issues/34) — done
- [x] devcontainer image with JetBrains JDK 21 and the pinned Android platform and build-tools — [#35](../../issues/35) — done
- [x] CI Gate job on the `ci-gate` runners — [#36](../../issues/36) — done
- [x] test-suite audit — [#84](../../issues/84), PR #116 — done
- [x] trivy flags of the lz4-java CVE in the integration image on main — [#98](../../issues/98) — done
- [x] plain technical text in comments and docs — [#103](../../issues/103), PR #112, PR #117 — done
- [x] image build downloads retried on transient errors — [#109](../../issues/109), PR #110 — done
- [x] one preflight job for the changed-files detection and the architecture gates — [#114](../../issues/114), PR #115 — done

## Now

None.

## Next

None.

## Later

- **password-vault-rpcs** — password store and seal store RPCs handled — [#55](../../issues/55) — blocked: the USB PasswordVault verbs are not yet served by go-xkms; the desktop-sent `Password*`/`SealStore*` handlers shipped in PR #42 (#12)
- nightly CI run — [#91](../../issues/91) — suspended; not a SPEC.md feature

## Future

- **trusted-computing-enrollment** — Android initiators for the TCG IDevID, credential-activation and quote methods of the go-xkms pairing wire contract — no issue — blocked: not scheduled, dormant on both sides

## Dependencies

- Up: none pinned (not a Go module); wire-compatible with the go-xkms pairing contract, `go-xkms/xkey/pkg/pairing`.
- Up: go-xkms `local.verifyUser` wire (go-xkms#1716, main 109f9c16f); the desktop verifier and pinUvAuthToken via UV are go-xkms's.
- Down: go-xkms xkmsd `phone` key backend, `xkey device *` pairing and `xkey fido2 --backend phone`.
