# xkey-android roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-20
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

## Now

Release-readiness checklist for [Dev complete](../../milestone/23); none of these is a SPEC.md feature:

- [ ] `docs/` scrubbed for spec review — [#26](../../issues/26) — blocked: waits for its slot in [dept-software#126](../../../dept-software/issues/126)
- [ ] SPEC.md feature names in kebab-case — [#32](../../issues/32) — in review
- [ ] ROADMAP.md items in the roadmap.md item form — [#33](../../issues/33) — in review
- [ ] `docs/` files moved into feature folders — [#34](../../issues/34) — open
- [ ] devcontainer image with JetBrains JDK 21, platforms;android-34 and build-tools;36.0.0 — [#35](../../issues/35) — open
- [ ] CI Gate job on the `ci-gate` runners — [#36](../../issues/36) — in review

## Next

None.

## Later

- **remote-backup-password** — password sent on remote backup create and restore ([go-xkms#690](../../../go-xkms/issues/690)) — [#11](../../issues/11) — blocked: needs the #35 devcontainer image
- **password-vault-rpcs** — password store and seal store RPCs handled — [#12](../../issues/12) — blocked: needs the #35 devcontainer image
- **password-vault-rpcs** — USB transport supports the per-user password vault — [#15](../../issues/15) — blocked: needs the #35 devcontainer image
- **phone-initiated-pairing** — phone-initiated attestation and pairing SAS display ([go-xkms#1306](../../../go-xkms/issues/1306)) — [#14](../../issues/14) — blocked: needs the #35 devcontainer image
- **request-generation-echo** — pairing responses echo per-request generation — [#10](../../issues/10) — blocked: [go-xkms#128](../../../go-xkms/issues/128)
- **fido2-built-in-uv** — biometric-gated verify-user RPC for FIDO2 built-in UV — [#13](../../issues/13) — blocked: `verifyUser` undefined in go-xkms
- **protected-memory** — Noise static and session keys under an Android protected-memory clause — [#6](../../issues/6) — blocked: needs the #35 devcontainer image
- **attestation-challenge-keys** — attestation-challenge key generation wired or its removal ruled — [#5](../../issues/5) — blocked: needs the #35 devcontainer image

## Future

- **trusted-computing-enrollment** — Android initiators for the TCG IDevID, credential-activation and quote methods (handbook `software/docs/12-xkey-android-wire-contract.md` §The contract) — no issue — blocked: not scheduled, dormant on both sides

## Dependencies

- Up: none pinned (not a Go module); wire contract with go-xkms per the handbook's xkey-android wire contract (software docs/12).
- Up: [go-xkms#128](../../../go-xkms/issues/128) per-request generation, needed by #10.
- Up: go-xkms defines the `verifyUser` RPC, needed by #13.
- Up: the [#35](../../issues/35) devcontainer image (JetBrains JDK 21, platforms;android-34, build-tools;36.0.0), needed by #5, #6, #11, #12, #14 and #15.
- Down: go-xkms xkmsd `phone` key backend, `xkey device *` pairing and `xkey fido2 --backend phone`.
