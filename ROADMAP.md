# xkey-android roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-12
> Changes are proposed by docs-only PR.

## Mission

Android phone-as-HSM companion to go-xkms: a native Kotlin app whose keys stay in the TEE / StrongBox.
Serves as the xkmsd `phone` key backend behind `xkey device *`.
Wire-coupled to go-xkms through the pairing contract (Noise-XX + JSON-RPC), not a Go import.

## Current milestone

- [Release candidate](../../milestone/23) — target kind RC — projected date: per department plan

## Now

- [#25](../../issues/25) roadmap conforms to the handbook roadmap convention — `docs/` (no feature folder) — in review
- [#26](../../issues/26) `docs/` scrubbed for spec review — `docs/` (all feature folders) — blocked: waits for its slot in [dept-software#126](../../../dept-software/issues/126)
- [#11](../../issues/11) password sent on remote backup create and restore ([go-xkms#690](../../../go-xkms/issues/690)) — `docs/remote-backup/` (folder to add) — blocked: needs a JDK 17 + Android SDK 34 worker image
- [#12](../../issues/12) password store and seal store RPCs handled — `docs/password-vault/` (folder to add) — blocked: needs a JDK 17 + Android SDK 34 worker image
- [#14](../../issues/14) phone-initiated attestation and pairing SAS display ([go-xkms#1306](../../../go-xkms/issues/1306)) — `docs/pairing/` (folder to add) — blocked: needs a JDK 17 + Android SDK 34 worker image
- [#15](../../issues/15) USB transport supports the per-user password vault — `docs/usb-transport/` (folder to add) — blocked: needs a JDK 17 + Android SDK 34 worker image
- [#6](../../issues/6) Noise static and session keys zeroized under an Android protected-memory clause — `docs/pairing/` (folder to add) — blocked: needs a JDK 17 + Android SDK 34 worker image
- [#5](../../issues/5) attestation-challenge key generation wired or removed — `docs/attestation/` (folder to add) — blocked: needs a JDK 17 + Android SDK 34 worker image

## Next

- [#10](../../issues/10) pairing responses echo per-request generation — `docs/pairing/` (folder to add) — blocked: [go-xkms#128](../../../go-xkms/issues/128)
- [#13](../../issues/13) biometric-gated verify-user RPC for FIDO2 built-in UV — `docs/fido2-user-verification/` (folder to add) — blocked: verifyUser undefined in go-xkms

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: none pinned (not a Go module); wire contract with go-xkms per the handbook's xkey-android wire contract (software docs/12).
- Up: [go-xkms#128](../../../go-xkms/issues/128) per-request generation, needed by #10.
- Up: go-xkms defines the `verifyUser` RPC, needed by #13.
- Up: a JDK 17 + Android SDK 34 worker image, needed by #5, #6, #11, #12, #14 and #15.
- Down: go-xkms xkmsd `phone` key backend and `xkey device *` pairing.

## Non-goals

- Server-side pairing, key management and the wire contract itself belong to go-xkms; see the handbook constitution (software docs/00) §R.
