# xkey-android roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
> Changes are proposed by docs-only PR.

## Mission

Android phone-as-HSM companion to go-xkms: a native Kotlin app whose keys stay in the TEE / StrongBox.
Serves as the xkmsd `phone` key backend behind `xkey device *`.
Wire-coupled to go-xkms through the pairing contract (Noise-XX + JSON-RPC), not a Go import.

## Current milestone

None. Unscheduled until P1 ships; target kind RC.

## Now

- [#7](../../issues/7) merge gate with CI and review engine on this repo — open
- [#10](../../issues/10) pairing responses echo per-request generation (go-xkms#128) — open
- [#11](../../issues/11) password sent on remote backup create and restore (go-xkms#690) — open
- [#12](../../issues/12) password store and seal store RPCs handled — open
- [#13](../../issues/13) biometric-gated verify-user RPC for FIDO2 built-in UV — open
- [#14](../../issues/14) phone-initiated attestation and pairing SAS display (go-xkms#1306) — open
- [#15](../../issues/15) USB transport supports the per-user password vault — open

## Next

- [#6](../../issues/6) Noise static and session keys zeroized under an Android protected-memory clause — open
- [#20](../../issues/20) docs index, banners and stamps conform — open
- [#5](../../issues/5) attestation-challenge key generation wired or removed — open

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: none pinned (not a Go module); wire contract with go-xkms per [docs/12](../handbook/software/docs/12-xkey-android-wire-contract.md).
- Down: go-xkms xkmsd `phone` key backend and `xkey device *` pairing.

## Non-goals

- Server-side pairing, key management and the wire contract itself belong to go-xkms; see [docs/00](../handbook/software/docs/00-ownership-and-sdk-boundary.md).
