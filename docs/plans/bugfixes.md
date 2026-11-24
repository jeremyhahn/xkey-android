# Production fixes carried onto main

## Objective

Fixes were made on `fix/*` branches cut from an older main and never reached
main through a pull request. This branch, `fix/production-bugfixes`, carries
those that can land now onto current main, one `git cherry-pick -x` per
commit, each fix after the test that shows it. Commits main already has in a
later form are skipped. Commits that need a file an open pull request changes
are deferred until that pull request lands.

Each source branch's own commits are
`fix/production-readiness..fix/<branch>`.

## Commits

| Source branch | Commit | Subject | Status | Tests |
|---|---|---|---|---|
| passkey-caller-uv | b928ee91 | test: a caller-supplied client data hash needs a verified browser origin | carried | PasskeyCallerOriginTest; PasskeySignCounterHandlerTest and AssertionSignCountTest callers are browsers on the RP |
| passkey-caller-uv | 7cb12d4e | fix: take a caller's client data hash only from a privileged browser on the relying party | carried | as above, plus the device request fixtures (below) |
| passkey-caller-uv | 1d7e7173 | test: a time-window passkey key is prompted for before UV is reported | deferred: needs `BiometricHelper.authenticateWithoutCrypto(allowDeviceCredential)`, which row/318-pin-lockout-audit adds to BiometricHelper.kt | PasskeyTimeWindowUvTest |
| passkey-caller-uv | f0ef0ebf | fix: report UV only for verification done in this ceremony | deferred with 1d7e7173 (same parameter) | PasskeyTimeWindowUvTest |
| passkey-caller-uv | c256e186 | test: PIN verification accepts exactly the stored hash | carried | PinHasherVerifyTest |
| passkey-caller-uv | 1ab320c0 | fix: compare PIN hashes in constant time | carried | PinHasherVerifyTest |
| error-path-hardening | 8435a6f5 | test: only a StrongBox-unavailable failure falls back to the TEE | carried | StrongBoxFallbackTest |
| error-path-hardening | f12be3e0 | fix: fall back from StrongBox to the TEE only when StrongBox is unavailable | carried without DeviceAttestationKey.kt (row/343-cov-device-identity changes it); StrongBoxFallback.kt and UserVerificationKey.kt carried | StrongBoxFallbackTest |
| ui-scanner-fingerprint-notice | 0bc81814 | test: the IDevID fingerprint is the whole SHA-256, shown and copied | carried | IdevidFingerprintTest |
| ui-scanner-fingerprint-notice | 1f061e3f | fix: show and copy the whole IDevID SHA-256 fingerprint | carried | IdevidFingerprintTest |
| media-auto-sign | f944face | test: a burst of events for one capture signs it once | carried | AutoSignQueueTest |
| media-auto-sign | bdcce100 | fix: claim a capture before the signing delay | carried | AutoSignQueueTest |
| ui-scanner-fingerprint-notice | b7e1020f, 16606360 | QR scanner reads again after a rejected code | skipped: on main since d141d8aa (QrScannerRejectedCodeTest, QrCodeScannerHelper resets `processing` on restart) | - |
| secret-screens | 53efa1f9, c4718028 | 45 s clipboard clear for passwords and OATH codes | skipped: on main since d141d8aa (SensitiveClipboard, `CLEAR_AFTER_MS = 45_000L`, SensitiveClipboardTest) | - |
| passkey-caller-uv | 402f4208, db66fc29, 6df18004, 12f37567 | StrongBox-to-TEE fallback and device credential option in KeystoreManager | deferred: KeystoreManager.kt is changed by row/318-pin-lockout-audit, row/333-key-algorithm-parity, row/338-pqc-keys | - |
| error-path-hardening | f12be3e0 (DeviceAttestationKey.kt hunk) | StrongBox fallback for the device attestation key | deferred: DeviceAttestationKey.kt is changed by row/343-cov-device-identity | - |
| ui-scanner-fingerprint-notice | 9cffb927, 56f72c36 | approval notification names no relying party on the lock screen | deferred: XKeyApplication.kt (row/338-pqc-keys); strings.xml (row/318-pin-lockout-audit, row/338-pqc-keys, fix/piv-ed25519) | - |
| media-auto-sign | 5587a22f, 1199e7c9 | keep an auto-signature the app may not write into the capture | deferred: XKeyApplication.kt (row/338-pqc-keys) | - |
| secret-screens | 6baa4eb2, ceb6ff3c | key IDs wrap on the key details screen | deferred: KeyDetailActivity.kt (row/318-pin-lockout-audit) | - |
| secret-screens | 14474cc0, 37e171f3 | password list without decrypting, an unreadable entry opens as an error | deferred: PasswordManagementActivity.kt, PasswordManagementActivityTest.kt, strings.xml (row/318-pin-lockout-audit) | - |
| secret-screens | bf318f06, cad32685 | add password dialog validates in place | deferred: same files (row/318-pin-lockout-audit) | - |

## Follow-on edits on this branch

- 7cb12d4e refuses a caller-supplied client data hash unless the caller is a
  privileged browser on an origin the rpId is valid for, and it checks the
  origin before the challenge. The instrumented request fixtures defaulted to
  a caller with no origin, so their default caller is now a browser on
  `https://<rpId>` (mocked, since Android verifies a browser by its signing
  certificate). CreateCredentialHandlerTest and GetCredentialHandlerTest gain
  two refusals each: a supplied hash from a caller with no verified origin,
  and from a browser on another site.

## Deferred pairs that land after row/318

1d7e7173 and f0ef0ebf apply cleanly to this branch, but call
`authenticateWithoutCrypto(..., allowDeviceCredential = ...)` (five
arguments). Main's BiometricHelper has four. row/318-pin-lockout-audit adds
that parameter with the same name and default. Picking them before it lands
needs either an edit to BiometricHelper.kt, which conflicts with row/318, or
dropping the device-credential option, which would leave a screen-lock-only
user unable to use a time-window passkey. Pick both, in order, once row/318
is on main.

Gradle was not run for this branch (no Android SDK where it was built); the
carried tests were read against main's signatures.
