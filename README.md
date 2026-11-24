# xKey Android

xKey turns an Android phone into a hardware security module for a desktop. The
keys live in Android Keystore on the phone, in StrongBox when the phone has one
and in the TEE otherwise. The desktop never holds them: it sends a request over
an encrypted pairing session, you confirm with a fingerprint or face unlock on
the phone, and the phone sends back a signature, a decrypted block or a code.

The desktop side is the `xkey` CLI and the `xkmsd` daemon from go-xkms. `xkey`
pairs with the phone (`xkey device pair`), and `xkmsd` can use a paired phone as
a key backend (`BackendType "phone"`). The two projects share a wire protocol,
not code: `go-xkms/xkey/pkg/pairing` is the desktop half and this app is the
phone half. A change to one side has to be made on the other by hand.

The phone also works on its own. It is a passkey provider for Android apps and
browsers, an OATH authenticator, a password manager, and it signs, encrypts and
verifies files and photos.

[docs/SPEC.md](docs/SPEC.md) lists every feature with its status. This page
describes what is on `main`.

## Phones and Android versions

| | |
|---|---|
| Minimum | Android 9 (API 28), `minSdk` in `app/build.gradle.kts` |
| Target | Android 14 (API 34), `targetSdk` |
| Compile | API 37, `compileSdk` |
| Package | `com.automatethethings.xkey`; debug builds add `.debug` |

Some features need a newer release than the minimum:

- The passkey provider needs Android 14 (API 34), where Android added the
  credential provider API.
- `local.ecdh` needs Android 12 (API 31), the first release where Keystore EC
  keys can do key agreement. Below that the phone refuses the call and
  `local.getCapabilities` does not list ECDH.
- Keys bound to biometric authentication use `setUserAuthenticationParameters`
  on Android 11 (API 30) and later, and the older validity-duration call below
  that.

## Hardware

Bluetooth Low Energy is the one hard requirement: the manifest declares
`android.hardware.bluetooth_le` as required. Fingerprint, camera and
USB accessory support are declared optional.

**Key storage.** `KeystoreManager` checks `FEATURE_STRONGBOX_KEYSTORE` and asks
for a StrongBox-backed key when the phone reports one. Some phones report
StrongBox and then fail to generate a key in it; in that case the key is made
in the TEE instead, unless the caller asked for StrongBox only. Each key records
where it ended up (`software`, `tee` or `strongbox`, the `securityLevel` on the
wire), read from the key's own `KeyInfo` rather than from what was requested.
A key is kept in software only when its material is meant to leave the phone,
such as an exportable symmetric key the desktop asks for.

**Biometrics.** Prompts and auth-bound keys accept Class 3 (`BIOMETRIC_STRONG`)
biometrics only. Class 2 face unlock on many phones does not qualify. The
passkey screens also accept the device PIN, pattern or password
(`DEVICE_CREDENTIAL`). A phone with no strong biometric enrolled can still run
the app with user verification set to Disabled, but it cannot create auth-bound
keys.

**USB.** Native USB uses Android Open Accessory: the desktop is the USB host and
the phone is the accessory. No ADB is involved.

**NPU.** The app does not use the NPU, GPU or any ML accelerator. Nothing in the
code picks a compute backend; the only hardware choice it makes is StrongBox
versus TEE for keys.

## Installing

There is no store listing. Build the debug APK and install it over ADB:

```bash
make install    # builds, then adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`make install` finds `adb` through `ADB=`, `$ANDROID_HOME`, `$ANDROID_SDK_ROOT`,
`sdk.dir` in `local.properties`, then your `PATH`, and stops early if no device
is connected. Release builds need signing credentials; see
[Release signing](#release-signing).

Starting the BLE service asks for the Nearby devices permission (Bluetooth) on
Android 12 and later. The camera permission is asked for the first time you scan
a QR code. The app does not ask for the notification permission itself; on
Android 13 and later, allow notifications for xKey in system settings, or the
service notification and the prompts that bring up a biometric request while
the app is in the background will not show.

## Pairing with a desktop

Every transport runs the same protocol: a short identity exchange, then a
`Noise_XX_25519_ChaChaPoly_SHA256` handshake, then JSON-RPC 2.0 inside the Noise
session. The first time a desktop connects, the phone shows a pairing dialog and
nothing happens until you approve it. Paired desktops are listed under Paired
Devices, where you can revoke them.

**Bluetooth.** Turn on the BLE switch on the home screen. A foreground service
(`XKeyGattService`) advertises the xKey GATT service and keeps advertising with
the screen off. Then, on the desktop:

```bash
xkey device pair
xkey device status
```

**USB.** Turn on Native USB Mode in Settings and plug the phone into the
desktop. When go-xkms opens the phone as an accessory, Android hands it to xKey
and the session starts over the cable. Unplugging ends the session; plugging back
in starts a new one. A few method families (the password store and seal store)
are served over USB only.

**TCP, for development.** TCP Pairing (ADB) in Settings starts a server on
loopback port 8444. It exists for emulators and the end-to-end suites: forward
the port with `adb forward tcp:8444 tcp:8444` and point the desktop at it. It
needs ADB enabled on the phone, which is why it is not the production path.

## Features

Each feature has a folder under `docs/` with the detail.

**Hardware-backed keys.** The `local.*` crypto methods generate, sign, decrypt,
encrypt, run ECDH and HMAC, and report key info and attestation. The algorithms
are ES256, ES384, ES512, RS256, RS384, RS512, AES-128, AES-256, HMAC-SHA256 and
HMAC-SHA512. Keys are managed from the Keys screen.
[docs/hardware-backed-keys](docs/hardware-backed-keys/architecture.md),
[docs/exportable-symmetric-keys](docs/exportable-symmetric-keys/architecture.md)

**Key sharing.** A key's public half can be shared with a paired desktop, and
exportable symmetric keys can be shared or synced. Each key has a per-desktop
sharing policy set from its detail screen. Private halves of hardware keys never
leave the phone. [docs/key-sharing](docs/key-sharing/architecture.md)

**User verification.** Settings chooses when the phone asks for a biometric:
per operation, once per time window, or once per session. A session is one
connection: a desktop approved in that mode stays approved while its
connection is up, even with the app in the background or closed, and a
disconnect clears the approvals. User verification can also be turned off for phones without an
enrolled biometric. [docs/user-verification](docs/user-verification/architecture.md),
[docs/fido2-built-in-uv](docs/fido2-built-in-uv/architecture.md)

**Passkey provider.** On Android 14, xKey registers as a credential provider.
Apps and Chrome can create and use passkeys whose keys stay in xKey's Keystore.
[docs/passkey-provider](docs/passkey-provider/architecture.md)

**FIDO2 for the desktop.** `xkey fido2 --backend phone` lists and signs with the
phone's passkeys over the paired session (`local.listFido2Credentials`,
`local.signFido2Assertion`). A CTAP2-over-BLE authenticator is built and unit
tested but not yet verified on a device.
[docs/fido2-phone-backend](docs/fido2-phone-backend/architecture.md)

**PIN.** A user PIN with lockout after failed attempts, managed on the PIN
Management screen and over `local.pin*`. [docs/pin](docs/pin/architecture.md)

**PIV.** The PIV slots of NIST SP 800-73 (9A, 9C, 9D, 9E, the attestation slot
F9 and the twenty retired slots 82 to 95) each hold a Keystore key and an
optional certificate, on the PIV Smart Card screen and over `local.piv*`.
[docs/piv](docs/piv/architecture.md)

**OATH.** TOTP and HOTP codes, added by scanning an `otpauth://` QR code or by
hand; the desktop can read them over `local.oath*`. [docs/oath](docs/oath/architecture.md)

**Passwords.** A password store on the phone, encrypted under a Keystore key,
synced with the desktop. Over USB the desktop also reaches it through the
`Password*` methods. [docs/password-vault](docs/password-vault/architecture.md),
[docs/password-vault-rpcs](docs/password-vault-rpcs/engineering.md)

**Sync and backup.** One sync engine merges the trust store, OATH accounts and
passwords with the desktop, and the phone keeps encrypted backups for a paired
desktop. [docs/store-sync](docs/store-sync/architecture.md),
[docs/desktop-backup-store](docs/desktop-backup-store/architecture.md),
[docs/remote-backup-password](docs/remote-backup-password/architecture.md)

**Desktop keys from the phone.** The phone can call `remote.*` methods on the
paired desktop and use the keys behind xkmsd. They show up under Desktop Keys on
a paired device's screen. [docs/remote-key-access](docs/remote-key-access/architecture.md)

**Certificates and trust store.** A local CA on the phone issues X.509 and SSH
certificates by profile. The trust store fetches the platform CA bundle and
verifies IDevID certificates.
[docs/certificate-authority](docs/certificate-authority/architecture.md),
[docs/trust-store-bootstrap](docs/trust-store-bootstrap/architecture.md)

**Contacts.** Other people's public keys, imported by QR code or file, used to
encrypt to them and to verify their signatures. [docs/contacts](docs/contacts/architecture.md)

**Files and media.** Share any file to xKey to sign, verify, encrypt or decrypt
it. A background service can sign new photos and videos as they land in the
gallery, several phones can co-sign one item, and a viewer shows whether a
picture's signature checks out.
[docs/file-operations](docs/file-operations/architecture.md),
[docs/media-signing](docs/media-signing/architecture.md),
[docs/co-signing](docs/co-signing/architecture.md),
[docs/verified-media-viewer](docs/verified-media-viewer/architecture.md)

**Audit log.** Key use, pairing, settings changes and authentication results are
recorded on the phone, shown on the Audit Log screen and in recent activity on
the home screen, and can be exported. [docs/audit-log](docs/audit-log/architecture.md)

## Building and testing

Builds run either on a machine with the Android SDK or in the devcontainer image
(`build/docker/devcontainer/`). `make docker-run CMD="make build test"` runs any
target inside the image. Tool versions and checksums are pinned in
`scripts/tool-pins.sh`.

### Available targets

`make help` prints every target. The ones you will use:

```bash
make build              # debug APK (./gradlew assembleDebug)
make test               # JVM unit tests, no device
make coverage           # unit tests plus a JaCoCo report; no threshold is enforced
make lint               # Android lint on the debug variant
make lint-gates         # actionlint and the tests of the repository's own scripts
make security           # trivy fs scan; make install-tools installs the pinned trivy
make ci-fast            # lint, lint-gates, build, test
make ci                 # ci-fast plus security
make release-check      # release APK signed with a throwaway key, checked with apksigner
make install            # build and install the debug APK over adb
make integration-test   # every instrumented test on a connected device or emulator
make protocol-test      # the wire-protocol suite only
make webauthn-test      # passkey ceremonies against the go-xkms relying party
make e2e-setup          # prepare a device for the go-xkms e2eprobe
make docker-build       # build the toolchain and integration images
make it-jvm-test        # the unit suite inside the integration image
make clean              # remove build output
```

### Test layers

| Layer | Command | What it checks |
|-------|---------|----------------|
| Unit | `make test` | Codecs, crypto helpers, protocol shapes, handlers with fakes |
| Instrumented | `make integration-test` | Activities, Room, Keystore and the wire protocol on a device |
| Wire protocol | `make protocol-test` | The real pairing stack driven by a Kotlin copy of the desktop initiator |
| Live E2E | `make e2e-setup`, then `go run ./cmd/e2eprobe` in go-xkms | Interop with the real go-xkms initiator |
| WebAuthn | `make webauthn-test` | Passkey ceremonies verified by the go-xkms relying party |

CI (`.github/workflows/ci.yml`) has no device. It runs lint, the build and the
unit tests with coverage in the devcontainer image, `make lint-gates`, and the
unit suite again inside the hardened integration image, and ends in the
`CI Gate` job that branch protection requires. The trivy scan runs from
`scans.yml`. Run the instrumented and end-to-end suites yourself before merging
a change to the Keystore code, Room or the wire protocol.

### Instrumented tests on a personal phone

The test phone on the bench is a personal phone, there only to test the xkey
application. App install and test over adb only; it is never wiped, flashed,
unlocked, enrolled or otherwise modified. Flashing and enrollment tests wait
for a second phone, not yet bought. The instrumented test runner's temporary
settings changes, restored after the run (below), are accepted for app
testing; anything beyond them needs approval.

The instrumented suite runs under `XKeyTestRunner`
(`app/src/androidTest/kotlin/com/automatethethings/xkey/XKeyTestRunner.kt`),
which makes an unattended run on a locked, everyday phone behave like one on
an emulator. Before the first test it:

- sets `window_animation_scale`, `transition_animation_scale` and
  `animator_duration_scale` to 0;
- wakes the screen, sets `stay_on_while_plugged_in` so the screen stays on
  while the phone is powered, and raises `screen_off_timeout` to 30 minutes;
- shows every activity of the app's test process over the keyguard and turns
  the screen on for it. A PIN, pattern or password lock is never removed or
  bypassed; only a swipe keyguard is dismissed.

After the last test it writes every changed setting back to the value it read
(or deletes it, if it had none). The original values sit in `Settings.Global`
under `xkey_test_saved_*` keys while the run lasts; if a run is killed before
it can restore them, the next run restores them instead. To put a phone back
by hand, read those keys with `adb shell settings list global | grep
xkey_test_saved_` and write each value back.

Keep the phone on USB power for the run. Tests that expect the biometric
prompt to fail at once (nothing enrolled, as on an emulator) are skipped on a
phone with a fingerprint or face enrolled, with the reason in the report.

### Wire-protocol suite

`make protocol-test` runs `ProtocolIntegrationTest`. It starts the app's own
pairing stack (`TcpHsmServer`, `StreamPairingSession`, `RequestHandler`) inside
the test process and drives it from `ProtocolTestClient`, a Kotlin version of
the go-xkms initiator that does the identity exchange, Noise XX and encrypted
JSON-RPC. It covers the base methods, key lifecycle with signatures verified
off the device, symmetric crypto, ECDH checked against a locally computed
secret, PIN, PIV, OATH, sync, backup, key sharing and attestation. It also
checks that hardware keys never export private material.

### Live E2E probe

`go-xkms/xkey/cmd/e2eprobe` runs the same sweep from the real Go initiator over
an adb-forwarded socket, and verifies the results on the Go side (ECDSA
signatures, ECDH agreement, TOTP codes, certificate and backup round trips).

```bash
make e2e-setup                  # installs, turns on TCP pairing, forwards :8444
# open the app and turn BLE on
cd ~/sources/go-xkms/xkey && go run ./cmd/e2eprobe
# approve the pairing dialog on the phone
```

`make e2e-setup` also sets user verification to Disabled, because an emulator
has no enrolled biometric and Keystore will not create auth-bound keys without
one. On a real phone with a fingerprint enrolled, turn it back on and approve
each prompt.

### WebAuthn against the go-xkms relying party

`make webauthn-test` runs a passkey registration and sign-in from Chrome on the
phone, through Android's credential manager into xKey, against the go-xkms
example relying party. The server checks the attestation and the assertion, so
a pass means the backend accepted real output.

`scripts/webauthn-backend.sh` builds `go-xkms/examples/webauthn/server`, runs it
over plain HTTP, and uses `adb reverse` so the phone sees it at
`http://localhost`. WebAuthn treats localhost as a secure context, so no
certificate has to be installed on the phone.

Before the first run, open Chrome once on the phone to get through its first-run
screens. `scripts/webauthn-backend.sh provider` registers xKey as the credential
provider (the same as turning it on in system settings). The test skips, rather
than fails, when the backend is not running, so a plain `make integration-test`
still passes without it.

### Release signing

Release builds are signed with credentials kept out of the repository.
`assembleRelease` and `bundleRelease` stop with an error naming what is missing
instead of producing an unsigned APK. For a local release build, create
`keystore.properties` at the repository root (it is in `.gitignore`):

```properties
storeFile=release.jks
storePassword=...
keyAlias=xkey
keyPassword=...
```

`storeFile` is relative to the repository root. In CI, set
`XKEY_KEYSTORE_FILE`, `XKEY_KEYSTORE_PASSWORD`, `XKEY_KEY_ALIAS` and
`XKEY_KEY_PASSWORD` instead. If both are present, the properties file wins. See
[docs/release-signing](docs/release-signing/architecture.md).

### Output locations

| Artifact | Path |
|----------|------|
| Debug APK | `app/build/outputs/apk/debug/app-debug.apk` |
| Release APK | `app/build/outputs/apk/release/app-release.apk` |
| Unit test reports | `app/build/reports/tests/testDebugUnitTest/` |
| Instrumented test reports | `app/build/reports/androidTests/connected/` |
| Lint report | `app/build/reports/lint-results-debug.html` |
| Coverage report | `app/build/reports/jacoco/coverageReport/html/index.html` |

## Security model

Hardware keys are generated inside Keystore and their private halves cannot be
read out, by the app or anyone else. Only software keys marked `exportable` and
`shareable` can have their material shared or synced; `local.generateKey`
refuses an exportable asymmetric key.

Every transport carries Noise XX, and the phone answers nothing until you have
approved the desktop on the phone. The BLE characteristics do not require
Bluetooth link encryption; the Noise session is what protects the traffic. With
protocol version 2 the phone proves itself with a Device Attestation Key
attested to the Android hardware root
([docs/device-attestation](docs/device-attestation/architecture.md)).

Signing with an auth-bound key needs a Class 3 biometric on the phone, at the
frequency set in Settings. Android backup is off (`allowBackup="false"` and data
extraction rules), so the app's data does not go to cloud backup or
device-to-device transfer. `NoiseSession` zeroes key material once it is done
with it, which on a garbage-collected heap reduces copies but cannot rule them
out ([docs/protected-memory](docs/protected-memory/architecture.md)).

## Troubleshooting

Read the app's logs with `adb logcat | grep -i xkey`.

If a build fails on resources after switching branches, run `make clean` and
build again.

If `make install` says no device is reachable, check `adb devices` and that USB
debugging is on (Settings > Developer options > USB debugging).

If BLE will not start, grant the Nearby devices permission in the app's system
settings. The app asks for `BLUETOOTH_SCAN` with `neverForLocation`, so it does
not need location permission.

## Documentation

[docs/README.md](docs/README.md) indexes every folder under `docs/`.
[docs/SPEC.md](docs/SPEC.md) is the feature list with each feature's status.
