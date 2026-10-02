# xKey Android

Android companion app for xKey FIDO2/WebAuthn authentication. This app transforms your Android device into a hardware security key that communicates with computers over Bluetooth Low Energy (BLE).

## Features

- **Hardware-Backed Keys**: Cryptographic keys stored in Android Keystore with StrongBox support
- **Biometric Authentication**: Fingerprint and face authentication for secure signing
- **BLE FIDO2**: CTAP2 over Bluetooth Low Energy for cross-platform authentication
- **Passkey Support**: Compatible with WebAuthn/FIDO2 passkey flows

## Requirements

### Build Requirements

- Docker and Docker Compose
- Make
- ADB (for device installation)

### Device Requirements

- Android 9 (API 28) or higher
- Bluetooth Low Energy support
- Biometric hardware (fingerprint sensor or face recognition)
- Hardware-backed keystore (StrongBox recommended)

## Building

### Quick Start

```bash
# Build debug APK
make build

# Build and install on connected device
make install
```

### Available Targets

```bash
make help             # Show all available targets
make build            # Build debug APK
make test             # Run unit tests
make lint             # Android lint + actionlint
make security         # trivy fs (vuln + secret); `make install-tools` installs the pinned trivy
make ci               # Everything CI runs: lint, build, test, security
make integration-test # Run all instrumented (on-device) tests
make protocol-test    # Run the wire-protocol integration suite only
make e2e-setup        # Prepare a device for the go-xkms conformance probe
make webauthn-test    # Run the WebAuthn E2E against the go-xkms relying party
make install          # Build and install debug APK via ADB
make clean            # Clean build artifacts
```

## Testing

Three layers, from fastest to most realistic:

| Layer | Command | What it proves |
|-------|---------|----------------|
| Unit | `make test` | Pure-Kotlin logic (codecs, crypto helpers, protocol shapes) |
| Instrumented | `make integration-test` | Activities, Room, Keystore, and the wire protocol on a real device |
| Live E2E | `make e2e-setup` + `go run ./cmd/e2eprobe` | Real interop with the go-xkms desktop initiator |
| WebAuthn E2E | `make webauthn-test` | Real passkey ceremonies verified by the go-xkms relying party |

### CI

`.github/workflows/ci.yml` runs Lint, Build, Test and Security (each a `make`
target above) and ends in the `CI Gate` job that branch protection requires.
Only the unit layer runs in CI: instrumented and E2E suites need a device or
emulator, which the CI runners do not provide, so run them locally before
merging changes that touch the Keystore, Room or the wire protocol.

### Wire-protocol integration suite

`make protocol-test` runs `ProtocolIntegrationTest`, which starts the app's
real pairing stack (`TcpHsmServer` -> `StreamPairingSession` ->
`RequestHandler`) in-process and drives it from `ProtocolTestClient`, a
reimplementation of the go-xkms desktop initiator (identity exchange +
Noise_XX + encrypted JSON-RPC). It covers every protocol family — base
methods, key lifecycle with off-device signature verification, symmetric
crypto (hardware and software-backed), ECDH cross-checked against a
locally-computed secret, PIN, PIV, OATH, sync, backup, key sharing, and
attestation — plus the sharing-policy boundary that hardware keys never
export private material.

### Live E2E conformance probe

`go-xkms/xkey/cmd/e2eprobe` is the same sweep driven by the *actual*
`pkg/pairing` initiator over an adb-forwarded socket, with Go-side
verification (ECDSA verify, ECDH agreement, TOTP cross-compute, certificate
and backup round-trips):

```bash
make e2e-setup                  # installs, enables TCP pairing, forwards :8444
# launch the app and switch BLE on
cd ~/sources/go-xkms/xkey && go run ./cmd/e2eprobe
# approve the pairing dialog on the device
```

`make e2e-setup` also sets user verification to DISABLED, because an emulator
has no enrolled biometrics and Keystore refuses to generate auth-bound keys
without them. On real hardware with biometrics enrolled, skip that and approve
each prompt on the device.

### WebAuthn against the go-xkms relying party

`make webauthn-test` runs a real passkey ceremony end to end — Chrome to the
go-xkms RP, through Android CredentialManager into xKey, and back — with the
**server** verifying the attestation and the assertion. Nothing is stubbed and
no public site is involved, so the test proves interop with the backend rather
than with a mock.

`scripts/webauthn-backend.sh` builds and runs `go-xkms/examples/webauthn/server`
on plain HTTP and runs `adb reverse`, which puts the RP on `http://localhost` as
seen by the device. localhost is a WebAuthn secure context, so no certificate
has to be trusted on the device just to run a ceremony.

Prerequisites on the device: Chrome must have completed its first-run flow, and
xKey must be registered as a credential provider (`scripts/webauthn-backend.sh
provider` does this, equivalent to enabling it under Settings > Passwords &
accounts). The test skips rather than fails when the backend is not running, so
it does not break a plain `make integration-test`.

### Release Signing

Release builds are signed with credentials supplied outside version control.
`assembleRelease` and `bundleRelease` fail with an explanatory message if they
are missing, rather than emitting an unsigned APK that cannot be installed.

For local release builds, create `keystore.properties` at the repository root
(already listed in `.gitignore`):

```properties
storeFile=release.jks
storePassword=…
keyAlias=xkey
keyPassword=…
```

`storeFile` is resolved relative to the repository root. For CI, set the same
four values as environment variables instead — `XKEY_KEYSTORE_FILE`,
`XKEY_KEYSTORE_PASSWORD`, `XKEY_KEY_ALIAS` and `XKEY_KEY_PASSWORD`. The
properties file wins where both are present.

### Output Locations

| Artifact | Path |
|----------|------|
| Debug APK | `app/build/outputs/apk/debug/app-debug.apk` |
| Release APK | `app/build/outputs/apk/release/app-release.apk` |
| Test Reports | `app/build/reports/tests/` |
| Lint Reports | `app/build/reports/lint-results.html` |

### Local Build (requires Android SDK)

If you have Android SDK installed locally:

```bash
./gradlew assembleDebug
./gradlew assembleRelease
```

## Installation

### Via Make (Recommended)

```bash
# Build and install in one command
make install

# Or install release build
make install-release
```

### Via ADB

```bash
# Install debug APK
adb install app/build/outputs/apk/debug/app-debug.apk

# Install with replacement (upgrade)
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### Via Android Studio

1. Open the project in Android Studio
2. Connect your device or start an emulator
3. Click Run (Shift+F10)

## Usage

### First-Time Setup

1. **On Phone**:
   - Open xKey app
   - Grant Bluetooth permissions when prompted
   - Tap "Start" to begin BLE advertising

2. **On Desktop**:
   ```bash
   # Scan and pair with phone
   xkey device pair

   # Verify connection
   xkey device status
   ```

3. **Use as Authenticator**:
   ```bash
   # Start virtual FIDO2 device using phone backend
   xkey fido2 --backend phone
   ```

### Daily Use

1. Open xKey app on phone
2. Tap "Start" to enable BLE
3. On desktop, run `xkey fido2 --backend phone`
4. When authenticating, confirm biometric prompt on phone

## Project Structure

```
xkey-android/
├── app/
│   ├── src/main/
│   │   ├── kotlin/com/automatethethings/xkey/
│   │   │   ├── XKeyApplication.kt       # Application class
│   │   │   ├── ui/                      # UI components
│   │   │   ├── ble/                     # BLE GATT service
│   │   │   ├── crypto/                  # Keystore operations
│   │   │   └── protocol/                # JSON-RPC messages
│   │   ├── res/                         # Android resources
│   │   └── AndroidManifest.xml
│   └── build.gradle.kts
├── gradle/
│   └── libs.versions.toml               # Version catalog
├── build.gradle.kts                     # Root build file
├── settings.gradle.kts
├── Makefile                             # Build targets
├── Dockerfile                           # Android build environment
└── docker-compose.yml                   # Docker services
```

## Permissions

The app requires the following permissions:

| Permission | Purpose |
|------------|---------|
| BLUETOOTH_CONNECT | Connect to BLE devices |
| BLUETOOTH_ADVERTISE | Advertise as FIDO2 authenticator |
| BLUETOOTH_SCAN | Scan for nearby devices |
| USE_BIOMETRIC | Biometric authentication |
| FOREGROUND_SERVICE | Keep BLE service running |

## Security

- All cryptographic keys are stored in Android Keystore
- StrongBox hardware security module used when available
- Keys require biometric authentication for every signing operation
- No key material ever leaves the secure hardware
- Cloud backup is disabled to prevent key extraction
- BLE communication is double-encrypted (link layer + Noise protocol)

## Debugging

### View Logs

```bash
# xKey-specific logs
make logcat

# All logs with filtering
adb logcat | grep -i xkey
```

### Common Issues

**Build fails with resource error**:
```bash
make clean
make docker-build
make build
```

**ADB device not found**:
```bash
# Check device is connected
adb devices

# Enable USB debugging on phone
# Settings > Developer options > USB debugging
```

**Bluetooth permissions denied**:
- On Android 12+, grant "Nearby devices" permission
- On older versions, grant Location permission

## Documentation

- [BLE Protocol Specification](docs/architecture/BLE_PROTOCOL.md)
- [Architecture Overview](docs/architecture/OVERVIEW.md)
- [Data Model](docs/architecture/DATA_MODEL.md)

## License

See LICENSE file in the root repository.
