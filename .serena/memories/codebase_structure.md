# Codebase Structure

```
xkey-android/
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── kotlin/com/automatethethings/xkey/
│   │   │   │   ├── auth/          # Authentication
│   │   │   │   ├── credential/    # Credential management (handlers, UI)
│   │   │   │   ├── crypto/        # Cryptographic operations
│   │   │   │   ├── keychain/      # Keychain management
│   │   │   │   ├── protocol/      # BLE/CTAP2 protocol
│   │   │   │   ├── bootstrap/     # Trust bootstrap
│   │   │   │   ├── ca/            # CA integration
│   │   │   │   ├── oath/          # TOTP/HOTP
│   │   │   │   ├── qr/            # QR scanning
│   │   │   │   ├── usb/           # USB CCID
│   │   │   │   ├── truststore/    # Trust store
│   │   │   │   ├── settings/      # App settings
│   │   │   │   ├── media/         # Media
│   │   │   │   └── remote/        # Remote device
│   │   │   ├── res/               # Android resources
│   │   │   └── AndroidManifest.xml
│   │   ├── test/                  # Unit tests
│   │   └── androidTest/           # Instrumented tests
│   └── build.gradle.kts
├── scripts/
├── docs/
├── gradle/
├── build.gradle.kts               # Root build config
├── settings.gradle.kts
├── Makefile
├── Dockerfile
└── docker-compose.yml
```
