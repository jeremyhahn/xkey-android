# xkey-android

Android companion app for xKey FIDO2/WebAuthn authentication. Transforms an Android device into a hardware security key communicating over Bluetooth Low Energy (BLE).

## Purpose
Mobile companion for the xKey desktop application, providing hardware-backed cryptographic keys, biometric authentication, and BLE FIDO2/CTAP2 cross-platform authentication.

## Features
- Hardware-backed keys (Android Keystore, StrongBox)
- Biometric authentication (fingerprint, face)
- BLE FIDO2/CTAP2 transport
- Passkey/WebAuthn support
- QR code scanning for pairing
- OATH TOTP/HOTP
- USB CCID
- CA trust bootstrap
- Remote device management

## Tech Stack
- Language: Kotlin
- Platform: Android (API 28+, Android 9+)
- Build: Gradle (Kotlin DSL) + Makefile
- Package: `com.automatethethings.xkey`
- Requirements: BLE hardware, biometric hardware, hardware keystore
- Build tools: Docker + Docker Compose (or local Gradle)

## Architecture
- `app/src/main/kotlin/com/automatethethings/xkey/`
  - `auth/` - Authentication
  - `credential/` - Credential management (handlers, UI)
  - `crypto/` - Cryptographic operations
  - `keychain/` - Keychain management
  - `protocol/` - BLE/CTAP2 protocol
  - `bootstrap/` - Trust bootstrap
  - `ca/` - CA integration
  - `oath/` - TOTP/HOTP
  - `qr/` - QR scanning
  - `usb/` - USB CCID
  - `truststore/` - Trust store
  - `settings/` - App settings
  - `media/` - Media handling
  - `remote/` - Remote device
