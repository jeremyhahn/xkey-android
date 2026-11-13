# USB transport architecture

> **Status: REFERENCE** · Last verified: 2026-11-12
> As-built description of the USB accessory (AOA) transport: the phone is the USB accessory, the desktop is the host, and both speak the same framed Noise XX pairing protocol as the TCP transport.

## Summary

When a desktop running go-xkms opens the phone in Android Open Accessory mode,
Android delivers `USB_ACCESSORY_ATTACHED` to `MainActivity`, which hands the
accessory to `XKeyGattService`. If the **Native USB Mode** setting is on, the
service builds a `UsbAccessoryServer`, opens the accessory's file descriptor
and runs the shared `StreamPairingSession` responder over it. Every frame is a
2-byte big-endian length followed by one Noise message (`StreamMessageFraming`),
byte-identical to TCP. USB alone also serves the password-store and seal-store
method families, ahead of the `RequestHandler` that BLE and TCP share.

## Components

| Component | File | Role |
|-----------|------|------|
| `usb_accessory_filter` | `app/src/main/res/xml/usb_accessory_filter.xml` | Matches the accessory `manufacturer="xKey" model="Desktop" version="1.0"`; referenced from `app/src/main/AndroidManifest.xml` with the `USB_ACCESSORY_ATTACHED` intent filter |
| `MainActivity.handleUsbAccessoryIntent` | `app/src/main/kotlin/com/automatethethings/xkey/ui/MainActivity.kt` | Reads `UsbManager.EXTRA_ACCESSORY`, starts the service if it is not bound, calls `onUsbAccessoryAttached` |
| `XKeyGattService.onUsbAccessoryAttached` / `onUsbAccessoryDetached` | `app/src/main/kotlin/com/automatethethings/xkey/ble/XKeyGattService.kt` | Checks `nativeUsbEnabled`, builds the per-session `BidirectionalMessageRouter`, `PasswordVault`, `PasswordStoreMethods` and `SealStoreMethods`, creates and connects the server; tears it down |
| `UsbAccessoryServer` | `app/src/main/kotlin/com/automatethethings/xkey/usb/UsbAccessoryServer.kt` | Accessory lifecycle: `UsbManager.openAccessory`, file streams, a coroutine scope, `UsbAccessoryState`; delegates the protocol to `StreamPairingSession` with `transportLabel = "USB"`; implements `MessageSender` for outbound `remote.*` |
| `UsbAccessoryState` | same file | `Disconnected`, `Handshaking`, `Connected(accessoryInfo)`, `Error(message)` |
| `StreamPairingSession` | `app/src/main/kotlin/com/automatethethings/xkey/transport/StreamPairingSession.kt` | Responder shared with TCP: identity exchange, Noise XX handshake, pairing gate, message loop, revocation |
| `StreamMessageFraming` | `app/src/main/kotlin/com/automatethethings/xkey/transport/StreamMessageFraming.kt` | `readMessage` / `writeMessage`; `LENGTH_PREFIX_SIZE = 2`, `MAX_MESSAGE_SIZE = 65535` |
| `MessageTooLargeException` | `app/src/main/kotlin/com/automatethethings/xkey/transport/MessageTooLargeException.kt` | Thrown by `writeMessage` for a payload over 65535 bytes |
| `FrameBudget` | `app/src/main/kotlin/com/automatethethings/xkey/usb/FrameBudget.kt` | Sizes USB store results (Noise tag, JSON-RPC envelope, `GENERATION_RESERVE`) so a response fits one frame; pages lists with `page` |
| `PasswordStoreMethods`, `SealStoreMethods` | `app/src/main/kotlin/com/automatethethings/xkey/usb/` | `TransportMethods` families served on USB only |
| `UsbHsmSettingsRepository` / `UsbHsmSettingsData` | `app/src/main/kotlin/com/automatethethings/xkey/usb/UsbHsmSettings.kt` | DataStore flags `native_usb_enabled` (USB) and `tcp_hsm_enabled` (TCP), both default `false`; each change is audited as a `SETTINGS_CHANGED` entry with setting `nativeUsb` or `tcpPairing` and its old and new values, written with the change through `AuditLogger.editAuditedSetting` so a committed write is audited even when its caller is cancelled |

## Wire methods and Android entry points

- Android entry point: the `android.hardware.usb.action.USB_ACCESSORY_ATTACHED`
  intent, filtered by `@xml/usb_accessory_filter`, delivered to `MainActivity`.
- Pre-handshake identity exchange: the desktop sends `[0x01 | publicKey(32)]`;
  the phone answers `[0x01 | fingerprint(32)]` for a paired device whose stored
  `deviceFingerprint` is 32 bytes (and sets the Noise prologue to
  `SHA256(publicKey || fingerprint || "xkey-v1")`), otherwise `[0x00]`. A first
  frame that is not a 33-byte identity message is taken as Noise msg1.
- `pairing.confirm` (`MethodNames.PAIRING_CONFIRM`), intercepted by the session
  before routing.
- USB-only families (`StreamPairingSession.routeTransportMethod`):
  `PasswordAdd`, `PasswordGet`, `PasswordList`, `PasswordUpdate`,
  `PasswordDelete`, `PasswordStoreUnlock`, `PasswordStoreLock`,
  `PasswordStoreStatus`, `PasswordGenerate`; `SealStorePut`, `SealStoreGet`,
  `SealStoreDelete`, `SealStoreList`, `SealStoreReseal`, `SealStoreStatus`.
  Their responses carry the request's `generation`.
- Every other method goes to `BidirectionalMessageRouter.processMessage`, which
  passes requests to the shared `RequestHandler` and settles responses to the
  phone's own `remote.*` requests.

## Main flow

```mermaid
sequenceDiagram
    participant Desk as go-xkms (USB host)
    participant OS as Android UsbManager
    participant MA as MainActivity
    participant Svc as XKeyGattService
    participant USB as UsbAccessoryServer
    participant SPS as StreamPairingSession
    participant RH as RequestHandler / store methods

    Desk->>OS: AOA start (xKey / Desktop / 1.0)
    OS->>MA: USB_ACCESSORY_ATTACHED (EXTRA_ACCESSORY)
    MA->>Svc: onUsbAccessoryAttached(accessory)
    Svc->>Svc: getSettings().nativeUsbEnabled?
    Svc->>USB: UsbAccessoryServer(handler, router, this, repo, storeMethods)
    Svc->>USB: connect(context, accessory)
    USB->>OS: openAccessory(accessory)
    USB->>SPS: serve(input, output, NoiseSession, ...)
    Desk->>SPS: [0x01 | publicKey]
    SPS-->>Desk: [0x01 | fingerprint] or [0x00]
    Desk->>SPS: Noise msg1
    SPS-->>Desk: Noise msg2
    Desk->>SPS: Noise msg3
    SPS->>SPS: install(); adoptExistingPairing()
    SPS->>USB: onConnected (state Connected)
    Desk->>SPS: encrypted pairing.confirm (new device)
    SPS->>Svc: onPairingConfirmationRequired(name, key, SAS)
    SPS-->>Desk: PairingConfirmResult
    Desk->>SPS: encrypted request
    SPS->>RH: routeTransportMethod or router.processMessage
    RH-->>SPS: JSON-RPC response
    SPS-->>Desk: encrypted response frame
```

## Errors and refusals

- Native USB Mode off: `onUsbAccessoryAttached` logs and ignores the accessory.
- A second attach while a `UsbAccessoryServer` exists is ignored
  ("already active"); `UsbAccessoryServer.connect` likewise ignores a second
  `connect`.
- `openAccessory` returns null: state `Error("Failed to open USB accessory")`.
- Handshake deadline: `StreamPairingSession.HANDSHAKE_TIMEOUT_MS` (10 s) covers
  the identity exchange and the whole Noise handshake; on expiry the streams
  are closed and the connection ends.
- Before pairing is confirmed every method except `pairing.confirm` answers
  `ErrorCodes.PAIRING_REQUIRED` (-32025). `pairing.confirm` answers
  `ErrorCodes.PAIRING_REJECTED` (-32017) when there is no authenticated peer,
  when its `publicKeyHex` differs from the Noise peer key, or when the user
  rejects the SAS prompt.
- A response over `MAX_MESSAGE_SIZE` makes `writeMessage` throw
  `MessageTooLargeException`; the peer gets no answer, so the store methods size
  their results with `FrameBudget` (`PageOverflowException` when one item cannot
  fit).
- Unpairing the connected desktop revokes the connection: the running request
  is cancelled, the streams are closed and the keys are zeroed.
- `onUsbAccessoryDetached` is called from `XKeyGattService.cleanupComponents`
  (service shutdown); no handler for `USB_ACCESSORY_DETACHED` was found in the
  code. When the stream ends, `UsbAccessoryServer` sets its state to
  `Disconnected`; whether a later attach is accepted without a service restart
  was not determined from the code.

## Tests

- JVM: `UsbAccessoryServerTest`, `UsbAccessoryStateTest`, `UsbWireContractTest`,
  `UsbHsmSettingsTest`, `FrameBudgetTest`, `PasswordStoreMethodsTest`,
  `SealStoreMethodsTest` (`app/src/test/kotlin/com/automatethethings/xkey/usb/`);
  `StreamMessageFramingTest`, `StreamPairingSessionRevocationTest`,
  `StreamResponseDrainTest`, `VerifyUserPerConnectionTest`
  (`app/src/test/kotlin/com/automatethethings/xkey/transport/`).
- Instrumented: `StreamPairingSessionTest`
  (`app/src/androidTest/kotlin/com/automatethethings/xkey/transport/`),
  `SealStoreFrameBudgetTest`
  (`app/src/androidTest/kotlin/com/automatethethings/xkey/usb/`).

## Related features

- [tcp-pairing](../tcp-pairing/architecture.md): the same `StreamPairingSession` over a loopback socket.
- [device-attestation](../device-attestation/architecture.md): the `deviceFingerprint` the identity exchange returns.
- [request-generation-echo](../request-generation-echo/architecture.md): the `generation` every response echoes.
- [password-vault](../password-vault/): the password store behind the USB-only `Password*` methods.
