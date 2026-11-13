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
| `XKeyGattService.onUsbAccessoryAttached` / `onUsbAccessoryDetached` | `app/src/main/kotlin/com/automatethethings/xkey/ble/XKeyGattService.kt` | Checks `nativeUsbEnabled`, builds the per-session `BidirectionalMessageRouter`, `PasswordVault`, `PasswordStoreMethods` and `SealStoreMethods`, and opens a server through `UsbAccessoryServerSlot.open`; `onUsbAccessoryDetached` (also called from `cleanupComponents` on service shutdown) calls `UsbAccessoryServerSlot.clear` |
| `UsbAccessoryServerSlot` | `app/src/main/kotlin/com/automatethethings/xkey/usb/UsbAccessoryServerSlot.kt` | Holds the service's one `UsbAccessoryServer` and its router under a lock; publishes a new server before it connects, drops it when it reports a close (`onClosed`), and waits for the previous server's session to end (up to `TEARDOWN_WAIT_MS`, 5 s) before opening the next one |
| `AccessoryDetachWatcher` / `BroadcastAccessoryDetachWatcher` | `app/src/main/kotlin/com/automatethethings/xkey/usb/AccessoryDetachWatcher.kt` | Receiver for `UsbManager.ACTION_USB_ACCESSORY_DETACHED`, registered at runtime on the application context with `RECEIVER_NOT_EXPORTED` while an accessory is open; passes the `EXTRA_ACCESSORY` it names to the server |
| `UsbAccessoryServer` | `app/src/main/kotlin/com/automatethethings/xkey/usb/UsbAccessoryServer.kt` | Accessory lifecycle: starts the detach watch, `UsbManager.openAccessory`, file streams, a coroutine scope, `UsbAccessoryState`; gives each opened accessory an immutable `usb:<uuid>` connection id, which it passes to `StreamPairingSession.serve` so every request on that connection carries it (no handler-wide session id); on a detach of its accessory closes the streams, cancels the session and calls `onClosed`, as it does when the session ends by itself or the open is refused; delegates the protocol to `StreamPairingSession` with `transportLabel = "USB"`; implements `MessageSender` for outbound `remote.*` |
| `UsbAccessoryState` | same file | `Disconnected`, `Handshaking`, `Connected(accessoryInfo)`, `Error(message)` |
| `StreamPairingSession` | `app/src/main/kotlin/com/automatethethings/xkey/transport/StreamPairingSession.kt` | Responder shared with TCP: identity exchange, Noise XX handshake, pairing gate, message loop, revocation |
| `StreamMessageFraming` | `app/src/main/kotlin/com/automatethethings/xkey/transport/StreamMessageFraming.kt` | `readMessage` / `writeMessage`; `LENGTH_PREFIX_SIZE = 2`, `MAX_MESSAGE_SIZE = 65535` |
| `MessageTooLargeException` | `app/src/main/kotlin/com/automatethethings/xkey/transport/MessageTooLargeException.kt` | Thrown by `writeMessage` for a payload over 65535 bytes |
| `FrameBudget` | `app/src/main/kotlin/com/automatethethings/xkey/usb/FrameBudget.kt` | Sizes USB store results (Noise tag, JSON-RPC envelope, `GENERATION_RESERVE`) so a response fits one frame; pages lists with `page` |
| `PasswordStoreMethods`, `SealStoreMethods` | `app/src/main/kotlin/com/automatethethings/xkey/usb/` | `TransportMethods` families served on USB only |
| `UsbHsmSettingsRepository` / `UsbHsmSettingsData` | `app/src/main/kotlin/com/automatethethings/xkey/usb/UsbHsmSettings.kt` | DataStore flags `native_usb_enabled` (USB) and `tcp_hsm_enabled` (TCP), both default `false` |

## Wire methods and Android entry points

- Android entry point: the `android.hardware.usb.action.USB_ACCESSORY_ATTACHED`
  intent, filtered by `@xml/usb_accessory_filter`, delivered to `MainActivity`.
- Android detach signal: the `android.hardware.usb.action.USB_ACCESSORY_DETACHED`
  broadcast, received by `BroadcastAccessoryDetachWatcher` (no manifest
  receiver).
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
    participant Slot as UsbAccessoryServerSlot
    participant USB as UsbAccessoryServer
    participant SPS as StreamPairingSession
    participant RH as RequestHandler / store methods

    Desk->>OS: AOA start (xKey / Desktop / 1.0)
    OS->>MA: USB_ACCESSORY_ATTACHED (EXTRA_ACCESSORY)
    MA->>Svc: onUsbAccessoryAttached(accessory)
    Svc->>Svc: getSettings().nativeUsbEnabled?
    Svc->>Slot: open(context, accessory, handler, router, ...)
    Slot->>USB: UsbAccessoryServer(handler, router, this, repo, storeMethods)
    Slot->>USB: connect(context, accessory)
    USB->>OS: register USB_ACCESSORY_DETACHED receiver
    USB->>OS: openAccessory(accessory)
    USB->>USB: connectionId = "usb:<uuid>"
    USB->>SPS: serve(input, output, NoiseSession, ..., connectionId)
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

## Detach and reattach

`UsbAccessoryServer.connect` starts its `AccessoryDetachWatcher` before it
calls `openAccessory`, so a detach that lands during the open is still seen;
the descriptor of an accessory that went away during the open is closed. When
`USB_ACCESSORY_DETACHED` names the open accessory (or names none),
`onAccessoryDetached` calls `disconnect`, which stops the watcher, closes the
streams and cancels the session scope (state `Disconnected`), then reports the
close through `onClosed`. A detach of another accessory is ignored. A session
that ends by itself, with or without the broadcast, and a refused open
(`openAccessory` returns null) report the close the same way.

`UsbAccessoryServerSlot` drops the server that reported the close, so the next
`USB_ACCESSORY_ATTACHED` builds and serves a new `UsbAccessoryServer` without
a service restart.

Each opened accessory gets an immutable `usb:<uuid>` connection id, which
`UsbAccessoryServer` passes to `StreamPairingSession.serve`. Every request on
that connection runs in `RequestHandler.servedConnection(..., connectionId)`,
and `SessionAuthManager` records and checks a `PER_SESSION` biometric approval
against the connection id the request carries, never against handler-wide
state. A reattach opens a new connection with a new id, so an approval given
before a detach is not reused after it: the next protected request prompts
again. BLE (`ble:`) and TCP (`tcp:`) connections carry their own ids, so an
approval on one transport never authenticates another.

The shared `RequestHandler` holds one connected peer identity, set by the
session that set it (`setConnectedDevicePublicKeyHex(key, owner)`). The
detached session's `StreamPairingSession` teardown clears it only through
`clearConnectedDevicePublicKeyHex(owner)`, which does nothing once another
session has set its own identity. The slot also waits (up to 5 s, then logs a
warning and opens anyway) for the old session to end before it opens the
replacement; a teardown that ends later still leaves the new identity in
place.

`UsbAccessoryServerSlot` is the one place a USB server is published and
observed. `clear()` (service shutdown) advances the slot's generation, so an
attach still waiting for the old teardown publishes nothing once it resumes.
The service follows `UsbAccessoryServerSlot.states`, the state of whichever
server the slot currently holds, with one observer for its lifetime, so a
late attach cannot replace the observer of the server that holds the slot.

```mermaid
sequenceDiagram
    participant Desk as go-xkms (USB host)
    participant OS as Android UsbManager
    participant W as BroadcastAccessoryDetachWatcher
    participant USB as UsbAccessoryServer (old)
    participant Slot as UsbAccessoryServerSlot
    participant MA as MainActivity
    participant Svc as XKeyGattService
    participant New as UsbAccessoryServer (new)
    participant RH as RequestHandler

    Desk--xOS: cable pulled
    OS->>W: USB_ACCESSORY_DETACHED (EXTRA_ACCESSORY)
    W->>USB: onAccessoryDetached(accessory)
    USB->>W: stop()
    USB->>USB: close streams, cancel session scope (Disconnected)
    USB->>Slot: onClosed()
    Slot->>Slot: drop server, remember its session job
    USB->>RH: session teardown: clearConnectedDevicePublicKeyHex(owner)
    Desk->>OS: AOA start again
    OS->>MA: USB_ACCESSORY_ATTACHED
    MA->>Svc: onUsbAccessoryAttached(accessory)
    Svc->>Slot: open(...)
    Slot->>Slot: join old session job (up to 5 s)
    Slot->>New: UsbAccessoryServer(...); connect(context, accessory)
    New->>OS: register detach receiver; openAccessory(accessory)
    New->>New: connectionId = "usb:<new uuid>"
    Note over New,RH: Noise handshake; the new session sets its peer identity<br/>(setConnectedDevicePublicKeyHex(key, owner)); requests carry the<br/>new connection id, so a PER_SESSION request prompts again
```

## Errors and refusals

- Native USB Mode off: `onUsbAccessoryAttached` logs and ignores the accessory.
- A second attach while `UsbAccessoryServerSlot` holds a server is ignored
  ("already active"); `UsbAccessoryServer.connect` likewise ignores a second
  `connect`.
- `openAccessory` returns null: state `Error("Failed to open USB accessory")`;
  the watcher stops and the slot drops the server, so the next attach tries
  again.
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
- Service shutdown: `XKeyGattService.cleanupComponents` calls
  `onUsbAccessoryDetached`, which clears the slot and disconnects the server.

## Tests

- JVM: `UsbAccessoryServerTest`, `UsbAccessoryServerSlotTest` (detach
  through the production receiver, reattach, fresh `PER_SESSION` approval,
  peer identity kept across a slow teardown), `UsbAccessoryStateTest`, `UsbWireContractTest`,
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
