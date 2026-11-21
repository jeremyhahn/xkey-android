# BLE transport architecture

> **Status: REFERENCE** · Last verified: 2026-11-17
> As-built description of the BLE transport in xKey. The wire contract is `go-xkms/xkey/pkg/pairing`.

This document describes the BLE communication protocol used between xKey
(Android authenticator) and desktop clients (go-xkms). The protocol
provides authenticated, encrypted, bidirectional communication for
cryptographic operations.

## Transport Stack

```mermaid
graph TB
    APP[JSON-RPC Application Messages]
    NOISE[Noise_XX_25519_ChaChaPoly_SHA256 Encryption]
    FRAG[Fragment / Reassemble Layer]
    GATT[BLE GATT Characteristics]

    APP --> NOISE
    NOISE --> FRAG
    FRAG --> GATT
```

| Layer | Component | Responsibility |
|-------|-----------|---------------|
| Application | `RequestHandler`, `Messages` | JSON-RPC request/response dispatch |
| Encryption | `NoiseSession` | Noise_XX handshake and transport encryption |
| Framing | `FragmentReassembler`, `Fragmenter` | Message splitting for BLE MTU limits |
| Transport | `GattServer`, `BleClient` | BLE GATT characteristic read/write |

### Other transports

BLE is one of three transports carrying the same pairing protocol and JSON-RPC
surface. The stream transports share a single responder implementation so they
stay byte-identical with the go-xkms desktop initiator:

| Transport | Component | Framing |
|-----------|-----------|---------|
| BLE GATT | `GattServer` | 7-byte fragment header (see below) |
| USB (AOA) | `UsbAccessoryServer` -> `StreamPairingSession` | `StreamMessageFraming`, 2-byte big-endian length |
| TCP (loopback `:8444`, for ADB/emulator) | `TcpHsmServer` -> `StreamPairingSession` | `StreamMessageFraming`, 2-byte big-endian length |

All three perform the pre-handshake identity exchange before Noise_XX; the
desktop initiator always sends it.

## Fragment Protocol

BLE GATT characteristics have a limited MTU (typically 20-512 bytes). Messages
larger than the negotiated MTU are split into fragments.

### Fragment Header Format (7 bytes, big-endian)

```
Offset  Size  Field       Description
0       1     flags       Bit 0 = first fragment, Bit 1 = last fragment
1       2     sequence    Fragment sequence number (0-based)
3       2     total       Total number of fragments in message
5       2     length      Payload length in this fragment
7       var   payload     Fragment payload data
```

### Constraints

| Parameter | Value |
|-----------|-------|
| Header size | 7 bytes |
| Default payload size | 237 bytes (MTU 247 - 3 ATT overhead - 7 header) |
| Maximum message size | 1 MB |
| Maximum fragments | 1000 |
| Reassembly timeout | 30 seconds |

### Fragmentation Example

A 600-byte message with default MTU would be split into 3 fragments:

```
Fragment 0: flags=0x01 seq=0 total=3 len=237 [237 bytes payload]
Fragment 1: flags=0x00 seq=1 total=3 len=237 [237 bytes payload]
Fragment 2: flags=0x02 seq=2 total=3 len=126 [126 bytes payload]
```

## FIDO GATT service (0xFFFD)

Beside the xkey service, the phone is a standard CTAP2 BLE authenticator
(CTAP 2.1, Bluetooth transport). It has its own `BluetoothGattServer`
(`ble/fido/FidoGattServer.kt`), so the xkey service's table, callbacks,
queues and framing above do not change. `XKeyGattService` starts it after the
xkey GATT server (best effort: the xkey service runs without it) and stops and
destroys it with that server. `Advertiser` adds the 16-bit UUID 0xFFFD to the
advertisement: flags (3), the 128-bit xkey list (18) and the 16-bit list (4)
fit the 31-byte PDU.

| Characteristic | UUID | Properties | Permissions | Value |
|----------------|------|------------|-------------|-------|
| fidoControlPoint | `F1D0FFF1-DEAF-ADDA-1234-56789ABCDEF0` | write | write, encrypted MITM | request frames, at most 512 bytes |
| fidoStatus | `F1D0FFF2-DEAF-ADDA-1234-56789ABCDEF0` | notify (CCCD read/write, encrypted MITM) | none | response frames |
| fidoControlPointLength | `F1D0FFF3-DEAF-ADDA-1234-56789ABCDEF0` | read | read, encrypted MITM | 512, 2 bytes big-endian |
| fidoServiceRevisionBitfield | `F1D0FFF4-DEAF-ADDA-1234-56789ABCDEF0` | read, write | read/write, encrypted MITM | 0x20 (FIDO2 only); a write of anything else is refused |

The MITM permissions make the stack require an authenticated, encrypted bond
before a client reads or writes, so a client pairs with the phone first.

Framing (`ble/fido/FidoBleFraming.kt`) is the CTAP one, not the 7-byte xkey
header: a CMD frame `CMD | HLEN | LLEN | DATA`, then CONT frames `SEQ | DATA`
with SEQ 0..0x7F wrapping. Commands are PING 0x81 (echoed), KEEPALIVE 0x82,
MSG 0x83, CANCEL 0xBE and ERROR 0xBF. `FidoBleReassembler` answers framing
faults with an ERROR frame: a CONT without a CMD, a wrong SEQ, or a new CMD
mid-message gives INVALID_SEQ; a message over 1024 bytes, or a frame
carrying more than its CMD declared, gives INVALID_LEN. An unknown command
gives INVALID_CMD.

Each connected client gets one `FidoBleSession`. A MSG goes to
`Ctap2Authenticator` (see
[fido2-phone-backend](../fido2-phone-backend/architecture.md)); while it
runs a KEEPALIVE goes out every 400 ms, PROCESSING, then UP_NEEDED once the
phone prompts the user. CANCEL stops the request, which then answers
CTAP2_ERR_KEEPALIVE_CANCEL. A second MSG while one runs answers ERROR BUSY.
Replies are fragmented to the ATT MTU less 3 (20 bytes until the MTU changes)
and notified one at a time: the next frame goes out on `onNotificationSent`.
Frames are sent only while the client has notifications enabled. A
disconnect closes the session and cancels its request.

## Service Configuration

| Property | Value |
|----------|-------|
| Foreground service type | `connectedDevice` |
| Notification channel | `XKeyApplication.NOTIFICATION_CHANNEL_ID` |
| Restart policy | `START_STICKY` |
| Wake lock | Partial, held while advertising |
| State observation | `StateFlow<ServiceState>` |

## Service States

```mermaid
stateDiagram-v2
    [*] --> Stopped
    Stopped --> Ready: onCreate / initializeComponents
    Ready --> Advertising: startAdvertising()
    Advertising --> Connecting: BLE connection received
    Connecting --> Connected: Noise handshake complete
    Connected --> Advertising: Device disconnects
    Advertising --> Ready: stopAdvertising()
    Ready --> Stopped: onDestroy
    Connected --> Ready: stopAdvertising()

    Ready --> Error: Bluetooth unavailable
    Advertising --> Error: Advertising failure
    Error --> Ready: Recovery
```

## Service Layer

### XKeyGattService

Foreground service managing BLE GATT server and USB AOA transport. Exposes a
`StateFlow<ServiceState>` for UI observation. Handles the full lifecycle of
advertising, connection, Noise_XX handshake, and encrypted JSON-RPC dispatch.

- Foreground service type: `connectedDevice`
- Wake lock: partial, held while advertising
- Restart policy: `START_STICKY` (auto-resumes advertising after system kill)

## Activity to Service Communication

### MainActivity to XKeyGattService

| Mechanism | Direction | Purpose |
|-----------|-----------|---------|
| `bindService()` | Activity -> Service | Get `LocalBinder` reference |
| `startService(ACTION_START_ADVERTISING)` | Activity -> Service | Start BLE advertising |
| `startService(ACTION_STOP_ADVERTISING)` | Activity -> Service | Stop BLE advertising |
| `StateFlow<ServiceState>` | Service -> Activity | Observe service state changes |
| `setActivity(activity)` | Activity -> Service | Provide activity for biometric prompts |

```kotlin
// Binding
val connection = object : ServiceConnection {
    override fun onServiceConnected(name: ComponentName, service: IBinder) {
        val binder = service as XKeyGattService.LocalBinder
        gattService = binder.getService()
        gattService.setActivity(this@MainActivity)
    }
}
bindService(intent, connection, BIND_AUTO_CREATE)

// State observation
lifecycleScope.launch {
    gattService.serviceState.collect { state ->
        updateUI(state)
    }
}
```
