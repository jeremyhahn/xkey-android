# Remote key access architecture

> **Status: REFERENCE** · Last verified: 2026-11-13
> As-built description of how xKey forwards `remote.*` requests to the desktop.

## Message Types

### Remote Methods (forwarded to desktop)

Messages prefixed with `remote.*` are forwarded through the
`BidirectionalMessageRouter` to the connected desktop client.

| Method | Description |
|--------|-------------|
| `remote.listKeys` | List keys on the desktop keychain |
| `remote.sign` | Request signing from desktop key |
| `remote.getPublicKey` | Get desktop public key |
| `remote.attestDevice` | Request device attestation from desktop |
| `remote.sharePublicKey` | Send a phone key's public half (and certificate) for the desktop to import |
| `remote.shareSymmetric` | Send symmetric key material for the desktop to import (client only; see [key sharing](../key-sharing/architecture.md#sending-keys-to-the-paired-desktop)) |
| `remote.importSharedKey` | Ask the desktop to export one of its keys to the phone |
| `remote.oathAdd` | Store a phone OATH credential on the desktop (`RemoteOathClient.oathAdd`) |
| `remote.oathGenerate` | Get the current code and expiry of a desktop-stored OATH credential (`RemoteOathClient.oathGenerate`) |
| `remote.pivListSlots` | List the desktop's PIV slots (`backend` optional) |
| `remote.pivGetCert` | Get the DER certificate in one desktop PIV slot |
| `remote.pivSign` | Sign base64 `data` with one desktop PIV slot key |

The three sharing methods are sent by `remote/RemoteShareClient.kt`, with
params and results as go-xkms `pkg/pairingproto` `RemoteSharePublicKey*`,
`RemoteShareSymmetric*` and `RemoteImportSharedKey*` (xkey/v0.64.2-alpha).
`[]byte` fields, the PEM fields included, travel as base64 strings. A reply
with a missing field or a wrong type is rejected.

### OATH methods

`RemoteOathClient` sends both methods to the desktop it was built from (see
[Session binding](#session-binding)). Shapes follow go-xkms `pkg/pairing/protocol_oath.go` at `xkey/v0.64.2-alpha`:

| Method | Params | Result |
|--------|--------|--------|
| `remote.oathAdd` | `{"credential": {name, issuer?, account_name?, secret (Base32), type ("totp"/"hotp"), algorithm?, digits?, period?, counter?}}` | `{success, credential_id, message?}` |
| `remote.oathGenerate` | `{"credential_id"}` | `{code, expires_in?}` (seconds, TOTP only) |

- Request IDs come from one counter shared by all `RemoteOathClient`
  instances, starting above 5,000,000 (key 1M, sync 2M, enrollment 3M,
  backup 4M).
- The oathAdd body is built by hand so the secret never becomes a String;
  the caller's secret chars are zeroed once encoded and the body as soon as
  it is sent, before the reply is awaited.
- Replies are type checked: `success` must be a boolean, `credential_id` a
  non-empty string, `code` a digit string and `expires_in` a non-negative
  integer. `success: false` or anything off-shape throws `ProtocolException`.
- The OATH screen offers "Copy to desktop" and, once a credential has a
  desktop copy, "Show desktop code". The phone keeps only the oathId to
  `credential_id` link (SharedPreferences `oath_desktop_links`). With no
  desktop connected neither entry shows and nothing is sent.

### Session binding

Every outbound `remote.*` client (`RemoteKeyClient`, `RemoteSyncClient`,
`RemoteBackupClient`, `RemoteOathClient`) is built from a `ConnectedDesktop`,
never from a transport. `XKeyGattService.connectedDesktop()` is the only
source; it asks BLE, then TCP, then USB.

| Transport | Hands out a desktop when | The desktop's sender |
|-----------|--------------------------|----------------------|
| BLE (`GattServer`) | the Noise session is established and current | encrypts on that session for that device; fails with `IOException` once the session or device is replaced or ended |
| TCP (`TcpHsmServer`) | `TcpHsmState.Connected` | writes on that `StreamPairingSession` connection; fails once it ends or another connection is installed |
| USB (`UsbAccessoryServer`) | `UsbAccessoryState.Connected` | as TCP |

- `peerKeyHex` is the static key the handshake authenticated; OATH desktop
  links are keyed by it.
- A sender never re-resolves the transport's current session at send time,
  so a request built for desktop A never reaches desktop B, even when B
  replaces A between the lookup and the send.
- Clients take only a `ConnectedDesktop`, whose sender is a `SessionSender`
  that only the transports make; `ConnectedDesktopBindingTest` fails if a
  client or the service takes or hands out any other sender.
- `XKeyGattService.remoteKeyClient()`, `desktopSession()` and device
  attestation go through `DesktopSessions`, whose transports are the
  `connectedDesktop()` of each server: one `RemoteKeyClient` per router, and
  once the peer is confirmed, bound to the `ConfirmedConnection` it was
  confirmed on.
- A bound sender also carries the scoped send: `confirmedConnection()`
  answers only its own connection's confirmed peer, and
  `sendEncryptedMessageOn(c)` refuses with `ConnectionChangedException`
  unless `c` is that connection and it is still current and confirmed for
  the same peer, checked again at the admission that consumes the nonce.
  `RemoteShareClient` (key sharing) sends only that way.

## Desktop keys screen

`ui/DesktopKeysActivity` shows the keys the paired desktop's xkmsd backends
hold. It is opened from the Desktop keys button on the device detail screen,
which shows only while that device's desktop session is up
(`XKeyGattService.remoteKeyClient()` returns a client only then, one cached
client per active router). The state logic is the view-free
`ui/DesktopKeysController`, tested on the JVM with a fake client.

| Step | Requests sent |
|------|---------------|
| Open the screen | `remote.listBackends` |
| Choose a backend | `remote.listKeys` |
| Choose a key | `remote.getKeyInfo`, `remote.getPublicKey` |
| Sign and verify a test message | `remote.sign`, then `remote.verify` with the algorithm the desktop signed with |
| Attest this key | `remote.attestKey` with a fresh 32-byte nonce |

The sign test is offered for backends that sign, attestation for backends
that attest. A failed request keeps the previous screen and shows a typed
error (no session, key not found, denied, unsupported, attestation failed,
other desktop error, link failure) with Retry. The screen adds no wire
method: it only calls `RemoteKeyClient`.

## Desktop PIV slots

`RemoteKeyClient.pivListSlots`, `pivGetCert` and `pivSign` send the three
`remote.piv*` methods with the params and results of go-xkms
`pkg/pairingproto/protocol_piv.go`. Byte fields (`data`, `signature`,
`certificate_der`) are standard base64. A reply with a missing or mistyped
field raises `ProtocolException` with `PARSE_ERROR`.

The PIV screen lists the paired desktop's slots read-only below the phone's
own. With no desktop connected, or when the desktop errors, the section stays
hidden and the phone's slots show as before. A desktop slot's detail view
fetches its certificate with `remote.pivGetCert` (`PIV_SLOT_NOT_FOUND` means
no certificate), and its "sign test" action sends `remote.pivSign`. The section follows
`XKeyGattService.desktopSession`, which publishes the same client
`remoteKeyClient()` returns: bound to the connection its peer was confirmed on.

## BLE Protocol Communication Stack

```mermaid
sequenceDiagram
    participant Desktop
    participant GATT as GattServer
    participant FR as FragmentReassembler
    participant NS as NoiseSession
    participant BMR as BidirectionalMessageRouter
    participant RH as RequestHandler
    participant KM as KeystoreManager

    Desktop->>GATT: BLE write (fragment bytes)
    GATT->>FR: addFragment(data)
    FR-->>GATT: Complete message (or null)

    alt Complete message received
        GATT->>NS: decrypt(ciphertext)
        NS-->>GATT: plaintext JSON

        GATT->>GATT: Parse Request from JSON

        alt local.* method
            GATT->>RH: handleRequest(request)
            RH->>KM: cryptographic operation
            KM-->>RH: result
            RH-->>GATT: Response
        else remote.* method
            GATT->>BMR: routeRequest(request)
            BMR-->>GATT: Forwarded response
        else cosign.* method
            GATT->>RH: handleCosignRequest(request)
            RH-->>GATT: Response
        end

        GATT->>NS: encrypt(response JSON)
        NS-->>GATT: ciphertext

        GATT->>FR: fragment(ciphertext)
        FR-->>GATT: List of fragment packets

        loop Each fragment
            GATT->>Desktop: BLE notify (fragment bytes)
        end
    end
```
