# Protected memory architecture

> **Status: REFERENCE** · Last verified: 2026-11-12
> As-built description of how `NoiseSession` overwrites Noise key material on the heap with `fill(0)`, and the limits of that on Android's managed heap.

## Summary

`NoiseSession` runs the responder side of `Noise_XX_25519_ChaChaPoly_SHA256`
for the BLE (`GattServer`), TCP (`TcpHsmServer`) and USB
(`UsbAccessoryServer`) transports. It keeps its secrets in `ByteArray` fields
it owns, and it overwrites each one with zeros (`fill(0)`) before it drops or
replaces the reference. The secrets are the static private key, the ephemeral
private key, the chaining key, the handshake encryption key, the handshake
hash and the send and receive transport keys. The intermediates are zeroed
too: DH outputs, the HKDF pseudorandom key, PKCS#8 encodings and the clamped
scalar copy.

The class KDoc says this is **best effort** and hygiene, not a compliance
claim. A generational collector may copy an array before it is zeroed. The
JCA objects (`SecretKeySpec`, `PKCS8EncodedKeySpec`, `PrivateKey`, `Mac`,
`Cipher`) keep their own clones. The static key is stored as an immutable
Base64 `String`. The pure-Kotlin X25519 fallback (`x25519ScalarMultPure`)
holds the ladder state in immutable `BigInteger` values. The static private
key lives as long as the session object.

Public keys (ours, the peer's, both ephemerals) and the prologue are not
secret and are not zeroed. Their getters (`getRemoteStaticKey`,
`getStaticPublicKey`, `getPrologue`) return copies.

## Components

| Component | File | Role |
|-----------|------|------|
| `NoiseSession` | `app/src/main/kotlin/com/automatethethings/xkey/ble/NoiseSession.kt` | Owns the secret arrays. Zeroes them in `generateStaticKey`, `generateEphemeralKey`, `loadStaticKey`, `mixHash`, `mixKey`, `mixDh`, `hkdf2`, `splitSymmetricState`, `processHandshakeFinal`, `x25519ScalarMult`, `x25519ScalarMultPure` and `reset` |
| `NoiseSession.getStoredStaticKeyPair` | same | Companion loader for the stored static key pair; zeroes the PKCS#8 encoding once the raw key is cut out |
| `NoiseSession.secretArraysForTest` | same | Test seam that returns the live secret arrays (not copies) by field name |
| `GattServer` (`zeroOnce`) | `app/src/main/kotlin/com/automatethethings/xkey/ble/GattServer.kt` | Calls `reset()` once per session on BLE teardown, under `sendMutex` and `noiseMutex` |
| `StreamPairingSession` (`zeroKeys`, `keysZeroed`) | `app/src/main/kotlin/com/automatethethings/xkey/transport/StreamPairingSession.kt` | Calls `reset()` once on stream (TCP/USB) teardown, under the send lock, so a frame that is being sent is never zeroed mid-send |

At rest, the static key pair lives in `EncryptedSharedPreferences`
(`xkey_noise_keys`, Keystore `MasterKey` AES256_GCM) as Base64 strings. That
is outside the scope of zeroization.

## Android entry points served

There are no wire methods or UI entry points. This behaviour runs inside every
Noise session the transports create (`NoiseSession()` in `GattServer`,
`TcpHsmServer` and `UsbAccessoryServer`), and on their teardown paths.

## Main flow

```mermaid
sequenceDiagram
    participant T as Transport (GattServer / StreamPairingSession)
    participant N as NoiseSession
    participant J as JCA (KeyAgreement, Mac, Cipher)

    T->>N: loadStaticKey(context)
    N->>N: PKCS#8 form? copy raw key, fill(0) encoding
    N->>N: replacing staticPrivateKey? fill(0) old
    T->>N: processHandshakeMessage(msg1)
    N->>N: generateEphemeralKey (fill(0) previous)
    N->>J: x25519ScalarMult (PKCS#8 wrapping fill(0) after spec built)
    N->>N: mixDh: mixKey(secret), finally secret.fill(0)
    N->>N: hkdf2: prk.fill(0); mixKey: old chainingKey / encryptionKey fill(0)
    N->>N: mixHash: previous handshakeHash fill(0)
    T->>N: processHandshakeMessage(msg3)
    N->>N: splitSymmetricState: sendKey / recvKey set, chainingKey and encryptionKey fill(0)
    N->>N: ephemeralPrivateKey fill(0), dropped
    Note over T,N: transport messages with sendKey / recvKey
    T->>N: reset() on teardown (once)
    N->>N: fill(0) ephemeral, chaining, hash, encryption, send, recv keys
    Note over N: staticPrivateKey kept (device identity)
```

## Errors and refusals

| Condition | Behaviour |
|-----------|-----------|
| DH mixing throws | `mixDh` still zeroes the DH output (`finally`) |
| HKDF expand throws | `hkdf2` still zeroes the pseudorandom key (`finally`) |
| Java X25519 fails | `x25519ScalarMult` falls back to `x25519ScalarMultPure`; the clamped scalar copy is zeroed, the `BigInteger` ladder state cannot be |
| Building the `PKCS8EncodedKeySpec` throws | The PKCS#8 wrapping is zeroed (`finally`) |
| Loading the static key from storage fails | `loadStaticKey` generates a new static key in memory; it is not saved on this path |
| Teardown reached twice | `GattServer.zeroOnce` and `StreamPairingSession.zeroKeys` reset only once per session |

Nothing is refused: zeroization raises no errors of its own. When a handshake
fails part way, the session's handshake secrets stay in place until the
transport's teardown calls `reset()`; whether every failure path reaches that
teardown was not determined from the code.

## Tests

- Unit (`app/src/test`): `NoiseSessionZeroizationTest` (`resetMidHandshakeOverwritesTheHandshakeSecrets`, `resetOverwritesEveryTransientSecretOfACompletedSession`, `completingTheHandshakeOverwritesTheHandshakeKeys`, `aKeyHandedOutByAGetterSurvivesAReset`), and `NoiseHandshakeTest`, which provides the handshake harness (`NoiseInitiatorSession`).
- Instrumented (`app/src/androidTest`): `NoiseStaticKeyMigrationTest` (the stored-key format conversion on the load path).

The tests prove only that the session overwrites the arrays it owns. They do
not prove that no copy is left on the heap.

## Related features

- [Noise pairing](../noise-pairing/architecture.md) — the handshake these keys belong to.
- [BLE transport](../ble-transport/architecture.md)
- [Exportable symmetric keys](../exportable-symmetric-keys/architecture.md) — software key material, which is outside this zeroization scope.
