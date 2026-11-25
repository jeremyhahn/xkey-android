# PIN architecture

> **Status: REFERENCE** · Last verified: 2026-11-23
> As-built description of the phone's SO PIN and User PIN: the `local.pin*` wire family, hashing, lockout and storage.

## Summary

The phone keeps two PINs on the PKCS#11 model: a Security Officer PIN
(`PinType.SO_PIN`), set first, and a User PIN (`PinType.USER_PIN`), which only
the SO PIN can provision. Each PIN is stored as an Argon2id hash with its own
salt, and each has its own failed-attempt counter and lockout. The SO PIN can
clear the User PIN's lockout. The desktop drives this through the
`local.pin*` methods; on the phone, `PinManagementActivity` uses the same
`PinManager`.

All transports share one `RequestHandler`, built in `XKeyGattService` with a
`PinManager(PinSettingsRepository(this))`, and handed to the BLE
(`GattServer`), TCP (`TcpHsmServer`) and USB (`UsbAccessoryServer`) servers.
A `RequestHandler` built without a `PinManager` answers every `local.pin*`
call with `FEATURE_UNAVAILABLE`.

## Components

| Component | File | Role |
|-----------|------|------|
| `RequestHandler` (`handlePinStatus`, `handlePinVerify`, `handlePinSet`, `handlePinChange`, `handlePinResetLockout`) | `app/src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt` | Wire handlers; map `PinManager` exceptions to error codes |
| `PinManager`, `PinType`, `LockoutStatus`, `PinException`, `PinLockedException` | `app/src/main/kotlin/com/automatethethings/xkey/pin/PinManager.kt` | PIN lifecycle and lockout; every read-modify-write runs under one process-wide `pinStateMutex`, shared by all `PinManager` instances |
| `PinHasher` | `app/src/main/kotlin/com/automatethethings/xkey/pin/PinHasher.kt` | Argon2id (Signal `org.signal.argon2`): 64 MiB, 3 iterations, 4 lanes, 32-byte hash, 16-byte salt; PIN length 6 to 63 UTF-8 bytes (`MIN_PIN_LENGTH`, `MAX_PIN_LENGTH`) |
| `PinLockout` | `app/src/main/kotlin/com/automatethethings/xkey/pin/PinLockout.kt` | One lockout rule on a monotonic clock, with backoff and a permanent block, also used for the password vault's passphrase (`PasswordVault`, which keeps its counter in the same settings through `PinSettingsVaultUnlockAttemptStore`); see [Lockout](#lockout). Only a success or a reset clears the count |
| `PinSettingsData`, `PinSettingsRepository` | `app/src/main/kotlin/com/automatethethings/xkey/settings/PinSettings.kt` | Jetpack DataStore persistence of the hashes and salts (Base64, `NO_WRAP`), attempt counters and each PIN's lockout state (time left plus a monotonic anchor, so a lockout survives a restart); defaults `maxPinAttempts = 5`, `lockoutDurationSeconds = 300`, `backoffEnabled = true` |
| `PinManagementActivity` | `app/src/main/kotlin/com/automatethethings/xkey/ui/PinManagementActivity.kt` | On-phone PIN screen over its own `PinManager` |
| `AuditLogger` (`logPinSet`, `logPinChanged`, `logPinVerificationSuccess`, `logPinVerificationFailed`, `logPinLockoutReset`) | `app/src/main/kotlin/com/automatethethings/xkey/audit/AuditLogger.kt` | Audit records for every PIN event |

## Wire methods served

| Method | Constant | Params | Result |
|--------|----------|--------|--------|
| `local.pinStatus` | `MethodNames.LOCAL_PIN_STATUS` | none | `soPinSet`, `userPinSet`, `initialized`, `soLocked`, `userLocked` |
| `local.pinVerify` | `LOCAL_PIN_VERIFY` | `pin`, `pinType` (`USER_PIN` default, or `SO_PIN`) | `verified: true` |
| `local.pinSet` | `LOCAL_PIN_SET` | `pinType`, `newPin`; `currentPin` for an SO PIN that is already set; `soPin` for `USER_PIN` | `success: true` |
| `local.pinChange` | `LOCAL_PIN_CHANGE` | `pinType`, `currentPin`, `newPin` | `success: true` |
| `local.pinResetLockout` | `LOCAL_PIN_RESET_LOCKOUT` | `soPin` | `success: true` (clears the User PIN counter and lock, a permanent block included) |

## Main flow

```mermaid
sequenceDiagram
    participant D as Desktop
    participant H as RequestHandler
    participant M as PinManager
    participant Hs as PinHasher
    participant S as PinSettingsRepository

    D->>H: local.pinSet {pinType SO_PIN, newPin}
    H->>M: setSOPIN(null, newPin)
    M->>Hs: validatePinLength, generateSalt, hashPin
    M->>S: updateSettings(soPinSet, hash, salt, counters 0)
    H-->>D: {success: true}

    D->>H: local.pinSet {pinType USER_PIN, soPin, newPin}
    H->>M: setUserPIN(soPin, newPin)
    M->>M: verifyPinInternal(SO_PIN)
    M->>S: updateSettings(userPinSet, hash, salt)
    H-->>D: {success: true}

    D->>H: local.pinVerify {pin}
    H->>M: verifyUserPIN(pin)
    M->>M: buildLockoutStatus: locked? throw PinLockedException
    M->>Hs: verifyPin(pin, salt, hash)
    alt correct
        M->>S: reset counter
        H-->>D: {verified: true}
    else wrong
        M->>S: counter + 1, lockout state from PinLockout
        H-->>D: error PIN_INCORRECT
    end
```

## Lockout

`PinLockout` is the one failed-attempt rule for both PINs. Each PIN keeps its
own consecutive failure count; a correct PIN clears it.

- **First lockout.** The failure that brings the count to `maxPinAttempts`
  locks the PIN for `lockoutDurationSeconds`.
- **Escalation.** With `backoffEnabled` (the default), each further failure
  doubles the previous lockout, capped at 24 hours (`MAX_LOCKOUT_MS`, or the
  base duration when that is longer). Without backoff every lockout is the
  base duration.
- **Permanent block.** At 15 consecutive failures
  (`PERMANENT_BLOCK_ATTEMPTS`, or `maxPinAttempts` when that is higher) the
  PIN is blocked until it is reset; no amount of time ends it. A blocked User
  PIN is cleared by `local.pinResetLockout` with the SO PIN; a blocked SO PIN
  only by a full reset of the PIN settings.
- **Monotonic clock.** The stored state is the failed count, the time left
  and an anchor: `elapsedRealtime` and the boot identifier at which the time
  left was measured. On the same boot the time left runs down with elapsed
  realtime; after a reboot the stored remainder resumes whole and is
  re-anchored. Moving the wall clock forward or back neither ends nor
  extends a lockout. A lock time stored by an older version as a wall-clock
  deadline is migrated once, by the wall clock.

`LockoutStatus` reports `permanent` for a blocked PIN. Its `lockoutUntil`,
also sent as `lockoutUntil` in the `PIN_LOCKED` error data, is an
informational wall-clock deadline only (`Long.MAX_VALUE` when blocked); the
lock itself never reads it.

The password vault passphrase uses the same clock-safe rule and backoff, but
without the permanent block, which would make the vault unrecoverable.

## Errors and refusals

| Condition | Error code |
|-----------|------------|
| Handler built without a `PinManager` | `FEATURE_UNAVAILABLE` ("PIN support is not available on this transport") |
| Missing params, missing `newPin` on set or change, unknown `pinType` (an absent `pinType` on verify is the User PIN) | `INVALID_PARAMS` |
| New PIN outside 6 to 63 UTF-8 bytes (`PinHasher.validatePinLength`, checked before the `PinManager` is called) | `INVALID_PARAMS` |
| Empty `pin` on verify; missing `currentPin` on change; missing `soPin` on User PIN set or reset | `PIN_REQUIRED` |
| PIN not set (or its hash not stored); SO PIN already set and set without `currentPin` (`PinRequiredException`) | `PIN_REQUIRED` |
| Wrong PIN (`PinIncorrectException`; the failed attempt is counted) | `PIN_INCORRECT` |
| Locked PIN on verify, set, change or reset lockout | `PIN_LOCKED` with `lockoutUntil` and `failedAttempts` in the error data |
| Any other exception | `INTERNAL_ERROR` |

## Tests

- Unit (`app/src/test`): `PinLockoutTest` (wall-clock changes, escalation, permanent block), `PinManagerTest`, `PinHasherTest`, `PinSettingsDataTest`, `ProtocolConstantsTest`, `PinOathHandlerErrorsTest` (the handler error codes above), `PinSettingsVaultUnlockAttemptStoreTest`.
- Instrumented (`app/src/androidTest`): `PinLockoutPersistenceTest` (lockout and block survive a restart), `PinHasherInstrumentedTest`, `PinSettingsRepositoryTest`, `RequestHandlerPinAndDataFamilyTest`, `RequestHandlerErrorPathTest`, `ProtocolIntegrationTest`, `PinManagementActivityUiTest`, `PinManagementFlowTest`.

## Related features

- [PIV](../piv/architecture.md): the other smart-card style family served next to it.
- [User verification](../user-verification/architecture.md)
- [Audit log](../audit-log/architecture.md)
- [Password vault RPCs](../password-vault-rpcs/engineering.md): shares the `PinLockout` rule for the vault passphrase.
