/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.pin

import android.util.Base64
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.settings.PinSettingsRepository
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * PIN type discriminator following the PKCS#11 security model.
 *
 * - [SO_PIN]: Security Officer PIN used for administrative operations
 *   (managing User PINs, recovering from lockouts).
 * - [USER_PIN]: Standard user PIN for day-to-day authentication.
 */
enum class PinType {
    /** Security Officer PIN. */
    SO_PIN,

    /** User PIN. */
    USER_PIN;

    /**
     * The token written to the audit log. Fixed strings rather than [name], so
     * renaming the constant cannot silently rewrite history already on disk.
     */
    val auditName: String
        get() = when (this) {
            SO_PIN -> "SO_PIN"
            USER_PIN -> "USER_PIN"
        }
}

/**
 * Represents the current lockout status for a PIN type.
 *
 * @property failedAttempts Number of consecutive failed attempts.
 * @property maxAttempts Maximum allowed attempts before lockout.
 * @property isLocked Whether the PIN is currently locked.
 * @property lockoutUntil Epoch milliseconds until lockout expires (0 = not locked).
 * @property recoverySeconds Remaining seconds until lockout expires.
 */
data class LockoutStatus(
    val failedAttempts: Int,
    val maxAttempts: Int,
    val isLocked: Boolean,
    val lockoutUntil: Long,
    val recoverySeconds: Int
)

/**
 * Exception thrown when a PIN operation fails due to invalid input or state.
 *
 * @param message Description of the PIN error.
 */
class PinException(message: String) : Exception(message)

/**
 * Exception thrown when a PIN verification is attempted while the PIN is locked.
 *
 * @property lockoutStatus The current lockout status at the time of the exception.
 */
class PinLockedException(val lockoutStatus: LockoutStatus) :
    Exception("PIN is locked until ${lockoutStatus.lockoutUntil}")

/**
 * Core PIN management logic for the xKey security key.
 *
 * Manages SO PIN (Security Officer) and User PIN lifecycle including
 * initial setup, change, verification, lockout enforcement, and lockout
 * recovery. Follows the PKCS#11 security model where:
 *
 * - The SO PIN is the first PIN set during device initialization.
 * - The User PIN requires SO PIN authentication to set.
 * - The SO PIN can reset User PIN lockouts.
 * - Both PINs enforce independent lockout counters with configurable
 *   maximum attempts and lockout duration.
 *
 * All PIN hashes and salts are persisted via [PinSettingsRepository]
 * using Base64 encoding (android.util.Base64, NO_WRAP flag).
 *
 * Every operation that mutates PIN state is serialized process-wide so that
 * concurrent attempts cannot interleave their read-modify-write of the
 * lockout counters (see [pinStateMutex]).
 *
 * Usage:
 * ```kotlin
 * val pinManager = PinManager(pinSettingsRepository)
 *
 * // First-time SO PIN setup
 * pinManager.setSOPIN(currentSOPIN = null, newSOPIN = "123456")
 *
 * // Set User PIN (requires SO PIN)
 * pinManager.setUserPIN(soPIN = "123456", newUserPIN = "654321")
 *
 * // Verify User PIN
 * val valid = pinManager.verifyUserPIN("654321")
 * ```
 *
 * @param pinSettingsRepository Repository for persisting PIN settings.
 */
class PinManager(
    private val pinSettingsRepository: PinSettingsRepository
) {

    private companion object {
        /**
         * Serializes every PIN read-modify-write in the process.
         *
         * Attempt counters are read, incremented and written back in separate
         * DataStore transactions, and several components (PIN UI, GATT/USB/TCP
         * request handler) each construct their own [PinManager] over the same
         * store. The lock therefore has to be shared by all instances,
         * otherwise concurrent wrong-PIN attempts can each read the same
         * counter and write back the same value, burning many attempts while
         * the lockout only advances once.
         */
        val pinStateMutex = Mutex()
    }

    /**
     * Set the SO PIN for the first time or change it with current SO PIN authentication.
     *
     * For first-time setup, pass `null` for [currentSOPIN]. For subsequent changes,
     * the current SO PIN must be provided and verified.
     *
     * @param currentSOPIN The current SO PIN for verification, or `null` for first-time setup.
     * @param newSOPIN The new SO PIN to set.
     * @throws PinException if the SO PIN is already set and [currentSOPIN] is null.
     * @throws PinException if the current SO PIN verification fails.
     * @throws PinLockedException if the SO PIN is currently locked out.
     * @throws IllegalArgumentException if the new SO PIN length is invalid.
     */
    suspend fun setSOPIN(currentSOPIN: String?, newSOPIN: String) {
        pinStateMutex.withLock {
            setSOPINLocked(currentSOPIN, newSOPIN)
        }
    }

    /**
     * [setSOPIN] body, to be called with [pinStateMutex] already held.
     */
    private suspend fun setSOPINLocked(currentSOPIN: String?, newSOPIN: String) {
        val settings = pinSettingsRepository.getSettings()

        if (settings.soPinSet) {
            if (currentSOPIN == null) {
                throw PinException("SO PIN is already set; current SO PIN is required to change it")
            }
            verifyPinInternal(currentSOPIN, PinType.SO_PIN, settings)
        }

        PinHasher.validatePinLength(newSOPIN)
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin(newSOPIN, salt)

        val wasAlreadySet = settings.soPinSet
        pinSettingsRepository.updateSettings(
            settings.copy(
                soPinSet = true,
                soPinHashBase64 = Base64.encodeToString(hash, Base64.NO_WRAP),
                soPinSaltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP),
                failedSoPinAttempts = 0,
                soPinLockedUntil = 0
            )
        )
        if (wasAlreadySet) AuditLogger.logPinChanged(PinType.SO_PIN.auditName)
        else AuditLogger.logPinSet(PinType.SO_PIN.auditName)
    }

    /**
     * Change the SO PIN, requiring the current SO PIN for authentication.
     *
     * This is a convenience wrapper around [setSOPIN] that enforces that
     * the current SO PIN is always provided.
     *
     * @param currentSOPIN The current SO PIN for verification.
     * @param newSOPIN The new SO PIN to set.
     * @throws PinException if the SO PIN has not been set yet.
     * @throws PinException if the current SO PIN verification fails.
     * @throws PinLockedException if the SO PIN is currently locked out.
     * @throws IllegalArgumentException if the new SO PIN length is invalid.
     */
    suspend fun changeSOPIN(currentSOPIN: String, newSOPIN: String) {
        pinStateMutex.withLock {
            val settings = pinSettingsRepository.getSettings()
            if (!settings.soPinSet) {
                throw PinException("SO PIN has not been set yet")
            }
            setSOPINLocked(currentSOPIN, newSOPIN)
        }
    }

    /**
     * Verify the SO PIN.
     *
     * Checks lockout status before verification. On success, resets the
     * failed attempt counter. On failure, increments the counter and
     * triggers lockout if the maximum is exceeded.
     *
     * @param pin The SO PIN to verify.
     * @return `true` if the PIN is correct.
     * @throws PinException if the SO PIN has not been set.
     * @throws PinLockedException if the SO PIN is currently locked out.
     * @throws PinException if the PIN verification fails (incorrect PIN).
     */
    suspend fun verifySOPIN(pin: String): Boolean = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.soPinSet) {
            throw PinException("SO PIN has not been set")
        }
        verifyPinInternal(pin, PinType.SO_PIN, settings)
    }

    /**
     * Set the User PIN, requiring SO PIN authentication.
     *
     * The SO PIN must be verified before the User PIN can be set.
     * This enforces the PKCS#11 security model where the Security Officer
     * controls User PIN provisioning.
     *
     * @param soPIN The SO PIN for administrative authentication.
     * @param newUserPIN The new User PIN to set.
     * @throws PinException if the SO PIN has not been set.
     * @throws PinException if the SO PIN verification fails.
     * @throws PinLockedException if the SO PIN is currently locked out.
     * @throws IllegalArgumentException if the new User PIN length is invalid.
     */
    suspend fun setUserPIN(soPIN: String, newUserPIN: String) = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.soPinSet) {
            throw PinException("SO PIN must be set before setting User PIN")
        }

        verifyPinInternal(soPIN, PinType.SO_PIN, settings)

        PinHasher.validatePinLength(newUserPIN)
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin(newUserPIN, salt)

        // Re-read settings after SO PIN verification (it may have updated attempt counters)
        val currentSettings = pinSettingsRepository.getSettings()
        val wasAlreadySet = currentSettings.userPinSet
        pinSettingsRepository.updateSettings(
            currentSettings.copy(
                userPinSet = true,
                userPinHashBase64 = Base64.encodeToString(hash, Base64.NO_WRAP),
                userPinSaltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP),
                failedUserPinAttempts = 0,
                userPinLockedUntil = 0
            )
        )
        if (wasAlreadySet) AuditLogger.logPinChanged(PinType.USER_PIN.auditName)
        else AuditLogger.logPinSet(PinType.USER_PIN.auditName)
    }

    /**
     * Change the User PIN, requiring the current User PIN for authentication.
     *
     * @param currentUserPIN The current User PIN for verification.
     * @param newUserPIN The new User PIN to set.
     * @throws PinException if the User PIN has not been set yet.
     * @throws PinException if the current User PIN verification fails.
     * @throws PinLockedException if the User PIN is currently locked out.
     * @throws IllegalArgumentException if the new User PIN length is invalid.
     */
    suspend fun changeUserPIN(currentUserPIN: String, newUserPIN: String) = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.userPinSet) {
            throw PinException("User PIN has not been set yet")
        }

        verifyPinInternal(currentUserPIN, PinType.USER_PIN, settings)

        PinHasher.validatePinLength(newUserPIN)
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin(newUserPIN, salt)

        // Re-read settings after User PIN verification (it may have updated attempt counters)
        val currentSettings = pinSettingsRepository.getSettings()
        pinSettingsRepository.updateSettings(
            currentSettings.copy(
                userPinSet = true,
                userPinHashBase64 = Base64.encodeToString(hash, Base64.NO_WRAP),
                userPinSaltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP),
                failedUserPinAttempts = 0,
                userPinLockedUntil = 0
            )
        )
        AuditLogger.logPinChanged(PinType.USER_PIN.auditName)
    }

    /**
     * Verify the User PIN.
     *
     * Checks lockout status before verification. On success, resets the
     * failed attempt counter. On failure, increments the counter and
     * triggers lockout if the maximum is exceeded.
     *
     * @param pin The User PIN to verify.
     * @return `true` if the PIN is correct.
     * @throws PinException if the User PIN has not been set.
     * @throws PinLockedException if the User PIN is currently locked out.
     * @throws PinException if the PIN verification fails (incorrect PIN).
     */
    suspend fun verifyUserPIN(pin: String): Boolean = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.userPinSet) {
            throw PinException("User PIN has not been set")
        }
        verifyPinInternal(pin, PinType.USER_PIN, settings)
    }

    /**
     * Get the current lockout status for a PIN type.
     *
     * @param pinType The PIN type to check.
     * @return The current [LockoutStatus].
     */
    suspend fun getLockoutStatus(pinType: PinType): LockoutStatus {
        val settings = pinSettingsRepository.getSettings()
        return buildLockoutStatus(pinType, settings)
    }

    /**
     * Reset the User PIN lockout counter using SO PIN authentication.
     *
     * This allows the Security Officer to unlock the User PIN after
     * too many failed attempts, without needing to know the User PIN.
     *
     * @param soPIN The SO PIN for administrative authentication.
     * @throws PinException if the SO PIN has not been set.
     * @throws PinException if the SO PIN verification fails.
     * @throws PinLockedException if the SO PIN is currently locked out.
     */
    suspend fun resetLockout(soPIN: String) = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.soPinSet) {
            throw PinException("SO PIN must be set to reset lockout")
        }

        verifyPinInternal(soPIN, PinType.SO_PIN, settings)

        // Re-read settings after SO PIN verification
        val currentSettings = pinSettingsRepository.getSettings()
        pinSettingsRepository.updateSettings(
            currentSettings.copy(
                failedUserPinAttempts = 0,
                userPinLockedUntil = 0
            )
        )
        AuditLogger.logPinLockoutReset()
    }

    /**
     * Check whether the PIN system has been initialized (SO PIN set).
     *
     * @return `true` if the SO PIN has been configured.
     */
    suspend fun isInitialized(): Boolean {
        return pinSettingsRepository.getSettings().soPinSet
    }

    /**
     * Check whether the SO PIN has been set.
     *
     * @return `true` if the SO PIN is configured.
     */
    suspend fun soPINSet(): Boolean {
        return pinSettingsRepository.getSettings().soPinSet
    }

    /**
     * Check whether the User PIN has been set.
     *
     * @return `true` if the User PIN is configured.
     */
    suspend fun userPINSet(): Boolean {
        return pinSettingsRepository.getSettings().userPinSet
    }

    /**
     * Internal PIN verification with lockout enforcement.
     *
     * Steps:
     * 1. Check lockout status; throw [PinLockedException] if locked.
     * 2. Hash the input PIN with the stored salt.
     * 3. Compare against the stored hash.
     * 4. On failure: increment failed attempts, trigger lockout if max exceeded.
     * 5. On success: reset failed attempts counter.
     *
     * @param pin The plaintext PIN to verify.
     * @param pinType The type of PIN being verified.
     * @param settings The current PIN settings snapshot.
     * @return `true` if the PIN is correct.
     * @throws PinLockedException if the PIN is currently locked out.
     * @throws PinException if the PIN is incorrect.
     */
    private suspend fun verifyPinInternal(
        pin: String,
        pinType: PinType,
        settings: com.automatethethings.xkey.settings.PinSettingsData
    ): Boolean {
        // Step 1: Check lockout status
        val lockoutStatus = buildLockoutStatus(pinType, settings)
        if (lockoutStatus.isLocked) {
            AuditLogger.logPinVerificationFailed(pinType.auditName, lockoutStatus.failedAttempts)
            throw PinLockedException(lockoutStatus)
        }

        // Step 2: Retrieve stored hash and salt
        val hashBase64: String
        val saltBase64: String
        when (pinType) {
            PinType.SO_PIN -> {
                hashBase64 = settings.soPinHashBase64
                    ?: throw PinException("SO PIN hash is not stored")
                saltBase64 = settings.soPinSaltBase64
                    ?: throw PinException("SO PIN salt is not stored")
            }
            PinType.USER_PIN -> {
                hashBase64 = settings.userPinHashBase64
                    ?: throw PinException("User PIN hash is not stored")
                saltBase64 = settings.userPinSaltBase64
                    ?: throw PinException("User PIN salt is not stored")
            }
        }

        val expectedHash = Base64.decode(hashBase64, Base64.NO_WRAP)
        val salt = Base64.decode(saltBase64, Base64.NO_WRAP)

        // Step 3: Hash and compare
        val isValid = PinHasher.verifyPin(pin, salt, expectedHash)

        if (isValid) {
            // Step 5: Reset failed attempts on success
            when (pinType) {
                PinType.SO_PIN -> {
                    pinSettingsRepository.updateSettings(
                        settings.copy(
                            failedSoPinAttempts = 0,
                            soPinLockedUntil = 0
                        )
                    )
                }
                PinType.USER_PIN -> {
                    pinSettingsRepository.updateSettings(
                        settings.copy(
                            failedUserPinAttempts = 0,
                            userPinLockedUntil = 0
                        )
                    )
                }
            }
            AuditLogger.logPinVerificationSuccess(pinType.auditName)
            return true
        }

        // Step 4: Increment failed attempts on failure, possibly trigger lockout
        val newFailedAttempts: Int
        when (pinType) {
            PinType.SO_PIN -> {
                newFailedAttempts = settings.failedSoPinAttempts + 1
                val lockedUntil = if (newFailedAttempts >= settings.maxPinAttempts) {
                    System.currentTimeMillis() + (settings.lockoutDurationSeconds * 1000L)
                } else {
                    0L
                }
                pinSettingsRepository.updateSettings(
                    settings.copy(
                        failedSoPinAttempts = newFailedAttempts,
                        soPinLockedUntil = lockedUntil
                    )
                )
            }
            PinType.USER_PIN -> {
                newFailedAttempts = settings.failedUserPinAttempts + 1
                val lockedUntil = if (newFailedAttempts >= settings.maxPinAttempts) {
                    System.currentTimeMillis() + (settings.lockoutDurationSeconds * 1000L)
                } else {
                    0L
                }
                pinSettingsRepository.updateSettings(
                    settings.copy(
                        failedUserPinAttempts = newFailedAttempts,
                        userPinLockedUntil = lockedUntil
                    )
                )
            }
        }

        AuditLogger.logPinVerificationFailed(pinType.auditName, newFailedAttempts)
        if (newFailedAttempts >= settings.maxPinAttempts) {
            AuditLogger.logPinLockoutTriggered(
                pinType.auditName,
                System.currentTimeMillis() + (settings.lockoutDurationSeconds * 1000L)
            )
        }
        throw PinException("Incorrect PIN")
    }

    /**
     * Build a [LockoutStatus] from the current settings snapshot.
     *
     * If the lockout time has expired, the PIN is not considered locked
     * even if [lockoutUntil] is non-zero (the counter will be cleared
     * on the next successful verification).
     *
     * @param pinType The PIN type to check.
     * @param settings The current settings snapshot.
     * @return The computed [LockoutStatus].
     */
    private fun buildLockoutStatus(
        pinType: PinType,
        settings: com.automatethethings.xkey.settings.PinSettingsData
    ): LockoutStatus {
        val failedAttempts: Int
        val lockedUntil: Long
        when (pinType) {
            PinType.SO_PIN -> {
                failedAttempts = settings.failedSoPinAttempts
                lockedUntil = settings.soPinLockedUntil
            }
            PinType.USER_PIN -> {
                failedAttempts = settings.failedUserPinAttempts
                lockedUntil = settings.userPinLockedUntil
            }
        }

        val now = System.currentTimeMillis()
        val isLocked = lockedUntil > now
        val recoverySeconds = if (isLocked) {
            ((lockedUntil - now) / 1000).toInt().coerceAtLeast(0)
        } else {
            0
        }

        return LockoutStatus(
            failedAttempts = failedAttempts,
            maxAttempts = settings.maxPinAttempts,
            isLocked = isLocked,
            lockoutUntil = lockedUntil,
            recoverySeconds = recoverySeconds
        )
    }
}
