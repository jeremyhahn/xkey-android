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
 * @property isLocked Whether the PIN is currently locked (timed or permanent).
 * @property lockoutUntil Informational wall-clock epoch milliseconds the lockout
 *   ends at (0 = not locked, [Long.MAX_VALUE] = blocked for good). The lockout
 *   runs on a monotonic clock; this is the remaining time added to the wall
 *   clock when the status was built.
 * @property recoverySeconds Remaining seconds until the lockout ends
 *   ([Int.MAX_VALUE] when blocked for good).
 * @property permanent Whether the PIN is blocked until reset: the User PIN by
 *   [PinManager.resetLockout], the SO PIN only by a full reset.
 */
data class LockoutStatus(
    val failedAttempts: Int,
    val maxAttempts: Int,
    val isLocked: Boolean,
    val lockoutUntil: Long,
    val recoverySeconds: Int,
    val permanent: Boolean = false
)

/**
 * Exception thrown when a PIN operation fails due to invalid input or state.
 *
 * @param message Description of the PIN error.
 */
open class PinException(message: String) : Exception(message)

/**
 * A PIN was supplied and verified against the stored hash, and it was wrong.
 * The failed attempt has been counted.
 *
 * @param message Description of the PIN error.
 */
class PinIncorrectException(message: String = "Incorrect PIN") : PinException(message)

/**
 * The operation needs a PIN that is not set (or whose hash is not stored), or
 * a current PIN that the caller did not supply. No attempt is counted.
 *
 * @param message Description of the PIN error.
 */
class PinRequiredException(message: String) : PinException(message)

/**
 * Exception thrown when a PIN verification is attempted while the PIN is locked.
 *
 * @property lockoutStatus The current lockout status at the time of the exception.
 */
class PinLockedException(val lockoutStatus: LockoutStatus) :
    Exception(
        if (lockoutStatus.permanent) "PIN is blocked until reset"
        else "PIN is locked until ${lockoutStatus.lockoutUntil}"
    )

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
 * @param clock The monotonic time base of the lockout ([PinLockout]).
 */
class PinManager(
    private val pinSettingsRepository: PinSettingsRepository,
    private val clock: LockoutClock = pinSettingsRepository.lockoutClock
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
     * @throws PinRequiredException if the SO PIN is already set and [currentSOPIN] is null.
     * @throws PinIncorrectException if the current SO PIN verification fails.
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
                throw PinRequiredException("SO PIN is already set; current SO PIN is required to change it")
            }
            verifyPinInternal(currentSOPIN, PinType.SO_PIN, settings)
        }

        PinHasher.validatePinLength(newSOPIN)
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin(newSOPIN, salt)

        val wasAlreadySet = settings.soPinSet
        pinSettingsRepository.updateSettings(
            withLockoutState(PinType.SO_PIN, settings, LockoutState()).copy(
                soPinSet = true,
                soPinHashBase64 = Base64.encodeToString(hash, Base64.NO_WRAP),
                soPinSaltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP)
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
     * @throws PinRequiredException if the SO PIN has not been set yet.
     * @throws PinIncorrectException if the current SO PIN verification fails.
     * @throws PinLockedException if the SO PIN is currently locked out.
     * @throws IllegalArgumentException if the new SO PIN length is invalid.
     */
    suspend fun changeSOPIN(currentSOPIN: String, newSOPIN: String) {
        pinStateMutex.withLock {
            val settings = pinSettingsRepository.getSettings()
            if (!settings.soPinSet) {
                throw PinRequiredException("SO PIN has not been set yet")
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
     * @throws PinRequiredException if the SO PIN has not been set.
     * @throws PinLockedException if the SO PIN is currently locked out.
     * @throws PinIncorrectException if the PIN verification fails (incorrect PIN).
     */
    suspend fun verifySOPIN(pin: String): Boolean = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.soPinSet) {
            throw PinRequiredException("SO PIN has not been set")
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
     * @throws PinRequiredException if the SO PIN has not been set.
     * @throws PinIncorrectException if the SO PIN verification fails.
     * @throws PinLockedException if the SO PIN is currently locked out.
     * @throws IllegalArgumentException if the new User PIN length is invalid.
     */
    suspend fun setUserPIN(soPIN: String, newUserPIN: String) = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.soPinSet) {
            throw PinRequiredException("SO PIN must be set before setting User PIN")
        }

        verifyPinInternal(soPIN, PinType.SO_PIN, settings)

        PinHasher.validatePinLength(newUserPIN)
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin(newUserPIN, salt)

        // Re-read settings after SO PIN verification (it may have updated attempt counters)
        val currentSettings = pinSettingsRepository.getSettings()
        val wasAlreadySet = currentSettings.userPinSet
        pinSettingsRepository.updateSettings(
            withLockoutState(PinType.USER_PIN, currentSettings, LockoutState()).copy(
                userPinSet = true,
                userPinHashBase64 = Base64.encodeToString(hash, Base64.NO_WRAP),
                userPinSaltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP)
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
     * @throws PinRequiredException if the User PIN has not been set yet.
     * @throws PinIncorrectException if the current User PIN verification fails.
     * @throws PinLockedException if the User PIN is currently locked out.
     * @throws IllegalArgumentException if the new User PIN length is invalid.
     */
    suspend fun changeUserPIN(currentUserPIN: String, newUserPIN: String) = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.userPinSet) {
            throw PinRequiredException("User PIN has not been set yet")
        }

        verifyPinInternal(currentUserPIN, PinType.USER_PIN, settings)

        PinHasher.validatePinLength(newUserPIN)
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin(newUserPIN, salt)

        // Re-read settings after User PIN verification (it may have updated attempt counters)
        val currentSettings = pinSettingsRepository.getSettings()
        pinSettingsRepository.updateSettings(
            withLockoutState(PinType.USER_PIN, currentSettings, LockoutState()).copy(
                userPinSet = true,
                userPinHashBase64 = Base64.encodeToString(hash, Base64.NO_WRAP),
                userPinSaltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP)
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
     * @throws PinRequiredException if the User PIN has not been set.
     * @throws PinLockedException if the User PIN is currently locked out.
     * @throws PinIncorrectException if the PIN verification fails (incorrect PIN).
     */
    suspend fun verifyUserPIN(pin: String): Boolean = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.userPinSet) {
            throw PinRequiredException("User PIN has not been set")
        }
        verifyPinInternal(pin, PinType.USER_PIN, settings)
    }

    /**
     * Get the current lockout status for a PIN type.
     *
     * @param pinType The PIN type to check.
     * @return The current [LockoutStatus].
     */
    suspend fun getLockoutStatus(pinType: PinType): LockoutStatus = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        val state = lockoutState(pinType, settings)
        val policy = policy(settings)
        // Re-anchor a running timed lockout to this boot, so a restart resumes
        // from what was left now rather than from an older measurement.
        if (PinLockout.remainingMs(state, clock) > 0) {
            val reanchored = PinLockout.reanchor(state, clock)
            if (reanchored != state) {
                pinSettingsRepository.updateSettings(withLockoutState(pinType, settings, reanchored))
            }
            return@withLock statusOf(reanchored, policy)
        }
        statusOf(state, policy)
    }

    /**
     * Reset the User PIN lockout counter using SO PIN authentication.
     *
     * This allows the Security Officer to unlock the User PIN after
     * too many failed attempts, without needing to know the User PIN.
     *
     * @param soPIN The SO PIN for administrative authentication.
     * @throws PinRequiredException if the SO PIN has not been set.
     * @throws PinIncorrectException if the SO PIN verification fails.
     * @throws PinLockedException if the SO PIN is currently locked out.
     */
    suspend fun resetLockout(soPIN: String) = pinStateMutex.withLock {
        val settings = pinSettingsRepository.getSettings()
        if (!settings.soPinSet) {
            throw PinRequiredException("SO PIN must be set to reset lockout")
        }

        verifyPinInternal(soPIN, PinType.SO_PIN, settings)

        // Re-read settings after SO PIN verification
        val currentSettings = pinSettingsRepository.getSettings()
        pinSettingsRepository.updateSettings(
            withLockoutState(PinType.USER_PIN, currentSettings, LockoutState())
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

    private suspend fun verifyPinInternal(
        pin: String,
        pinType: PinType,
        settings: com.automatethethings.xkey.settings.PinSettingsData
    ): Boolean {
        // Step 1: Check lockout status. A timed lockout is re-anchored to this
        // boot as it is refused, so a later boot resumes from here.
        val state = lockoutState(pinType, settings)
        val policy = policy(settings)
        if (PinLockout.isLocked(state, policy, clock)) {
            val reanchored = PinLockout.reanchor(state, clock)
            if (reanchored != state) {
                pinSettingsRepository.updateSettings(withLockoutState(pinType, settings, reanchored))
            }
            val lockoutStatus = statusOf(reanchored, policy)
            AuditLogger.logPinVerificationFailed(pinType.auditName, lockoutStatus.failedAttempts)
            throw PinLockedException(lockoutStatus)
        }

        // Step 2: Retrieve stored hash and salt
        val hashBase64: String
        val saltBase64: String
        when (pinType) {
            PinType.SO_PIN -> {
                hashBase64 = settings.soPinHashBase64
                    ?: throw PinRequiredException("SO PIN hash is not stored")
                saltBase64 = settings.soPinSaltBase64
                    ?: throw PinRequiredException("SO PIN salt is not stored")
            }
            PinType.USER_PIN -> {
                hashBase64 = settings.userPinHashBase64
                    ?: throw PinRequiredException("User PIN hash is not stored")
                saltBase64 = settings.userPinSaltBase64
                    ?: throw PinRequiredException("User PIN salt is not stored")
            }
        }

        val expectedHash = Base64.decode(hashBase64, Base64.NO_WRAP)
        val salt = Base64.decode(saltBase64, Base64.NO_WRAP)

        // Step 3: Hash and compare
        val isValid = PinHasher.verifyPin(pin, salt, expectedHash)

        if (isValid) {
            // Step 5: Reset failed attempts on success
            pinSettingsRepository.updateSettings(withLockoutState(pinType, settings, LockoutState()))
            AuditLogger.logPinVerificationSuccess(pinType.auditName)
            return true
        }

        // Step 4: Count the failure; it may start a (longer) lockout or a permanent block
        val failed = PinLockout.recordFailure(state, policy, clock)
        pinSettingsRepository.updateSettings(withLockoutState(pinType, settings, failed))

        AuditLogger.logPinVerificationFailed(pinType.auditName, failed.failedAttempts)
        if (PinLockout.isLocked(failed, policy, clock)) {
            AuditLogger.logPinLockoutTriggered(
                pinType.auditName,
                PinLockout.displayDeadline(failed, policy, clock)
            )
        }
        throw PinIncorrectException()
    }

    /**
     * The lockout policy the PINs are held to: the configured thresholds and
     * backoff, with the permanent block at [PinLockout.PERMANENT_BLOCK_ATTEMPTS].
     */
    private fun policy(settings: com.automatethethings.xkey.settings.PinSettingsData) =
        PinLockout.Policy(
            maxAttempts = settings.maxPinAttempts,
            lockoutDurationSeconds = settings.lockoutDurationSeconds,
            backoff = settings.backoffEnabled,
            permanentBlock = true
        )

    /** The stored lockout state of [pinType], migrating an old epoch deadline. */
    private fun lockoutState(
        pinType: PinType,
        settings: com.automatethethings.xkey.settings.PinSettingsData
    ): LockoutState = when (pinType) {
        PinType.SO_PIN -> PinLockout.fromStored(
            failedAttempts = settings.failedSoPinAttempts,
            remainingMs = settings.soPinLockoutRemainingMs,
            anchorElapsedMs = settings.soPinLockoutAnchorElapsedMs,
            anchorBootId = settings.soPinLockoutBootId,
            legacyLockedUntil = settings.soPinLockedUntil,
            wallNow = clock.currentTimeMillis()
        )
        PinType.USER_PIN -> PinLockout.fromStored(
            failedAttempts = settings.failedUserPinAttempts,
            remainingMs = settings.userPinLockoutRemainingMs,
            anchorElapsedMs = settings.userPinLockoutAnchorElapsedMs,
            anchorBootId = settings.userPinLockoutBootId,
            legacyLockedUntil = settings.userPinLockedUntil,
            wallNow = clock.currentTimeMillis()
        )
    }

    /** [settings] with [pinType]'s lockout replaced by [state]; a default [LockoutState] clears it. */
    private fun withLockoutState(
        pinType: PinType,
        settings: com.automatethethings.xkey.settings.PinSettingsData,
        state: LockoutState
    ): com.automatethethings.xkey.settings.PinSettingsData {
        val deadline = PinLockout.displayDeadline(state, policy(settings), clock)
        return when (pinType) {
            PinType.SO_PIN -> settings.copy(
                failedSoPinAttempts = state.failedAttempts,
                soPinLockedUntil = deadline,
                soPinLockoutRemainingMs = state.remainingMs,
                soPinLockoutAnchorElapsedMs = state.anchorElapsedMs,
                soPinLockoutBootId = state.anchorBootId
            )
            PinType.USER_PIN -> settings.copy(
                failedUserPinAttempts = state.failedAttempts,
                userPinLockedUntil = deadline,
                userPinLockoutRemainingMs = state.remainingMs,
                userPinLockoutAnchorElapsedMs = state.anchorElapsedMs,
                userPinLockoutBootId = state.anchorBootId
            )
        }
    }

    /** The [LockoutStatus] of [state] under [policy], measured now. */
    private fun statusOf(state: LockoutState, policy: PinLockout.Policy): LockoutStatus {
        val permanent = PinLockout.isPermanent(state.failedAttempts, policy)
        val remaining = PinLockout.remainingMs(state, clock)
        return LockoutStatus(
            failedAttempts = state.failedAttempts,
            maxAttempts = policy.maxAttempts,
            isLocked = permanent || remaining > 0,
            lockoutUntil = PinLockout.displayDeadline(state, policy, clock),
            recoverySeconds = when {
                permanent -> Int.MAX_VALUE
                remaining > 0 -> ((remaining + 999) / 1000).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                else -> 0
            },
            permanent = permanent
        )
    }

    private fun buildLockoutStatus(
        pinType: PinType,
        settings: com.automatethethings.xkey.settings.PinSettingsData
    ): LockoutStatus = statusOf(lockoutState(pinType, settings), policy(settings))
}
