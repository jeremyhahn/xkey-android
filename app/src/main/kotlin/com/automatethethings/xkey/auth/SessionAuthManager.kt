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
package com.automatethethings.xkey.auth

import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Manages authentication state across different biometric modes.
 *
 * This class provides thread-safe tracking of authentication state to support
 * various user verification policies:
 * - **DISABLED**: No biometric required, only user presence
 * - **PER_OPERATION**: Biometric required for every operation
 * - **TIME_WINDOW**: Biometric valid for a configurable duration after authentication
 * - **PER_SESSION**: Biometric required once per BLE connection session
 *
 * Thread Safety:
 * - [lastAuthTime] uses [AtomicLong] for lock-free timestamp updates
 * - [currentSessionId] uses [AtomicReference] for lock-free session tracking
 * - [sessionAuthenticated] uses volatile for visibility guarantees
 *
 * Usage:
 * ```kotlin
 * val authManager = SessionAuthManager()
 *
 * // Check if biometric is required before an operation
 * if (authManager.isBiometricRequired(settings, sessionId)) {
 *     // Prompt for biometric
 *     biometricHelper.authenticate(...)
 *     authManager.recordAuthentication(sessionId)
 * }
 *
 * // Clear state on BLE disconnect
 * authManager.clearSession()
 * ```
 *
 * @see BiometricSettingsData
 * @see BiometricAuthMode
 */
class SessionAuthManager {

    /**
     * Timestamp (in milliseconds) of the last successful biometric authentication.
     *
     * Used by [BiometricAuthMode.TIME_WINDOW] to determine if the authentication
     * window has expired. A value of 0 indicates no prior authentication.
     */
    private val lastAuthTime: AtomicLong = AtomicLong(0L)

    /**
     * Current BLE session identifier (typically the device address).
     *
     * Used by [BiometricAuthMode.PER_SESSION] to detect session changes and
     * reset the authenticated state when a new device connects.
     */
    private val currentSessionId: AtomicReference<String?> = AtomicReference(null)

    /**
     * Whether the current session has been authenticated.
     *
     * This flag is set to true after successful biometric authentication in
     * [BiometricAuthMode.PER_SESSION] mode, allowing subsequent operations
     * to skip biometric prompts until the session ends.
     *
     * Volatile ensures visibility across threads without requiring synchronization.
     */
    @Volatile
    private var sessionAuthenticated: Boolean = false

    /**
     * Determines whether biometric authentication is required for the current operation.
     *
     * The decision is based on the [BiometricSettingsData.uvPolicy] and
     * [BiometricSettingsData.authMode] settings:
     *
     * - **UV DISABLED**: Always returns `false` - only user presence required
     * - **PER_OPERATION**: Always returns `true` - every operation requires biometric
     * - **TIME_WINDOW**: Returns `true` if elapsed time since last auth >= [BiometricSettingsData.timeWindowSeconds]
     * - **PER_SESSION**: Returns `true` if this is a new session or session not yet authenticated
     *
     * For [BiometricAuthMode.PER_SESSION], this method has a side effect: if a new
     * session is detected (different [sessionId]), it resets [sessionAuthenticated]
     * to `false` and updates [currentSessionId].
     *
     * @param settings The current biometric settings containing UV policy and auth mode.
     * @param sessionId The current BLE session identifier (device address), or null if not connected.
     * @return `true` if biometric authentication should be prompted, `false` otherwise.
     */
    fun isBiometricRequired(settings: BiometricSettingsData, sessionId: String?): Boolean {
        // UV disabled means no biometric required - only user presence
        if (settings.uvPolicy == UserVerificationPolicy.DISABLED) {
            return false
        }

        // UV is required - determine based on auth mode
        return when (settings.authMode) {
            BiometricAuthMode.PER_OPERATION -> {
                // Always require biometric for every operation
                true
            }

            BiometricAuthMode.TIME_WINDOW -> {
                // Check if the time window has expired
                val elapsedMs = System.currentTimeMillis() - lastAuthTime.get()
                val windowMs = settings.timeWindowSeconds * MILLIS_PER_SECOND
                elapsedMs >= windowMs
            }

            BiometricAuthMode.PER_SESSION -> {
                // Check if this is a new session
                val storedSession = currentSessionId.get()
                if (storedSession != sessionId) {
                    // New session detected - reset authentication state
                    sessionAuthenticated = false
                    currentSessionId.set(sessionId)
                }
                // Require biometric if session not yet authenticated
                !sessionAuthenticated
            }
        }
    }

    /**
     * Records a successful biometric authentication.
     *
     * This method should be called after the user successfully completes
     * biometric verification. It updates:
     * - [lastAuthTime] to the current timestamp (for TIME_WINDOW mode)
     * - [currentSessionId] to the provided session ID
     * - [sessionAuthenticated] to `true` (for PER_SESSION mode)
     *
     * @param sessionId The current BLE session identifier (device address), or null if not connected.
     */
    fun recordAuthentication(sessionId: String?) {
        lastAuthTime.set(System.currentTimeMillis())
        currentSessionId.set(sessionId)
        sessionAuthenticated = true
    }

    /**
     * Clears the session state.
     *
     * This method should be called when a BLE connection is disconnected.
     * It resets:
     * - [currentSessionId] to null
     * - [sessionAuthenticated] to `false`
     *
     * Note: [lastAuthTime] is intentionally NOT cleared, allowing
     * [BiometricAuthMode.TIME_WINDOW] to maintain its window across sessions.
     * This means if a user authenticates, disconnects, and reconnects within
     * the time window, they won't need to re-authenticate.
     */
    fun clearSession() {
        currentSessionId.set(null)
        sessionAuthenticated = false
    }

    /**
     * Invalidates all authentication state, forcing re-authentication.
     *
     * This method clears:
     * - [lastAuthTime] to 0 (invalidating any TIME_WINDOW grace period)
     * - [sessionAuthenticated] to `false` (requiring PER_SESSION re-auth)
     *
     * Use cases:
     * - User explicitly requests re-authentication
     * - Security-sensitive operations require fresh authentication
     * - Administrative action to force re-verification
     *
     * Note: [currentSessionId] is not cleared, preserving session tracking.
     */
    fun invalidateAuth() {
        lastAuthTime.set(0L)
        sessionAuthenticated = false
    }

    private companion object {
        /** Conversion factor from seconds to milliseconds. */
        const val MILLIS_PER_SECOND = 1000L
    }
}
