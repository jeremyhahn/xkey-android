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

/**
 * Manages authentication state across different biometric modes.
 *
 * This class provides thread-safe tracking of authentication state to support
 * various user verification policies:
 * - **DISABLED**: No biometric required, only user presence
 * - **PER_OPERATION**: Biometric required for every operation
 * - **TIME_WINDOW**: Biometric valid for a configurable duration after authentication
 * - **PER_SESSION**: Biometric required once per connection; each live
 *   connection (USB, BLE, TCP) keeps its own approval (#134)
 *
 * Thread Safety:
 * - [lastAuthTime] uses [AtomicLong] for lock-free timestamp updates
 * - [authenticatedSessions] is guarded by its own monitor
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
     * The connection ids approved for [BiometricAuthMode.PER_SESSION], oldest
     * first. A request on one connection never changes another's approval, so
     * a BLE request between two USB requests leaves USB approved. Bounded by
     * [MAX_SESSIONS]: past it the oldest approval is dropped, which only
     * costs that connection a prompt. A null id is a session of its own.
     */
    private val authenticatedSessions = LinkedHashSet<String>()

    /**
     * Determines whether biometric authentication is required for the current operation.
     *
     * The decision is based on the [BiometricSettingsData.uvPolicy] and
     * [BiometricSettingsData.authMode] settings:
     *
     * - **UV DISABLED**: Always returns `false` - only user presence required
     * - **PER_OPERATION**: Always returns `true` - every operation requires biometric
     * - **TIME_WINDOW**: Returns `true` if elapsed time since last auth >= [BiometricSettingsData.timeWindowSeconds]
     * - **PER_SESSION**: Returns `true` until [sessionId] has been approved
     *
     * The check has no side effect: it never changes another connection's approval.
     *
     * @param settings The current biometric settings containing UV policy and auth mode.
     * @param sessionId The id of the connection the request arrived on, or null.
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
                // Require biometric until this connection has been approved
                synchronized(authenticatedSessions) { key(sessionId) !in authenticatedSessions }
            }
        }
    }

    /**
     * Records a successful biometric authentication.
     *
     * This method should be called after the user successfully completes
     * biometric verification. It updates:
     * - [lastAuthTime] to the current timestamp (for TIME_WINDOW mode)
     * - [authenticatedSessions] to include [sessionId] (for PER_SESSION mode)
     *
     * @param sessionId The id of the connection the user approved, or null.
     */
    fun recordAuthentication(sessionId: String?) {
        lastAuthTime.set(System.currentTimeMillis())
        synchronized(authenticatedSessions) {
            val id = key(sessionId)
            authenticatedSessions.remove(id)
            authenticatedSessions.add(id)
            if (authenticatedSessions.size > MAX_SESSIONS) {
                authenticatedSessions.remove(authenticatedSessions.first())
            }
        }
    }

    /**
     * Clears the session state.
     *
     * This method should be called when a BLE connection is disconnected.
     * It drops every connection's PER_SESSION approval ([authenticatedSessions]).
     *
     * Note: [lastAuthTime] is intentionally NOT cleared, allowing
     * [BiometricAuthMode.TIME_WINDOW] to maintain its window across sessions.
     * This means if a user authenticates, disconnects, and reconnects within
     * the time window, they won't need to re-authenticate.
     */
    fun clearSession() {
        synchronized(authenticatedSessions) { authenticatedSessions.clear() }
    }

    /**
     * Invalidates all authentication state, forcing re-authentication.
     *
     * This method clears:
     * - [lastAuthTime] to 0 (invalidating any TIME_WINDOW grace period)
     * - [authenticatedSessions] (requiring PER_SESSION re-auth on every connection)
     *
     * Use cases:
     * - User explicitly requests re-authentication
     * - Security-sensitive operations require fresh authentication
     * - Administrative action to force re-verification
     */
    fun invalidateAuth() {
        lastAuthTime.set(0L)
        synchronized(authenticatedSessions) { authenticatedSessions.clear() }
    }

    /** The set key for [sessionId]; null maps to a key no connection id uses. */
    private fun key(sessionId: String?): String = sessionId?.let { "id:$it" } ?: NULL_SESSION

    private companion object {
        /** Conversion factor from seconds to milliseconds. */
        const val MILLIS_PER_SECOND = 1000L

        /** Most connections approved at once before the oldest is dropped. */
        const val MAX_SESSIONS = 64

        /** The key of the null session id. */
        const val NULL_SESSION = "null"
    }
}
