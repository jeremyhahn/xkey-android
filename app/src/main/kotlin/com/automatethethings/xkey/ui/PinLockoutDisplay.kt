// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.ui

import com.automatethethings.xkey.pin.LockoutStatus
import com.automatethethings.xkey.settings.PinSettingsData

/**
 * What the PIN screen shows about lockouts: the lockout card, its countdown
 * and the Reset Lockout card.
 *
 * Built only from the [LockoutStatus] values `PinManager.getLockoutStatus`
 * measures on its monotonic clock, so a wall-clock change neither ends nor
 * extends what the screen shows.
 *
 * @property user The User PIN line, or null when it has no failed attempts
 *   and is not locked.
 * @property so The SO PIN line, or null when it has no failed attempts and is
 *   not locked.
 * @property countdownMs Milliseconds to count down, the longer of the timed
 *   lockouts; null when nothing is locked or a PIN is blocked until reset.
 * @property showResetLockout Whether the Reset Lockout card is shown: the
 *   User PIN is locked, for a time or until reset.
 */
data class PinLockoutDisplay(
    val user: Line?,
    val so: Line?,
    val countdownMs: Long?,
    val showResetLockout: Boolean
) {
    /** One PIN's failed attempts and whether it is locked now. */
    data class Line(val failedAttempts: Int, val maxAttempts: Int, val locked: Boolean)

    /** Whether the lockout card is shown at all. */
    val visible: Boolean get() = user != null || so != null

    /** Whether either PIN is locked now. */
    val isLocked: Boolean get() = user?.locked == true || so?.locked == true

    companion object {
        /** The display for the User PIN's [user] and the SO PIN's [so] status. */
        fun from(user: LockoutStatus, so: LockoutStatus): PinLockoutDisplay {
            val permanent = (user.isLocked && user.permanent) || (so.isLocked && so.permanent)
            val timedMs = listOf(user, so)
                .filter { it.isLocked && !it.permanent && it.recoverySeconds > 0 }
                .maxOfOrNull { it.recoverySeconds.toLong() * 1000L }
            return PinLockoutDisplay(
                user = lineOf(user),
                so = lineOf(so),
                countdownMs = if (permanent) null else timedMs,
                showResetLockout = user.isLocked
            )
        }

        /**
         * The settings that can change the lockout status other than the clock.
         *
         * Reading the status re-anchors a running lockout and writes the
         * re-anchored remainder to settings; that write leaves this key
         * unchanged, so the screen reads the status again only when an
         * attempt, a reset or the policy changes it.
         */
        fun refreshKey(settings: PinSettingsData): RefreshKey = RefreshKey(
            failedUserPinAttempts = settings.failedUserPinAttempts,
            failedSoPinAttempts = settings.failedSoPinAttempts,
            maxPinAttempts = settings.maxPinAttempts,
            lockoutDurationSeconds = settings.lockoutDurationSeconds,
            backoffEnabled = settings.backoffEnabled,
            userPinSet = settings.userPinSet,
            soPinSet = settings.soPinSet
        )

        private fun lineOf(status: LockoutStatus): Line? =
            if (status.failedAttempts > 0 || status.isLocked) {
                Line(status.failedAttempts, status.maxAttempts, status.isLocked)
            } else {
                null
            }
    }

    /** See [refreshKey]. */
    data class RefreshKey(
        val failedUserPinAttempts: Int,
        val failedSoPinAttempts: Int,
        val maxPinAttempts: Int,
        val lockoutDurationSeconds: Int,
        val backoffEnabled: Boolean,
        val userPinSet: Boolean,
        val soPinSet: Boolean
    )
}
