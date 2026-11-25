// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.ui

import com.automatethethings.xkey.pin.LockoutStatus
import com.automatethethings.xkey.settings.PinSettingsData
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The PIN screen's lockout card and Reset Lockout card come only from the
 * [LockoutStatus] values PinManager measures on its monotonic clock, never
 * from the informational wall-clock deadline.
 */
class PinLockoutDisplayTest {

    private val clear = LockoutStatus(
        failedAttempts = 0,
        maxAttempts = 5,
        isLocked = false,
        lockoutUntil = 0,
        recoverySeconds = 0
    )

    @Test
    fun aTimedLockoutStaysLockedAfterTheWallClockJumpsPastItsDeadline() {
        // The wall clock moved forward past the informational deadline; the
        // monotonic remainder still has two minutes.
        val user = LockoutStatus(
            failedAttempts = 5,
            maxAttempts = 5,
            isLocked = true,
            lockoutUntil = 1_000L,
            recoverySeconds = 120
        )

        val display = PinLockoutDisplay.from(user = user, so = clear)

        assertTrue(display.visible)
        assertTrue(display.isLocked)
        assertTrue(display.showResetLockout)
        assertEquals(PinLockoutDisplay.Line(5, 5, locked = true), display.user)
        assertNull(display.so)
        assertEquals(120_000L, display.countdownMs)
    }

    @Test
    fun aPermanentUserBlockShowsResetLockoutWithoutACountdown() {
        val user = LockoutStatus(
            failedAttempts = 10,
            maxAttempts = 5,
            isLocked = true,
            lockoutUntil = Long.MAX_VALUE,
            recoverySeconds = Int.MAX_VALUE,
            permanent = true
        )

        val display = PinLockoutDisplay.from(user = user, so = clear)

        assertTrue(display.isLocked)
        assertTrue(display.showResetLockout)
        assertEquals(PinLockoutDisplay.Line(10, 5, locked = true), display.user)
        assertNull(display.countdownMs)
    }

    @Test
    fun aPermanentBlockSuppressesTheOtherPinsCountdown() {
        val user = LockoutStatus(10, 5, true, Long.MAX_VALUE, Int.MAX_VALUE, permanent = true)
        val so = LockoutStatus(5, 5, true, 1_000L, 60)

        val display = PinLockoutDisplay.from(user = user, so = so)

        assertTrue(display.isLocked)
        assertNull(display.countdownMs)
    }

    @Test
    fun failedAttemptsWithoutALockoutShowTheCardUnlocked() {
        val user = LockoutStatus(2, 5, false, 0, 0)
        val so = LockoutStatus(1, 5, false, 0, 0)

        val display = PinLockoutDisplay.from(user = user, so = so)

        assertTrue(display.visible)
        assertFalse(display.isLocked)
        assertFalse(display.showResetLockout)
        assertEquals(PinLockoutDisplay.Line(2, 5, locked = false), display.user)
        assertEquals(PinLockoutDisplay.Line(1, 5, locked = false), display.so)
        assertNull(display.countdownMs)
    }

    @Test
    fun noAttemptsAndNoLockoutShowNothing() {
        val display = PinLockoutDisplay.from(user = clear, so = clear)

        assertFalse(display.visible)
        assertFalse(display.isLocked)
        assertFalse(display.showResetLockout)
        assertNull(display.user)
        assertNull(display.so)
        assertNull(display.countdownMs)
    }

    @Test
    fun anSoOnlyLockoutShowsNoResetLockoutCard() {
        val so = LockoutStatus(5, 5, true, 1_000L, 30)

        val display = PinLockoutDisplay.from(user = clear, so = so)

        assertTrue(display.isLocked)
        assertFalse(display.showResetLockout)
        assertNull(display.user)
        assertEquals(PinLockoutDisplay.Line(5, 5, locked = true), display.so)
        assertEquals(30_000L, display.countdownMs)
    }

    @Test
    fun theCountdownRunsToTheLongerTimedLockout() {
        val user = LockoutStatus(5, 5, true, 1_000L, 45)
        val so = LockoutStatus(5, 5, true, 1_000L, 90)

        val display = PinLockoutDisplay.from(user = user, so = so)

        assertNotNull(display.countdownMs)
        assertEquals(90_000L, display.countdownMs)
    }

    @Test
    fun reanchoringALockoutDoesNotChangeTheRefreshKey() {
        // getLockoutStatus re-anchors a running lockout and writes settings;
        // the screen must not read the status again for that write, or it loops.
        val before = PinSettingsData(
            failedUserPinAttempts = 5,
            userPinLockedUntil = 10_000L,
            userPinLockoutRemainingMs = 60_000L,
            userPinLockoutAnchorElapsedMs = 100L,
            userPinLockoutBootId = "boot-a"
        )
        val after = before.copy(
            userPinLockedUntil = 20_000L,
            userPinLockoutRemainingMs = 59_000L,
            userPinLockoutAnchorElapsedMs = 1_100L,
            userPinLockoutBootId = "boot-b",
            soPinLockedUntil = 5L,
            soPinLockoutRemainingMs = 1L,
            soPinLockoutAnchorElapsedMs = 2L,
            soPinLockoutBootId = "boot-b"
        )

        assertEquals(PinLockoutDisplay.refreshKey(before), PinLockoutDisplay.refreshKey(after))
    }

    @Test
    fun aFailedAttemptOrAResetChangesTheRefreshKey() {
        val base = PinSettingsData(failedUserPinAttempts = 4)

        assertNotEquals(
            PinLockoutDisplay.refreshKey(base),
            PinLockoutDisplay.refreshKey(base.copy(failedUserPinAttempts = 5))
        )
        assertNotEquals(
            PinLockoutDisplay.refreshKey(base),
            PinLockoutDisplay.refreshKey(base.copy(failedUserPinAttempts = 0))
        )
        assertNotEquals(
            PinLockoutDisplay.refreshKey(base),
            PinLockoutDisplay.refreshKey(base.copy(failedSoPinAttempts = 1))
        )
        assertNotEquals(
            PinLockoutDisplay.refreshKey(base),
            PinLockoutDisplay.refreshKey(base.copy(maxPinAttempts = 3))
        )
    }
}
