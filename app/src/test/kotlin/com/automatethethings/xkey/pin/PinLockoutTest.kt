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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A [LockoutClock] the tests drive: the monotonic clock, the wall clock and
 * the boot identifier move independently.
 */
internal class FakeLockoutClock(
    var elapsed: Long = 10_000L,
    var wall: Long = 1_700_000_000_000L,
    var boot: String? = "boot-1"
) : LockoutClock {
    override fun elapsedRealtime(): Long = elapsed
    override fun bootId(): String? = boot
    override fun currentTimeMillis(): Long = wall

    /** Real time passing: both clocks move. */
    fun advance(ms: Long) {
        elapsed += ms
        wall += ms
    }

    /** A reboot after [downMs] powered off: realtime restarts near zero. */
    fun reboot(newBoot: String, downMs: Long = 60_000L) {
        boot = newBoot
        elapsed = 5_000L
        wall += downMs
    }
}

/**
 * Unit tests for [PinLockout]: the lockout survives wall-clock changes and
 * restarts, escalates with backoff and ends in a permanent block.
 */
class PinLockoutTest {

    private val clock = FakeLockoutClock()

    private val fixed = PinLockout.Policy(
        maxAttempts = 5, lockoutDurationSeconds = 300, backoff = false, permanentBlock = true
    )
    private val backoff = fixed.copy(backoff = true)

    private fun failTimes(n: Int, policy: PinLockout.Policy, from: LockoutState = LockoutState()): LockoutState {
        var state = from
        repeat(n) { state = PinLockout.recordFailure(state, policy, clock) }
        return state
    }

    @Test
    fun `failures under the limit only count`() {
        val state = failTimes(4, fixed)

        assertEquals(4, state.failedAttempts)
        assertEquals(LockoutState(failedAttempts = 4), state)
        assertFalse(PinLockout.isLocked(state, fixed, clock))
    }

    @Test
    fun `the failure that reaches the limit locks for the duration`() {
        val state = failTimes(5, fixed)

        assertTrue(PinLockout.isLocked(state, fixed, clock))
        assertEquals(300_000L, PinLockout.remainingMs(state, clock))
        clock.advance(299_999L)
        assertTrue(PinLockout.isLocked(state, fixed, clock))
        clock.advance(1L)
        assertFalse(PinLockout.isLocked(state, fixed, clock))
    }

    @Test
    fun `moving the wall clock forward does not end a lockout`() {
        val state = failTimes(5, fixed)

        clock.wall += 365L * 24 * 60 * 60 * 1000

        assertTrue(PinLockout.isLocked(state, fixed, clock))
        assertEquals(300_000L, PinLockout.remainingMs(state, clock))
    }

    @Test
    fun `moving the wall clock back does not extend a lockout`() {
        val state = failTimes(5, fixed)

        clock.wall -= 365L * 24 * 60 * 60 * 1000
        clock.elapsed += 300_000L

        assertFalse(PinLockout.isLocked(state, fixed, clock))
        assertEquals(0L, PinLockout.remainingMs(state, clock))
    }

    @Test
    fun `a reboot resumes the stored remainder, never zero`() {
        val state = failTimes(5, fixed)
        clock.advance(100_000L)
        val checkpoint = PinLockout.reanchor(state, clock)
        assertEquals(200_000L, checkpoint.remainingMs)

        clock.reboot("boot-2", downMs = 10L * 60 * 60 * 1000)

        assertTrue(PinLockout.isLocked(checkpoint, fixed, clock))
        assertEquals(200_000L, PinLockout.remainingMs(checkpoint, clock))

        // Re-anchored on the new boot, it runs down from there.
        val resumed = PinLockout.reanchor(checkpoint, clock)
        clock.advance(199_999L)
        assertTrue(PinLockout.isLocked(resumed, fixed, clock))
        clock.advance(1L)
        assertFalse(PinLockout.isLocked(resumed, fixed, clock))
    }

    @Test
    fun `realtime going backwards counts as a new boot even without a boot id`() {
        clock.boot = null
        clock.elapsed = 1_000_000L
        val state = failTimes(5, fixed)

        clock.elapsed = 1_000L

        assertEquals(300_000L, PinLockout.remainingMs(state, clock))
    }

    @Test
    fun `without backoff each lockout lasts the base duration`() {
        val schedule = (5..9).map { PinLockout.lockoutDurationMs(it, fixed) }

        assertEquals(List(5) { 300_000L }, schedule)
    }

    @Test
    fun `with backoff each lockout after the first doubles up to the cap`() {
        val schedule = (5..14).map { PinLockout.lockoutDurationMs(it, backoff) }

        val minute = 60_000L
        assertEquals(
            listOf(5L, 10L, 20L, 40L, 80L, 160L, 320L, 640L, 1280L, 1440L).map { it * minute },
            schedule
        )
        assertEquals(PinLockout.MAX_LOCKOUT_MS, PinLockout.lockoutDurationMs(1_000, backoff))
    }

    @Test
    fun `a failure after a lockout ends starts the next, longer one`() {
        var state = failTimes(5, backoff)
        clock.advance(300_000L)
        assertFalse(PinLockout.isLocked(state, backoff, clock))

        state = PinLockout.recordFailure(state, backoff, clock)

        assertEquals(600_000L, PinLockout.remainingMs(state, clock))
    }

    @Test
    fun `the ceiling of consecutive failures blocks for good`() {
        val state = failTimes(PinLockout.PERMANENT_BLOCK_ATTEMPTS, backoff)

        assertTrue(PinLockout.isPermanent(state.failedAttempts, backoff))
        clock.advance(10L * PinLockout.MAX_LOCKOUT_MS)
        clock.reboot("boot-9")
        assertTrue(PinLockout.isLocked(state, backoff, clock))
        assertEquals(Long.MAX_VALUE, PinLockout.displayDeadline(state, backoff, clock))
    }

    @Test
    fun `one failure under the ceiling is not a permanent block`() {
        val state = failTimes(PinLockout.PERMANENT_BLOCK_ATTEMPTS - 1, backoff)

        assertFalse(PinLockout.isPermanent(state.failedAttempts, backoff))
        clock.advance(PinLockout.MAX_LOCKOUT_MS)
        assertFalse(PinLockout.isLocked(state, backoff, clock))
    }

    @Test
    fun `a policy without the permanent block never blocks for good`() {
        val vault = backoff.copy(permanentBlock = false)
        val state = failTimes(100, vault)

        assertFalse(PinLockout.isPermanent(state.failedAttempts, vault))
        clock.advance(PinLockout.MAX_LOCKOUT_MS)
        assertFalse(PinLockout.isLocked(state, vault, clock))
    }

    @Test
    fun `the permanent block is the ceiling or the attempt limit, whichever is higher`() {
        assertEquals(15, PinLockout.permanentBlockAt(fixed))
        assertEquals(20, PinLockout.permanentBlockAt(fixed.copy(maxAttempts = 20)))
        assertEquals(null, PinLockout.permanentBlockAt(fixed.copy(permanentBlock = false)))
    }

    @Test
    fun `a reset state is unlocked`() {
        val blocked = failTimes(PinLockout.PERMANENT_BLOCK_ATTEMPTS, backoff)
        assertTrue(PinLockout.isLocked(blocked, backoff, clock))

        val reset = LockoutState()

        assertFalse(PinLockout.isLocked(reset, backoff, clock))
        assertEquals(0L, PinLockout.displayDeadline(reset, backoff, clock))
    }

    @Test
    fun `an old epoch deadline migrates once and then ignores the wall clock`() {
        val state = PinLockout.fromStored(
            failedAttempts = 5,
            remainingMs = 0,
            anchorElapsedMs = PinLockout.UNANCHORED,
            anchorBootId = null,
            legacyLockedUntil = clock.wall + 120_000L,
            wallNow = clock.wall
        )
        assertEquals(120_000L, state.remainingMs)
        assertEquals(PinLockout.UNANCHORED, state.anchorElapsedMs)

        val anchored = PinLockout.reanchor(state, clock)
        clock.wall += 365L * 24 * 60 * 60 * 1000

        assertEquals(120_000L, PinLockout.remainingMs(anchored, clock))
        clock.elapsed += 120_000L
        assertFalse(PinLockout.isLocked(anchored, fixed, clock))
    }

    @Test
    fun `a stored monotonic state wins over the old epoch deadline`() {
        val stored = PinLockout.fromStored(
            failedAttempts = 5,
            remainingMs = 1_000L,
            anchorElapsedMs = clock.elapsed,
            anchorBootId = clock.boot,
            legacyLockedUntil = clock.wall + 10_000_000L,
            wallNow = clock.wall
        )

        assertEquals(1_000L, PinLockout.remainingMs(stored, clock))
    }

    @Test
    fun `an expired old epoch deadline is not a lockout`() {
        val state = PinLockout.fromStored(
            failedAttempts = 5,
            remainingMs = 0,
            anchorElapsedMs = PinLockout.UNANCHORED,
            anchorBootId = null,
            legacyLockedUntil = clock.wall - 1L,
            wallNow = clock.wall
        )

        assertFalse(PinLockout.isLocked(state, fixed, clock))
    }
}
