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

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.PinSettingsRepository
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The PIN lockout read back from the real DataStore: a [PinManager] rebuilt
 * from storage, as after a process restart, still holds a timed lockout with
 * time left and a permanent block, whatever the wall clock says.
 *
 * The suite saves the device's PIN state in @Before and writes it back in
 * @After.
 */
@RunWith(AndroidJUnit4::class)
class PinLockoutPersistenceTest {

    /** Clocks the test drives; the real Argon2 hasher and DataStore stay. */
    private class TestClock(
        var elapsed: Long = 50_000L,
        var wall: Long = System.currentTimeMillis(),
        var boot: String? = "boot-1"
    ) : LockoutClock {
        override fun elapsedRealtime(): Long = elapsed
        override fun bootId(): String? = boot
        override fun currentTimeMillis(): Long = wall
    }

    private lateinit var context: Context
    private lateinit var original: PinSettingsData
    private val clock = TestClock()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        runBlocking {
            val repository = PinSettingsRepository(context)
            original = repository.getSettings()
            repository.updateSettings(PinSettingsData(backoffEnabled = true))
            val manager = PinManager(repository, clock)
            manager.setSOPIN(currentSOPIN = null, newSOPIN = SO_PIN)
            manager.setUserPIN(soPIN = SO_PIN, newUserPIN = USER_PIN)
        }
    }

    @After
    fun tearDown() {
        runBlocking { PinSettingsRepository(context).updateSettings(original) }
    }

    /** A manager over a freshly built repository: what a restarted process gets. */
    private fun restarted() = PinManager(PinSettingsRepository(context), clock)

    private fun wrongUserPin(manager: PinManager): Throwable? =
        runBlocking { runCatching { manager.verifyUserPIN(WRONG_PIN) }.exceptionOrNull() }

    @Test
    fun lockedUserPinStaysLockedAfterRestart() {
        val first = restarted()
        val max = runBlocking { first.getLockoutStatus(PinType.USER_PIN).maxAttempts }
        repeat(max) { assertTrue(wrongUserPin(first) is PinIncorrectException) }
        clock.elapsed += 60_000L
        clock.wall += 60_000L
        runBlocking { assertTrue(first.getLockoutStatus(PinType.USER_PIN).isLocked) }

        // Restart on a new boot, with the wall clock moved a year ahead.
        clock.boot = "boot-2"
        clock.elapsed = 1_000L
        clock.wall += 365L * 24 * 60 * 60 * 1000
        val second = restarted()

        val status = runBlocking { second.getLockoutStatus(PinType.USER_PIN) }
        assertTrue("the lockout survives the restart", status.isLocked)
        assertTrue("with time left", status.recoverySeconds > 0)
        assertFalse(status.permanent)
        assertEquals(max, status.failedAttempts)
        val e = runBlocking { runCatching { second.verifyUserPIN(USER_PIN) }.exceptionOrNull() }
        assertTrue("the right PIN is refused while locked: $e", e is PinLockedException)
    }

    @Test
    fun permanentBlockPersistsAcrossRestart() {
        runBlocking {
            val repository = PinSettingsRepository(context)
            // One failure short of the ceiling, the last lockout already over.
            repository.updateSettings(
                repository.getSettings().copy(
                    failedUserPinAttempts = PinLockout.PERMANENT_BLOCK_ATTEMPTS - 1,
                    userPinLockedUntil = 0,
                    userPinLockoutRemainingMs = 0,
                    userPinLockoutAnchorElapsedMs = PinLockout.UNANCHORED,
                    userPinLockoutBootId = null
                )
            )
        }
        assertTrue(wrongUserPin(restarted()) is PinIncorrectException)

        clock.boot = "boot-2"
        clock.elapsed = 1_000L
        clock.wall += 365L * 24 * 60 * 60 * 1000
        val second = restarted()

        val status = runBlocking { second.getLockoutStatus(PinType.USER_PIN) }
        assertTrue(status.isLocked)
        assertTrue(status.permanent)
        val e = runBlocking { runCatching { second.verifyUserPIN(USER_PIN) }.exceptionOrNull() }
        assertTrue(e is PinLockedException && e.lockoutStatus.permanent)

        runBlocking { second.resetLockout(SO_PIN) }
        assertTrue(runBlocking { restarted().verifyUserPIN(USER_PIN) })
    }

    private companion object {
        const val SO_PIN = "so-pin-123456"
        const val USER_PIN = "user-pin-123456"
        const val WRONG_PIN = "wrong-pin-123456"
    }
}
