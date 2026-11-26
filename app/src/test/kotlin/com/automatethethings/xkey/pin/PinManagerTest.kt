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
import android.util.Log
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.PinSettingsRepository
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [PinManager].
 *
 * Uses [mockkObject] to mock the [PinHasher] singleton (which requires Signal
 * Argon2 JNI at runtime) and a mocked [PinSettingsRepository] for DataStore
 * persistence.
 */
class PinManagerTest {

    private lateinit var pinSettingsRepo: PinSettingsRepository
    private lateinit var pinManager: PinManager

    /** Fixed salt returned by mocked PinHasher.generateSalt(). */
    private val fixedSalt = ByteArray(16) { 0x42 }

    /** Fixed hash returned by mocked PinHasher.hashPin() for any input. */
    private val fixedHash = ByteArray(32) { 0x7F }

    /**
     * Captured settings from updateSettings calls.
     * Re-created per test to avoid cross-test leakage.
     */
    private val settingsSlot = slot<PinSettingsData>()

    /**
     * The mutable settings snapshot returned by getSettings().
     * Each test configures this to its initial state.
     */
    private var currentSettings = PinSettingsData()

    @Before
    fun setUp() {
        // Mock PinHasher (Kotlin object)
        mockkObject(PinHasher)
        every { PinHasher.generateSalt() } returns fixedSalt
        every { PinHasher.hashPin(any(), any()) } returns fixedHash
        every { PinHasher.verifyPin(any(), any(), any()) } answers {
            // Simple mock: compare the pin string with a convention --
            // "correct-pin" always matches; anything else fails.
            val pin = firstArg<String>()
            pin == "correct-pin" || pin == "correct-so-pin" || pin == "correct-user-pin"
        }
        every { PinHasher.validatePinLength(any()) } just Runs

        // PinManager now writes an audit record for every verification, set,
        // change and lockout. AuditLogger drops entries when it has no DAO, but
        // it says so through android.util.Log, which throws off-device.
        mockkStatic(Log::class)
        every { Log.v(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0

        // Mock android.util.Base64 (not available in JVM unit tests)
        mockkStatic(Base64::class)
        every { Base64.encodeToString(any(), any()) } answers {
            java.util.Base64.getEncoder().encodeToString(firstArg())
        }
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }

        // Mock PinSettingsRepository
        pinSettingsRepo = mockk(relaxed = true)
        coEvery { pinSettingsRepo.getSettings() } answers { currentSettings }
        coEvery { pinSettingsRepo.updateSettings(capture(settingsSlot)) } answers {
            currentSettings = settingsSlot.captured
        }

        pinManager = PinManager(pinSettingsRepo, clock)
    }

    /** The lockout's clocks; the wall clock starts at the real time the epoch-field tests use. */
    private val clock = FakeLockoutClock(wall = System.currentTimeMillis())

    @After
    fun tearDown() {
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // Initialization checks
    // -------------------------------------------------------------------------

    @Test
    fun `isInitialized returns false when no PINs set`() = runTest {
        currentSettings = PinSettingsData(soPinSet = false, userPinSet = false)

        assertFalse(pinManager.isInitialized())
    }

    @Test
    fun `isInitialized returns true after SO PIN set`() = runTest {
        currentSettings = PinSettingsData(soPinSet = true)

        assertTrue(pinManager.isInitialized())
    }

    @Test
    fun `soPINSet returns true after SO PIN set`() = runTest {
        currentSettings = PinSettingsData(soPinSet = true)

        assertTrue(pinManager.soPINSet())
    }

    @Test
    fun `userPINSet returns false when not set`() = runTest {
        currentSettings = PinSettingsData(userPinSet = false)

        assertFalse(pinManager.userPINSet())
    }

    // -------------------------------------------------------------------------
    // setSOPIN
    // -------------------------------------------------------------------------

    @Test
    fun `setSOPIN first time succeeds`() = runTest {
        currentSettings = PinSettingsData(soPinSet = false)

        pinManager.setSOPIN(currentSOPIN = null, newSOPIN = "123456")

        coVerify { pinSettingsRepo.updateSettings(any()) }
        assertTrue(settingsSlot.captured.soPinSet)
        assertEquals(0, settingsSlot.captured.failedSoPinAttempts)
    }

    @Test(expected = PinException::class)
    fun `setSOPIN when already set requires current PIN`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = encodedHash(),
            soPinSaltBase64 = encodedSalt()
        )

        // Passing null for currentSOPIN when soPinSet=true should throw
        pinManager.setSOPIN(currentSOPIN = null, newSOPIN = "new-pin-123456")
    }

    @Test
    fun `setSOPIN when already set with correct current PIN succeeds`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = encodedHash(),
            soPinSaltBase64 = encodedSalt()
        )

        pinManager.setSOPIN(currentSOPIN = "correct-so-pin", newSOPIN = "new-pin-123456")

        coVerify(atLeast = 1) { pinSettingsRepo.updateSettings(any()) }
        assertTrue(settingsSlot.captured.soPinSet)
    }

    // -------------------------------------------------------------------------
    // verifySOPIN
    // -------------------------------------------------------------------------

    @Test
    fun `verifySOPIN returns true for correct PIN`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = encodedHash(),
            soPinSaltBase64 = encodedSalt(),
            failedSoPinAttempts = 0,
            soPinLockedUntil = 0
        )

        val result = pinManager.verifySOPIN("correct-so-pin")

        assertTrue(result)
    }

    @Test(expected = PinException::class)
    fun `verifySOPIN throws for wrong PIN and increments failures`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = encodedHash(),
            soPinSaltBase64 = encodedSalt(),
            failedSoPinAttempts = 0,
            soPinLockedUntil = 0,
            maxPinAttempts = 5
        )

        try {
            pinManager.verifySOPIN("wrong-pin")
        } catch (e: PinException) {
            assertEquals(1, currentSettings.failedSoPinAttempts)
            throw e
        }
    }

    @Test(expected = PinLockedException::class)
    fun `verifySOPIN throws PinLockedException after max attempts`() = runTest {
        // SO PIN is locked (lockout in the future)
        currentSettings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = encodedHash(),
            soPinSaltBase64 = encodedSalt(),
            failedSoPinAttempts = 5,
            maxPinAttempts = 5,
            soPinLockedUntil = System.currentTimeMillis() + 300_000L
        )

        pinManager.verifySOPIN("correct-so-pin")
    }

    @Test(expected = PinException::class)
    fun `verifySOPIN throws when SO PIN has not been set`() = runTest {
        currentSettings = PinSettingsData(soPinSet = false)

        pinManager.verifySOPIN("any-pin")
    }

    // -------------------------------------------------------------------------
    // setUserPIN
    // -------------------------------------------------------------------------

    @Test
    fun `setUserPIN requires valid SO PIN`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = encodedHash(),
            soPinSaltBase64 = encodedSalt(),
            failedSoPinAttempts = 0,
            soPinLockedUntil = 0
        )

        pinManager.setUserPIN(soPIN = "correct-so-pin", newUserPIN = "user-pin-123456")

        assertTrue(currentSettings.userPinSet)
        assertEquals(0, currentSettings.failedUserPinAttempts)
    }

    @Test(expected = PinException::class)
    fun `setUserPIN throws when SO PIN not set`() = runTest {
        currentSettings = PinSettingsData(soPinSet = false)

        pinManager.setUserPIN(soPIN = "any-pin", newUserPIN = "user-pin-123456")
    }

    @Test(expected = PinException::class)
    fun `setUserPIN throws when SO PIN verification fails`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = encodedHash(),
            soPinSaltBase64 = encodedSalt(),
            failedSoPinAttempts = 0,
            soPinLockedUntil = 0
        )

        pinManager.setUserPIN(soPIN = "wrong-so-pin", newUserPIN = "user-pin-123456")
    }

    // -------------------------------------------------------------------------
    // changeUserPIN
    // -------------------------------------------------------------------------

    @Test(expected = PinException::class)
    fun `changeUserPIN with wrong current PIN fails`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            userPinSet = true,
            userPinHashBase64 = encodedHash(),
            userPinSaltBase64 = encodedSalt(),
            failedUserPinAttempts = 0,
            userPinLockedUntil = 0
        )

        pinManager.changeUserPIN(
            currentUserPIN = "wrong-pin",
            newUserPIN = "new-user-pin-123456"
        )
    }

    @Test(expected = PinException::class)
    fun `changeUserPIN throws when user PIN not set`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            userPinSet = false
        )

        pinManager.changeUserPIN(
            currentUserPIN = "correct-user-pin",
            newUserPIN = "new-user-pin-123456"
        )
    }

    @Test
    fun `changeUserPIN succeeds with correct current PIN`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            userPinSet = true,
            userPinHashBase64 = encodedHash(),
            userPinSaltBase64 = encodedSalt(),
            failedUserPinAttempts = 0,
            userPinLockedUntil = 0
        )

        pinManager.changeUserPIN(
            currentUserPIN = "correct-user-pin",
            newUserPIN = "new-user-pin-123456"
        )

        assertTrue(currentSettings.userPinSet)
        assertEquals(0, currentSettings.failedUserPinAttempts)
    }

    // -------------------------------------------------------------------------
    // resetLockout
    // -------------------------------------------------------------------------

    @Test
    fun `resetLockout with valid SO PIN resets user PIN lockout`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = encodedHash(),
            soPinSaltBase64 = encodedSalt(),
            failedSoPinAttempts = 0,
            soPinLockedUntil = 0,
            userPinSet = true,
            failedUserPinAttempts = 5,
            userPinLockedUntil = System.currentTimeMillis() + 300_000L
        )

        pinManager.resetLockout(soPIN = "correct-so-pin")

        assertEquals(0, currentSettings.failedUserPinAttempts)
        assertEquals(0L, currentSettings.userPinLockedUntil)
    }

    @Test(expected = PinException::class)
    fun `resetLockout throws when SO PIN not set`() = runTest {
        currentSettings = PinSettingsData(soPinSet = false)

        pinManager.resetLockout(soPIN = "any-pin")
    }

    @Test(expected = PinException::class)
    fun `resetLockout throws when SO PIN is incorrect`() = runTest {
        currentSettings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = encodedHash(),
            soPinSaltBase64 = encodedSalt(),
            failedSoPinAttempts = 0,
            soPinLockedUntil = 0
        )

        pinManager.resetLockout(soPIN = "wrong-so-pin")
    }

    // -------------------------------------------------------------------------
    // getLockoutStatus
    // -------------------------------------------------------------------------

    @Test
    fun `getLockoutStatus returns correct status when not locked`() = runTest {
        currentSettings = PinSettingsData(
            failedUserPinAttempts = 2,
            maxPinAttempts = 5,
            userPinLockedUntil = 0
        )

        val status = pinManager.getLockoutStatus(PinType.USER_PIN)

        assertEquals(2, status.failedAttempts)
        assertEquals(5, status.maxAttempts)
        assertFalse(status.isLocked)
        assertEquals(0L, status.lockoutUntil)
        assertEquals(0, status.recoverySeconds)
    }

    @Test
    fun `getLockoutStatus returns locked when lockout in the future`() = runTest {
        val futureTime = System.currentTimeMillis() + 120_000L
        currentSettings = PinSettingsData(
            failedSoPinAttempts = 5,
            maxPinAttempts = 5,
            soPinLockedUntil = futureTime
        )

        val status = pinManager.getLockoutStatus(PinType.SO_PIN)

        assertEquals(5, status.failedAttempts)
        assertEquals(5, status.maxAttempts)
        assertTrue(status.isLocked)
        assertEquals(futureTime, status.lockoutUntil)
        assertTrue(status.recoverySeconds > 0)
    }

    @Test
    fun `getLockoutStatus returns not locked when lockout has expired`() = runTest {
        currentSettings = PinSettingsData(
            failedUserPinAttempts = 5,
            maxPinAttempts = 5,
            userPinLockedUntil = System.currentTimeMillis() - 1000L // in the past
        )

        val status = pinManager.getLockoutStatus(PinType.USER_PIN)

        assertFalse(status.isLocked)
        assertEquals(0, status.recoverySeconds)
    }

    // -------------------------------------------------------------------------
    // Monotonic lockout, escalation and permanent block
    // -------------------------------------------------------------------------

    @Test
    fun `moving the wall clock forward does not end a User PIN lockout`() = runTest {
        currentSettings = userPinProvisioned(backoffEnabled = false)
        repeat(5) { assertTrue(wrongUserPin() is PinIncorrectException) }

        clock.wall += YEAR_MS

        val e = runCatching { pinManager.verifyUserPIN("correct-user-pin") }.exceptionOrNull()
        assertTrue("still locked after the wall clock jumped: $e", e is PinLockedException)
        assertTrue(pinManager.getLockoutStatus(PinType.USER_PIN).isLocked)
    }

    @Test
    fun `moving the wall clock back does not extend a User PIN lockout`() = runTest {
        currentSettings = userPinProvisioned(backoffEnabled = false)
        repeat(5) { wrongUserPin() }

        clock.wall -= YEAR_MS
        clock.elapsed += 300_000L

        assertTrue(pinManager.verifyUserPIN("correct-user-pin"))
        assertEquals(0, currentSettings.failedUserPinAttempts)
        assertEquals(0L, currentSettings.userPinLockoutRemainingMs)
    }

    @Test
    fun `a User PIN lockout survives a restart on a new boot`() = runTest {
        currentSettings = userPinProvisioned(backoffEnabled = false)
        repeat(5) { wrongUserPin() }
        clock.advance(100_000L)
        assertEquals(200, pinManager.getLockoutStatus(PinType.USER_PIN).recoverySeconds)

        clock.reboot("boot-2")
        val restarted = PinManager(pinSettingsRepo, clock)

        val status = restarted.getLockoutStatus(PinType.USER_PIN)
        assertTrue(status.isLocked)
        assertEquals(200, status.recoverySeconds)
        val e = runCatching { restarted.verifyUserPIN("correct-user-pin") }.exceptionOrNull()
        assertTrue(e is PinLockedException)
    }

    @Test
    fun `with backoff the next lockout doubles`() = runTest {
        currentSettings = userPinProvisioned(backoffEnabled = true)
        repeat(5) { wrongUserPin() }
        assertEquals(300, pinManager.getLockoutStatus(PinType.USER_PIN).recoverySeconds)

        clock.advance(300_000L)
        assertTrue(wrongUserPin() is PinIncorrectException)

        val status = pinManager.getLockoutStatus(PinType.USER_PIN)
        assertEquals(6, status.failedAttempts)
        assertEquals(600, status.recoverySeconds)
        assertFalse(status.permanent)
    }

    @Test
    fun `without backoff every lockout lasts the configured duration`() = runTest {
        currentSettings = userPinProvisioned(backoffEnabled = false)
        repeat(5) { wrongUserPin() }
        clock.advance(300_000L)

        wrongUserPin()

        assertEquals(300, pinManager.getLockoutStatus(PinType.USER_PIN).recoverySeconds)
    }

    @Test
    fun `the User PIN blocks for good at the ceiling and only resetLockout clears it`() = runTest {
        currentSettings = userPinProvisioned(backoffEnabled = true)
        failUserPinToCeiling()

        val status = pinManager.getLockoutStatus(PinType.USER_PIN)
        assertTrue(status.isLocked)
        assertTrue(status.permanent)
        assertEquals(PinLockout.PERMANENT_BLOCK_ATTEMPTS, status.failedAttempts)
        assertEquals(Long.MAX_VALUE, status.lockoutUntil)

        clock.advance(100L * PinLockout.MAX_LOCKOUT_MS)
        clock.reboot("boot-3")
        val e = runCatching { pinManager.verifyUserPIN("correct-user-pin") }.exceptionOrNull()
        assertTrue(e is PinLockedException)
        assertTrue((e as PinLockedException).lockoutStatus.permanent)

        pinManager.resetLockout(soPIN = "correct-so-pin")

        assertFalse(pinManager.getLockoutStatus(PinType.USER_PIN).isLocked)
        assertTrue(pinManager.verifyUserPIN("correct-user-pin"))
    }

    @Test
    fun `a permanently blocked SO PIN cannot reset itself`() = runTest {
        currentSettings = userPinProvisioned(backoffEnabled = true)
        repeat(PinLockout.PERMANENT_BLOCK_ATTEMPTS) {
            runCatching { pinManager.verifySOPIN("wrong-so-pin") }
            clock.advance(PinLockout.MAX_LOCKOUT_MS)
        }
        assertTrue(pinManager.getLockoutStatus(PinType.SO_PIN).permanent)

        val e = runCatching { pinManager.resetLockout(soPIN = "correct-so-pin") }.exceptionOrNull()

        assertTrue(e is PinLockedException)
        assertTrue((e as PinLockedException).lockoutStatus.permanent)
    }

    @Test
    fun `a success before the ceiling clears the count and the lockout`() = runTest {
        currentSettings = userPinProvisioned(backoffEnabled = true)
        repeat(5) { wrongUserPin() }
        clock.advance(300_000L)

        assertTrue(pinManager.verifyUserPIN("correct-user-pin"))

        val status = pinManager.getLockoutStatus(PinType.USER_PIN)
        assertEquals(0, status.failedAttempts)
        assertFalse(status.isLocked)
        assertEquals(0L, status.lockoutUntil)
    }

    // -------------------------------------------------------------------------
    // Helper methods
    // -------------------------------------------------------------------------

    /** SO and User PIN set, with the default thresholds (5 attempts, 300 s). */
    private fun userPinProvisioned(backoffEnabled: Boolean) = PinSettingsData(
        soPinSet = true,
        soPinHashBase64 = encodedHash(),
        soPinSaltBase64 = encodedSalt(),
        userPinSet = true,
        userPinHashBase64 = encodedHash(),
        userPinSaltBase64 = encodedSalt(),
        backoffEnabled = backoffEnabled
    )

    /** One wrong User PIN; returns what it threw. */
    private suspend fun wrongUserPin(): Throwable? =
        runCatching { pinManager.verifyUserPIN("wrong-user-pin") }.exceptionOrNull()

    /** Wrong User PINs, waiting out each lockout, up to the permanent block. */
    private suspend fun failUserPinToCeiling() {
        repeat(PinLockout.PERMANENT_BLOCK_ATTEMPTS) {
            assertTrue(wrongUserPin() is PinIncorrectException)
            clock.advance(PinLockout.MAX_LOCKOUT_MS)
        }
    }

    private companion object {
        const val YEAR_MS = 365L * 24 * 60 * 60 * 1000
    }

    /** Returns a Base64-encoded version of [fixedHash] using java.util.Base64. */
    private fun encodedHash(): String =
        java.util.Base64.getEncoder().encodeToString(fixedHash)

    /** Returns a Base64-encoded version of [fixedSalt] using java.util.Base64. */
    private fun encodedSalt(): String =
        java.util.Base64.getEncoder().encodeToString(fixedSalt)
}
