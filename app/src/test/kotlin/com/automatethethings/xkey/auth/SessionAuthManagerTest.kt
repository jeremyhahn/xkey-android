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

import com.automatethethings.xkey.settings.AuthTimeWindow
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Unit tests for [SessionAuthManager].
 *
 * The manager decides whether a biometric prompt is owed before a cryptographic
 * operation, so a false negative silently weakens user verification. These
 * tests cover each [BiometricAuthMode] independently, the UV-disabled
 * short-circuit, the session-change side effect, the deliberate asymmetry
 * between [SessionAuthManager.clearSession] (keeps the time window) and
 * [SessionAuthManager.invalidateAuth] (drops it), and the zero/negative window
 * boundaries.
 *
 * The class is pure JVM state (atomics + a volatile flag). Its default clock is
 * android.jar's `SystemClock.elapsedRealtime`, which throws in plain JVM
 * tests, so every test drives a fake monotonic clock through [now].
 */
class SessionAuthManagerTest {

    private lateinit var manager: SessionAuthManager

    /** The fake clock's reading, in milliseconds. */
    @Volatile
    private var now: Long = BOOT_PLUS_AN_HOUR_MS

    @Before
    fun setUp() {
        now = BOOT_PLUS_AN_HOUR_MS
        manager = SessionAuthManager(clock = { now })
    }

    private fun settings(
        mode: BiometricAuthMode,
        uv: UserVerificationPolicy = UserVerificationPolicy.REQUIRED,
        windowSeconds: Int = AuthTimeWindow.MINUTES_10.seconds
    ) = BiometricSettingsData(uvPolicy = uv, authMode = mode, timeWindowSeconds = windowSeconds)

    // -------------------------------------------------------------------------
    // UV disabled
    // -------------------------------------------------------------------------

    @Test
    fun `uv disabled never requires biometric regardless of mode`() {
        for (mode in BiometricAuthMode.entries) {
            val disabled = settings(mode, uv = UserVerificationPolicy.DISABLED)
            assertFalse(
                "UV DISABLED must short-circuit for $mode",
                manager.isBiometricRequired(disabled, "device-a")
            )
        }
    }

    // -------------------------------------------------------------------------
    // PER_OPERATION
    // -------------------------------------------------------------------------

    @Test
    fun `per operation always requires biometric`() {
        val perOperation = settings(BiometricAuthMode.PER_OPERATION)

        assertTrue(manager.isBiometricRequired(perOperation, "device-a"))

        manager.recordAuthentication("device-a")
        assertTrue(
            "a successful auth must not grant a second free operation",
            manager.isBiometricRequired(perOperation, "device-a")
        )
        assertTrue(manager.isBiometricRequired(perOperation, null))
    }

    // -------------------------------------------------------------------------
    // TIME_WINDOW
    // -------------------------------------------------------------------------

    @Test
    fun `time window requires biometric before any authentication`() {
        assertTrue(manager.isBiometricRequired(settings(BiometricAuthMode.TIME_WINDOW), "device-a"))
    }

    @Test
    fun `time window ignores the session id`() {
        val timeWindow = settings(BiometricAuthMode.TIME_WINDOW)
        manager.recordAuthentication("device-a")

        assertFalse(
            "the window is device-independent by design",
            manager.isBiometricRequired(timeWindow, "device-b")
        )
        assertFalse(manager.isBiometricRequired(timeWindow, null))
    }

    @Test
    fun `a zero second window always requires biometric`() {
        val zeroWindow = settings(BiometricAuthMode.TIME_WINDOW, windowSeconds = 0)
        manager.recordAuthentication("device-a")

        assertTrue(
            "elapsed >= 0 holds immediately, so a zero window degrades to per-operation",
            manager.isBiometricRequired(zeroWindow, "device-a")
        )
    }

    @Test
    fun `time window survives a session clear`() {
        // Documented behaviour: disconnecting and reconnecting inside the window
        // must not re-prompt.
        val timeWindow = settings(BiometricAuthMode.TIME_WINDOW)
        manager.recordAuthentication("device-a")

        manager.clearSession()

        assertFalse(manager.isBiometricRequired(timeWindow, "device-a"))
    }

    @Test
    fun `invalidateAuth drops the time window`() {
        val timeWindow = settings(BiometricAuthMode.TIME_WINDOW)
        manager.recordAuthentication("device-a")

        manager.invalidateAuth()

        assertTrue(manager.isBiometricRequired(timeWindow, "device-a"))
    }

    @Test
    fun `time window stays open until one millisecond before it ends`() {
        val timeWindow = settings(BiometricAuthMode.TIME_WINDOW)
        manager.recordAuthentication("device-a")

        now += WINDOW_MS - 1

        assertFalse(manager.isBiometricRequired(timeWindow, "device-a"))
    }

    @Test
    fun `time window requires biometric at and after its end`() {
        val timeWindow = settings(BiometricAuthMode.TIME_WINDOW)
        manager.recordAuthentication("device-a")

        now += WINDOW_MS
        assertTrue("the window is half-open", manager.isBiometricRequired(timeWindow, "device-a"))

        now += 1
        assertTrue(manager.isBiometricRequired(timeWindow, "device-a"))
    }

    @Test
    fun `a clock reading below the recorded authentication counts as expired`() {
        val timeWindow = settings(BiometricAuthMode.TIME_WINDOW)
        manager.recordAuthentication("device-a")

        now -= 1

        assertTrue(
            "a clock that went backwards must not keep the window open",
            manager.isBiometricRequired(timeWindow, "device-a")
        )
    }

    @Test
    fun `time window requires biometric just after boot before any authentication`() {
        now = 1_000L

        assertTrue(
            "never authenticated is not a timestamp at zero",
            manager.isBiometricRequired(settings(BiometricAuthMode.TIME_WINDOW), "device-a")
        )
    }

    @Test
    fun `time window requires biometric just after boot after invalidateAuth`() {
        val timeWindow = settings(BiometricAuthMode.TIME_WINDOW)
        now = 1_000L
        manager.recordAuthentication("device-a")

        manager.invalidateAuth()

        assertTrue(manager.isBiometricRequired(timeWindow, "device-a"))
    }

    @Test
    fun `recordAuthentication after invalidateAuth opens a fresh window`() {
        val timeWindow = settings(BiometricAuthMode.TIME_WINDOW)
        manager.recordAuthentication("device-a")
        manager.invalidateAuth()
        now += WINDOW_MS

        manager.recordAuthentication("device-a")

        now += WINDOW_MS - 1
        assertFalse(manager.isBiometricRequired(timeWindow, "device-a"))
        now += 1
        assertTrue(manager.isBiometricRequired(timeWindow, "device-a"))
    }

    // -------------------------------------------------------------------------
    // PER_SESSION
    // -------------------------------------------------------------------------

    @Test
    fun `per session requires biometric for a fresh session`() {
        assertTrue(manager.isBiometricRequired(settings(BiometricAuthMode.PER_SESSION), "device-a"))
    }

    @Test
    fun `per session prompts on a different connection and keeps the first one's approval`() {
        val perSession = settings(BiometricAuthMode.PER_SESSION)
        manager.recordAuthentication("device-a")

        assertTrue(manager.isBiometricRequired(perSession, "device-b"))
        // device-b stays unauthenticated until it verifies.
        assertTrue(manager.isBiometricRequired(perSession, "device-b"))
        // A request on device-b, still live, does not discard device-a's approval (#134).
        assertFalse(manager.isBiometricRequired(perSession, "device-a"))
    }

    @Test
    fun `per session treats a null session id as its own session`() {
        val perSession = settings(BiometricAuthMode.PER_SESSION)
        manager.recordAuthentication(null)

        assertFalse("null == null is the same session", manager.isBiometricRequired(perSession, null))
        assertTrue(manager.isBiometricRequired(perSession, "device-a"))
    }

    @Test
    fun `per session requires biometric again after clearSession`() {
        val perSession = settings(BiometricAuthMode.PER_SESSION)
        manager.recordAuthentication("device-a")
        assertFalse(manager.isBiometricRequired(perSession, "device-a"))

        manager.clearSession()

        assertTrue(manager.isBiometricRequired(perSession, "device-a"))
    }

    @Test
    fun `per session requires biometric again after invalidateAuth`() {
        val perSession = settings(BiometricAuthMode.PER_SESSION)
        manager.recordAuthentication("device-a")

        manager.invalidateAuth()

        assertTrue(manager.isBiometricRequired(perSession, "device-a"))
    }

    @Test
    fun `re-authenticating after a session change restores the skip`() {
        val perSession = settings(BiometricAuthMode.PER_SESSION)
        manager.recordAuthentication("device-a")
        manager.isBiometricRequired(perSession, "device-b")

        manager.recordAuthentication("device-b")

        assertFalse(manager.isBiometricRequired(perSession, "device-b"))
        assertFalse(manager.isBiometricRequired(perSession, "device-a"))
    }

    // -------------------------------------------------------------------------
    // Mode switching and concurrency
    // -------------------------------------------------------------------------

    @Test
    fun `one authentication satisfies both the time window and the session`() {
        manager.recordAuthentication("device-a")

        assertFalse(manager.isBiometricRequired(settings(BiometricAuthMode.TIME_WINDOW), "device-a"))
        assertFalse(manager.isBiometricRequired(settings(BiometricAuthMode.PER_SESSION), "device-a"))
        assertTrue(manager.isBiometricRequired(settings(BiometricAuthMode.PER_OPERATION), "device-a"))
    }

    @Test
    fun `concurrent reads and writes do not throw and converge on authenticated`() {
        val perSession = settings(BiometricAuthMode.PER_SESSION)
        val pool = Executors.newFixedThreadPool(THREADS)
        val start = CountDownLatch(1)
        val done = CountDownLatch(THREADS)

        repeat(THREADS) { index ->
            pool.execute {
                start.await()
                repeat(ITERATIONS) {
                    if (index % 2 == 0) {
                        manager.recordAuthentication("device-a")
                    } else {
                        manager.isBiometricRequired(perSession, "device-a")
                    }
                }
                done.countDown()
            }
        }
        start.countDown()

        assertTrue(done.await(30, TimeUnit.SECONDS))
        pool.shutdown()

        manager.recordAuthentication("device-a")
        assertFalse(manager.isBiometricRequired(perSession, "device-a"))
    }

    private companion object {
        const val THREADS = 8
        const val ITERATIONS = 500

        /** A fake elapsed-realtime reading well past any window length. */
        const val BOOT_PLUS_AN_HOUR_MS = 3_600_000L

        /** The default [settings] window in milliseconds. */
        val WINDOW_MS = AuthTimeWindow.MINUTES_10.seconds * 1000L
    }
}
