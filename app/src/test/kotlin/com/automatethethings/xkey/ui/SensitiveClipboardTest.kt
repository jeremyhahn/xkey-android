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
package com.automatethethings.xkey.ui

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Looper
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.time.Duration

/**
 * [SensitiveClipboard] clears a copied secret only once it can read the
 * clipboard and finds its own token there. Android 10 and later hide the
 * clipboard from an app without window focus; the injected token reader
 * stands in for that, since a test in the app's own process cannot act as
 * another app.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class SensitiveClipboardTest {

    private lateinit var clipboard: ClipboardManager

    @Before
    fun setUp() {
        val context: Context = ApplicationProvider.getApplicationContext()
        clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    }

    @After
    fun tearDown() {
        unmockkAll()
        SensitiveClipboard.clock = MonotonicClock.SYSTEM
        readable()
    }

    @Test
    fun `the deadline clock is the sleep-inclusive one`() {
        assertTrue(SensitiveClipboard.clock === MonotonicClock.SYSTEM)
    }

    @Test
    fun `a clip set while the clipboard is unreadable is not cleared`() {
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")
        unreadable()
        clipboard.setPrimaryClip(ClipData.newPlainText("note", "shopping list"))

        idle(45)

        assertEquals("shopping list", clipText())
    }

    @Test
    fun `an unreadable clipboard is left alone when the time is up`() {
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")
        unreadable()

        idle(45)

        assertEquals("hunter2", clipText())
    }

    @Test
    fun `the clear waits until the clipboard shows the copy is ours`() {
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")
        unreadable()
        idle(45)

        readable()
        SensitiveClipboard.retryPendingClears(clipboard)

        assertTrue("clipboard still holds the secret", clipText().isNullOrEmpty())
    }

    @Test
    fun `a retry finding another clip leaves it`() {
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")
        unreadable()
        clipboard.setPrimaryClip(ClipData.newPlainText("note", "shopping list"))
        idle(45)

        readable()
        SensitiveClipboard.retryPendingClears(clipboard)

        assertEquals("shopping list", clipText())
    }

    @Test
    fun `a retry before the time is up clears nothing`() {
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")
        idle(10)

        SensitiveClipboard.retryPendingClears(clipboard)

        assertEquals("hunter2", clipText())
    }

    @Test
    fun `a copy left asleep past its time is cleared on the next retry`() {
        val asleep = sleepingClock()
        unreadable()
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")

        // The looper is not idled: no awake time passes, only time asleep.
        asleep.ms = 60_000
        readable()
        SensitiveClipboard.retryPendingClears(clipboard)

        assertTrue("clipboard still holds the secret", clipText().isNullOrEmpty())
    }

    @Test
    fun `a copy asleep for less than its time is kept on the next retry`() {
        val asleep = sleepingClock()
        unreadable()
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")

        asleep.ms = 10_000
        readable()
        SensitiveClipboard.retryPendingClears(clipboard)

        assertEquals("hunter2", clipText())
    }

    @Test
    fun `a focus before the time is up after a sleep clears at the time left`() {
        val asleep = awakeAndSleepingClock()
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")
        asleep.ms = 30_000
        idle(5)

        // 35 s on the deadline clock, 5 s of uptime: the focus retry re-arms for the 10 s left.
        SensitiveClipboard.retryPendingClears(clipboard)
        assertEquals("hunter2", clipText())

        idle(9)
        assertEquals("hunter2", clipText())

        idle(1)
        assertTrue("clipboard still holds the secret", clipText().isNullOrEmpty())
    }

    @Test
    fun `a re-armed clear still leaves a clip that is not ours`() {
        val asleep = awakeAndSleepingClock()
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")
        asleep.ms = 30_000
        idle(5)
        SensitiveClipboard.retryPendingClears(clipboard)

        clipboard.setPrimaryClip(ClipData.newPlainText("note", "shopping list"))
        idle(15)

        assertEquals("shopping list", clipText())
    }

    /**
     * Drives [SensitiveClipboard.clock] as uptime plus [Asleep.ms]: idling the
     * paused looper advances awake time on both the timer and the deadline
     * clock, while [Asleep.ms] adds deep sleep to the deadline clock only.
     */
    private fun awakeAndSleepingClock(): Asleep {
        val asleep = Asleep()
        SensitiveClipboard.clock = MonotonicClock { SystemClock.uptimeMillis() + asleep.ms }
        return asleep
    }

    /** Time the device spent asleep: counted by elapsedRealtime, not by uptime. */
    private class Asleep(var ms: Long = 0)

    /**
     * Stubs only the sleep-inclusive clock to run [Asleep.ms] ahead of the
     * real one. Uptime is left alone: the paused looper runs on it.
     */
    private fun sleepingClock(): Asleep {
        val baseNanos = SystemClock.elapsedRealtimeNanos()
        val asleep = Asleep()
        mockkStatic(SystemClock::class)
        every { SystemClock.elapsedRealtimeNanos() } answers { baseNanos + asleep.ms * 1_000_000 }
        every { SystemClock.elapsedRealtime() } answers { baseNanos / 1_000_000 + asleep.ms }
        return asleep
    }

    private fun unreadable() {
        SensitiveClipboard.tokenReader = { SensitiveClipboard.TokenRead.Unreadable }
    }

    private fun readable() {
        SensitiveClipboard.tokenReader = SensitiveClipboard::readToken
    }

    private fun idle(seconds: Long) {
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(seconds))
    }

    private fun clipText(): String? =
        clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
}
