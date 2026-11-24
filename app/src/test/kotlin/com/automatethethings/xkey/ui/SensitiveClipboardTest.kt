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
import androidx.test.core.app.ApplicationProvider
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
        readable()
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
