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

import android.app.Activity
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
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.time.Duration

/**
 * A clear left pending by an unreadable clipboard finishes when any window
 * of the app gains focus, not only on the screens that copy. A plain
 * [Activity], which never calls [SensitiveClipboard] itself, stands in for a
 * screen such as the main one.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class ClipboardFocusRetryTest {

    private lateinit var app: Application
    private lateinit var clipboard: ClipboardManager
    private lateinit var controller: ActivityController<Activity>

    @Before
    fun setUp() {
        app = ApplicationProvider.getApplicationContext()
        app.registerActivityLifecycleCallbacks(ClipboardFocusRetry)
        clipboard = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        controller = Robolectric.buildActivity(Activity::class.java).setup()
    }

    @After
    fun tearDown() {
        SensitiveClipboard.tokenReader = SensitiveClipboard::readToken
        controller.pause().stop().destroy()
        app.unregisterActivityLifecycleCallbacks(ClipboardFocusRetry)
    }

    @Test
    fun `a pending clear finishes when any app window gains focus`() {
        SensitiveClipboard.tokenReader = { SensitiveClipboard.TokenRead.Unreadable }
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")
        controller.windowFocusChanged(false)
        idle(46)
        assertEquals("hunter2", clipText())

        SensitiveClipboard.tokenReader = SensitiveClipboard::readToken
        controller.windowFocusChanged(true)
        idle(1)

        assertTrue("clipboard still holds the secret", clipText().isNullOrEmpty())
    }

    @Test
    fun `a foreign clip set while unreadable stays after the focus retry`() {
        SensitiveClipboard.tokenReader = { SensitiveClipboard.TokenRead.Unreadable }
        SensitiveClipboard.copy(clipboard, "secret", "hunter2")
        controller.windowFocusChanged(false)
        clipboard.setPrimaryClip(ClipData.newPlainText("note", "shopping list"))
        idle(46)

        SensitiveClipboard.tokenReader = SensitiveClipboard::readToken
        controller.windowFocusChanged(true)
        idle(1)

        assertEquals("shopping list", clipText())
    }

    private fun idle(seconds: Long) {
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(seconds))
    }

    private fun clipText(): String? =
        clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
}
