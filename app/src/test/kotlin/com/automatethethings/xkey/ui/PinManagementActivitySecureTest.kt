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
import android.view.WindowManager
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The PIN management screen, where a PIN is set and changed, is kept off
 * screenshots, recordings, casts and the recents thumbnail: FLAG_SECURE.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class PinManagementActivitySecureTest {

    @Test
    fun `the PIN management window is FLAG_SECURE`() {
        val activity = Robolectric.buildActivity(PinManagementActivity::class.java).create().get()

        assertTrue(
            "FLAG_SECURE not set",
            activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
        )
    }
}
