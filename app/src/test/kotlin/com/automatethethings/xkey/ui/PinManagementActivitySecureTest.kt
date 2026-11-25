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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowDialog

/**
 * The PIN management screen, where a PIN is set and changed, is kept off
 * screenshots, recordings, casts and the recents thumbnail: FLAG_SECURE.
 * A dialog is a window of its own, so every PIN dialog is checked too.
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

    @Test
    fun `the set SO PIN dialog is FLAG_SECURE`() = assertDialogSecure("showSetSoPinDialog")

    @Test
    fun `the set user PIN dialog is FLAG_SECURE`() = assertDialogSecure("showSetUserPinDialog")

    @Test
    fun `the change SO PIN dialog is FLAG_SECURE`() = assertDialogSecure("showChangeSoPinDialog")

    @Test
    fun `the change user PIN dialog is FLAG_SECURE`() = assertDialogSecure("showChangeUserPinDialog")

    @Test
    fun `the reset lockout dialog is FLAG_SECURE`() = assertDialogSecure("showResetLockoutDialog")

    private fun assertDialogSecure(opener: String) {
        val activity = Robolectric.buildActivity(PinManagementActivity::class.java).create().get()

        PinManagementActivity::class.java.getDeclaredMethod(opener)
            .apply { isAccessible = true }
            .invoke(activity)

        val dialog = ShadowDialog.getLatestDialog()
        assertNotNull("$opener showed no dialog", dialog)
        assertTrue(
            "$opener: FLAG_SECURE not set",
            dialog.window!!.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
        )
    }
}
