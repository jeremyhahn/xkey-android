/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.settings

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.R
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * A per-session approval lasts as long as the desktop's connection
 * ([com.automatethethings.xkey.auth.SessionAuthManager] clears it on
 * disconnect); sending the app to the background does not end it. The
 * Settings text says what the code does.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class PerSessionDescriptionTest {

    private val description: String
        get() = ApplicationProvider.getApplicationContext<Application>()
            .getString(R.string.settings_auth_mode_per_session_description)

    @Test
    fun `the per-session text does not tie the approval to the app going to the background`() {
        assertFalse(description, description.contains("background", ignoreCase = true))
    }

    @Test
    fun `the per-session text names the desktop connection`() {
        assertTrue(description, description.contains("connection", ignoreCase = true))
    }
}
