/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * The integer dp/px conversions at a non-integer density (390 dpi, density
 * 2.4375, as on a Pixel 9 Pro Fold). Truncating either direction loses a
 * whole unit: 40dp is 97.5px, and 97px back is 39.79dp.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class, qualifiers = "390dpi")
class UIHelpersRoundingTest {

    private val context get() = RuntimeEnvironment.getApplication()

    @Test
    fun theDisplayDensityIsNotAnInteger() {
        assertEquals(DENSITY, context.resources.displayMetrics.density, 0.0001f)
    }

    @Test
    fun dpToPxInt_roundsToTheNearestPixel() {
        assertEquals(98, UIHelpers.dpToPxInt(context, 40))
        assertEquals(39, UIHelpers.dpToPxInt(context, 16))
    }

    @Test
    fun pxToDpInt_roundsToTheNearestDp() {
        assertEquals(40, UIHelpers.pxToDpInt(context, 97))
        assertEquals(0, UIHelpers.pxToDpInt(context, 1))
    }

    @Test
    fun pxToDpInt_invertsDpToPxInt() {
        for (dp in 0..400) {
            val px = UIHelpers.dpToPxInt(context, dp)
            assertEquals("round trip of ${dp}dp via ${px}px", dp, UIHelpers.pxToDpInt(context, px))
        }
    }

    private companion object {
        const val DENSITY = 390f / 160f
    }
}
