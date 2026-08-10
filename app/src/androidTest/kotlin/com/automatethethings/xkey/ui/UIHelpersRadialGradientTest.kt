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

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Pins down what [UIHelpers.createRadialGradient]'s radius actually means.
 *
 * The helper used to take a 0..1 `radiusRatio`, multiply it by 1000 and comment
 * that the result "will be scaled by view bounds". It is not:
 * [GradientDrawable.setGradientRadius] records a bare float as
 * `RADIUS_TYPE_PIXELS`, and the fraction-relative types can only be chosen from
 * XML, so every caller silently got a fixed 500px radius on a view of any size.
 * The parameter is now `radiusPx` and is passed through untouched.
 */
@RunWith(AndroidJUnit4::class)
class UIHelpersRadialGradientTest {

    private lateinit var hostScenario: ActivityScenario<MainActivity>

    @Before
    fun launchHostActivity() {
        hostScenario = ActivityScenario.launch(MainActivity::class.java)
    }

    @After
    fun closeHostActivity() {
        if (::hostScenario.isInitialized) hostScenario.close()
    }

    @Test
    fun createRadialGradient_usesTheGivenRadiusVerbatim() {
        val gradient = UIHelpers.createRadialGradient(
            centerColor = Color.WHITE,
            edgeColor = Color.BLACK,
            radiusPx = 250f,
            cornerRadius = 4f
        )

        assertEquals(GradientDrawable.RADIAL_GRADIENT, gradient.gradientType)
        assertEquals(
            "The radius must not be rescaled behind the caller's back",
            250f,
            gradient.gradientRadius,
            TOLERANCE_PX
        )
        assertEquals(4f, gradient.cornerRadius, TOLERANCE_PX)
        assertTrue(intArrayOf(Color.WHITE, Color.BLACK).contentEquals(gradient.colors))
    }

    /** A dp-derived radius is the intended way to size one of these. */
    @Test
    fun createRadialGradient_acceptsADensityDerivedRadius() {
        withActivity(hostScenario) { activity ->
            val expected = UIHelpers.dpToPx(activity, 48f)

            val gradient = UIHelpers.createRadialGradient(
                centerColor = Color.RED,
                edgeColor = Color.TRANSPARENT,
                radiusPx = expected
            )

            assertEquals(expected, gradient.gradientRadius, TOLERANCE_PX)
            assertEquals("No corner radius was asked for", 0f, gradient.cornerRadius, TOLERANCE_PX)
        }
    }

    private companion object {
        /** Sub-pixel slack for float comparisons. */
        const val TOLERANCE_PX = 0.01f
    }
}
