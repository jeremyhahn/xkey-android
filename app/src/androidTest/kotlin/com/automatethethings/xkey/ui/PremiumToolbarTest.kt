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
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.appcompat.app.ActionBar
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import org.junit.AfterClass
import org.junit.Before
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [PremiumToolbar], the gradient app bar twelve screens
 * install instead of hand-rolling their own.
 *
 * [PremiumToolbar.install] needs an [androidx.appcompat.app.AppCompatActivity]
 * because it ends by calling `setSupportActionBar`, so these tests run against a
 * real [MainActivity]. The app bar is appended to a *detached* scratch
 * [LinearLayout] rather than to the activity's own content, which keeps the host
 * screen intact and lets one activity serve the whole class: each test installs
 * its own bar, and the only shared state — the support action bar — is replaced
 * by every install.
 *
 * All assertions run inside a single main-thread turn so they observe exactly
 * what `install` produced, before AppCompat's posted options-menu invalidation
 * has a chance to run.
 *
 * Coverage:
 * - both `install` overloads (string resources and pre-resolved text)
 * - the title-only bar versus the title + subtitle bar
 * - the gradient container for both [PremiumToolbar.Accent] families
 * - toolbar sizing, transparency, elevation and up-affordance
 * - menu inflation, present and absent
 * - subtitle typography, dimming and its 72dp title-aligned inset
 */
@RunWith(AndroidJUnit4::class)
class PremiumToolbarTest {

    // ---------------------------------------------------------------
    // Structure
    // ---------------------------------------------------------------

    @Test
    fun install_appendsAGradientColumnToTheGivenParent() {
        onHost { activity ->
            val parent = scratchParent(activity)

            val installed = PremiumToolbar.install(
                activity = activity,
                parent = parent,
                titleRes = R.string.key_vault_title
            )

            assertEquals(1, parent.childCount)
            assertSame(installed.container, parent.getChildAt(0))
            assertEquals(LinearLayout.VERTICAL, installed.container.orientation)

            val params = installed.container.layoutParams
            assertEquals(ViewGroup.LayoutParams.MATCH_PARENT, params.width)
            assertEquals(ViewGroup.LayoutParams.WRAP_CONTENT, params.height)
        }
    }

    @Test
    fun install_fromStringResources_setsTheTitleAndSubtitle() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                titleRes = R.string.key_vault_title,
                subtitleRes = R.string.key_vault_subtitle
            )

            assertEquals(
                activity.getString(R.string.key_vault_title),
                installed.toolbar.title.toString()
            )
            assertNotNull("A subtitle was requested", installed.subtitleView)
            assertEquals(
                activity.getString(R.string.key_vault_subtitle),
                installed.subtitleView!!.text.toString()
            )
            assertEquals(
                "The subtitle sits under the toolbar",
                2,
                installed.container.childCount
            )
            assertSame(installed.subtitleView, installed.container.getChildAt(1))
        }
    }

    /** `subtitleRes = 0` is how callers ask for a title-only bar. */
    @Test
    fun install_withoutASubtitleResource_buildsATitleOnlyBar() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                titleRes = R.string.key_vault_title,
                subtitleRes = 0
            )

            assertNull("No subtitle was requested", installed.subtitleView)
            assertEquals(1, installed.container.childCount)
            assertSame(installed.toolbar, installed.container.getChildAt(0))
        }
    }

    @Test
    fun install_fromResolvedText_usesTheTextVerbatim() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                title = "Key detail",
                subtitle = "ES256 - signing"
            )

            assertEquals("Key detail", installed.toolbar.title.toString())
            assertEquals("ES256 - signing", installed.subtitleView!!.text.toString())
        }
    }

    @Test
    fun install_fromResolvedText_acceptsANullSubtitle() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                title = "Key detail",
                subtitle = null
            )

            assertNull(installed.subtitleView)
        }
    }

    // ---------------------------------------------------------------
    // Gradient accents
    // ---------------------------------------------------------------

    @Test
    fun install_paintsThePrimaryGradientByDefault() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                titleRes = R.string.key_vault_title
            )

            val gradient = installed.container.background as GradientDrawable
            assertEquals(GradientDrawable.Orientation.LEFT_RIGHT, gradient.orientation)
            assertTrue(
                "The default accent is the indigo primary pair",
                intArrayOf(
                    ContextCompat.getColor(activity, R.color.gradient_primary_start),
                    ContextCompat.getColor(activity, R.color.gradient_primary_end)
                ).contentEquals(gradient.colors)
            )
        }
    }

    /** The PIV screens are colour-coded away from the rest of the app. */
    @Test
    fun install_paintsTheTertiaryGradientWhenAsked() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                titleRes = R.string.piv_title,
                accent = PremiumToolbar.Accent.TERTIARY
            )

            val gradient = installed.container.background as GradientDrawable
            assertTrue(
                intArrayOf(
                    ContextCompat.getColor(activity, R.color.gradient_tertiary_start),
                    ContextCompat.getColor(activity, R.color.tertiary_variant)
                ).contentEquals(gradient.colors)
            )
        }
    }

    @Test
    fun accent_coversEveryGradientFamily() {
        assertEquals(
            "A new accent needs its own coverage here",
            2,
            PremiumToolbar.Accent.entries.size
        )
    }

    // ---------------------------------------------------------------
    // Toolbar
    // ---------------------------------------------------------------

    @Test
    fun install_sizesTheToolbarToTheThemesActionBarHeight() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                titleRes = R.string.key_vault_title
            )

            val params = installed.toolbar.layoutParams as LinearLayout.LayoutParams
            assertEquals(ViewGroup.LayoutParams.MATCH_PARENT, params.width)
            assertEquals(UIHelpers.resolveActionBarSize(activity), params.height)
        }
    }

    /** The gradient belongs to the container; the toolbar must not paint over it. */
    @Test
    fun install_leavesTheToolbarTransparentAndFlat() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                titleRes = R.string.key_vault_title
            )

            assertEquals(
                Color.TRANSPARENT,
                (installed.toolbar.background as ColorDrawable).color
            )
            assertEquals(0f, installed.toolbar.elevation, 0.01f)
        }
    }

    @Test
    fun install_becomesTheSupportActionBarWithAnUpAffordance() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                titleRes = R.string.key_vault_title
            )

            val actionBar = activity.supportActionBar
            assertNotNull("install() must call setSupportActionBar", actionBar)
            assertEquals(
                "Screens rely on the up button to navigate back",
                ActionBar.DISPLAY_HOME_AS_UP,
                actionBar!!.displayOptions and ActionBar.DISPLAY_HOME_AS_UP
            )
            assertNotNull(
                "The default up indicator should be installed",
                installed.toolbar.navigationIcon
            )
        }
    }

    /** Passing 0 means "keep the platform default", not "no up button". */
    @Test
    fun install_withoutAnUpIndicator_stillEnablesTheUpButton() {
        onHost { activity ->
            PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                titleRes = R.string.key_vault_title,
                homeAsUpIndicator = 0
            )

            val actionBar = activity.supportActionBar
            assertNotNull(actionBar)
            assertEquals(
                ActionBar.DISPLAY_HOME_AS_UP,
                actionBar!!.displayOptions and ActionBar.DISPLAY_HOME_AS_UP
            )
        }
    }

    // ---------------------------------------------------------------
    // Menu
    // ---------------------------------------------------------------

    @Test
    fun install_leavesTheToolbarMenuEmpty() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                titleRes = R.string.key_vault_title
            )

            assertEquals(0, installed.toolbar.menu.size())
        }
    }


    // ---------------------------------------------------------------
    // Subtitle styling
    // ---------------------------------------------------------------

    @Test
    fun install_dimsTheSubtitleAgainstTheGradient() {
        onHost { activity ->
            val installed = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                title = "Key detail",
                subtitle = "ES256"
            )

            val onPrimary = ContextCompat.getColor(activity, R.color.on_primary)
            assertEquals(
                UIHelpers.applyAlpha(onPrimary, 0.85f),
                installed.subtitleView!!.currentTextColor
            )
            assertEquals(
                UIHelpers.spToPx(activity, 14f),
                installed.subtitleView!!.textSize,
                1f
            )
        }
    }

    /**
     * The 72dp start inset is what lines the subtitle up under the title rather
     * than under the navigation icon.
     */
    @Test
    fun install_insetsTheSubtitleToClearTheNavigationIcon() {
        onHost { activity ->
            val subtitle = PremiumToolbar.install(
                activity = activity,
                parent = scratchParent(activity),
                title = "Key detail",
                subtitle = "ES256"
            ).subtitleView!!

            assertEquals(UIHelpers.dpToPxInt(activity, 72), subtitle.paddingLeft)
            assertEquals(0, subtitle.paddingTop)
            assertEquals(UIHelpers.dpToPxInt(activity, 16), subtitle.paddingRight)
            assertEquals(UIHelpers.dpToPxInt(activity, 12), subtitle.paddingBottom)
        }
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * A detached column to install the app bar into.
     *
     * Using the host activity's real content view would replace the home screen's
     * own layout for the rest of the class; the helper only ever calls
     * `parent.addView`, so an unattached parent exercises it identically.
     */
    private fun scratchParent(activity: MainActivity): LinearLayout =
        LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }

    /** Runs [block] against the shared host activity on the main thread. */
    private lateinit var hostScenario: ActivityScenario<MainActivity>

    /**
     * A fresh host per test. Sharing one activity across the class is cheaper,
     * but any test that finishes it — or any teardown elsewhere in the run that
     * clears the task — leaves every later test failing with "Cannot run
     * onActivity since Activity has been destroyed already".
     */
    @Before
    fun launchHostActivity() {
        hostScenario = ActivityScenario.launch(MainActivity::class.java)
    }

    @After
    fun closeHostActivity() {
        if (::hostScenario.isInitialized) hostScenario.close()
    }

    private fun <T> onHost(block: (MainActivity) -> T): T = withActivity(hostScenario, block)

}
