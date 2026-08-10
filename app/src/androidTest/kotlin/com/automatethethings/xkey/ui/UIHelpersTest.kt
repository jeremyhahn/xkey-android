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
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip
import org.junit.AfterClass
import org.junit.Before
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [UIHelpers], the Context-only view/drawable toolkit
 * every xKey screen builds its programmatic UI from.
 *
 * These are unit tests that happen to need a device: nearly every helper reads
 * display metrics, resolves a Material3 theme attribute, or instantiates a
 * Material widget, none of which exist on the JVM. They run against a single
 * [MainActivity] launched once for the whole class ([hostScenario]) because the
 * helpers never mutate their host — they only need a themed [android.content.Context]
 * and the main thread to build views on.
 *
 * Assertions deliberately avoid pinning theme attributes to specific colour
 * resources: `res/values-night/themes.xml` remaps `colorPrimary` and friends, so
 * `resolveThemeColor` is checked for the properties that hold in both modes
 * (opacity, stability, agreement with the ColorStateList overload). Colours the
 * helpers reference *directly* by resource id (`R.color.on_primary`) are safe to
 * compare, since the test resolves the same resource under the same config.
 *
 * Coverage:
 * - the four dp/px conversions plus the sp conversion
 * - theme colour / colour-state-list / action-bar-size resolution and alpha maths
 * - every gradient factory, its orientation, colours and optional corner radius
 * - rounded and pill drawables
 * - badges (plain, all six [UIHelpers.StatusType] variants, custom text, hero)
 * - chips and filter chips, with and without listeners and icons
 * - the empty-state container and both [UIHelpers.fillEmptyState] shapes
 * - detail rows: weights, colour override, monospace variant and stacking
 */
@RunWith(AndroidJUnit4::class)
class UIHelpersTest {

    // ---------------------------------------------------------------
    // Dimension conversions
    // ---------------------------------------------------------------

    @Test
    fun dpToPx_scalesByTheDisplayDensity() {
        onHost { activity ->
            val density = activity.resources.displayMetrics.density
            assertEquals(24f * density, UIHelpers.dpToPx(activity, 24f), TOLERANCE_PX)
        }
    }

    @Test
    fun dpToPx_ofZeroIsZero() {
        onHost { activity ->
            assertEquals(0f, UIHelpers.dpToPx(activity, 0f), TOLERANCE_PX)
        }
    }

    @Test
    fun dpToPxInt_truncatesToWholePixels() {
        onHost { activity ->
            val density = activity.resources.displayMetrics.density
            assertEquals((24 * density).toInt(), UIHelpers.dpToPxInt(activity, 24))
        }
    }

    @Test
    fun pxToDp_invertsDpToPx() {
        onHost { activity ->
            val px = UIHelpers.dpToPx(activity, 16f)
            assertEquals(16f, UIHelpers.pxToDp(activity, px), TOLERANCE_PX)
        }
    }

    @Test
    fun pxToDpInt_invertsDpToPxInt() {
        onHost { activity ->
            val px = UIHelpers.dpToPxInt(activity, 40)
            assertEquals(40, UIHelpers.pxToDpInt(activity, px))
        }
    }

    /**
     * sp scaling depends on the user's font-size preference, so this asserts the
     * relationship rather than a fixed factor: the conversion is linear and
     * anchored at zero.
     */
    @Test
    fun spToPx_isLinearAndAnchoredAtZero() {
        onHost { activity ->
            assertEquals(0f, UIHelpers.spToPx(activity, 0f), TOLERANCE_PX)
            val single = UIHelpers.spToPx(activity, 8f)
            assertTrue("8sp should be a positive pixel value", single > 0f)
            assertEquals(single * 2f, UIHelpers.spToPx(activity, 16f), TOLERANCE_PX)
        }
    }

    // ---------------------------------------------------------------
    // Theme resolution
    // ---------------------------------------------------------------

    @Test
    fun resolveThemeColor_returnsAnOpaqueStableColour() {
        onHost { activity ->
            val first = UIHelpers.resolveThemeColor(
                activity,
                com.google.android.material.R.attr.colorPrimary
            )
            val second = UIHelpers.resolveThemeColor(
                activity,
                com.google.android.material.R.attr.colorPrimary
            )
            assertEquals("Resolution should be stable", first, second)
            assertEquals("Theme colours are opaque", 0xFF, Color.alpha(first))
        }
    }

    @Test
    fun resolveThemeColor_distinguishesDifferentAttributes() {
        onHost { activity ->
            val primary = UIHelpers.resolveThemeColor(
                activity,
                com.google.android.material.R.attr.colorPrimary
            )
            val surface = UIHelpers.resolveThemeColor(
                activity,
                com.google.android.material.R.attr.colorSurface
            )
            assertNotEquals("colorPrimary and colorSurface must differ", primary, surface)
        }
    }

    @Test
    fun resolveThemeColorStateList_agreesWithTheFlatColour() {
        onHost { activity ->
            val list = UIHelpers.resolveThemeColorStateList(
                activity,
                com.google.android.material.R.attr.colorOnSurface
            )
            assertNotNull("colorOnSurface should resolve to a state list", list)
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorOnSurface
                ),
                list!!.defaultColor
            )
        }
    }

    @Test
    fun resolveActionBarSize_isAPositivePixelHeight() {
        onHost { activity ->
            assertTrue(
                "The theme must supply an action bar height",
                UIHelpers.resolveActionBarSize(activity) > 0
            )
        }
    }

    @Test
    fun applyAlpha_replacesAlphaAndPreservesRgb() {
        val faded = UIHelpers.applyAlpha(Color.argb(0xFF, 0x33, 0x66, 0x99), 0.5f)

        assertEquals((0.5f * 255).toInt(), Color.alpha(faded))
        assertEquals(0x33, Color.red(faded))
        assertEquals(0x66, Color.green(faded))
        assertEquals(0x99, Color.blue(faded))
    }

    @Test
    fun applyAlpha_clampsOutOfRangeValues() {
        val opaque = UIHelpers.applyAlpha(Color.RED, 4f)
        val clear = UIHelpers.applyAlpha(Color.RED, -1f)

        assertEquals(0xFF, Color.alpha(opaque))
        assertEquals(0x00, Color.alpha(clear))
        assertEquals(Color.red(Color.RED), Color.red(clear))
    }

    // ---------------------------------------------------------------
    // Gradients
    // ---------------------------------------------------------------

    @Test
    fun createHorizontalGradient_runsLeftToRight() {
        val gradient = UIHelpers.createHorizontalGradient(Color.RED, Color.BLUE)

        assertEquals(GradientDrawable.Orientation.LEFT_RIGHT, gradient.orientation)
        assertTrue(intArrayOf(Color.RED, Color.BLUE).contentEquals(gradient.colors))
    }

    @Test
    fun createVerticalGradient_runsTopToBottom() {
        val gradient = UIHelpers.createVerticalGradient(Color.RED, Color.BLUE)

        assertEquals(GradientDrawable.Orientation.TOP_BOTTOM, gradient.orientation)
        assertTrue(intArrayOf(Color.RED, Color.BLUE).contentEquals(gradient.colors))
    }

    @Test
    fun createDiagonalGradient_runsTopLeftToBottomRight() {
        val gradient = UIHelpers.createDiagonalGradient(Color.RED, Color.BLUE)

        assertEquals(GradientDrawable.Orientation.TL_BR, gradient.orientation)
        assertTrue(intArrayOf(Color.RED, Color.BLUE).contentEquals(gradient.colors))
    }

    /** The corner radius is optional and must stay square when it is omitted. */
    @Test
    fun gradients_haveSquareCornersByDefault() {
        assertEquals(0f, UIHelpers.createHorizontalGradient(Color.RED, Color.BLUE).cornerRadius, 0f)
        assertEquals(0f, UIHelpers.createVerticalGradient(Color.RED, Color.BLUE).cornerRadius, 0f)
        assertEquals(0f, UIHelpers.createDiagonalGradient(Color.RED, Color.BLUE).cornerRadius, 0f)
    }

    @Test
    fun gradients_applyARequestedCornerRadius() {
        assertEquals(
            12f,
            UIHelpers.createHorizontalGradient(Color.RED, Color.BLUE, 12f).cornerRadius,
            TOLERANCE_PX
        )
        assertEquals(
            12f,
            UIHelpers.createVerticalGradient(Color.RED, Color.BLUE, 12f).cornerRadius,
            TOLERANCE_PX
        )
        assertEquals(
            12f,
            UIHelpers.createDiagonalGradient(Color.RED, Color.BLUE, 12f).cornerRadius,
            TOLERANCE_PX
        )
    }

    @Test
    fun createMultiColorGradient_keepsEveryStopAndOrientation() {
        val stops = intArrayOf(Color.RED, Color.GREEN, Color.BLUE)

        val gradient = UIHelpers.createMultiColorGradient(
            colors = stops,
            orientation = GradientDrawable.Orientation.BOTTOM_TOP,
            cornerRadius = 8f
        )

        assertEquals(GradientDrawable.Orientation.BOTTOM_TOP, gradient.orientation)
        assertTrue(stops.contentEquals(gradient.colors))
        assertEquals(8f, gradient.cornerRadius, TOLERANCE_PX)
    }

    @Test(expected = IllegalArgumentException::class)
    fun createMultiColorGradient_rejectsASingleColour() {
        UIHelpers.createMultiColorGradient(
            colors = intArrayOf(Color.RED),
            orientation = GradientDrawable.Orientation.LEFT_RIGHT
        )
    }

    @Test
    fun createRadialGradient_usesTheRadiusItIsGiven() {
        val gradient = UIHelpers.createRadialGradient(
            centerColor = Color.WHITE,
            edgeColor = Color.BLACK,
            radiusPx = 250f,
            cornerRadius = 4f
        )

        assertEquals(GradientDrawable.RADIAL_GRADIENT, gradient.gradientType)
        assertEquals(250f, gradient.gradientRadius, TOLERANCE_PX)
        assertTrue(intArrayOf(Color.WHITE, Color.BLACK).contentEquals(gradient.colors))
        assertEquals(4f, gradient.cornerRadius, TOLERANCE_PX)
    }

    @Test
    fun createRoundedDrawable_fillsAndRoundsWithoutAStroke() {
        val drawable = UIHelpers.createRoundedDrawable(Color.MAGENTA, 6f)

        assertEquals(Color.MAGENTA, drawable.color?.defaultColor)
        assertEquals(6f, drawable.cornerRadius, TOLERANCE_PX)
    }

    @Test
    fun createRoundedDrawable_acceptsAStroke() {
        val drawable = UIHelpers.createRoundedDrawable(
            color = Color.MAGENTA,
            cornerRadius = 6f,
            strokeWidth = 3,
            strokeColor = Color.CYAN
        )

        assertEquals(Color.MAGENTA, drawable.color?.defaultColor)
        assertEquals(6f, drawable.cornerRadius, TOLERANCE_PX)
    }

    @Test
    fun createPillDrawable_roundsToHalfItsHeight() {
        val drawable = UIHelpers.createPillDrawable(Color.GREEN, height = 40f)

        assertEquals(20f, drawable.cornerRadius, TOLERANCE_PX)
        assertEquals(Color.GREEN, drawable.color?.defaultColor)
    }

    // ---------------------------------------------------------------
    // Badges and chips
    // ---------------------------------------------------------------

    @Test
    fun createBadge_appliesTextColourPaddingAndPillBackground() {
        onHost { activity ->
            val badge = UIHelpers.createBadge(activity, "7 keys", Color.DKGRAY, Color.WHITE)

            assertEquals("7 keys", badge.text.toString())
            assertEquals(Color.WHITE, badge.currentTextColor)
            assertEquals(UIHelpers.spToPx(activity, 12f), badge.textSize, TOLERANCE_TEXT_PX)
            assertEquals(UIHelpers.dpToPxInt(activity, 8), badge.paddingLeft)
            assertEquals(UIHelpers.dpToPxInt(activity, 8), badge.paddingRight)
            assertEquals(UIHelpers.dpToPxInt(activity, 4), badge.paddingTop)
            assertEquals(UIHelpers.dpToPxInt(activity, 4), badge.paddingBottom)

            val background = badge.background as GradientDrawable
            assertEquals(Color.DKGRAY, background.color?.defaultColor)
            assertEquals(
                UIHelpers.dpToPx(activity, 12f),
                background.cornerRadius,
                TOLERANCE_PX
            )
        }
    }

    @Test
    fun createBadge_wrapsItsContent() {
        onHost { activity ->
            val params = UIHelpers.createBadge(activity, "x", Color.DKGRAY, Color.WHITE)
                .layoutParams as LinearLayout.LayoutParams

            assertEquals(ViewGroup.LayoutParams.WRAP_CONTENT, params.width)
            assertEquals(ViewGroup.LayoutParams.WRAP_CONTENT, params.height)
        }
    }

    /** Every [UIHelpers.StatusType] must produce its own label. */
    @Test
    fun createStatusBadge_labelsEveryStatusType() {
        onHost { activity ->
            val expected = mapOf(
                UIHelpers.StatusType.ACTIVE to "Active",
                UIHelpers.StatusType.INACTIVE to "Inactive",
                UIHelpers.StatusType.PENDING to "Pending",
                UIHelpers.StatusType.ERROR to "Error",
                UIHelpers.StatusType.SUCCESS to "Success",
                UIHelpers.StatusType.WARNING to "Warning"
            )

            assertEquals(
                "Every StatusType needs a label",
                UIHelpers.StatusType.entries.size,
                expected.size
            )
            for (status in UIHelpers.StatusType.entries) {
                val badge = UIHelpers.createStatusBadge(activity, status)
                assertEquals(expected[status], badge.text.toString())
                assertNotNull("$status should carry a pill background", badge.background)
            }
        }
    }

    @Test
    fun createStatusBadge_stylesEachTypeFromTheTheme() {
        onHost { activity ->
            val active = UIHelpers.createStatusBadge(activity, UIHelpers.StatusType.ACTIVE)
            val error = UIHelpers.createStatusBadge(activity, UIHelpers.StatusType.ERROR)

            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorOnTertiary
                ),
                active.currentTextColor
            )
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorErrorContainer
                ),
                (error.background as GradientDrawable).color?.defaultColor
            )
        }
    }

    @Test
    fun createStatusBadge_withCustomText_keepsTheStatusStyling() {
        onHost { activity ->
            val standard = UIHelpers.createStatusBadge(activity, UIHelpers.StatusType.WARNING)
            val custom = UIHelpers.createStatusBadge(
                activity,
                UIHelpers.StatusType.WARNING,
                "Expiring soon"
            )

            assertEquals("Expiring soon", custom.text.toString())
            assertEquals(standard.currentTextColor, custom.currentTextColor)
            assertEquals(
                (standard.background as GradientDrawable).color?.defaultColor,
                (custom.background as GradientDrawable).color?.defaultColor
            )
        }
    }

    @Test
    fun createChip_defaultsToAClickableNonCheckableChip() {
        onHost { activity ->
            val chip = UIHelpers.createChip(activity, "All")

            assertEquals("All", chip.text.toString())
            assertFalse("Plain chips are not checkable", chip.isCheckable)
            assertTrue(chip.isClickable)
            assertTrue(chip.isFocusable)
            assertNotNull(chip.chipBackgroundColor)
        }
    }

    @Test
    fun createChip_canBeCheckable() {
        onHost { activity ->
            assertTrue(UIHelpers.createChip(activity, "Signing", isCheckable = true).isCheckable)
        }
    }

    @Test
    fun createChip_handsTheChipItselfToTheClickListener() {
        onHost { activity ->
            var clicked: Chip? = null
            val chip = UIHelpers.createChip(activity, "Export") { clicked = it }

            chip.performClick()

            assertSame("The listener receives the chip it was attached to", chip, clicked)
        }
    }

    @Test
    fun createFilterChip_isCheckableAndShowsItsCheckedIcon() {
        onHost { activity ->
            val chip = UIHelpers.createFilterChip(activity, "Errors")

            assertTrue(chip.isCheckable)
            assertTrue(chip.isCheckedIconVisible)
            assertNull("No icon was requested", chip.chipIcon)
        }
    }

    @Test
    fun createFilterChip_showsTheRequestedIcon() {
        onHost { activity ->
            val chip = UIHelpers.createFilterChip(activity, "Keys", iconRes = R.drawable.ic_lock)

            assertNotNull(chip.chipIcon)
            assertTrue(chip.isChipIconVisible)
        }
    }

    @Test
    fun createFilterChip_reportsCheckedChanges() {
        onHost { activity ->
            val observed = mutableListOf<Boolean>()
            val chip = UIHelpers.createFilterChip(activity, "Keys") { _, isChecked ->
                observed.add(isChecked)
            }

            chip.isChecked = true
            chip.isChecked = false

            assertEquals(listOf(true, false), observed)
        }
    }

    @Test
    fun createHeroBadge_dimsTheTintAndUsesOnPrimaryText() {
        onHost { activity ->
            val badge = UIHelpers.createHeroBadge(activity, "3 hardware", Color.GREEN)

            assertEquals("3 hardware", badge.text.toString())
            assertEquals(
                ContextCompat.getColor(activity, R.color.on_primary),
                badge.currentTextColor
            )
            assertEquals(UIHelpers.spToPx(activity, 11f), badge.textSize, TOLERANCE_TEXT_PX)

            val background = badge.background as GradientDrawable
            assertEquals(
                "The helper, not the caller, dims the tint",
                UIHelpers.applyAlpha(Color.GREEN, 0.3f),
                background.color?.defaultColor
            )
            assertEquals(
                UIHelpers.dpToPx(activity, 12f),
                background.cornerRadius,
                TOLERANCE_PX
            )
        }
    }

    @Test
    fun createHeroBadge_padsAndSeparatesStackedBadges() {
        onHost { activity ->
            val badge = UIHelpers.createHeroBadge(activity, "2 software", Color.GREEN)

            assertEquals(UIHelpers.dpToPxInt(activity, 10), badge.paddingLeft)
            assertEquals(UIHelpers.dpToPxInt(activity, 10), badge.paddingRight)
            assertEquals(UIHelpers.dpToPxInt(activity, 4), badge.paddingTop)
            assertEquals(UIHelpers.dpToPxInt(activity, 4), badge.paddingBottom)
            assertEquals(
                UIHelpers.dpToPxInt(activity, 4),
                (badge.layoutParams as LinearLayout.LayoutParams).bottomMargin
            )
        }
    }

    // ---------------------------------------------------------------
    // Empty states
    // ---------------------------------------------------------------

    @Test
    fun createEmptyStateContainer_startsHiddenCentredAndWeighted() {
        onHost { activity ->
            val container = UIHelpers.createEmptyStateContainer(activity)

            assertEquals(LinearLayout.VERTICAL, container.orientation)
            assertEquals(Gravity.CENTER, container.gravity)
            assertEquals(View.GONE, container.visibility)
            assertEquals(0, container.childCount)

            val params = container.layoutParams as LinearLayout.LayoutParams
            assertEquals(ViewGroup.LayoutParams.MATCH_PARENT, params.width)
            assertEquals(0, params.height)
            assertEquals(1f, params.weight, TOLERANCE_PX)

            val padding = UIHelpers.dpToPxInt(activity, 48)
            assertEquals(padding, container.paddingLeft)
            assertEquals(padding, container.paddingTop)
            assertEquals(padding, container.paddingRight)
            assertEquals(padding, container.paddingBottom)
        }
    }

    @Test
    fun fillEmptyState_buildsAnIconTitleAndMessage() {
        onHost { activity ->
            val container = UIHelpers.createEmptyStateContainer(activity)

            UIHelpers.fillEmptyState(
                container = container,
                iconRes = R.drawable.ic_lock,
                title = "No keys yet",
                message = "Generate a key to get started."
            )

            assertEquals(3, container.childCount)
            val icon = container.getChildAt(0) as ImageView
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorOutlineVariant
                ),
                icon.imageTintList?.defaultColor
            )
            val iconParams = icon.layoutParams as LinearLayout.LayoutParams
            assertEquals(UIHelpers.dpToPxInt(activity, 96), iconParams.width)
            assertEquals(UIHelpers.dpToPxInt(activity, 96), iconParams.height)
            assertEquals(UIHelpers.dpToPxInt(activity, 24), iconParams.bottomMargin)

            val title = container.getChildAt(1) as TextView
            assertEquals("No keys yet", title.text.toString())
            assertEquals(UIHelpers.spToPx(activity, 20f), title.textSize, TOLERANCE_TEXT_PX)

            val message = container.getChildAt(2) as TextView
            assertEquals("Generate a key to get started.", message.text.toString())
            assertEquals(UIHelpers.spToPx(activity, 14f), message.textSize, TOLERANCE_TEXT_PX)
        }
    }

    /** Without a call to action the message is the last row, so it takes no spacer. */
    @Test
    fun fillEmptyState_withoutAnAction_leavesTheMessageUnspaced() {
        onHost { activity ->
            val container = UIHelpers.createEmptyStateContainer(activity)

            UIHelpers.fillEmptyState(container, R.drawable.ic_lock, "Empty", "Nothing here")

            val message = container.getChildAt(2) as TextView
            assertEquals(0, (message.layoutParams as LinearLayout.LayoutParams).bottomMargin)
            assertTrue(
                "A passive empty state has no button",
                collectViews(container) { it is MaterialButton }.isEmpty()
            )
        }
    }

    @Test
    fun fillEmptyState_withAnAction_appendsAButtonAndSpacesTheMessage() {
        onHost { activity ->
            val container = UIHelpers.createEmptyStateContainer(activity)
            var invoked = 0

            UIHelpers.fillEmptyState(
                container = container,
                iconRes = R.drawable.ic_lock,
                title = "No keys yet",
                message = "Generate a key to get started.",
                actionLabel = "Generate key",
                onAction = { invoked++ }
            )

            assertEquals(4, container.childCount)
            val message = container.getChildAt(2) as TextView
            assertEquals(
                UIHelpers.dpToPxInt(activity, 32),
                (message.layoutParams as LinearLayout.LayoutParams).bottomMargin
            )

            val button = container.getChildAt(3) as MaterialButton
            assertEquals("Generate key", button.text.toString())
            button.performClick()
            assertEquals("The action fires exactly once per tap", 1, invoked)
        }
    }

    /** An action callback without a label has nothing to attach to and must be ignored. */
    @Test
    fun fillEmptyState_ignoresAnActionCallbackWithNoLabel() {
        onHost { activity ->
            val container = UIHelpers.createEmptyStateContainer(activity)
            var invoked = 0

            UIHelpers.fillEmptyState(
                container = container,
                iconRes = R.drawable.ic_lock,
                title = "Empty",
                message = "Nothing here",
                actionLabel = null,
                onAction = { invoked++ }
            )

            assertEquals(3, container.childCount)
            assertEquals(0, invoked)
        }
    }

    /** Screens refill the container when a filter changes the wording. */
    @Test
    fun fillEmptyState_replacesPreviousContent() {
        onHost { activity ->
            val container = UIHelpers.createEmptyStateContainer(activity)

            UIHelpers.fillEmptyState(container, R.drawable.ic_lock, "First", "First message")
            UIHelpers.fillEmptyState(container, R.drawable.ic_lock, "Second", "Second message")

            assertEquals("Refilling must not stack rows", 3, container.childCount)
            assertEquals("Second", (container.getChildAt(1) as TextView).text.toString())
            assertNull(findTextViewContaining(container, "First message"))
        }
    }

    // ---------------------------------------------------------------
    // Detail rows
    // ---------------------------------------------------------------

    @Test
    fun addDetailRow_appendsAWeightedLabelAndValue() {
        onHost { activity ->
            val column = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }

            val value = UIHelpers.addDetailRow(column, "Algorithm", "ES256")

            assertEquals(1, column.childCount)
            val row = column.getChildAt(0) as LinearLayout
            assertEquals(LinearLayout.HORIZONTAL, row.orientation)
            assertEquals(2, row.childCount)

            val label = row.getChildAt(0) as TextView
            assertEquals("Algorithm", label.text.toString())
            assertEquals(0.4f, (label.layoutParams as LinearLayout.LayoutParams).weight, 0.001f)

            assertSame("The value view is returned for in-place updates", row.getChildAt(1), value)
            assertEquals("ES256", value.text.toString())
            assertEquals(0.6f, (value.layoutParams as LinearLayout.LayoutParams).weight, 0.001f)
            assertEquals(
                Gravity.END,
                value.gravity and Gravity.END
            )
            assertEquals(Typeface.DEFAULT_BOLD, value.typeface)
        }
    }

    @Test
    fun addDetailRow_colorsTheLabelAndValueFromTheTheme() {
        onHost { activity ->
            val column = LinearLayout(activity)

            val value = UIHelpers.addDetailRow(column, "Created", "today")

            val label = (column.getChildAt(0) as LinearLayout).getChildAt(0) as TextView
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ),
                label.currentTextColor
            )
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorOnSurface
                ),
                value.currentTextColor
            )
        }
    }

    @Test
    fun addDetailRow_honoursAValueColourOverride() {
        onHost { activity ->
            val column = LinearLayout(activity)

            val value = UIHelpers.addDetailRow(
                parent = column,
                label = "Status",
                value = "Expired",
                valueColor = Color.RED
            )

            assertEquals(Color.RED, value.currentTextColor)
        }
    }

    @Test
    fun addDetailRow_monospaceValuesAreFixedWidthAndSingleLine() {
        onHost { activity ->
            val column = LinearLayout(activity)

            val value = UIHelpers.addDetailRow(
                parent = column,
                label = "Fingerprint",
                value = "AA:BB:CC:DD",
                monospace = true
            )

            assertEquals(Typeface.MONOSPACE, value.typeface)
            assertEquals(1, value.maxLines)
            assertEquals(UIHelpers.spToPx(activity, 10f), value.textSize, TOLERANCE_TEXT_PX)
        }
    }

    @Test
    fun addDetailRow_stacksRowsWithSpacing() {
        onHost { activity ->
            val column = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }

            UIHelpers.addDetailRow(column, "One", "1")
            UIHelpers.addDetailRow(column, "Two", "2")

            assertEquals(2, column.childCount)
            val secondRow = column.getChildAt(1) as LinearLayout
            assertEquals(
                UIHelpers.dpToPxInt(activity, 8),
                (secondRow.layoutParams as LinearLayout.LayoutParams).bottomMargin
            )
        }
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Runs [block] against the shared host activity on the main thread.
     *
     * Views must be built on the UI thread, and the helpers need a themed
     * Activity context so Material widgets resolve their default styles.
     */
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

    companion object {
        /** Sub-pixel slack for float comparisons. */
        private const val TOLERANCE_PX = 0.01f

        /** Text sizes go through sp scaling, which rounds; a pixel of slack is enough. */
        private const val TOLERANCE_TEXT_PX = 1f

        /**
         * One host activity for the whole class: [UIHelpers] never mutates its
         * context, so relaunching per test would only pay MainActivity's start-up
         * cost thirty-odd times over.
         */


    }
}
