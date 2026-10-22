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
import android.view.Gravity
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.google.android.material.card.MaterialCardView
import org.junit.AfterClass
import org.junit.Before
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [PremiumCardFactory], the card recipes shared by every
 * xKey screen.
 *
 * The factory is pure view construction, but each recipe resolves Material3 theme
 * attributes and converts dp to px, so it needs a real themed Activity. A single
 * [MainActivity] hosts the whole class ([hostScenario]); the factory never touches
 * its host beyond using it as a Context.
 *
 * Expected dimensions are recomputed through [UIHelpers] rather than hard-coded in
 * pixels, so the assertions hold at any display density. Colours are compared to
 * the theme attribute the factory claims to use (or, for the hero gradient, to the
 * colour resource it names), which keeps them valid in light and dark mode alike.
 *
 * Coverage:
 * - the five base cards: elevated, outlined, glass, hero, compact
 * - [PremiumCardFactory.createHeroSummary]'s whole view tree and gradient
 * - the three gradient appliers plus the multi-colour guard clause
 * - click / non-interactive / selected / error state mutators
 * - the six presets: section, action, info, warning, error, success
 */
@RunWith(AndroidJUnit4::class)
class PremiumCardFactoryTest {

    // ---------------------------------------------------------------
    // Base cards
    // ---------------------------------------------------------------

    @Test
    fun createElevatedCard_isARaisedContainerOnTheHighestSurface() {
        onHost { activity ->
            val card = PremiumCardFactory.createElevatedCard(activity)

            assertEquals(UIHelpers.dpToPx(activity, 16f), card.radius, TOLERANCE_PX)
            assertEquals(UIHelpers.dpToPx(activity, 4f), card.cardElevation, TOLERANCE_PX)
            assertEquals("Elevated cards carry no outline", 0, card.strokeWidth)
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorSurfaceContainerHigh
                ),
                card.cardBackgroundColor.defaultColor
            )
            assertTrue(card.isClickable)
            assertTrue(card.isFocusable)
        }
    }

    @Test
    fun createElevatedCard_usesTheDefaultCardMargins() {
        onHost { activity ->
            val params = PremiumCardFactory.createElevatedCard(activity)
                .layoutParams as LinearLayout.LayoutParams

            assertEquals(ViewGroup.LayoutParams.MATCH_PARENT, params.width)
            assertEquals(ViewGroup.LayoutParams.WRAP_CONTENT, params.height)
            assertEquals(UIHelpers.dpToPxInt(activity, 4), params.leftMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 4), params.rightMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 6), params.topMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 6), params.bottomMargin)
        }
    }

    @Test
    fun createOutlinedCard_isFlatWithAHairlineOutline() {
        onHost { activity ->
            val card = PremiumCardFactory.createOutlinedCard(activity)

            assertEquals(UIHelpers.dpToPx(activity, 16f), card.radius, TOLERANCE_PX)
            assertEquals(0f, card.cardElevation, TOLERANCE_PX)
            assertEquals(UIHelpers.dpToPxInt(activity, 1), card.strokeWidth)
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorOutlineVariant
                ),
                card.strokeColor
            )
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorSurface
                ),
                card.cardBackgroundColor.defaultColor
            )
        }
    }

    @Test
    fun createGlassCard_isTranslucentAndFloating() {
        onHost { activity ->
            val card = PremiumCardFactory.createGlassCard(activity)

            assertEquals(UIHelpers.dpToPx(activity, 24f), card.radius, TOLERANCE_PX)
            assertEquals(UIHelpers.dpToPx(activity, 8f), card.cardElevation, TOLERANCE_PX)
            assertTrue("Glass cards reserve room for their shadow", card.useCompatPadding)
            assertEquals(
                UIHelpers.applyAlpha(
                    UIHelpers.resolveThemeColor(
                        activity,
                        com.google.android.material.R.attr.colorSurface
                    ),
                    0.95f
                ),
                card.cardBackgroundColor.defaultColor
            )
            assertEquals(
                "The outline is dimmed to half opacity",
                (0.5f * 255).toInt(),
                Color.alpha(card.strokeColor)
            )
        }
    }

    @Test
    fun createHeroCard_isALargeFeatureContainer() {
        onHost { activity ->
            val card = PremiumCardFactory.createHeroCard(activity)

            assertEquals(UIHelpers.dpToPx(activity, 24f), card.radius, TOLERANCE_PX)
            assertEquals(UIHelpers.dpToPx(activity, 6f), card.cardElevation, TOLERANCE_PX)
            assertEquals(UIHelpers.dpToPxInt(activity, 120), card.minimumHeight)
            assertTrue(card.useCompatPadding)
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorPrimaryContainer
                ),
                card.cardBackgroundColor.defaultColor
            )

            val params = card.layoutParams as LinearLayout.LayoutParams
            val margin = UIHelpers.dpToPxInt(activity, 16)
            assertEquals(margin, params.leftMargin)
            assertEquals(margin, params.topMargin)
            assertEquals(margin, params.rightMargin)
            assertEquals(margin, params.bottomMargin)
        }
    }

    @Test
    fun createCompactCard_isDenserThanTheOtherVariants() {
        onHost { activity ->
            val card = PremiumCardFactory.createCompactCard(activity)

            assertEquals(UIHelpers.dpToPx(activity, 12f), card.radius, TOLERANCE_PX)
            assertEquals(UIHelpers.dpToPx(activity, 2f), card.cardElevation, TOLERANCE_PX)
            assertEquals(0, card.strokeWidth)

            val params = card.layoutParams as LinearLayout.LayoutParams
            assertEquals(UIHelpers.dpToPxInt(activity, 12), params.leftMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 12), params.rightMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 6), params.topMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 6), params.bottomMargin)
        }
    }

    // ---------------------------------------------------------------
    // Hero summary
    // ---------------------------------------------------------------

    @Test
    fun createHeroSummary_startsAtZeroWithTheGivenLabel() {
        onHost { activity ->
            val summary = PremiumCardFactory.createHeroSummary(
                activity,
                R.drawable.ic_lock,
                "Stored keys"
            )

            assertEquals("0", summary.countText.text.toString())
            assertEquals("Stored keys", summary.labelText.text.toString())
            assertEquals("Badges start empty", 0, summary.badgeContainer.childCount)
        }
    }

    @Test
    fun createHeroSummary_tightensTheHeroCardsBottomMarginAndHeight() {
        onHost { activity ->
            val summary = PremiumCardFactory.createHeroSummary(
                activity,
                R.drawable.ic_lock,
                "Stored keys"
            )

            val params = summary.card.layoutParams as LinearLayout.LayoutParams
            assertEquals(UIHelpers.dpToPxInt(activity, 16), params.leftMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 16), params.topMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 16), params.rightMargin)
            assertEquals(
                "The summary sits closer to the list than a plain hero card",
                UIHelpers.dpToPxInt(activity, 8),
                params.bottomMargin
            )
            assertEquals(UIHelpers.dpToPxInt(activity, 100), summary.card.minimumHeight)
        }
    }

    @Test
    fun createHeroSummary_paintsTheSecurityGradientDiagonally() {
        onHost { activity ->
            val summary = PremiumCardFactory.createHeroSummary(
                activity,
                R.drawable.ic_lock,
                "Stored keys"
            )

            val gradient = summary.card.background as GradientDrawable
            assertEquals(GradientDrawable.Orientation.TL_BR, gradient.orientation)
            assertTrue(
                intArrayOf(
                    ContextCompat.getColor(activity, R.color.gradient_security_start),
                    ContextCompat.getColor(activity, R.color.gradient_security_end)
                ).contentEquals(gradient.colors)
            )
            assertEquals(
                "The gradient must follow the card's corners",
                summary.card.radius,
                gradient.cornerRadius,
                TOLERANCE_PX
            )
        }
    }

    /**
     * The tree is walked upwards from the handles the factory returns rather than
     * downwards from the card, so the assertions describe the relationships the
     * callers depend on and stay independent of how [MaterialCardView] chooses to
     * host its content.
     */
    @Test
    fun createHeroSummary_buildsTheCountSectionAndBadgeColumn() {
        onHost { activity ->
            val summary = PremiumCardFactory.createHeroSummary(
                activity,
                R.drawable.ic_lock,
                "Stored keys"
            )

            val textSection = summary.countText.parent as LinearLayout
            assertEquals(LinearLayout.VERTICAL, textSection.orientation)
            assertSame("The count and label share a column", textSection, summary.labelText.parent)
            assertSame(summary.countText, textSection.getChildAt(0))
            assertSame(summary.labelText, textSection.getChildAt(1))

            val countSection = textSection.parent as LinearLayout
            assertEquals(LinearLayout.HORIZONTAL, countSection.orientation)
            assertEquals(
                "The count section takes the leftover width",
                1f,
                (countSection.layoutParams as LinearLayout.LayoutParams).weight,
                0.001f
            )
            assertEquals(
                Gravity.CENTER_VERTICAL,
                countSection.gravity and Gravity.CENTER_VERTICAL
            )

            val icon = countSection.getChildAt(0) as ImageView
            val iconParams = icon.layoutParams as LinearLayout.LayoutParams
            assertEquals(UIHelpers.dpToPxInt(activity, 64), iconParams.width)
            assertEquals(UIHelpers.dpToPxInt(activity, 64), iconParams.height)
            assertEquals(UIHelpers.dpToPxInt(activity, 16), iconParams.marginEnd)

            val content = countSection.parent as LinearLayout
            assertEquals(LinearLayout.HORIZONTAL, content.orientation)
            assertEquals(UIHelpers.dpToPxInt(activity, 20), content.paddingLeft)
            assertEquals(2, content.childCount)
            assertSame(summary.badgeContainer, content.getChildAt(1))
            assertEquals(Gravity.END, summary.badgeContainer.gravity and Gravity.END)
        }
    }

    @Test
    fun createHeroSummary_scalesTheCountAndDimsTheLabel() {
        onHost { activity ->
            val onPrimary = ContextCompat.getColor(activity, R.color.on_primary)
            val summary = PremiumCardFactory.createHeroSummary(
                activity,
                R.drawable.ic_lock,
                "Stored keys"
            )

            assertEquals(
                UIHelpers.spToPx(activity, 48f),
                summary.countText.textSize,
                TOLERANCE_TEXT_PX
            )
            assertEquals(onPrimary, summary.countText.currentTextColor)
            assertEquals(
                UIHelpers.spToPx(activity, 14f),
                summary.labelText.textSize,
                TOLERANCE_TEXT_PX
            )
            assertEquals(
                UIHelpers.applyAlpha(onPrimary, 0.9f),
                summary.labelText.currentTextColor
            )

            val countSection = (summary.countText.parent as LinearLayout).parent as LinearLayout
            val icon = countSection.getChildAt(0) as ImageView
            assertEquals(
                "The icon is a watermark, not a focal point",
                UIHelpers.applyAlpha(onPrimary, 0.3f),
                icon.imageTintList?.defaultColor
            )
        }
    }

    /** Badges are added by the caller; the container must accept them as-is. */
    @Test
    fun createHeroSummary_badgeContainerAcceptsHeroBadges() {
        onHost { activity ->
            val summary = PremiumCardFactory.createHeroSummary(
                activity,
                R.drawable.ic_lock,
                "Stored keys"
            )

            summary.badgeContainer.addView(
                UIHelpers.createHeroBadge(activity, "1 hardware", Color.GREEN)
            )

            assertEquals(1, summary.badgeContainer.childCount)
            assertEquals(
                "1 hardware",
                (summary.badgeContainer.getChildAt(0) as TextView).text.toString()
            )
        }
    }

    // ---------------------------------------------------------------
    // Gradient appliers
    // ---------------------------------------------------------------

    @Test
    fun applyGradientBackground_paintsLeftToRightAtTheCardsRadius() {
        onHost { activity ->
            val card = PremiumCardFactory.createElevatedCard(activity)

            PremiumCardFactory.applyGradientBackground(card, Color.RED, Color.BLUE)

            val gradient = card.background as GradientDrawable
            assertEquals(GradientDrawable.Orientation.LEFT_RIGHT, gradient.orientation)
            assertTrue(intArrayOf(Color.RED, Color.BLUE).contentEquals(gradient.colors))
            assertEquals(card.radius, gradient.cornerRadius, TOLERANCE_PX)
        }
    }

    @Test
    fun applyDiagonalGradient_paintsTopLeftToBottomRight() {
        onHost { activity ->
            val card = PremiumCardFactory.createCompactCard(activity)

            PremiumCardFactory.applyDiagonalGradient(card, Color.RED, Color.BLUE)

            val gradient = card.background as GradientDrawable
            assertEquals(GradientDrawable.Orientation.TL_BR, gradient.orientation)
            assertEquals(card.radius, gradient.cornerRadius, TOLERANCE_PX)
        }
    }

    @Test
    fun applyMultiColorGradient_defaultsToLeftToRight() {
        onHost { activity ->
            val card = PremiumCardFactory.createElevatedCard(activity)
            val stops = intArrayOf(Color.RED, Color.GREEN, Color.BLUE)

            PremiumCardFactory.applyMultiColorGradient(card, stops)

            val gradient = card.background as GradientDrawable
            assertEquals(GradientDrawable.Orientation.LEFT_RIGHT, gradient.orientation)
            assertTrue(stops.contentEquals(gradient.colors))
        }
    }

    @Test
    fun applyMultiColorGradient_honoursAnExplicitOrientation() {
        onHost { activity ->
            val card = PremiumCardFactory.createElevatedCard(activity)

            PremiumCardFactory.applyMultiColorGradient(
                card,
                intArrayOf(Color.RED, Color.GREEN),
                GradientDrawable.Orientation.BR_TL
            )

            assertEquals(
                GradientDrawable.Orientation.BR_TL,
                (card.background as GradientDrawable).orientation
            )
        }
    }

    /**
     * The guard clause is asserted off the main thread on purpose: an exception
     * raised inside `onActivity` would be reported through the scenario rather
     * than as the expected failure of this test.
     */
    @Test(expected = IllegalArgumentException::class)
    fun applyMultiColorGradient_rejectsASingleColour() {
        val card = onHost { PremiumCardFactory.createElevatedCard(it) }

        PremiumCardFactory.applyMultiColorGradient(card, intArrayOf(Color.RED))
    }

    // ---------------------------------------------------------------
    // State mutators
    // ---------------------------------------------------------------

    @Test
    fun setCardClickListener_makesTheCardInteractiveAndFiresOnce() {
        onHost { activity ->
            val card = PremiumCardFactory.createOutlinedCard(activity)
            var taps = 0

            PremiumCardFactory.setCardClickListener(card) { taps++ }
            card.performClick()

            assertTrue(card.isClickable)
            assertTrue(card.isFocusable)
            assertEquals(1, taps)
        }
    }

    @Test
    fun setNonInteractive_dropsTheClickListenerAndFocus() {
        onHost { activity ->
            val card = PremiumCardFactory.createOutlinedCard(activity)
            var taps = 0
            PremiumCardFactory.setCardClickListener(card) { taps++ }

            PremiumCardFactory.setNonInteractive(card)
            card.performClick()

            assertFalse(card.isClickable)
            assertFalse(card.isFocusable)
            assertEquals("A display-only card must not call back", 0, taps)
        }
    }

    @Test
    fun setSelectedState_thickensTheOutlineAndTintsTheFill() {
        onHost { activity ->
            val card = PremiumCardFactory.createOutlinedCard(activity)
            val primary = UIHelpers.resolveThemeColor(
                activity,
                androidx.appcompat.R.attr.colorPrimary
            )

            PremiumCardFactory.setSelectedState(card, activity, true)

            assertEquals(UIHelpers.dpToPxInt(activity, 2), card.strokeWidth)
            assertEquals(primary, card.strokeColor)
            assertEquals(
                UIHelpers.applyAlpha(primary, 0.08f),
                card.cardBackgroundColor.defaultColor
            )
        }
    }

    @Test
    fun setSelectedState_restoresTheOutlinedLookWhenDeselected() {
        onHost { activity ->
            val card = PremiumCardFactory.createOutlinedCard(activity)
            PremiumCardFactory.setSelectedState(card, activity, true)

            PremiumCardFactory.setSelectedState(card, activity, false)

            assertEquals(UIHelpers.dpToPxInt(activity, 1), card.strokeWidth)
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorOutlineVariant
                ),
                card.strokeColor
            )
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorSurface
                ),
                card.cardBackgroundColor.defaultColor
            )
        }
    }

    @Test
    fun setErrorState_outlinesInTheErrorColour() {
        onHost { activity ->
            val card = PremiumCardFactory.createOutlinedCard(activity)

            PremiumCardFactory.setErrorState(card, activity, true)

            assertEquals(UIHelpers.dpToPxInt(activity, 2), card.strokeWidth)
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    androidx.appcompat.R.attr.colorError
                ),
                card.strokeColor
            )
        }
    }

    @Test
    fun setErrorState_clearingRestoresTheHairlineOutline() {
        onHost { activity ->
            val card = PremiumCardFactory.createOutlinedCard(activity)
            PremiumCardFactory.setErrorState(card, activity, true)

            PremiumCardFactory.setErrorState(card, activity, false)

            assertEquals(UIHelpers.dpToPxInt(activity, 1), card.strokeWidth)
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    com.google.android.material.R.attr.colorOutlineVariant
                ),
                card.strokeColor
            )
        }
    }

    /** The error state must not repaint the fill, only the outline. */
    @Test
    fun setErrorState_leavesTheBackgroundAlone() {
        onHost { activity ->
            val card = PremiumCardFactory.createOutlinedCard(activity)
            val before = card.cardBackgroundColor.defaultColor

            PremiumCardFactory.setErrorState(card, activity, true)

            assertEquals(before, card.cardBackgroundColor.defaultColor)
        }
    }

    // ---------------------------------------------------------------
    // Presets
    // ---------------------------------------------------------------

    @Test
    fun createSectionCard_isAnOutlinedCardWithSectionMargins() {
        onHost { activity ->
            val card = PremiumCardFactory.createSectionCard(activity)

            assertEquals(UIHelpers.dpToPxInt(activity, 1), card.strokeWidth)

            val params = card.layoutParams as LinearLayout.LayoutParams
            assertEquals(UIHelpers.dpToPxInt(activity, 16), params.leftMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 16), params.rightMargin)
            assertEquals(UIHelpers.dpToPxInt(activity, 12), params.topMargin)
            assertEquals("Sections butt up against what follows", 0, params.bottomMargin)
        }
    }

    @Test
    fun createActionCard_isAnElevatedCardFilledWithThePrimaryColour() {
        onHost { activity ->
            val card = PremiumCardFactory.createActionCard(activity)

            assertEquals(UIHelpers.dpToPx(activity, 4f), card.cardElevation, TOLERANCE_PX)
            assertEquals(
                UIHelpers.resolveThemeColor(
                    activity,
                    androidx.appcompat.R.attr.colorPrimary
                ),
                card.cardBackgroundColor.defaultColor
            )
        }
    }

    @Test
    fun createInfoCard_usesTheTertiaryContainer() {
        assertPreset(
            preset = { PremiumCardFactory.createInfoCard(it) },
            fillAttr = com.google.android.material.R.attr.colorTertiaryContainer,
            strokeAttr = com.google.android.material.R.attr.colorTertiary
        )
    }

    @Test
    fun createWarningCard_usesTheSecondaryContainer() {
        assertPreset(
            preset = { PremiumCardFactory.createWarningCard(it) },
            fillAttr = com.google.android.material.R.attr.colorSecondaryContainer,
            strokeAttr = com.google.android.material.R.attr.colorSecondary
        )
    }

    @Test
    fun createErrorCard_usesTheErrorContainer() {
        assertPreset(
            preset = { PremiumCardFactory.createErrorCard(it) },
            fillAttr = com.google.android.material.R.attr.colorErrorContainer,
            strokeAttr = androidx.appcompat.R.attr.colorError
        )
    }

    /**
     * Success uses the same green the app already means by "valid". It used to
     * be byte-identical to [PremiumCardFactory.createInfoCard], which made the
     * two indistinguishable on screen.
     */
    @Test
    fun createSuccessCard_usesTheVerifiedGreenAndIsDistinctFromInfo() {
        onHost { activity ->
            val success = PremiumCardFactory.createSuccessCard(activity)
            assertEquals(
                ContextCompat.getColor(activity, R.color.security_verified_container),
                success.cardBackgroundColor.defaultColor
            )
            assertEquals(
                ContextCompat.getColor(activity, R.color.security_verified),
                success.strokeColor
            )
            assertNotEquals(
                "success must not look like info",
                PremiumCardFactory.createInfoCard(activity).cardBackgroundColor.defaultColor,
                success.cardBackgroundColor.defaultColor
            )
        }
    }

    /** The status presets must at least be told apart from a plain outlined card. */
    @Test
    fun statusPresets_differFromThePlainOutlinedCard() {
        onHost { activity ->
            val plain = PremiumCardFactory.createOutlinedCard(activity)
                .cardBackgroundColor.defaultColor

            assertNotEquals(
                plain,
                PremiumCardFactory.createInfoCard(activity).cardBackgroundColor.defaultColor
            )
            assertNotEquals(
                plain,
                PremiumCardFactory.createWarningCard(activity).cardBackgroundColor.defaultColor
            )
            assertNotEquals(
                plain,
                PremiumCardFactory.createErrorCard(activity).cardBackgroundColor.defaultColor
            )
        }
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /** Asserts a preset fills with [fillAttr] and outlines with [strokeAttr]. */
    private fun assertPreset(
        preset: (MainActivity) -> MaterialCardView,
        fillAttr: Int,
        strokeAttr: Int
    ) {
        onHost { activity ->
            val card = preset(activity)

            assertEquals(
                UIHelpers.resolveThemeColor(activity, fillAttr),
                card.cardBackgroundColor.defaultColor
            )
            assertEquals(UIHelpers.resolveThemeColor(activity, strokeAttr), card.strokeColor)
        }
    }

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

    companion object {
        /** Sub-pixel slack for float comparisons. */
        private const val TOLERANCE_PX = 0.01f

        /** Text sizes go through sp scaling, which rounds. */
        private const val TOLERANCE_TEXT_PX = 1f

        /** One host activity for the class; the factory only uses it as a Context. */


    }
}
