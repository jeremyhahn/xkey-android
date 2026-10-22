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

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.annotation.AttrRes
import androidx.annotation.ColorInt
import androidx.annotation.Dimension
import androidx.annotation.DrawableRes
import androidx.core.content.ContextCompat
import com.automatethethings.xkey.R
import com.google.android.material.card.MaterialCardView

/**
 * Factory object for creating consistent, professionally styled Material Design cards.
 *
 * Provides factory methods for different card variants optimized for various UI contexts:
 * - **Elevated**: Primary content cards with subtle shadow depth
 * - **Outlined**: Secondary cards with border definition
 * - **Glass**: Frosted glass effect for overlay contexts
 * - **Hero**: Large featured cards for prominent content
 * - **Compact**: Smaller cards optimized for list items
 *
 * All cards follow the xKey premium design system with:
 * - Material3 theme attribute integration
 * - Consistent corner radii and elevation scales
 * - Proper touch feedback and accessibility support
 *
 * Usage example:
 * ```kotlin
 * val card = PremiumCardFactory.createElevatedCard(context).apply {
 *     layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
 * }
 * card.addView(contentView)
 * parentLayout.addView(card)
 * ```
 *
 * @see UIHelpers For additional UI utility functions
 */
object PremiumCardFactory {

    // -------------------------------------------------------------------------
    // Design System Constants
    // -------------------------------------------------------------------------

    /** Corner radius for elevated cards (primary content). */
    private const val RADIUS_ELEVATED_DP = 16f

    /** Corner radius for outlined cards (secondary content). */
    private const val RADIUS_OUTLINED_DP = 16f

    /** Corner radius for glass cards (overlays). */
    private const val RADIUS_GLASS_DP = 24f

    /** Corner radius for hero cards (featured content). */
    private const val RADIUS_HERO_DP = 24f

    /** Corner radius for compact cards (list items). */
    private const val RADIUS_COMPACT_DP = 12f

    /** Elevation for elevated cards. */
    private const val ELEVATION_ELEVATED_DP = 4f

    /** Elevation for outlined cards (none). */
    private const val ELEVATION_OUTLINED_DP = 0f

    /** Elevation for glass cards (pronounced). */
    private const val ELEVATION_GLASS_DP = 8f

    /** Elevation for hero cards. */
    private const val ELEVATION_HERO_DP = 6f

    /** Elevation for compact cards (subtle). */
    private const val ELEVATION_COMPACT_DP = 2f

    /** Default stroke width for outlined cards. */
    private const val STROKE_WIDTH_DP = 1

    /** Alpha value for glass card effect (95%). */
    private const val GLASS_ALPHA = 0.95f

    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------

    /**
     * Creates an elevated card for primary content display.
     *
     * Elevated cards are the standard choice for main content areas. They feature:
     * - 16dp corner radius for a modern, friendly appearance
     * - 4dp elevation providing subtle depth without overwhelming shadows
     * - colorSurfaceContainerHigh background for Material3 surface tinting
     * - Proper ripple effect on touch
     *
     * Recommended uses:
     * - Main content sections
     * - Information panels
     * - Settings groups
     * - Feature showcases
     *
     * @param context The context for creating the view and resolving theme attributes.
     * @return A configured MaterialCardView ready for content addition.
     */
    fun createElevatedCard(context: Context): MaterialCardView {
        return MaterialCardView(context).apply {
            layoutParams = defaultLayoutParams(context)
            radius = dpToPx(context, RADIUS_ELEVATED_DP)
            cardElevation = dpToPx(context, ELEVATION_ELEVATED_DP)
            setCardBackgroundColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorSurfaceContainerHigh)
            )
            strokeWidth = 0
            isClickable = true
            isFocusable = true
        }
    }

    /**
     * Creates an outlined card for secondary content display.
     *
     * Outlined cards provide visual grouping without elevation. They feature:
     * - 16dp corner radius for a slightly tighter appearance
     * - No elevation (flat)
     * - 1dp stroke with colorOutlineVariant for subtle definition
     * - Surface color background
     *
     * Recommended uses:
     * - Secondary information
     * - List item containers
     * - Form sections
     * - Navigation items
     *
     * @param context The context for creating the view and resolving theme attributes.
     * @return A configured MaterialCardView ready for content addition.
     */
    fun createOutlinedCard(context: Context): MaterialCardView {
        return MaterialCardView(context).apply {
            layoutParams = defaultLayoutParams(context)
            radius = dpToPx(context, RADIUS_OUTLINED_DP)
            cardElevation = dpToPx(context, ELEVATION_OUTLINED_DP)
            setCardBackgroundColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorSurface)
            )
            strokeWidth = dpToPxInt(context, STROKE_WIDTH_DP)
            strokeColor = resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOutlineVariant
            )
            isClickable = true
            isFocusable = true
        }
    }

    /**
     * Creates a glass-effect card for overlay and modal contexts.
     *
     * Glass cards provide a frosted glass appearance suitable for overlays. They feature:
     * - 24dp corner radius for a softer, floating appearance
     * - 8dp elevation for pronounced depth
     * - 95% alpha surface color for translucency effect
     * - Subtle stroke for edge definition
     *
     * Note: The glass effect works best over content with color variation.
     * For true blur effects, consider using RenderScript or RenderEffect (API 31+).
     *
     * Recommended uses:
     * - Modal dialogs
     * - Bottom sheets
     * - Floating action panels
     * - Overlay cards
     *
     * @param context The context for creating the view and resolving theme attributes.
     * @return A configured MaterialCardView with glass styling.
     */
    fun createGlassCard(context: Context): MaterialCardView {
        val surfaceColor = resolveThemeColor(
            context,
            com.google.android.material.R.attr.colorSurface
        )
        val alphaColor = applyAlpha(surfaceColor, GLASS_ALPHA)

        return MaterialCardView(context).apply {
            layoutParams = defaultLayoutParams(context)
            radius = dpToPx(context, RADIUS_GLASS_DP)
            cardElevation = dpToPx(context, ELEVATION_GLASS_DP)
            setCardBackgroundColor(alphaColor)
            strokeWidth = dpToPxInt(context, STROKE_WIDTH_DP)
            strokeColor = applyAlpha(
                resolveThemeColor(context, com.google.android.material.R.attr.colorOutlineVariant),
                0.5f
            )
            isClickable = true
            isFocusable = true
            useCompatPadding = true
        }
    }

    /**
     * Creates a hero card for prominent featured content.
     *
     * Hero cards are designed for large, attention-grabbing content areas. They feature:
     * - 24dp corner radius matching the glass style for visual harmony
     * - 6dp elevation for notable but not excessive depth
     * - Gradient-ready background (solid by default)
     * - Larger touch target suitable for featured interactions
     *
     * For gradient backgrounds, use [applyGradientBackground] after creation.
     *
     * Recommended uses:
     * - Feature highlights
     * - Welcome banners
     * - Promotional content
     * - Dashboard summaries
     *
     * @param context The context for creating the view and resolving theme attributes.
     * @return A configured MaterialCardView ready for hero content.
     */
    fun createHeroCard(context: Context): MaterialCardView {
        return MaterialCardView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                val margin = dpToPxInt(context, 16)
                setMargins(margin, margin, margin, margin)
            }
            radius = dpToPx(context, RADIUS_HERO_DP)
            cardElevation = dpToPx(context, ELEVATION_HERO_DP)
            setCardBackgroundColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorPrimaryContainer)
            )
            strokeWidth = 0
            isClickable = true
            isFocusable = true
            useCompatPadding = true
            minimumHeight = dpToPxInt(context, 120)
        }
    }

    /**
     * Creates a compact card optimized for list items.
     *
     * Compact cards are space-efficient containers for repeated content. They feature:
     * - 12dp corner radius for a tighter, more efficient appearance
     * - 2dp elevation for subtle depth distinction
     * - Reduced margins for denser layouts
     * - Surface color background
     *
     * Recommended uses:
     * - List items
     * - Grid items
     * - Notification cards
     * - Quick action tiles
     *
     * @param context The context for creating the view and resolving theme attributes.
     * @return A configured MaterialCardView optimized for list contexts.
     */
    fun createCompactCard(context: Context): MaterialCardView {
        return MaterialCardView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                val horizontalMargin = dpToPxInt(context, 12)
                val verticalMargin = dpToPxInt(context, 6)
                setMargins(horizontalMargin, verticalMargin, horizontalMargin, verticalMargin)
            }
            radius = dpToPx(context, RADIUS_COMPACT_DP)
            cardElevation = dpToPx(context, ELEVATION_COMPACT_DP)
            setCardBackgroundColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorSurface)
            )
            strokeWidth = 0
            isClickable = true
            isFocusable = true
        }
    }

    // -------------------------------------------------------------------------
    // Hero Summary
    // -------------------------------------------------------------------------

    /**
     * The views that make up a hero summary card, handed back so the caller can
     * bind live data to them.
     *
     * @property card The card itself. The caller is responsible for adding it to a parent.
     * @property countText The large numeric total (e.g. "12"). Starts at "0".
     * @property labelText The caption underneath the count.
     * @property badgeContainer An end-aligned vertical container for status badges,
     *   normally populated with [UIHelpers.createHeroBadge].
     */
    data class HeroSummary(
        val card: MaterialCardView,
        val countText: TextView,
        val labelText: TextView,
        val badgeContainer: LinearLayout
    )

    /**
     * Creates the standard "hero summary" card used at the top of every list screen.
     *
     * This standardises the summary banner that Passkeys, OATH, PIV, Key Vault and the
     * other list screens each used to hand-roll identically. The recipe is:
     * - a [createHeroCard] with (16, 16, 16, 8)dp margins and a 100dp minimum height
     * - a diagonal `gradient_security_start` -> `gradient_security_end` background
     * - 20dp content padding, split into a weighted count section and a badge column
     * - a 64dp icon tinted `on_primary` at 30% alpha
     * - a 48sp `sans-serif-light` count over a 14sp label at 90% alpha
     *
     * The caller adds [HeroSummary.card] to its own layout and updates
     * [HeroSummary.countText] / [HeroSummary.badgeContainer] as data loads.
     *
     * @param context The context for creating views and resolving resources.
     * @param iconRes The drawable shown to the left of the count.
     * @param label The caption below the count (already localised).
     * @return The card plus its mutable child views.
     */
    fun createHeroSummary(
        context: Context,
        @DrawableRes iconRes: Int,
        label: CharSequence
    ): HeroSummary {
        val onPrimary = ContextCompat.getColor(context, R.color.on_primary)

        val card = createHeroCard(context).apply {
            (layoutParams as LinearLayout.LayoutParams).setMargins(
                dpToPxInt(context, 16),
                dpToPxInt(context, 16),
                dpToPxInt(context, 16),
                dpToPxInt(context, 8)
            )
            minimumHeight = dpToPxInt(context, 100)
        }
        applyDiagonalGradient(
            card,
            ContextCompat.getColor(context, R.color.gradient_security_start),
            ContextCompat.getColor(context, R.color.gradient_security_end)
        )

        val cardContent = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            val padding = dpToPxInt(context, 20)
            setPadding(padding, padding, padding, padding)
        }

        val countSection = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            gravity = Gravity.CENTER_VERTICAL
        }

        val icon = ImageView(context).apply {
            setImageResource(iconRes)
            imageTintList = ColorStateList.valueOf(applyAlpha(onPrimary, 0.3f))
            layoutParams = LinearLayout.LayoutParams(
                dpToPxInt(context, 64),
                dpToPxInt(context, 64)
            ).apply {
                marginEnd = dpToPxInt(context, 16)
            }
        }

        val textSection = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val countText = TextView(context).apply {
            text = "0"
            textSize = 48f
            setTextColor(onPrimary)
            typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
            includeFontPadding = false
        }

        val labelText = TextView(context).apply {
            text = label
            textSize = 14f
            setTextColor(applyAlpha(onPrimary, 0.9f))
        }

        val badgeContainer = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.END
        }

        textSection.addView(countText)
        textSection.addView(labelText)
        countSection.addView(icon)
        countSection.addView(textSection)
        cardContent.addView(countSection)
        cardContent.addView(badgeContainer)
        card.addView(cardContent)

        return HeroSummary(card, countText, labelText, badgeContainer)
    }

    // -------------------------------------------------------------------------
    // Customization Methods
    // -------------------------------------------------------------------------

    /**
     * Applies a horizontal gradient background to a card.
     *
     * Replaces the solid background color with a gradient drawable. The card's
     * corner radius is preserved in the gradient.
     *
     * @param card The MaterialCardView to modify.
     * @param startColor The color at the start (left) of the gradient.
     * @param endColor The color at the end (right) of the gradient.
     */
    fun applyGradientBackground(
        card: MaterialCardView,
        @ColorInt startColor: Int,
        @ColorInt endColor: Int
    ) {
        val gradient = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            intArrayOf(startColor, endColor)
        ).apply {
            cornerRadius = card.radius
        }
        card.background = gradient
    }

    /**
     * Applies a diagonal gradient background to a card.
     *
     * Creates a top-left to bottom-right gradient effect.
     *
     * @param card The MaterialCardView to modify.
     * @param startColor The color at the top-left corner.
     * @param endColor The color at the bottom-right corner.
     */
    fun applyDiagonalGradient(
        card: MaterialCardView,
        @ColorInt startColor: Int,
        @ColorInt endColor: Int
    ) {
        val gradient = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(startColor, endColor)
        ).apply {
            cornerRadius = card.radius
        }
        card.background = gradient
    }

    /**
     * Applies a multi-color gradient background to a card.
     *
     * @param card The MaterialCardView to modify.
     * @param colors Array of colors for the gradient (at least 2).
     * @param orientation The gradient orientation.
     */
    fun applyMultiColorGradient(
        card: MaterialCardView,
        colors: IntArray,
        orientation: GradientDrawable.Orientation = GradientDrawable.Orientation.LEFT_RIGHT
    ) {
        require(colors.size >= 2) { "Gradient requires at least 2 colors" }
        val gradient = GradientDrawable(orientation, colors).apply {
            cornerRadius = card.radius
        }
        card.background = gradient
    }

    /**
     * Sets the card's click behavior with visual feedback.
     *
     * Enables proper touch feedback including ripple effect and state changes.
     *
     * @param card The MaterialCardView to configure.
     * @param onClick The click handler to invoke.
     */
    fun setCardClickListener(card: MaterialCardView, onClick: () -> Unit) {
        card.isClickable = true
        card.isFocusable = true
        card.setOnClickListener { onClick() }
    }

    /**
     * Configures a card for non-interactive display.
     *
     * Disables click/focus behavior and removes ripple effect.
     *
     * @param card The MaterialCardView to configure.
     */
    fun setNonInteractive(card: MaterialCardView) {
        // Detach the listener first: View.setOnClickListener sets isClickable
        // back to true whenever the view is not already clickable, so clearing
        // the flags before this call left the card clickable and still
        // ripple-highlighting on touch.
        card.setOnClickListener(null)
        card.isClickable = false
        card.isFocusable = false
    }

    /**
     * Applies a checked/selected state to a card.
     *
     * Changes the stroke to primary color and increases stroke width
     * to indicate selection.
     *
     * @param card The MaterialCardView to modify.
     * @param context The context for resolving theme attributes.
     * @param isSelected Whether the card should appear selected.
     */
    fun setSelectedState(card: MaterialCardView, context: Context, isSelected: Boolean) {
        if (isSelected) {
            card.strokeWidth = dpToPxInt(context, 2)
            card.strokeColor = resolveThemeColor(
                context,
                androidx.appcompat.R.attr.colorPrimary
            )
            card.setCardBackgroundColor(
                applyAlpha(
                    resolveThemeColor(context, androidx.appcompat.R.attr.colorPrimary),
                    0.08f
                )
            )
        } else {
            card.strokeWidth = dpToPxInt(context, STROKE_WIDTH_DP)
            card.strokeColor = resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOutlineVariant
            )
            card.setCardBackgroundColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorSurface)
            )
        }
    }

    /**
     * Applies an error state to a card.
     *
     * Changes the stroke to error color for validation feedback.
     *
     * @param card The MaterialCardView to modify.
     * @param context The context for resolving theme attributes.
     * @param hasError Whether the card should display error styling.
     */
    fun setErrorState(card: MaterialCardView, context: Context, hasError: Boolean) {
        if (hasError) {
            card.strokeWidth = dpToPxInt(context, 2)
            card.strokeColor = resolveThemeColor(
                context,
                androidx.appcompat.R.attr.colorError
            )
        } else {
            card.strokeWidth = dpToPxInt(context, STROKE_WIDTH_DP)
            card.strokeColor = resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOutlineVariant
            )
        }
    }

    // -------------------------------------------------------------------------
    // Card Presets
    // -------------------------------------------------------------------------

    /**
     * Creates a card styled for section headers.
     *
     * An outlined card with 16dp side margins and a 12dp top margin, and no bottom
     * margin so the section butts up against whatever follows it. The card is empty:
     * the caller adds its own title and body views.
     *
     * @param context The context for creating the view.
     * @return A configured MaterialCardView for section headers.
     */
    fun createSectionCard(context: Context): MaterialCardView {
        return createOutlinedCard(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                val margin = dpToPxInt(context, 16)
                setMargins(margin, dpToPxInt(context, 12), margin, 0)
            }
        }
    }

    /**
     * Creates an action card with prominent styling.
     *
     * Suitable for call-to-action buttons or important interactive elements.
     *
     * @param context The context for creating the view.
     * @return A configured MaterialCardView for action contexts.
     */
    fun createActionCard(context: Context): MaterialCardView {
        return createElevatedCard(context).apply {
            setCardBackgroundColor(
                resolveThemeColor(context, androidx.appcompat.R.attr.colorPrimary)
            )
            // Note: Content text should use colorOnPrimary
        }
    }

    /**
     * Creates an info card for informational messages.
     *
     * Uses tertiary container colors for differentiation.
     *
     * @param context The context for creating the view.
     * @return A configured MaterialCardView for informational content.
     */
    fun createInfoCard(context: Context): MaterialCardView {
        return createOutlinedCard(context).apply {
            setCardBackgroundColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorTertiaryContainer)
            )
            strokeColor = resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorTertiary
            )
        }
    }

    /**
     * Creates a warning card for cautionary messages.
     *
     * Uses secondary container colors for attention without alarm.
     *
     * @param context The context for creating the view.
     * @return A configured MaterialCardView for warning content.
     */
    fun createWarningCard(context: Context): MaterialCardView {
        return createOutlinedCard(context).apply {
            setCardBackgroundColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorSecondaryContainer)
            )
            strokeColor = resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorSecondary
            )
        }
    }

    /**
     * Creates an error card for error messages.
     *
     * Uses error container colors for clear problem indication.
     *
     * @param context The context for creating the view.
     * @return A configured MaterialCardView for error content.
     */
    fun createErrorCard(context: Context): MaterialCardView {
        return createOutlinedCard(context).apply {
            setCardBackgroundColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorErrorContainer)
            )
            strokeColor = resolveThemeColor(
                context,
                androidx.appcompat.R.attr.colorError
            )
        }
    }

    /**
     * Creates a success card for success messages.
     *
     * Uses the `security_verified` green — the same semantic the rest of the app
     * paints a valid signature, a trusted certificate and a connected device with.
     * This card used to be byte-identical to [createInfoCard] (both the tertiary
     * container over a tertiary stroke), so "information" and "success" were
     * indistinguishable on screen.
     *
     * @param context The context for creating the view.
     * @return A configured MaterialCardView for success content.
     */
    fun createSuccessCard(context: Context): MaterialCardView {
        return createOutlinedCard(context).apply {
            setCardBackgroundColor(
                ContextCompat.getColor(context, R.color.security_verified_container)
            )
            strokeColor = ContextCompat.getColor(context, R.color.security_verified)
        }
    }

    // -------------------------------------------------------------------------
    // Helper Methods
    // -------------------------------------------------------------------------

    /**
     * Creates default layout parameters for cards.
     *
     * @param context The context for dimension conversion.
     * @return LayoutParams with standard margins.
     */
    private fun defaultLayoutParams(context: Context): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply {
            val horizontalMargin = dpToPxInt(context, 4)
            val verticalMargin = dpToPxInt(context, 6)
            setMargins(horizontalMargin, verticalMargin, horizontalMargin, verticalMargin)
        }
    }

    // The dimension and colour primitives below simply forward to [UIHelpers] so
    // that a single implementation of each conversion exists in the codebase.

    /** Converts dp to px. Delegates to [UIHelpers.dpToPx]. */
    private fun dpToPx(context: Context, @Dimension(unit = Dimension.DP) dp: Float): Float =
        UIHelpers.dpToPx(context, dp)

    /** Converts dp to whole px. Delegates to [UIHelpers.dpToPxInt]. */
    private fun dpToPxInt(context: Context, @Dimension(unit = Dimension.DP) dp: Int): Int =
        UIHelpers.dpToPxInt(context, dp)

    /** Resolves a theme colour attribute. Delegates to [UIHelpers.resolveThemeColor]. */
    @ColorInt
    private fun resolveThemeColor(context: Context, @AttrRes attr: Int): Int =
        UIHelpers.resolveThemeColor(context, attr)

    /** Applies alpha to a colour. Delegates to [UIHelpers.applyAlpha]. */
    @ColorInt
    private fun applyAlpha(@ColorInt color: Int, alpha: Float): Int =
        UIHelpers.applyAlpha(color, alpha)
}
