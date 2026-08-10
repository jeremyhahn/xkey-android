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
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
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
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip

/**
 * Common UI helper functions for the xKey application.
 *
 * Provides utility methods for dimension conversions, theme color resolution,
 * gradient drawable creation, and badge/chip creation. These helpers ensure
 * consistent UI implementation across the application and reduce boilerplate
 * code in Activity and Fragment classes.
 *
 * All methods are thread-safe and can be called from any thread, though views
 * should only be created and modified on the main thread.
 */
object UIHelpers {

    // -------------------------------------------------------------------------
    // Dimension Conversions
    // -------------------------------------------------------------------------

    /**
     * Converts density-independent pixels (dp) to physical pixels (px).
     *
     * Uses the device's display density to calculate the appropriate pixel value.
     * This ensures consistent physical sizes across devices with different screen
     * densities.
     *
     * @param context The context to access display metrics.
     * @param dp The value in density-independent pixels.
     * @return The equivalent value in physical pixels as a Float.
     */
    fun dpToPx(context: Context, @Dimension(unit = Dimension.DP) dp: Float): Float {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp,
            context.resources.displayMetrics
        )
    }

    /**
     * Converts density-independent pixels (dp) to physical pixels (px) as an integer.
     *
     * Convenience method for cases where an integer pixel value is required,
     * such as setting view dimensions or margins programmatically.
     *
     * @param context The context to access display metrics.
     * @param dp The value in density-independent pixels.
     * @return The equivalent value in physical pixels as an Int (rounded).
     */
    fun dpToPxInt(context: Context, @Dimension(unit = Dimension.DP) dp: Int): Int {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp.toFloat(),
            context.resources.displayMetrics
        ).toInt()
    }

    /**
     * Converts physical pixels (px) to density-independent pixels (dp).
     *
     * Useful when reading pixel values from the system and converting them
     * to density-independent units for consistent handling.
     *
     * @param context The context to access display metrics.
     * @param px The value in physical pixels.
     * @return The equivalent value in density-independent pixels.
     */
    fun pxToDp(context: Context, px: Float): Float {
        return px / context.resources.displayMetrics.density
    }

    /**
     * Converts physical pixels (px) to density-independent pixels (dp) as an integer.
     *
     * @param context The context to access display metrics.
     * @param px The value in physical pixels.
     * @return The equivalent value in density-independent pixels as an Int (rounded).
     */
    fun pxToDpInt(context: Context, px: Int): Int {
        return (px / context.resources.displayMetrics.density).toInt()
    }

    /**
     * Converts scale-independent pixels (sp) to physical pixels (px).
     *
     * Used for text sizes that should scale with user accessibility settings.
     *
     * @param context The context to access display metrics.
     * @param sp The value in scale-independent pixels.
     * @return The equivalent value in physical pixels.
     */
    fun spToPx(context: Context, sp: Float): Float {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_SP,
            sp,
            context.resources.displayMetrics
        )
    }

    // -------------------------------------------------------------------------
    // Theme Color Resolution
    // -------------------------------------------------------------------------

    /**
     * Resolves a theme color attribute to an actual color value.
     *
     * This method properly handles Material3 theme attributes by first resolving
     * the attribute to a resource ID, then fetching the actual color value.
     * Falls back to the attribute's data value if no resource ID is found.
     *
     * @param context The context with the theme to resolve against.
     * @param attr The theme attribute resource ID (e.g., R.attr.colorPrimary).
     * @return The resolved color as an ARGB integer.
     */
    @ColorInt
    fun resolveThemeColor(context: Context, @AttrRes attr: Int): Int {
        val typedValue = TypedValue()
        context.theme.resolveAttribute(attr, typedValue, true)
        return if (typedValue.resourceId != 0) {
            ContextCompat.getColor(context, typedValue.resourceId)
        } else {
            typedValue.data
        }
    }

    /**
     * Resolves a theme color attribute to a ColorStateList.
     *
     * Useful for views that require state-aware colors (e.g., pressed, focused).
     *
     * @param context The context with the theme to resolve against.
     * @param attr The theme attribute resource ID.
     * @return A ColorStateList with the resolved color, or null if resolution fails.
     */
    fun resolveThemeColorStateList(context: Context, @AttrRes attr: Int): ColorStateList? {
        val typedValue = TypedValue()
        context.theme.resolveAttribute(attr, typedValue, true)
        return if (typedValue.resourceId != 0) {
            ContextCompat.getColorStateList(context, typedValue.resourceId)
        } else {
            ColorStateList.valueOf(typedValue.data)
        }
    }

    /**
     * Resolves the action bar size from the current theme.
     *
     * @param context The context with the theme to resolve against.
     * @return The action bar height in pixels.
     */
    fun resolveActionBarSize(context: Context): Int {
        val typedValue = TypedValue()
        context.theme.resolveAttribute(android.R.attr.actionBarSize, typedValue, true)
        return TypedValue.complexToDimensionPixelSize(
            typedValue.data,
            context.resources.displayMetrics
        )
    }

    /**
     * Applies alpha to a color while preserving RGB components.
     *
     * @param color The base color as an ARGB integer.
     * @param alpha The alpha value (0.0 to 1.0).
     * @return The color with the new alpha value applied.
     */
    @ColorInt
    fun applyAlpha(@ColorInt color: Int, alpha: Float): Int {
        val alphaInt = (alpha.coerceIn(0f, 1f) * 255).toInt()
        return (color and 0x00FFFFFF) or (alphaInt shl 24)
    }

    // -------------------------------------------------------------------------
    // Gradient Drawable Creation
    // -------------------------------------------------------------------------

    /**
     * Creates a horizontal gradient drawable.
     *
     * @param startColor The color at the start (left) of the gradient.
     * @param endColor The color at the end (right) of the gradient.
     * @param cornerRadius The corner radius in pixels (default: 0).
     * @return A configured GradientDrawable.
     */
    fun createHorizontalGradient(
        @ColorInt startColor: Int,
        @ColorInt endColor: Int,
        cornerRadius: Float = 0f
    ): GradientDrawable {
        return GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            intArrayOf(startColor, endColor)
        ).apply {
            if (cornerRadius > 0f) {
                this.cornerRadius = cornerRadius
            }
        }
    }

    /**
     * Creates a vertical gradient drawable.
     *
     * @param topColor The color at the top of the gradient.
     * @param bottomColor The color at the bottom of the gradient.
     * @param cornerRadius The corner radius in pixels (default: 0).
     * @return A configured GradientDrawable.
     */
    fun createVerticalGradient(
        @ColorInt topColor: Int,
        @ColorInt bottomColor: Int,
        cornerRadius: Float = 0f
    ): GradientDrawable {
        return GradientDrawable(
            GradientDrawable.Orientation.TOP_BOTTOM,
            intArrayOf(topColor, bottomColor)
        ).apply {
            if (cornerRadius > 0f) {
                this.cornerRadius = cornerRadius
            }
        }
    }

    /**
     * Creates a diagonal gradient drawable (top-left to bottom-right).
     *
     * @param startColor The color at the top-left corner.
     * @param endColor The color at the bottom-right corner.
     * @param cornerRadius The corner radius in pixels (default: 0).
     * @return A configured GradientDrawable.
     */
    fun createDiagonalGradient(
        @ColorInt startColor: Int,
        @ColorInt endColor: Int,
        cornerRadius: Float = 0f
    ): GradientDrawable {
        return GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(startColor, endColor)
        ).apply {
            if (cornerRadius > 0f) {
                this.cornerRadius = cornerRadius
            }
        }
    }

    /**
     * Creates a multi-color gradient drawable with custom orientation.
     *
     * @param colors Array of colors for the gradient (at least 2).
     * @param orientation The gradient orientation.
     * @param cornerRadius The corner radius in pixels (default: 0).
     * @return A configured GradientDrawable.
     * @throws IllegalArgumentException if fewer than 2 colors are provided.
     */
    fun createMultiColorGradient(
        colors: IntArray,
        orientation: GradientDrawable.Orientation,
        cornerRadius: Float = 0f
    ): GradientDrawable {
        require(colors.size >= 2) { "Gradient requires at least 2 colors" }
        return GradientDrawable(orientation, colors).apply {
            if (cornerRadius > 0f) {
                this.cornerRadius = cornerRadius
            }
        }
    }

    /**
     * Creates a radial gradient drawable of a fixed pixel radius.
     *
     * **The radius is absolute, not relative.** [GradientDrawable.setGradientRadius]
     * stores a bare float as `RADIUS_TYPE_PIXELS`, and the fraction/bounds-relative
     * types can only be selected from XML (`android:gradientRadius="50%p"`) — the
     * framework exposes no setter for the radius type. A previous version of this
     * helper multiplied a 0..1 "ratio" by 1000 and claimed the result scaled with the
     * view, so every caller silently got a 500px radius no matter how large the view
     * was. Pass a real pixel value, normally derived from the view's size or from
     * [dpToPx].
     *
     * @param centerColor The color at the center of the gradient.
     * @param edgeColor The color at the edges of the gradient.
     * @param radiusPx The gradient radius in physical pixels.
     * @param cornerRadius The corner radius in pixels (default: 0).
     * @return A configured GradientDrawable centred on its bounds.
     */
    fun createRadialGradient(
        @ColorInt centerColor: Int,
        @ColorInt edgeColor: Int,
        radiusPx: Float,
        cornerRadius: Float = 0f
    ): GradientDrawable {
        return GradientDrawable().apply {
            gradientType = GradientDrawable.RADIAL_GRADIENT
            setColors(intArrayOf(centerColor, edgeColor))
            gradientRadius = radiusPx
            setGradientCenter(0.5f, 0.5f)
            if (cornerRadius > 0f) {
                this.cornerRadius = cornerRadius
            }
        }
    }

    /**
     * Creates a solid color drawable with rounded corners.
     *
     * @param color The fill color.
     * @param cornerRadius The corner radius in pixels.
     * @param strokeWidth The stroke width in pixels (0 for no stroke).
     * @param strokeColor The stroke color (ignored if strokeWidth is 0).
     * @return A configured GradientDrawable.
     */
    fun createRoundedDrawable(
        @ColorInt color: Int,
        cornerRadius: Float,
        strokeWidth: Int = 0,
        @ColorInt strokeColor: Int = Color.TRANSPARENT
    ): GradientDrawable {
        return GradientDrawable().apply {
            setColor(color)
            this.cornerRadius = cornerRadius
            if (strokeWidth > 0) {
                setStroke(strokeWidth, strokeColor)
            }
        }
    }

    /**
     * Creates a pill-shaped drawable (fully rounded ends).
     *
     * @param color The fill color.
     * @param height The height in pixels (used to calculate corner radius).
     * @param strokeWidth The stroke width in pixels (0 for no stroke).
     * @param strokeColor The stroke color (ignored if strokeWidth is 0).
     * @return A configured GradientDrawable.
     */
    fun createPillDrawable(
        @ColorInt color: Int,
        height: Float,
        strokeWidth: Int = 0,
        @ColorInt strokeColor: Int = Color.TRANSPARENT
    ): GradientDrawable {
        return createRoundedDrawable(
            color = color,
            cornerRadius = height / 2f,
            strokeWidth = strokeWidth,
            strokeColor = strokeColor
        )
    }

    // -------------------------------------------------------------------------
    // Badge and Chip Creation
    // -------------------------------------------------------------------------

    /**
     * Creates a simple text badge view.
     *
     * The badge is styled as a small pill-shaped label suitable for
     * status indicators, counts, or category labels.
     *
     * @param context The context for creating the view.
     * @param text The badge text.
     * @param backgroundColor The badge background color.
     * @param textColor The badge text color.
     * @return A configured TextView styled as a badge.
     */
    fun createBadge(
        context: Context,
        text: String,
        @ColorInt backgroundColor: Int,
        @ColorInt textColor: Int
    ): TextView {
        val paddingHorizontal = dpToPxInt(context, 8)
        val paddingVertical = dpToPxInt(context, 4)
        val cornerRadius = dpToPx(context, 12f)

        return TextView(context).apply {
            this.text = text
            setTextColor(textColor)
            textSize = 12f
            setPadding(paddingHorizontal, paddingVertical, paddingHorizontal, paddingVertical)
            background = createRoundedDrawable(backgroundColor, cornerRadius)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
    }

    /**
     * Creates a status badge with predefined styling for common states.
     *
     * @param context The context for creating the view.
     * @param status The status type.
     * @return A configured TextView styled as a status badge.
     */
    fun createStatusBadge(context: Context, status: StatusType): TextView {
        val (backgroundColor, textColor, text) = when (status) {
            StatusType.ACTIVE -> Triple(
                resolveThemeColor(context, com.google.android.material.R.attr.colorTertiary),
                resolveThemeColor(context, com.google.android.material.R.attr.colorOnTertiary),
                "Active"
            )
            StatusType.INACTIVE -> Triple(
                resolveThemeColor(context, com.google.android.material.R.attr.colorSurfaceVariant),
                resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant),
                "Inactive"
            )
            StatusType.PENDING -> Triple(
                resolveThemeColor(context, com.google.android.material.R.attr.colorSecondaryContainer),
                resolveThemeColor(context, com.google.android.material.R.attr.colorOnSecondaryContainer),
                "Pending"
            )
            StatusType.ERROR -> Triple(
                resolveThemeColor(context, com.google.android.material.R.attr.colorErrorContainer),
                resolveThemeColor(context, com.google.android.material.R.attr.colorOnErrorContainer),
                "Error"
            )
            StatusType.SUCCESS -> Triple(
                resolveThemeColor(context, com.google.android.material.R.attr.colorTertiaryContainer),
                resolveThemeColor(context, com.google.android.material.R.attr.colorOnTertiaryContainer),
                "Success"
            )
            StatusType.WARNING -> Triple(
                resolveThemeColor(context, com.google.android.material.R.attr.colorSecondary),
                resolveThemeColor(context, com.google.android.material.R.attr.colorOnSecondary),
                "Warning"
            )
        }

        return createBadge(context, text, backgroundColor, textColor)
    }

    /**
     * Creates a custom status badge with specified text.
     *
     * @param context The context for creating the view.
     * @param status The status type for styling.
     * @param customText Custom text to display instead of the default status name.
     * @return A configured TextView styled as a status badge.
     */
    fun createStatusBadge(context: Context, status: StatusType, customText: String): TextView {
        val badge = createStatusBadge(context, status)
        badge.text = customText
        return badge
    }

    /**
     * Creates a Material Design chip programmatically.
     *
     * @param context The context for creating the chip.
     * @param text The chip text.
     * @param isCheckable Whether the chip can be checked/selected.
     * @param onClickListener Optional click listener.
     * @return A configured Chip view.
     */
    fun createChip(
        context: Context,
        text: String,
        isCheckable: Boolean = false,
        onClickListener: ((Chip) -> Unit)? = null
    ): Chip {
        return Chip(context).apply {
            this.text = text
            this.isCheckable = isCheckable
            this.isClickable = true
            this.isFocusable = true

            chipBackgroundColor = resolveThemeColorStateList(
                context,
                com.google.android.material.R.attr.colorSurfaceContainerHigh
            )
            setTextColor(resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface))

            onClickListener?.let { listener ->
                setOnClickListener { listener(this) }
            }
        }
    }

    /**
     * Creates a filter chip with icon support.
     *
     * @param context The context for creating the chip.
     * @param text The chip text.
     * @param iconRes Optional icon resource ID (0 for no icon).
     * @param onCheckedChangeListener Optional checked state change listener.
     * @return A configured Chip view styled as a filter chip.
     */
    fun createFilterChip(
        context: Context,
        text: String,
        iconRes: Int = 0,
        onCheckedChangeListener: ((Chip, Boolean) -> Unit)? = null
    ): Chip {
        return Chip(context).apply {
            this.text = text
            this.isCheckable = true
            this.isCheckedIconVisible = true

            if (iconRes != 0) {
                setChipIconResource(iconRes)
                isChipIconVisible = true
            }

            onCheckedChangeListener?.let { listener ->
                setOnCheckedChangeListener { _, isChecked -> listener(this, isChecked) }
            }
        }
    }

    /**
     * Creates a badge sized for the hero summary card's badge column.
     *
     * This standardises the small pill that list screens stack down the right-hand
     * side of their hero card: 11sp text in `on_primary`, 10dp/4dp padding, a 12dp
     * rounded background of [tint] at **30% alpha**, and a 4dp bottom margin so
     * consecutive badges separate.
     *
     * The alpha is applied here rather than by the caller: four of the five previous
     * copies dimmed the tint to 0.3f and only the PIV screen passed an already-dimmed
     * colour, which made its badges read differently from every other screen.
     *
     * @param context The context for creating the view.
     * @param text The badge text (already localised).
     * @param tint The badge's base colour, at full opacity.
     * @return A configured TextView styled as a hero badge.
     */
    fun createHeroBadge(context: Context, text: CharSequence, @ColorInt tint: Int): TextView {
        return TextView(context).apply {
            this.text = text
            textSize = 11f
            setTextColor(ContextCompat.getColor(context, R.color.on_primary))
            setPadding(
                dpToPxInt(context, 10),
                dpToPxInt(context, 4),
                dpToPxInt(context, 10),
                dpToPxInt(context, 4)
            )
            background = createRoundedDrawable(
                applyAlpha(tint, 0.3f),
                dpToPx(context, 12f)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(context, 4)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Empty States
    // -------------------------------------------------------------------------

    /**
     * Creates the container for a screen's empty state.
     *
     * Standardises the placeholder shown when a list has no rows: a centred vertical
     * column that takes the remaining weight of its parent, is padded 48dp on all
     * sides, and starts hidden. The caller flips [View.VISIBLE]/[View.GONE] as data
     * loads and fills it once via [fillEmptyState].
     *
     * The returned layout params assume a vertical [LinearLayout] parent.
     *
     * @param context The context for creating the view.
     * @return An empty, GONE container ready for [fillEmptyState].
     */
    fun createEmptyStateContainer(context: Context): LinearLayout {
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            visibility = View.GONE
            val padding = dpToPxInt(context, 48)
            setPadding(padding, padding, padding, padding)
        }
    }

    /**
     * Populates an empty-state container with the standard icon/title/message stack.
     *
     * Standardises the illustration block every list screen duplicated: a 96dp icon
     * tinted `colorOutlineVariant`, a 20sp `sans-serif-medium` title in
     * `colorOnSurface`, and a 14sp message in `colorOnSurfaceVariant`, all centred.
     * When [actionLabel] is supplied a Material button is appended and the message
     * gains a 32dp bottom margin to separate it.
     *
     * Existing children are removed first, so the container may be refilled when the
     * empty state's wording depends on an active filter.
     *
     * @param container A container from [createEmptyStateContainer].
     * @param iconRes The illustration drawable.
     * @param title The headline (already localised).
     * @param message The explanatory copy (already localised).
     * @param actionLabel Optional call-to-action label; omit for a passive empty state.
     * @param onAction Invoked when the action button is tapped. Ignored without [actionLabel].
     */
    fun fillEmptyState(
        container: LinearLayout,
        @DrawableRes iconRes: Int,
        title: CharSequence,
        message: CharSequence,
        actionLabel: CharSequence? = null,
        onAction: (() -> Unit)? = null
    ) {
        val context = container.context
        container.removeAllViews()

        container.addView(ImageView(context).apply {
            setImageResource(iconRes)
            imageTintList = ColorStateList.valueOf(
                resolveThemeColor(context, com.google.android.material.R.attr.colorOutlineVariant)
            )
            layoutParams = LinearLayout.LayoutParams(
                dpToPxInt(context, 96),
                dpToPxInt(context, 96)
            ).apply {
                bottomMargin = dpToPxInt(context, 24)
            }
        })

        container.addView(TextView(context).apply {
            text = title
            textSize = 20f
            setTextColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(context, 8)
            }
        })

        container.addView(TextView(context).apply {
            text = message
            textSize = 14f
            setTextColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                if (actionLabel != null) {
                    bottomMargin = dpToPxInt(context, 32)
                }
            }
        })

        if (actionLabel != null) {
            container.addView(MaterialButton(context).apply {
                text = actionLabel
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                setOnClickListener { onAction?.invoke() }
            })
        }
    }

    // -------------------------------------------------------------------------
    // Detail Rows
    // -------------------------------------------------------------------------

    /**
     * Appends a label/value row to a detail card's content column.
     *
     * Standardises the two-column row the detail screens duplicated: a `BodySmall`
     * label in `colorOnSurfaceVariant` at 0.4 weight, and a bold, end-aligned
     * `BodySmall` value in `colorOnSurface` at 0.6 weight, with an 8dp bottom margin.
     *
     * Setting [monospace] switches the value to a 10sp single-line monospace face,
     * which is how fingerprints and other hex blobs are rendered.
     *
     * @param parent The column to append the row to.
     * @param label The row label (already localised).
     * @param value The row value.
     * @param valueColor Overrides the value colour, e.g. to flag an error. Null keeps `colorOnSurface`.
     * @param monospace True to render the value as fixed-width, single-line text.
     * @return The value TextView, so callers that update a row in place can keep a reference.
     */
    fun addDetailRow(
        parent: LinearLayout,
        label: CharSequence,
        value: CharSequence,
        @ColorInt valueColor: Int? = null,
        monospace: Boolean = false
    ): TextView {
        val context = parent.context

        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(context, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        row.addView(TextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f)
            text = label
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
        })

        val valueView = TextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f)
            text = value
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                valueColor
                    ?: resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
            gravity = Gravity.END
            if (monospace) {
                typeface = Typeface.MONOSPACE
                textSize = 10f
                maxLines = 1
            } else {
                typeface = Typeface.DEFAULT_BOLD
            }
        }
        row.addView(valueView)

        parent.addView(row)
        return valueView
    }

    // -------------------------------------------------------------------------
    // Utility Types
    // -------------------------------------------------------------------------

    /**
     * Common status types for badge styling.
     */
    enum class StatusType {
        ACTIVE,
        INACTIVE,
        PENDING,
        ERROR,
        SUCCESS,
        WARNING
    }
}
