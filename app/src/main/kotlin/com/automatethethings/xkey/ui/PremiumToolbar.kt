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

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.annotation.ColorRes
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import com.automatethethings.xkey.R

/**
 * Builds and installs the gradient app bar shared by every xKey detail and list screen.
 *
 * Twelve screens each hand-rolled the same block: a vertical container carrying a
 * left-to-right gradient, a transparent [Toolbar] sized to the theme's action bar
 * height, and a dimmed subtitle underneath the title. [install] is that recipe:
 *
 * - gradient background, [Accent.PRIMARY] by default
 * - toolbar background [Color.TRANSPARENT] with zero elevation, title in `on_primary`
 * - subtitle at 14sp in `on_primary` at 85% alpha, padded (72, 0, 16, 12)dp so it
 *   lines up under the title rather than under the navigation icon
 * - `ic_chevron_right` as the up indicator, tinted `on_primary`
 * - installed with `setSupportActionBar`, so the caller keeps `onOptionsItemSelected`
 *
 * **Menus are the host activity's job.** [install] deliberately takes no menu
 * resource: because it calls `setSupportActionBar`, the toolbar is wrapped in a
 * `ToolbarActionBar`, which replaces any menu-item click listener with one routing
 * to `Activity.onOptionsItemSelected` and then clears and repopulates the menu from
 * `Activity.onCreateOptionsMenu`. Anything inflated here would be discarded — that is
 * how `AuditLogActivity` lost its entire overflow menu. Override
 * `onCreateOptionsMenu` / `onOptionsItemSelected` on the activity instead.
 *
 * This lives outside [UIHelpers] because it needs an [AppCompatActivity] to call
 * `setSupportActionBar`, whereas UIHelpers is deliberately Context-only.
 *
 * ```kotlin
 * PremiumToolbar.install(
 *     activity = this,
 *     parent = contentLayout,
 *     titleRes = R.string.key_vault_title,
 *     subtitleRes = R.string.key_vault_subtitle
 * )
 * ```
 *
 * @see UIHelpers for the Context-only helpers this builds on.
 */
object PremiumToolbar {

    /**
     * The gradient family the app bar is painted with.
     *
     * [PRIMARY] is the indigo used by the majority of screens. [TERTIARY] is the teal
     * reserved for the PIV screens, which are colour-coded away from the rest of the app.
     */
    enum class Accent(
        @ColorRes internal val startColor: Int,
        @ColorRes internal val endColor: Int
    ) {
        PRIMARY(R.color.gradient_primary_start, R.color.gradient_primary_end),
        TERTIARY(R.color.gradient_tertiary_start, R.color.tertiary_variant)
    }

    /**
     * The views [install] created, returned so callers can retitle the bar or update
     * the subtitle after data loads.
     *
     * @property container The gradient-backed column already added to the parent.
     * @property toolbar The toolbar, already installed as the support action bar.
     * @property subtitleView The subtitle, or null when no subtitle was requested.
     */
    data class Installed(
        val container: LinearLayout,
        val toolbar: Toolbar,
        val subtitleView: TextView?
    )

    /**
     * Builds the premium app bar from string resources and adds it to [parent].
     *
     * @param activity The host activity; receives the toolbar via `setSupportActionBar`.
     * @param parent The view the app bar is appended to, normally the screen's root column.
     * @param titleRes The toolbar title.
     * @param subtitleRes The subtitle, or 0 for a title-only bar.
     * @param accent The gradient family. Defaults to [Accent.PRIMARY].
     * @param homeAsUpIndicator The up-affordance drawable, or 0 to keep the platform default.
     * @return The created views.
     */
    fun install(
        activity: AppCompatActivity,
        parent: ViewGroup,
        @StringRes titleRes: Int,
        @StringRes subtitleRes: Int = 0,
        accent: Accent = Accent.PRIMARY,
        @DrawableRes homeAsUpIndicator: Int = R.drawable.ic_chevron_right
    ): Installed {
        return install(
            activity = activity,
            parent = parent,
            title = activity.getString(titleRes),
            subtitle = if (subtitleRes != 0) activity.getString(subtitleRes) else null,
            accent = accent,
            homeAsUpIndicator = homeAsUpIndicator
        )
    }

    /**
     * Builds the premium app bar from already-resolved text and adds it to [parent].
     *
     * Use this overload when the title or subtitle is formatted at runtime, for example
     * a subtitle that names the record being viewed.
     *
     * @param activity The host activity; receives the toolbar via `setSupportActionBar`.
     * @param parent The view the app bar is appended to, normally the screen's root column.
     * @param title The toolbar title, already localised.
     * @param subtitle The subtitle, already localised, or null for a title-only bar.
     * @param accent The gradient family. Defaults to [Accent.PRIMARY].
     * @param homeAsUpIndicator The up-affordance drawable, or 0 to keep the platform default.
     * @return The created views.
     */
    fun install(
        activity: AppCompatActivity,
        parent: ViewGroup,
        title: CharSequence,
        subtitle: CharSequence? = null,
        accent: Accent = Accent.PRIMARY,
        @DrawableRes homeAsUpIndicator: Int = R.drawable.ic_chevron_right
    ): Installed {
        val onPrimary = ContextCompat.getColor(activity, R.color.on_primary)

        val container = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            background = GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                intArrayOf(
                    ContextCompat.getColor(activity, accent.startColor),
                    ContextCompat.getColor(activity, accent.endColor)
                )
            )
        }

        val toolbar = Toolbar(activity).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(activity)
            )
            setBackgroundColor(Color.TRANSPARENT)
            this.title = title
            setTitleTextColor(onPrimary)
            elevation = 0f
        }
        container.addView(toolbar)

        val subtitleView = subtitle?.let { text ->
            TextView(activity).apply {
                this.text = text
                textSize = 14f
                setTextColor(UIHelpers.applyAlpha(onPrimary, SUBTITLE_ALPHA))
                setPadding(
                    UIHelpers.dpToPxInt(activity, 72),
                    0,
                    UIHelpers.dpToPxInt(activity, 16),
                    UIHelpers.dpToPxInt(activity, 12)
                )
            }
        }
        subtitleView?.let(container::addView)

        parent.addView(container)

        activity.setSupportActionBar(toolbar)
        activity.supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
            if (homeAsUpIndicator != 0) {
                setHomeAsUpIndicator(homeAsUpIndicator)
            }
        }
        toolbar.navigationIcon?.setTint(onPrimary)

        return Installed(container, toolbar, subtitleView)
    }

    /** Opacity of the subtitle against the gradient, as used by the majority of screens. */
    private const val SUBTITLE_ALPHA = 0.85f
}
