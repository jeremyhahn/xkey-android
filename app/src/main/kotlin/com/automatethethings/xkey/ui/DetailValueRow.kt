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
import android.graphics.Typeface
import android.view.Gravity
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView

/**
 * A label / value row of the key details screen. A monospace value is an
 * identifier (a key ID, an attestation application ID).
 */
internal object DetailValueRow {

    /** Tag of the row's value view. */
    const val VALUE_TAG = "detail_value"

    fun create(
        context: Context,
        label: String,
        value: String,
        isMonospace: Boolean = false
    ): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(context, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val labelView = TextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f)
            text = label
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
        }
        row.addView(labelView)

        val valueView = TextView(context).apply {
            tag = VALUE_TAG
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f)
            text = value
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface))
            typeface = if (isMonospace) Typeface.MONOSPACE else Typeface.DEFAULT_BOLD
            gravity = Gravity.END
            maxLines = if (isMonospace) 1 else 2
            if (isMonospace) {
                textSize = 10f
            }
        }
        row.addView(valueView)
        return row
    }
}
