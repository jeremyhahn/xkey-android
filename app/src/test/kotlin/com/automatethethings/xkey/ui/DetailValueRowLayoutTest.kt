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

import android.app.Application
import android.content.Context
import android.view.ContextThemeWrapper
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * The key details screen on a 360dp phone: a key ID (a 36-character UUID)
 * and other monospace identifiers are shown whole, wrapping onto more lines
 * when the row is too narrow, never cut off, at font scale 1 and 1.5.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class, qualifiers = "w360dp-h740dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class DetailValueRowLayoutTest {

    private val keyId = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

    @Test
    fun `a UUID key ID shows whole at font scale 1`() {
        assertValueWhole(fontScale = 1.0f, value = keyId)
    }

    @Test
    fun `a UUID key ID shows whole at font scale 1_5`() {
        assertValueWhole(fontScale = 1.5f, value = keyId)
    }

    @Test
    fun `a long attestation application ID shows whole at font scale 1_5`() {
        assertValueWhole(
            fontScale = 1.5f,
            value = "com.example.authenticator.app:1:AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12"
        )
    }

    private fun assertValueWhole(fontScale: Float, value: String) {
        RuntimeEnvironment.setFontScale(fontScale)
        val context: Context = ContextThemeWrapper(
            ApplicationProvider.getApplicationContext<Context>(),
            R.style.Theme_xKey
        )
        assertEquals(360, context.resources.configuration.screenWidthDp)
        // The screen pads its cards and the card pads its content: a row gets
        // about the screen width less 64dp.
        val density = context.resources.displayMetrics.density
        val rowWidth = ((360 - 64) * density).toInt()

        val row = DetailValueRow.create(context, "Key ID", value, isMonospace = true)
        row.measure(
            View.MeasureSpec.makeMeasureSpec(rowWidth, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
        )
        row.layout(0, 0, row.measuredWidth, row.measuredHeight)

        val valueView = row.findViewWithTag<TextView>(DetailValueRow.VALUE_TAG)
        assertEquals(value, valueView.text.toString())
        val layout = valueView.layout
        for (line in 0 until layout.lineCount) {
            assertEquals("line $line ellipsized at font scale $fontScale", 0, layout.getEllipsisCount(line))
        }
        assertTrue(
            "${layout.lineCount} lines laid out, ${valueView.maxLines} shown at font scale $fontScale",
            layout.lineCount <= valueView.maxLines
        )
        assertEquals(
            "text past the last line at font scale $fontScale",
            value.length,
            layout.getLineEnd(layout.lineCount - 1)
        )
        assertTrue(
            "value view ${valueView.measuredHeight}px tall, text needs ${layout.height}px",
            valueView.measuredHeight - valueView.totalPaddingTop - valueView.totalPaddingBottom >= layout.height
        )
    }
}
