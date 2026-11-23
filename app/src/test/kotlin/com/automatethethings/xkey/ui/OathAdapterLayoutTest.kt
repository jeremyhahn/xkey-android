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
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.R
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathCredentialWithCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * The OATH list row on a narrow screen (a folding phone's outer display is
 * about 320dp wide) next to a long account name: the code must stay on one
 * line, unellipsized and inside the row, at the default font scale and at
 * the largest accessibility font scale. The issuer and account give way.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class, qualifiers = "w320dp-h700dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class OathAdapterLayoutTest {

    @Test
    fun `code stays whole beside a long account name at font scale 1`() {
        assertCodeWhole(fontScale = 1.0f)
    }

    @Test
    fun `code stays whole beside a long account name at font scale 2`() {
        assertCodeWhole(fontScale = 2.0f)
    }

    @Test
    fun `eight digit code stays whole at font scale 2`() {
        assertCodeWhole(fontScale = 2.0f, code = "12345678")
    }

    private fun assertCodeWhole(fontScale: Float, code: String = "123456") {
        RuntimeEnvironment.setFontScale(fontScale)
        val context: Context = ContextThemeWrapper(
            ApplicationProvider.getApplicationContext<Context>(),
            R.style.Theme_xKey
        )
        val list = RecyclerView(context).apply { layoutManager = LinearLayoutManager(context) }
        val adapter = OathAdapter(onItemClick = {}, onItemLongClick = { true })
        val holder = adapter.onCreateViewHolder(list, 0)
        holder.bind(item(code))

        // The list pads each side by 12dp, so a row gets the screen width less 24dp.
        val density = context.resources.displayMetrics.density
        val screenWidthDp = context.resources.configuration.screenWidthDp
        assertEquals(320, screenWidthDp)
        val rowWidth = ((screenWidthDp - 24) * density).toInt()
        val host = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        host.addView(holder.itemView)
        host.measure(
            View.MeasureSpec.makeMeasureSpec(rowWidth, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
        )
        host.layout(0, 0, host.measuredWidth, host.measuredHeight)

        val codeView = holder.itemView.findViewWithTag<TextView>("code")
        val text = codeView.text.toString()
        assertEquals(OathAdapter.formatCode(code), text)
        val layout = codeView.layout
        assertEquals("code wraps at font scale $fontScale", 1, layout.lineCount)
        assertEquals("code ellipsized at font scale $fontScale", 0, layout.getEllipsisCount(0))
        val textRoom = codeView.measuredWidth - codeView.totalPaddingLeft - codeView.totalPaddingRight
        assertTrue(
            "code needs ${codeView.paint.measureText(text)}px, has $textRoom px",
            codeView.paint.measureText(text) <= textRoom
        )
        assertTrue(
            "code line ${layout.getLineWidth(0)}px, has $textRoom px",
            layout.getLineWidth(0) <= textRoom
        )
        assertInsideRow(codeView, host)

        val account = holder.itemView.findViewWithTag<TextView>("account")
        val accountLayout = account.layout
        val lastLine = accountLayout.lineCount - 1
        assertTrue(
            "the long account is neither ellipsized nor wrapped",
            accountLayout.lineCount > 1 || accountLayout.getEllipsisCount(lastLine) > 0
        )
        assertInsideRow(account, host)
        assertInsideRow(holder.itemView.findViewWithTag<TextView>("issuer"), host)
    }

    /** The view lies wholly within the row horizontally (no clipping by a parent). */
    private fun assertInsideRow(view: View, host: ViewGroup) {
        var left = 0
        var current: View = view
        while (current !== host) {
            left += current.left
            current = current.parent as View
        }
        assertTrue("${view.tag} starts at $left", left >= 0)
        assertTrue(
            "${view.tag} ends at ${left + view.width}, row is ${host.width}",
            left + view.width <= host.width
        )
    }

    private fun item(code: String) = OathCredentialWithCode(
        credential = OathCredentialEntity(
            oathId = "authenticationtest.com:long",
            oathType = "TOTP",
            algorithm = "SHA1",
            digits = code.length,
            periodSeconds = 30,
            issuer = "authenticationtest.com",
            accountName = "a.very.long.mailbox.name.for.testing.purposes@subdomain.example.com",
            secretEncrypted = byteArrayOf(0x00),
            createdAt = 0L
        ),
        code = code,
        secondsRemaining = 17
    )
}
