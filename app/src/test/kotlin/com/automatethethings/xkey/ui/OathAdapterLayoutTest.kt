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
 * The OATH list row has one shape at every width and font scale: the issuer
 * and account as a small title at the top, the code on its own line below.
 * With a long account name the title ellipsizes; the code stays on one line,
 * unellipsized and inside the row, at a normal width, on a narrow screen and
 * at the largest accessibility font scale.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class OathAdapterLayoutTest {

    @Test
    fun `code sits below a long account name at normal width`() {
        val row = layoutRow(widthDp = 411, fontScale = 1.0f)
        assertStacked(row)
        assertCountdownBesideCode(row)
    }

    @Test
    fun `code sits below a long account name on a narrow screen`() {
        assertStacked(layoutRow(widthDp = 280, fontScale = 1.0f))
    }

    @Test
    fun `code sits below a long account name at font scale 2`() {
        assertStacked(layoutRow(widthDp = 411, fontScale = 2.0f))
    }

    @Test
    fun `code sits below a long account name on a narrow screen at font scale 2`() {
        assertStacked(layoutRow(widthDp = 280, fontScale = 2.0f))
    }

    @Test
    fun `eight digit code stays whole on a narrow screen at font scale 2`() {
        assertStacked(layoutRow(widthDp = 280, fontScale = 2.0f, code = "12345678"))
    }

    private class Row(val host: ViewGroup, val itemView: View, val code: String) {
        fun <T : View> tagged(tag: String): T = itemView.findViewWithTag(tag)
    }

    private fun layoutRow(widthDp: Int, fontScale: Float, code: String = "123456"): Row {
        RuntimeEnvironment.setQualifiers("w${widthDp}dp-h800dp")
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
        assertEquals(widthDp, screenWidthDp)
        val rowWidth = ((screenWidthDp - 24) * density).toInt()
        val host = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        host.addView(holder.itemView)
        host.measure(
            View.MeasureSpec.makeMeasureSpec(rowWidth, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
        )
        host.layout(0, 0, host.measuredWidth, host.measuredHeight)
        return Row(host, holder.itemView, code)
    }

    /** Title above, code below, code whole, title ellipsized. */
    private fun assertStacked(row: Row) {
        val codeView = row.tagged<TextView>("code")
        val issuer = row.tagged<TextView>("issuer")
        val account = row.tagged<TextView>("account")
        val text = codeView.text.toString()
        assertEquals(OathAdapter.formatCode(row.code), text)

        val codeTop = topIn(codeView, row.host)
        for (title in listOf(issuer, account)) {
            val bottom = topIn(title, row.host) + title.height
            assertTrue("${title.tag} ends at $bottom, below the code top $codeTop", codeTop >= bottom)
        }

        val layout = codeView.layout
        assertEquals("code wraps", 1, layout.lineCount)
        assertEquals("code ellipsized", 0, layout.getEllipsisCount(0))
        val textRoom = codeView.measuredWidth - codeView.totalPaddingLeft - codeView.totalPaddingRight
        assertTrue(
            "code needs ${codeView.paint.measureText(text)}px, has $textRoom px (row ${row.host.width})",
            codeView.paint.measureText(text) <= textRoom
        )
        assertTrue("code line ${layout.getLineWidth(0)}px, has $textRoom px", layout.getLineWidth(0) <= textRoom)
        assertInsideRow(codeView, row.host)

        val accountLayout = account.layout
        assertEquals("account wraps", 1, accountLayout.lineCount)
        assertTrue("the long account is not ellipsized", accountLayout.getEllipsisCount(0) > 0)
        assertInsideRow(account, row.host)
        assertInsideRow(issuer, row.host)
    }

    /** The countdown shares the code's line. */
    private fun assertCountdownBesideCode(row: Row) {
        val codeView = row.tagged<TextView>("code")
        val countdown = row.tagged<TextView>("countdown")
        val codeTop = topIn(codeView, row.host)
        val countdownTop = topIn(countdown, row.host)
        assertTrue(
            "countdown $countdownTop..${countdownTop + countdown.height} is not on the code line " +
                "$codeTop..${codeTop + codeView.height}",
            countdownTop < codeTop + codeView.height && countdownTop + countdown.height > codeTop
        )
        assertEquals(1, countdown.layout.lineCount)
        assertEquals(0, countdown.layout.getEllipsisCount(0))
        assertInsideRow(countdown, row.host)
    }

    private fun topIn(view: View, host: ViewGroup): Int {
        var top = 0
        var current: View = view
        while (current !== host) {
            top += current.top
            current = current.parent as View
        }
        return top
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
