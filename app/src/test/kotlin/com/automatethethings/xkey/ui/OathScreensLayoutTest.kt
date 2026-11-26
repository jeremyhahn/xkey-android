/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.ui

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.Intent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.TextView
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.storage.XKeyDatabase
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.concurrent.atomic.AtomicReference

/**
 * The two OATH screens keep their codes out of screenshots, screen
 * recordings and the recents thumbnail (FLAG_SECURE), and the details
 * screen's code stays whole on a 320dp screen at the largest font scale.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class, qualifiers = "w320dp-h700dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class OathScreensLayoutTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Before
    fun setUp() {
        FakeAndroidKeyStore.install()
        val database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        @Suppress("UNCHECKED_CAST")
        val field = XKeyDatabase::class.java.getDeclaredField("instanceRef").apply { isAccessible = true }
        (field.get(null) as AtomicReference<XKeyDatabase?>).set(database)
    }

    @After
    fun tearDown() {
        RuntimeEnvironment.setFontScale(1.0f)
        XKeyDatabase.closeAndClear()
    }

    @Test
    fun `the OATH list window is secure`() {
        val activity = Robolectric.buildActivity(OathActivity::class.java).create().get()

        assertSecure(activity)
    }

    @Test
    fun `the OATH details window is secure`() {
        assertSecure(detailActivity())
    }

    @Test
    fun `a six digit code fits the details screen at font scale 2`() {
        assertCodeFits(code = "123456", fontScale = 2.0f)
    }

    @Test
    fun `an eight digit code fits the details screen at font scale 2`() {
        assertCodeFits(code = "12345678", fontScale = 2.0f)
    }

    private fun detailActivity(): OathCredentialDetailActivity {
        val intent = Intent(context, OathCredentialDetailActivity::class.java)
            .putExtra(OathCredentialDetailActivity.EXTRA_OATH_ID, "oath-1")
        return Robolectric.buildActivity(OathCredentialDetailActivity::class.java, intent).create().get()
    }

    private fun assertSecure(activity: Activity) {
        val flags = activity.window.attributes.flags
        assertTrue("FLAG_SECURE not set", flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
    }

    private fun assertCodeFits(code: String, fontScale: Float) {
        RuntimeEnvironment.setFontScale(fontScale)
        val activity = detailActivity()
        val codeView = activity.findViewById<View>(android.R.id.content).findViewWithTag<TextView>("code")
        codeView.text = OathAdapter.formatCode(code)

        val root = activity.findViewById<ViewGroup>(android.R.id.content)
        val metrics = activity.resources.displayMetrics
        assertEquals(320, activity.resources.configuration.screenWidthDp)
        root.measure(
            View.MeasureSpec.makeMeasureSpec(metrics.widthPixels, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(metrics.heightPixels, View.MeasureSpec.EXACTLY)
        )
        root.layout(0, 0, root.measuredWidth, root.measuredHeight)

        val text = codeView.text.toString()
        val layout = codeView.layout
        assertEquals("code wraps at font scale $fontScale", 1, layout.lineCount)
        assertEquals("code ellipsized at font scale $fontScale", 0, layout.getEllipsisCount(0))
        val textRoom = codeView.width - codeView.totalPaddingLeft - codeView.totalPaddingRight
        assertTrue(
            "code needs ${codeView.paint.measureText(text)}px, has $textRoom px at font scale $fontScale",
            codeView.paint.measureText(text) <= textRoom
        )
        assertTrue(
            "code line ${layout.getLineWidth(0)}px, has $textRoom px",
            layout.getLineWidth(0) <= textRoom
        )
        var left = 0
        var current: View = codeView
        while (current !== root) {
            left += current.left
            current = current.parent as View
        }
        assertTrue("code starts at $left", left >= 0)
        assertTrue("code ends at ${left + codeView.width}, screen is ${root.width}", left + codeView.width <= root.width)
    }
}
