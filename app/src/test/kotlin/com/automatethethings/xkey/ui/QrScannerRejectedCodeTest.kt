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

import android.Manifest
import android.app.Activity
import android.app.Application
import android.content.Intent
import android.os.Looper
import com.automatethethings.xkey.qr.QrCodeScannerHelper
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * A rejected code (a web link where an otpauth URI is wanted) leaves the
 * scanner reading: the next frame with the right code is decoded and returned.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class QrScannerRejectedCodeTest {

    /** Stands in for the camera: delivers one frame per [show], decoded to the value given. */
    private class FakeFrames : QrCodeScannerHelper.FrameSource {
        private var analyzer: ((QrCodeScannerHelper.Frame) -> Unit)? = null

        override fun bind(analyzer: (QrCodeScannerHelper.Frame) -> Unit) {
            this.analyzer = analyzer
        }

        override fun unbind() {
            analyzer = null
        }

        fun show(value: String) {
            analyzer?.invoke(object : QrCodeScannerHelper.Frame {
                override fun decode(onBarcodes: (List<String?>) -> Unit, onFailure: () -> Unit) {
                    onBarcodes(listOf(value))
                }

                override fun close() = Unit
            })
        }
    }

    private val frames = FakeFrames()

    @Before
    fun setUp() {
        QrScannerActivity.frameSourceForTest = frames
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.CAMERA)
    }

    @After
    fun tearDown() {
        QrScannerActivity.frameSourceForTest = null
    }

    @Test
    fun `after a rejected code the scanner reads the next one`() {
        val app = RuntimeEnvironment.getApplication()
        val otpauth = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        val activity = Robolectric.buildActivity(
            QrScannerActivity::class.java,
            Intent(app, QrScannerActivity::class.java)
        ).setup().get()

        frames.show("https://example.com")
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse("a rejected code does not finish the scanner", activity.isFinishing)

        frames.show(otpauth)
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue("the second code finishes the scanner", activity.isFinishing)
        val shadow = shadowOf(activity)
        assertEquals(Activity.RESULT_OK, shadow.resultCode)
        assertEquals(otpauth, shadow.resultIntent.getStringExtra(QrScannerActivity.EXTRA_SCANNED_URI))
    }
}
