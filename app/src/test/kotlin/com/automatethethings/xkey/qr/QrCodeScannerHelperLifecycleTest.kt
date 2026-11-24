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

package com.automatethethings.xkey.qr

import android.app.Application
import androidx.camera.view.PreviewView
import androidx.lifecycle.LifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanner
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * The helper holds one ML Kit client for its lifetime: restarts after a
 * rejected code reuse it, and stop() closes it once, after any decode in
 * flight has called back.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class QrCodeScannerHelperLifecycleTest {

    /** Stands in for the camera: [show] decodes at once, [showPending] when [finishPending] runs. */
    private class FakeFrames : QrCodeScannerHelper.FrameSource {
        private var analyzer: ((QrCodeScannerHelper.Frame) -> Unit)? = null
        private var pending: (() -> Unit)? = null

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

        fun showPending(value: String) {
            analyzer?.invoke(object : QrCodeScannerHelper.Frame {
                override fun decode(onBarcodes: (List<String?>) -> Unit, onFailure: () -> Unit) {
                    pending = { onBarcodes(listOf(value)) }
                }

                override fun close() = Unit
            })
        }

        fun finishPending() {
            val callback = pending
            pending = null
            callback?.invoke()
        }
    }

    private val frames = FakeFrames()
    private val scanner = mockk<BarcodeScanner>(relaxed = true)
    private var created = 0
    private val results = mutableListOf<String>()

    private fun helper() = QrCodeScannerHelper(
        context = RuntimeEnvironment.getApplication(),
        lifecycleOwner = mockk<LifecycleOwner>(relaxed = true),
        previewView = mockk<PreviewView>(relaxed = true),
        onResult = { results += it },
        frameSource = frames,
        scannerFactory = {
            created++
            scanner
        }
    )

    @Test
    fun `restarts after rejected codes reuse one client and stop closes it once`() {
        val helper = helper()

        helper.start()
        frames.show("https://example.com/1")
        helper.start()
        frames.show("https://example.com/2")
        helper.start()
        helper.stop()
        helper.stop()

        assertEquals(listOf("https://example.com/1", "https://example.com/2"), results)
        assertTrue("the factory ran $created times", created <= 1)
        verify(exactly = 1) { scanner.close() }
    }

    @Test
    fun `a stop during a pending decode closes the client only after that decode calls back`() {
        val helper = helper()

        helper.start()
        frames.showPending("https://example.com")
        helper.stop()
        verify(exactly = 0) { scanner.close() }

        frames.finishPending()

        verify(exactly = 1) { scanner.close() }
        assertTrue("a decode that ends after stop delivers nothing", results.isEmpty())
    }
}
