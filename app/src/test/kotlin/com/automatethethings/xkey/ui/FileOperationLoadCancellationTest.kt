/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.os.Looper
import com.automatethethings.xkey.media.AutoSignHash
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.google.android.material.button.MaterialButton
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.io.File

/**
 * Verifying a shared capture reads its original, an open the provider
 * serves from its own process. Leaving the share screen during that open
 * cancels it through the open's CancellationSignal: an interrupt of the
 * screen's worker alone never reaches another process.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class FileOperationLoadCancellationTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private lateinit var provider: FakeMediaProvider
    private var controller: ActivityController<FileOperationActivity>? = null
    private val capture = Uri.parse("content://media/external/images/media/7")
    private val originalHash: String = AutoSignHash.contentHash(XmpFixtures.png(), "image/png")

    @Before
    fun setUp() {
        db = TestDatabase()
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = File(folder.root, "capture.png").apply {
                writeBytes(XmpFixtures.png())
                XmpMetadataHelper.writeSignature(path, ContentAuthenticityData.fromJsonString(XmpFixtures.json(originalHash)))
            }
            mimeType = "image/png"
            stall = true
            stallAcrossProcess = true
        }
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        provider.release()
        runCatching { controller?.pause()?.stop()?.destroy() }
        db.close()
    }

    private fun field(name: String) =
        FileOperationActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    /** Waits up to 5 s for [condition], idling the main looper. */
    private fun within5s(message: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5_000
        while (!condition()) {
            assertTrue(message, System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
    }

    @Test
    fun `leaving the share screen cancels the open of the original being verified`() {
        val intent = Intent(Intent.ACTION_SEND).setType(provider.mimeType).putExtra(Intent.EXTRA_STREAM, capture)
        val built = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup()
        controller = built
        val activity = built.get()
        shadowOf(Looper.getMainLooper()).idle()
        field("selectedOperation").setInt(activity, 1) // OP_VERIFY
        (field("processButton").get(activity) as MaterialButton).performClick()
        shadowOf(Looper.getMainLooper()).idle()
        within5s("the verify reads the original") { provider.inStall.get() == 1 }

        built.pause().stop().destroy()
        controller = null

        within5s("the open of the original is cancelled when the screen goes, signals ${provider.readSignals}") {
            provider.stallCancelled.get() == 1
        }
        within5s("no read is left inside the provider") { provider.inStall.get() == 0 }
        assertTrue("every read open carries a cancel signal: ${provider.readSignals}", provider.readSignals.all { it })
    }
}
