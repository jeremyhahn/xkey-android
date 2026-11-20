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
import android.app.Activity
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.media.AutoSignHash
import com.automatethethings.xkey.media.CoSignResponse
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
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
import org.robolectric.annotation.Config
import java.io.File

/**
 * Co-signing a MediaStore capture reads the original bytes the signer
 * hashed. Without ACCESS_MEDIA_LOCATION only MediaStore's redacted view is
 * readable, and it hashes as other media: the append is refused as access
 * unavailable, never as changed media, and the redacted view is never read.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CoSignLocationAccessTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private lateinit var provider: FakeMediaProvider
    private val capture = Uri.parse("content://media/external/images/media/7")

    private val originalHash: String = AutoSignHash.contentHash(XmpFixtures.png(), "image/png")
    private val redactedPixels = XmpFixtures.bytes(0x78, 0x9C, 0x00, 0x00, 0x00)

    /** A PNG over [pixels] carrying signature data that names [originalHash]. */
    private fun signedPng(name: String, pixels: ByteArray? = null): File =
        File(folder.root, name).apply {
            writeBytes(if (pixels == null) XmpFixtures.png() else XmpFixtures.png(pixels))
            XmpMetadataHelper.writeSignature(path, ContentAuthenticityData.fromJsonString(XmpFixtures.json(originalHash)))
        }

    @Before
    fun setUp() {
        db = TestDatabase()
        val redacted = signedPng("redacted.png", redactedPixels).readBytes()
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = signedPng("capture.png")
            mimeType = "image/png"
            redact = { redacted }
        }
        shadowOf(RuntimeEnvironment.getApplication()).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun field(name: String) =
        CoSignActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    private fun exchange(activity: CoSignActivity) = field("exchange").get(activity) as CoSignExchange

    private fun findButton(view: View, text: String): Button? = when (view) {
        is Button -> view.takeIf { it.text == text }
        is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { findButton(view.getChildAt(it), text) }
        else -> null
    }

    private fun texts(view: View): List<String> = when (view) {
        is TextView -> listOf(view.text.toString())
        is ViewGroup -> (0 until view.childCount).flatMap { texts(view.getChildAt(it)) }
        else -> emptyList()
    }

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
    }

    @Test
    fun `co-signing a geotagged capture without location access reports access unavailable and never reads the redacted view`() {
        assertNotEquals(
            "the fixture's redacted view must hash as other media",
            originalHash,
            AutoSignHash.contentHash(XmpFixtures.png(redactedPixels), "image/png")
        )
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        field("exchange").set(activity, exchange(activity).copy(media = capture))
        field("currentSignatureData").set(activity, ContentAuthenticityData.fromJsonString(XmpFixtures.json(originalHash)))

        val scan = findButton(activity.window.decorView, activity.getString(R.string.cosign_scan_response))
        assertNotNull("the scan button", scan)
        scan!!.performClick()
        val scanner = shadowOf(activity).nextStartedActivityForResult
        val response = CoSignResponse("AAAA", "SHA256:witness", "Witness", "ES256").toJsonString()
        activity.activityResultRegistry.dispatchResult(
            scanner.requestCode,
            Activity.RESULT_OK,
            Intent().putExtra(QrScannerActivity.EXTRA_SCANNED_URI, response)
        )

        val unavailable = activity.getString(
            R.string.cosign_append_failed,
            MediaPublisher.OriginalUnavailableException(capture).message
        )
        val changed = activity.getString(R.string.cosign_error_media_changed)
        idleUntil {
            exchange(activity).runningAppend == null &&
                texts(activity.window.decorView).any { it == unavailable || changed in it }
        }

        val shown = texts(activity.window.decorView)
        assertTrue("the append reports access unavailable: $shown", unavailable in shown)
        assertFalse("never a content change: $shown", shown.any { changed in it })
        assertEquals("the redacted view is never read or hashed", emptyList<String>(), provider.openModes)
        assertEquals("nothing is co-signed", 0, exchange(activity).queued.size)
        assertEquals(
            "the staged copy is gone",
            emptyList<File>(),
            MediaPublisher.recoveryDirectory(activity).listFiles()!!.filter { it.name.startsWith("cosign-") }
        )
    }
}
