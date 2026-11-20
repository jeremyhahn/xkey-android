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
import android.content.pm.PackageManager
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
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.google.android.material.button.MaterialButton
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
 * Every interactive entry point that reads a MediaStore capture's original
 * asks for ACCESS_MEDIA_LOCATION first on a fresh install, and its action
 * then completes over the original bytes: verifying a shared file,
 * the verified-media viewer and co-signing.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class MediaLocationAccessEntryPointTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private lateinit var provider: FakeMediaProvider
    private val capture = Uri.parse("content://media/external/images/media/7")

    private val originalHash: String = AutoSignHash.contentHash(XmpFixtures.png(), "image/png")
    private val redactedPixels = XmpFixtures.bytes(0x78, 0x9C, 0x00, 0x00, 0x00)

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

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
    }

    private fun texts(view: View): List<String> = when (view) {
        is TextView -> listOf(view.text.toString())
        is ViewGroup -> (0 until view.childCount).flatMap { texts(view.getChildAt(it)) }
        else -> emptyList()
    }

    private fun originalRead() = provider.openUris.any { it.getQueryParameter("requireOriginal") == "1" }

    /** The user answers the location-access request [activity] made: granted. */
    private fun grant(activity: Activity) {
        shadowOf(Looper.getMainLooper()).idle()
        val request = shadowOf(activity).lastRequestedPermission
        assertNotNull("a fresh install is asked for location access", request)
        assertEquals(listOf(Manifest.permission.ACCESS_MEDIA_LOCATION), request.requestedPermissions.toList())
        assertFalse("nothing reads the original before the answer", originalRead())
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        activity.onRequestPermissionsResult(
            request.requestCode, request.requestedPermissions, intArrayOf(PackageManager.PERMISSION_GRANTED)
        )
    }

    @Test
    fun `verifying a shared capture asks for location access and verifies the original once granted`() {
        val intent = Intent(Intent.ACTION_SEND).setType("image/png").putExtra(Intent.EXTRA_STREAM, capture)
        val activity = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        fun field(name: String) = FileOperationActivity::class.java.getDeclaredField(name).apply { isAccessible = true }
        field("selectedOperation").setInt(activity, 1) // OP_VERIFY
        (field("processButton").get(activity) as MaterialButton).performClick()

        grant(activity)

        val resultCard = field("resultCard").get(activity) as View
        idleUntil { resultCard.visibility == View.VISIBLE }
        val shown = (field("resultText").get(activity) as TextView).text.toString()
        assertFalse("verified, not access unavailable: $shown", shown.contains(MediaHasher.ACCESS_UNAVAILABLE_MESSAGE))
        assertTrue("the original was read", originalRead())
    }

    @Test
    fun `the verified-media viewer asks for location access and verifies the original once granted`() {
        val intent = Intent(Intent.ACTION_VIEW).setDataAndType(capture, "image/png")
        val activity = Robolectric.buildActivity(VerifiedMediaViewerActivity::class.java, intent).setup().get()

        grant(activity)

        val signers = activity.findViewById<View>(R.id.signerListContainer)
        val none = activity.findViewById<TextView>(R.id.textNoSignatures)
        idleUntil { signers.visibility == View.VISIBLE || none.text.toString() == MediaHasher.ACCESS_UNAVAILABLE_MESSAGE }
        assertEquals("the signers are shown, not access unavailable", View.VISIBLE, signers.visibility)
        assertTrue("the original was read", originalRead())
    }

    @Test
    fun `co-signing a capture asks for location access and appends over the original once granted`() {
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        fun field(name: String) = CoSignActivity::class.java.getDeclaredField(name).apply { isAccessible = true }
        fun exchange() = field("exchange").get(activity) as CoSignExchange
        field("exchange").set(activity, exchange().copy(media = capture))
        field("currentSignatureData").set(activity, ContentAuthenticityData.fromJsonString(XmpFixtures.json(originalHash)))

        fun findButton(view: View, text: String): Button? = when (view) {
            is Button -> view.takeIf { it.text == text }
            is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { findButton(view.getChildAt(it), text) }
            else -> null
        }
        findButton(activity.window.decorView, activity.getString(R.string.cosign_scan_response))!!.performClick()
        val scanner = shadowOf(activity).nextStartedActivityForResult
        val response = CoSignResponse("AAAA", "SHA256:witness", "Witness", "ES256").toJsonString()
        activity.activityResultRegistry.dispatchResult(
            scanner.requestCode,
            Activity.RESULT_OK,
            Intent().putExtra(QrScannerActivity.EXTRA_SCANNED_URI, response)
        )

        grant(activity)

        idleUntil { exchange().runningAppend == null && originalRead() }
        val unavailable = activity.getString(
            R.string.cosign_append_failed,
            MediaPublisher.OriginalUnavailableException(capture).message
        )
        val shown = texts(activity.window.decorView)
        assertFalse("not access unavailable: $shown", unavailable in shown)
    }
}
