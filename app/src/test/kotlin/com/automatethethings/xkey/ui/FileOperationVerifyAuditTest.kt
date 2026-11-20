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
import android.widget.TextView
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.media.AutoSignHash
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.google.android.material.button.MaterialButton
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import kotlinx.coroutines.Dispatchers
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
import org.robolectric.shadows.ShadowActivity
import java.io.File
import java.util.Collections

/**
 * Verifying a MediaStore capture whose location access the user declined
 * checks nothing: only the redacted view is readable. The audit log then
 * records the verification as not verified, never as a success: the one
 * audit predicate both branches (embedded signature and sidecar) use
 * counts only a positive result, and a declined sidecar verify goes
 * through it end to end.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class FileOperationVerifyAuditTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private lateinit var provider: FakeMediaProvider
    private val capture = Uri.parse("content://media/external/images/media/7")
    private val originalHash: String = AutoSignHash.contentHash(XmpFixtures.png(), "image/png")

    /** The `verified` flag of every FILE_VERIFIED audit entry, in call order. */
    private val audited: MutableList<Boolean> = Collections.synchronizedList(mutableListOf())

    @Before
    fun setUp() {
        db = TestDatabase()
        mockkObject(AuditLogger)
        every { AuditLogger.logFileVerified(any(), any(), any()) } answers { audited += thirdArg<Boolean>() }
        shadowOf(RuntimeEnvironment.getApplication()).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        FileOperationActivity.verifyDispatcher = Dispatchers.Main
    }

    @After
    fun tearDown() {
        FileOperationActivity.verifyDispatcher = Dispatchers.IO
        unmockkObject(AuditLogger)
        db.close()
    }

    /**
     * Runs all the screen has queued, then expects [condition]. The verify
     * work is run by the main looper, so nothing is waited for in real time.
     */
    private fun settled(what: String, condition: () -> Boolean) {
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("$what once the main looper is idle", condition())
    }

    private fun field(name: String) =
        FileOperationActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    /** Opens the share screen on the capture, presses Verify and declines location access. */
    private fun verifyDeclined(): FileOperationActivity {
        val intent = Intent(Intent.ACTION_SEND).setType(provider.mimeType).putExtra(Intent.EXTRA_STREAM, capture)
        val activity = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        field("selectedOperation").setInt(activity, 1) // OP_VERIFY
        (field("processButton").get(activity) as MaterialButton).performClick()
        shadowOf(Looper.getMainLooper()).idle()
        val request = shadowOf(activity).lastRequestedPermission
        assertNotNull("a fresh install is asked for location access", request)
        activity.onRequestPermissionsResult(
            request.requestCode, request.requestedPermissions, intArrayOf(PackageManager.PERMISSION_DENIED)
        )
        return activity
    }

    private fun fileVerified(): List<Boolean> = synchronized(audited) { audited.toList() }

    /** The share screen on the capture, with location access granted, after Verify is pressed. */
    private fun verifyGranted(): FileOperationActivity {
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        val intent = Intent(Intent.ACTION_SEND).setType(provider.mimeType).putExtra(Intent.EXTRA_STREAM, capture)
        val activity = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        field("selectedOperation").setInt(activity, 1) // OP_VERIFY
        (field("processButton").get(activity) as MaterialButton).performClick()
        shadowOf(Looper.getMainLooper()).idle()
        return activity
    }

    /** Waits for the error result, then expects exactly one not-verified audit record. */
    private fun assertErrorAuditedOnce(activity: FileOperationActivity) {
        val resultCard = field("resultCard").get(activity) as View
        settled("the error is shown") { resultCard.visibility == View.VISIBLE }
        assertEquals("one verification is audited", 1, fileVerified().size)
        assertFalse("a verify that failed with an error verified nothing", fileVerified().single())
    }

    private fun assertShownUnavailable(activity: FileOperationActivity) {
        val resultCard = field("resultCard").get(activity) as View
        settled("the result is shown") { resultCard.visibility == View.VISIBLE }
        val shown = (field("resultText").get(activity) as TextView).text.toString()
        assertTrue("access unavailable is shown: $shown", shown.contains(MediaHasher.ACCESS_UNAVAILABLE_MESSAGE))
    }

    @Test
    fun `a verification reading only the redacted view is audited as not verified`() {
        // What both verify branches (embedded and sidecar) produce when the original is unreadable.
        val unavailable = listOf(MediaHasher.ACCESS_UNAVAILABLE_MESSAGE to "unavailable")
        assertFalse(FileOperationActivity.verificationSucceeded(unavailable))
        assertFalse("nothing checked is nothing verified", FileOperationActivity.verificationSucceeded(emptyList()))
        assertFalse(FileOperationActivity.verificationSucceeded(listOf("Signer" to "verified", "Other" to "failed")))
        assertFalse(FileOperationActivity.verificationSucceeded(listOf("Signer" to "unknown")))
        assertTrue(FileOperationActivity.verificationSucceeded(listOf("Signer" to "verified")))
    }

    @Test
    fun `a declined verify of an embedded capture is audited as not verified`() {
        // A PNG carries its signature in-band: reading it needs the original.
        val signed = File(folder.root, "capture.png").apply {
            writeBytes(XmpFixtures.png())
            XmpMetadataHelper.writeSignature(path, ContentAuthenticityData.fromJsonString(XmpFixtures.json(originalHash)))
        }
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = signed
            mimeType = "image/png"
            redact = { signed.readBytes() }
        }

        val activity = verifyDeclined()

        assertShownUnavailable(activity)
        settled("the verification is audited") { fileVerified().isNotEmpty() }
        assertEquals("one verification is audited", 1, fileVerified().size)
        assertFalse("the signature was never read, so nothing is verified", fileVerified().single())
    }

    @Test
    fun `a declined sidecar verify is audited as not verified`() {
        // A type with no in-band signature: its signature is a sidecar.
        val unsigned = File(folder.root, "capture.gif").apply { writeBytes(XmpFixtures.png()) }
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = unsigned
            mimeType = "image/gif"
            redact = { unsigned.readBytes() }
        }
        val sidecar = File(folder.root, "capture.gif.xkeysig").apply { writeText(XmpFixtures.json(originalHash)) }

        val activity = verifyDeclined()

        // No embedded signature: the screen asks for a sidecar, and the user picks one.
        var picker: ShadowActivity.IntentForResult? = null
        settled("the sidecar picker is open") {
            picker = generateSequence { shadowOf(activity).nextStartedActivityForResult }
                .firstOrNull { it.intent.action == Intent.ACTION_OPEN_DOCUMENT }
            picker != null
        }
        activity.activityResultRegistry.dispatchResult(
            picker!!.requestCode, Activity.RESULT_OK, Intent().setData(Uri.fromFile(sidecar))
        )

        assertShownUnavailable(activity)
        settled("the verification is audited") { fileVerified().isNotEmpty() }
        assertEquals("one verification is audited", 1, fileVerified().size)
        assertFalse("nothing was hashed or checked, so nothing is verified", fileVerified().single())
    }

    @Test
    fun `an embedded verify that fails with an error is audited as not verified`() {
        // A PNG whose bytes cannot be opened: reading its in-band signature throws.
        val missing = File(folder.root, "gone.png")
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = missing
            mimeType = "image/png"
        }

        assertErrorAuditedOnce(verifyGranted())
    }

    @Test
    fun `a sidecar that cannot be read is audited as not verified`() {
        val unsigned = File(folder.root, "capture.gif").apply { writeBytes(XmpFixtures.png()) }
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = unsigned
            mimeType = "image/gif"
        }

        val activity = verifyGranted()

        var picker: ShadowActivity.IntentForResult? = null
        settled("the sidecar picker is open") {
            picker = generateSequence { shadowOf(activity).nextStartedActivityForResult }
                .firstOrNull { it.intent.action == Intent.ACTION_OPEN_DOCUMENT }
            picker != null
        }
        // The picked sidecar is gone by the time it is read.
        val sidecar = File(folder.root, "missing.xkeysig")
        activity.activityResultRegistry.dispatchResult(
            picker!!.requestCode, Activity.RESULT_OK, Intent().setData(Uri.fromFile(sidecar))
        )

        assertErrorAuditedOnce(activity)
    }
}
