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

import android.app.Activity
import android.app.Application
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Looper
import android.os.ParcelFileDescriptor
import com.automatethethings.xkey.media.CoSignResponse
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.OutputStream
import java.util.Collections

/**
 * The media a provider holds that cannot be replaced atomically: readable,
 * typed by its name, and any open for writing is recorded and refused.
 */
class ReadOnlyMediaProvider : ContentProvider() {
    companion object {
        const val AUTHORITY = "xkey.test.media"
        val files = mutableMapOf<String, File>()
        val writeOpens: MutableList<String> = Collections.synchronizedList(mutableListOf())
    }

    override fun onCreate() = true
    override fun getType(uri: Uri): String? = when (uri.lastPathSegment?.substringAfterLast('.')) {
        "png" -> "image/png"
        "mp4" -> "video/mp4"
        else -> null
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") {
            writeOpens.add("$uri $mode")
            throw FileNotFoundException("the original is never opened for writing")
        }
        val file = files[uri.lastPathSegment] ?: throw FileNotFoundException(uri.toString())
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun query(uri: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, s: String?, a: Array<String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, s: String?, a: Array<String>?) = 0
}

/**
 * Co-signing media its provider cannot replace atomically never writes the
 * original: the co-signed form goes to a copy the user creates, and when
 * that write fails the co-signed bytes stay on disk for recovery.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CoSignPublishTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private lateinit var originalBytes: ByteArray
    private val original = Uri.parse("content://${ReadOnlyMediaProvider.AUTHORITY}/clip.png")

    @Before
    fun setUp() {
        db = TestDatabase()
        val file = File(folder.root, "clip.png").apply { writeBytes(XmpFixtures.png()) }
        XmpMetadataHelper.writeSignature(file.path, ContentAuthenticityData.fromJsonString(XmpFixtures.json("e".repeat(64))))
        originalBytes = file.readBytes()
        ReadOnlyMediaProvider.files.clear()
        ReadOnlyMediaProvider.files["clip.png"] = file
        ReadOnlyMediaProvider.writeOpens.clear()
        Robolectric.setupContentProvider(ReadOnlyMediaProvider::class.java, ReadOnlyMediaProvider.AUTHORITY)
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun field(name: String) =
        CoSignActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
    }

    /** Writes the first bytes, then fails, as a full disk or a vanished provider does. */
    private class FailingOutput : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
        override fun write(b: ByteArray, off: Int, len: Int): Unit = throw IOException("storage full")
    }

    /** Co-signs [original] as a witness and answers the copy picker with [copy], which opens [output]. */
    private fun coSignInto(copy: Uri, output: OutputStream): CoSignActivity {
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        shadowOf(activity.contentResolver).registerOutputStream(copy, output)
        shadowOf(activity.applicationContext.contentResolver).registerOutputStream(copy, output)
        field("selectedUri").set(activity, original)

        val response = CoSignResponse("AAAA", "SHA256:witness", "Witness", "ES256").toJsonString()
        CoSignActivity::class.java.getDeclaredMethod("onResponseScanned", String::class.java)
            .apply { isAccessible = true }.invoke(activity, response)

        var picker: Intent? = null
        var requestCode = 0
        idleUntil {
            shadowOf(activity).nextStartedActivityForResult?.let { picker = it.intent; requestCode = it.requestCode }
            picker != null
        }
        assertEquals(Intent.ACTION_CREATE_DOCUMENT, picker!!.action)
        assertEquals("clip-cosigned.png", picker!!.getStringExtra(Intent.EXTRA_TITLE))

        activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_OK, Intent().setData(copy))
        return activity
    }

    private fun recoveryFiles(activity: CoSignActivity): List<File> =
        MediaPublisher.recoveryDirectory(activity).listFiles()!!.filter { it.name.startsWith("cosign-") }

    @Test
    fun `a co-signed copy whose write fails leaves the original whole and keeps the co-signed bytes`() {
        val activity = coSignInto(Uri.parse("content://xkey.test.copies/clip-cosigned.png"), FailingOutput())
        idleUntil { field("pendingCopy").get(activity) == null && recoveryFiles(activity).isNotEmpty() }
        // The failed write runs on IO; give it time to settle before checking what it kept.
        Thread.sleep(200)
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals("the original is never opened for writing", emptyList<String>(), ReadOnlyMediaProvider.writeOpens)
        assertArrayEquals("the original is whole", originalBytes, ReadOnlyMediaProvider.files["clip.png"]!!.readBytes())
        val kept = recoveryFiles(activity)
        assertEquals(1, kept.size)
        val signatures = XmpMetadataHelper.readSignature(kept.single().path)
        assertNotNull("the kept bytes are the co-signed media", signatures)
        assertEquals(listOf("SHA256:testfp", "SHA256:witness"), signatures!!.signatures.map { it.keyFingerprint })
    }

    @Test
    fun `a co-signed copy written in full becomes the selected media and leaves nothing behind`() {
        val copy = Uri.parse("content://xkey.test.copies/clip-cosigned.png")
        val written = ByteArrayOutputStream()
        val activity = coSignInto(copy, written)
        idleUntil { field("selectedUri").get(activity) == copy }

        assertEquals(emptyList<String>(), ReadOnlyMediaProvider.writeOpens)
        assertArrayEquals(originalBytes, ReadOnlyMediaProvider.files["clip.png"]!!.readBytes())
        assertEquals("the staged copy is gone once written", emptyList<File>(), recoveryFiles(activity))
        val out = File(folder.root, "out.png").apply { writeBytes(written.toByteArray()) }
        assertEquals(
            listOf("SHA256:testfp", "SHA256:witness"),
            XmpMetadataHelper.readSignature(out.path)!!.signatures.map { it.keyFingerprint }
        )
    }
}
