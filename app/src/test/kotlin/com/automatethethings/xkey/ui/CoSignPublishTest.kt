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
import android.database.MatrixCursor
import android.net.Uri
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import com.automatethethings.xkey.media.CoSignResponse
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.OutputStream
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The media a provider holds that cannot be replaced atomically: readable,
 * typed by its name, and any open for writing is recorded and refused.
 */
class ReadOnlyMediaProvider : ContentProvider() {
    companion object {
        const val AUTHORITY = "xkey.test.media"
        val files = mutableMapOf<String, File>()
        /** Display names and types by last path segment, for opaque document ids. */
        val names = mutableMapOf<String, String>()
        val types = mutableMapOf<String, String>()
        val writeOpens: MutableList<String> = Collections.synchronizedList(mutableListOf())
        /** While set, every read waits for it, as a slow provider's does. */
        @Volatile var readGate: CountDownLatch? = null
    }

    override fun onCreate() = true
    override fun getType(uri: Uri): String? = types[uri.lastPathSegment] ?: when (uri.lastPathSegment?.substringAfterLast('.')) {
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
        readGate?.let { check(it.await(10, TimeUnit.SECONDS)) { "read never released" } }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun query(uri: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? {
        val name = names[uri.lastPathSegment] ?: return null
        return MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME)).apply { addRow(arrayOf(name)) }
    }
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
    private var original = Uri.parse("content://${ReadOnlyMediaProvider.AUTHORITY}/clip.png")

    private companion object {
        const val COPIES = "xkey.test.copies"
    }

    @Before
    fun setUp() {
        db = TestDatabase()
        val file = File(folder.root, "clip.png").apply { writeBytes(XmpFixtures.png()) }
        XmpMetadataHelper.writeSignature(file.path, ContentAuthenticityData.fromJsonString(XmpFixtures.json("e".repeat(64))))
        originalBytes = file.readBytes()
        ReadOnlyMediaProvider.files.clear()
        ReadOnlyMediaProvider.names.clear()
        ReadOnlyMediaProvider.types.clear()
        ReadOnlyMediaProvider.files["clip.png"] = file
        ReadOnlyMediaProvider.writeOpens.clear()
        ReadOnlyMediaProvider.readGate = null
        Robolectric.setupContentProvider(ReadOnlyMediaProvider::class.java, ReadOnlyMediaProvider.AUTHORITY)
        // Where the copies go: typed by name too, so a copy can be co-signed again.
        Robolectric.setupContentProvider(ReadOnlyMediaProvider::class.java, COPIES)
    }

    @After
    fun tearDown() {
        ReadOnlyMediaProvider.readGate?.countDown()
        ReadOnlyMediaProvider.readGate = null
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

    private fun register(activity: Activity, copy: Uri, output: OutputStream) {
        shadowOf(activity.contentResolver).registerOutputStream(copy, output)
        shadowOf(activity.applicationContext.contentResolver).registerOutputStream(copy, output)
    }

    private fun scanWitness(activity: CoSignActivity, fingerprint: String = "SHA256:witness") {
        val response = CoSignResponse("AAAA", fingerprint, "Witness", "ES256").toJsonString()
        CoSignActivity::class.java.getDeclaredMethod("onResponseScanned", String::class.java)
            .apply { isAccessible = true }.invoke(activity, response)
    }

    /** The save picker [activity] opens next, once it opens one: its intent and request code. */
    private fun awaitPicker(activity: CoSignActivity): Pair<Intent, Int> {
        var started: Pair<Intent, Int>? = null
        idleUntil {
            shadowOf(activity).nextStartedActivityForResult?.let { started = it.intent to it.requestCode }
            started != null
        }
        assertEquals(Intent.ACTION_CREATE_DOCUMENT, started!!.first.action)
        return started!!
    }

    /** Co-signs [original] as a witness and answers the copy picker with [copy], which opens [output]. */
    private fun coSignInto(
        copy: Uri,
        output: OutputStream,
        controller: ActivityController<CoSignActivity> = Robolectric.buildActivity(CoSignActivity::class.java).setup()
    ): CoSignActivity {
        val activity = controller.get()
        shadowOf(Looper.getMainLooper()).idle()
        register(activity, copy, output)
        field("selectedUri").set(activity, original)
        scanWitness(activity)

        val (picker, requestCode) = awaitPicker(activity)
        assertEquals("clip-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))
        assertEquals("the copy is created as the media's own type", "image/png", picker.type)

        activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_OK, Intent().setData(copy))
        return activity
    }

    private fun recoveryFiles(activity: CoSignActivity): List<File> =
        MediaPublisher.recoveryDirectory(activity).listFiles()!!.filter { it.name.startsWith("cosign-") }

    @Test
    fun `a co-signed copy whose write fails leaves the original whole and keeps the co-signed bytes`() {
        val activity = coSignInto(Uri.parse("content://$COPIES/clip-cosigned.png"), FailingOutput())
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
        val copy = Uri.parse("content://$COPIES/clip-cosigned.png")
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

    /** Holds its first write until [release], so a test can recreate the screen mid-write. */
    private class HeldOutput : OutputStream() {
        val writing = CountDownLatch(1)
        private val released = CountDownLatch(1)
        val bytes = ByteArrayOutputStream()

        fun release() = released.countDown()
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
        override fun write(b: ByteArray, off: Int, len: Int) {
            writing.countDown()
            check(released.await(10, TimeUnit.SECONDS)) { "never released" }
            synchronized(bytes) { bytes.write(b, off, len) }
        }
    }

    @Test
    fun `a rotation while the co-signed copy writes keeps its co-signature for the next witness`() {
        val copy = Uri.parse("content://$COPIES/clip-cosigned.png")
        val held = HeldOutput()
        val controller = Robolectric.buildActivity(CoSignActivity::class.java).setup()
        coSignInto(copy, held, controller)
        assertTrue("the copy's write started", held.writing.await(10, TimeUnit.SECONDS))

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()
        assertNotNull("the write is restored as running", field("runningCopy").get(activity))
        // The copy reads back as what was written to it.
        val readBack = { ByteArrayInputStream(synchronized(held.bytes) { held.bytes.toByteArray() }) }

        // A second witness scanned during the write waits for it, then co-signs
        // the copy, even across another rotation before the write ends.
        scanWitness(activity, "SHA256:second")
        shadowOf(Looper.getMainLooper()).idle()
        assertNull("nothing is staged from the original meanwhile", shadowOf(activity).nextStartedActivityForResult)

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val rotated = controller.get()
        assertEquals("the queued response is restored", 1, (field("queuedResponses").get(rotated) as List<*>).size)
        verifyCopiedAfterRelease(rotated, copy, held, readBack)
    }

    /** The copy's read-back for [activity], then the release, then the second witness's picker over the copy. */
    private fun verifyCopiedAfterRelease(
        activity: CoSignActivity,
        copy: Uri,
        held: HeldOutput,
        readBack: () -> ByteArrayInputStream
    ) {
        shadowOf(activity.contentResolver).registerInputStreamSupplier(copy, readBack)
        shadowOf(activity.applicationContext.contentResolver).registerInputStreamSupplier(copy, readBack)
        held.release()
        val (picker, _) = awaitPicker(activity)
        assertEquals("the copy is selected once written", copy, field("selectedUri").get(activity))
        assertEquals("clip-cosigned-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))

        val staged = field("pendingCopy").get(activity)!!.let { pending ->
            pending.javaClass.getDeclaredField("staged").apply { isAccessible = true }.get(pending) as File
        }
        assertEquals(
            "the second co-signature is added to the first",
            listOf("SHA256:testfp", "SHA256:witness", "SHA256:second"),
            XmpMetadataHelper.readSignature(staged.path)!!.signatures.map { it.keyFingerprint }
        )
        assertEquals(emptyList<String>(), ReadOnlyMediaProvider.writeOpens)
        assertArrayEquals(originalBytes, ReadOnlyMediaProvider.files["clip.png"]!!.readBytes())
    }

    @Test
    fun `a recreation after the copy is written but before the original reloads keeps the copy selected`() {
        val copy = Uri.parse("content://$COPIES/clip-cosigned.png")
        val held = HeldOutput()
        val controller = Robolectric.buildActivity(CoSignActivity::class.java).setup()
        coSignInto(copy, held, controller)
        assertTrue("the copy's write started", held.writing.await(10, TimeUnit.SECONDS))

        // The recreated instance reloads the original, slowly.
        val gate = CountDownLatch(1)
        ReadOnlyMediaProvider.readGate = gate
        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        held.release()
        // The write ends; the screen still waits on the original's reload.
        idleUntil { synchronized(held.bytes) { held.bytes.size() } > 0 }
        Thread.sleep(200)
        shadowOf(Looper.getMainLooper()).idle()
        assertNotNull("the copy runs until it is installed", field("runningCopy").get(controller.get()))

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()
        assertNotNull("the recreation keeps the copy to install", field("runningCopy").get(activity))
        ReadOnlyMediaProvider.readGate = null
        gate.countDown()
        idleUntil { field("selectedUri").get(activity) == copy }

        val readBack = { ByteArrayInputStream(synchronized(held.bytes) { held.bytes.toByteArray() }) }
        shadowOf(activity.contentResolver).registerInputStreamSupplier(copy, readBack)
        shadowOf(activity.applicationContext.contentResolver).registerInputStreamSupplier(copy, readBack)
        scanWitness(activity, "SHA256:second")
        val (picker, _) = awaitPicker(activity)
        assertEquals("clip-cosigned-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))
        val staged = field("pendingCopy").get(activity)!!.let { pending ->
            pending.javaClass.getDeclaredField("staged").apply { isAccessible = true }.get(pending) as File
        }
        assertEquals(
            "the next co-signature is added to the copy's",
            listOf("SHA256:testfp", "SHA256:witness", "SHA256:second"),
            XmpMetadataHelper.readSignature(staged.path)!!.signatures.map { it.keyFingerprint }
        )
    }

    @Test
    fun `an opaque document id names the copy after its display name and types it as the media`() {
        val file = ReadOnlyMediaProvider.files.remove("clip.png")!!
        ReadOnlyMediaProvider.files["image:123"] = file
        ReadOnlyMediaProvider.types["image:123"] = "image/png"
        ReadOnlyMediaProvider.names["image:123"] = "IMG_0042.png"
        original = Uri.parse("content://${ReadOnlyMediaProvider.AUTHORITY}/document/image%3A123")

        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        field("selectedUri").set(activity, original)
        scanWitness(activity)

        val (picker, _) = awaitPicker(activity)
        assertEquals("IMG_0042-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))
        assertEquals("image/png", picker.type)
    }

    @Test
    fun `an opaque document id with no display name still gets the media suffix`() {
        val file = ReadOnlyMediaProvider.files.remove("clip.png")!!
        ReadOnlyMediaProvider.files["image:123"] = file
        ReadOnlyMediaProvider.types["image:123"] = "image/png"
        original = Uri.parse("content://${ReadOnlyMediaProvider.AUTHORITY}/document/image%3A123")

        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        field("selectedUri").set(activity, original)
        scanWitness(activity)

        val (picker, _) = awaitPicker(activity)
        assertEquals("123-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))
        assertEquals("image/png", picker.type)
    }
}
