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
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import androidx.lifecycle.lifecycleScope
import com.automatethethings.xkey.R
import com.automatethethings.xkey.media.AutoSignHash
import com.automatethethings.xkey.media.CoSignResponse
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.MediaSaveRuns
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
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.cancel

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
        /** Reads opened so far, counted before [readGate] holds them. */
        val readsStarted = AtomicInteger()
        /** While set, the type queries it still allows; past them, a query is refused. */
        @Volatile var typeQueriesLeft: AtomicInteger? = null
    }

    override fun onCreate() = true
    override fun getType(uri: Uri): String? {
        typeQueriesLeft?.let { if (it.decrementAndGet() < 0) throw SecurityException("type refused") }
        return typeOf(uri)
    }

    private fun typeOf(uri: Uri): String? = types[uri.lastPathSegment] ?: when (uri.lastPathSegment?.substringAfterLast('.')) {
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
        readsStarted.incrementAndGet()
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
        /**
         * The content hash the original's signature data carries: its payload's
         * own, as the signer hashes it, so the append's payload check passes.
         */
        val ORIGINAL_HASH: String = AutoSignHash.contentHash(XmpFixtures.png(), "image/png")
    }

    /** The original's signature data, kept on [pixels] as the payload. */
    private fun signedPng(name: String, pixels: ByteArray? = null, hash: String = ORIGINAL_HASH): File =
        File(folder.root, name).apply {
            writeBytes(if (pixels == null) XmpFixtures.png() else XmpFixtures.png(pixels))
            XmpMetadataHelper.writeSignature(path, ContentAuthenticityData.fromJsonString(XmpFixtures.json(hash)))
        }

    @Before
    fun setUp() {
        db = TestDatabase()
        val file = signedPng("clip.png")
        originalBytes = file.readBytes()
        ReadOnlyMediaProvider.files.clear()
        ReadOnlyMediaProvider.names.clear()
        ReadOnlyMediaProvider.types.clear()
        ReadOnlyMediaProvider.files["clip.png"] = file
        ReadOnlyMediaProvider.writeOpens.clear()
        ReadOnlyMediaProvider.readGate = null
        ReadOnlyMediaProvider.readsStarted.set(0)
        ReadOnlyMediaProvider.typeQueriesLeft = null
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

    // The exchange state the screen keeps, read and set only here.
    private fun exchange(activity: CoSignActivity) = field("exchange").get(activity) as CoSignExchange
    private fun selected(activity: CoSignActivity): Any? = exchange(activity).media
    private fun select(activity: CoSignActivity, uri: Uri) = field("exchange").set(activity, exchange(activity).copy(media = uri))
    private fun pending(activity: CoSignActivity): Any? = exchange(activity).pendingCopy
    private fun running(activity: CoSignActivity): Any? = exchange(activity).runningCopy
    private fun runningAppend(activity: CoSignActivity): Any? = exchange(activity).runningAppend
    private fun queued(activity: CoSignActivity) = exchange(activity).queued

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
        answerScanner(activity, openResponseScanner(activity), fingerprint)
    }

    private fun findButton(view: View, text: String): Button? = when (view) {
        is Button -> view.takeIf { it.text == text }
        is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { findButton(view.getChildAt(it), text) }
        else -> null
    }

    /**
     * Taps "scan the witness's response" for the selected media, as shown
     * (its signatures read, with the original's hash unless a test set
     * others), and returns the request code of the scanner it opened.
     */
    private fun openResponseScanner(activity: CoSignActivity): Int {
        if (field("currentSignatureData").get(activity) == null) {
            field("currentSignatureData").set(activity, ContentAuthenticityData.fromJsonString(XmpFixtures.json(ORIGINAL_HASH)))
        }
        val button = findButton(activity.window.decorView, activity.getString(R.string.cosign_scan_response))
        assertNotNull("the scan button", button)
        button!!.performClick()
        val started = shadowOf(activity).nextStartedActivityForResult
        assertEquals(QrScannerActivity::class.java.name, started.intent.component?.className)
        return started.requestCode
    }

    /** The scanner opened with [requestCode] returns the witness's response. */
    private fun answerScanner(activity: CoSignActivity, requestCode: Int, fingerprint: String = "SHA256:witness") {
        val response = CoSignResponse("AAAA", fingerprint, "Witness", "ES256").toJsonString()
        activity.activityResultRegistry.dispatchResult(
            requestCode,
            Activity.RESULT_OK,
            Intent().putExtra(QrScannerActivity.EXTRA_SCANNED_URI, response)
        )
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
        select(activity, original)
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
        idleUntil { pending(activity) == null && recoveryFiles(activity).isNotEmpty() }
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
        idleUntil { selected(activity) == copy }

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
        assertNotNull("the write is restored as running", running(activity))
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
        assertEquals("the queued response is restored", 1, queued(rotated).size)
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
        assertEquals("the copy is selected once written", copy, selected(activity))
        assertEquals("clip-cosigned-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))

        val staged = pending(activity)!!.let { pending ->
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
        assertNotNull("the copy runs until it is installed", running(controller.get()))

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()
        assertNotNull("the recreation keeps the copy to install", running(activity))
        ReadOnlyMediaProvider.readGate = null
        gate.countDown()
        idleUntil { selected(activity) == copy }

        val readBack = { ByteArrayInputStream(synchronized(held.bytes) { held.bytes.toByteArray() }) }
        shadowOf(activity.contentResolver).registerInputStreamSupplier(copy, readBack)
        shadowOf(activity.applicationContext.contentResolver).registerInputStreamSupplier(copy, readBack)
        scanWitness(activity, "SHA256:second")
        val (picker, _) = awaitPicker(activity)
        assertEquals("clip-cosigned-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))
        val staged = pending(activity)!!.let { pending ->
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
        select(activity, original)
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
        select(activity, original)
        scanWitness(activity)

        val (picker, _) = awaitPicker(activity)
        assertEquals("123-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))
        assertEquals("image/png", picker.type)
    }

    /** Lets the screen's IO work settle, then runs what it posted. */
    private fun settle() {
        repeat(5) {
            Thread.sleep(60)
            shadowOf(Looper.getMainLooper()).idle()
        }
    }

    @Test
    fun `a response scanned for one media is never appended to another`() {
        val other = File(folder.root, "other.png").apply { writeBytes(originalBytes) }
        ReadOnlyMediaProvider.files["other.png"] = other
        val otherUri = Uri.parse("content://${ReadOnlyMediaProvider.AUTHORITY}/other.png")
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        select(activity, original)
        scanWitness(activity)
        val (_, requestCode) = awaitPicker(activity)
        // Scanned for the original while its copy's picker is open: it waits.
        scanWitness(activity, "SHA256:second")
        settle()
        assertEquals(1, queued(activity).size)

        // The selection changes without going through the media picker, and
        // the waiting response reaches the head of the queue.
        select(activity, otherUri)
        activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_CANCELED, null)
        settle()

        assertNull("nothing is co-signed for the other media", shadowOf(activity).nextStartedActivityForResult)
        assertEquals("the response is refused, not kept", 0, queued(activity).size)
        assertEquals(emptyList<File>(), recoveryFiles(activity))
    }

    @Test
    fun `a response is refused when the media no longer has the content it was scanned for`() {
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        select(activity, original)
        // The media showed another content hash when the witness signed it.
        field("currentSignatureData").set(activity, ContentAuthenticityData.fromJsonString(XmpFixtures.json("d".repeat(64))))
        scanWitness(activity)
        settle()

        assertNull("nothing is co-signed", shadowOf(activity).nextStartedActivityForResult)
        assertEquals(0, queued(activity).size)
        assertEquals("the staged copy is gone", emptyList<File>(), recoveryFiles(activity))
    }

    @Test
    fun `a recreation during a running append waits on it and appends exactly once`() {
        val gate = CountDownLatch(1)
        ReadOnlyMediaProvider.readGate = gate
        val controller = Robolectric.buildActivity(CoSignActivity::class.java).setup()
        shadowOf(Looper.getMainLooper()).idle()
        select(controller.get(), original)
        scanWitness(controller.get())
        idleUntil { ReadOnlyMediaProvider.readsStarted.get() >= 1 }

        // The append holds in its read of the original; the screen is recreated.
        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()
        ReadOnlyMediaProvider.readGate = null
        gate.countDown()

        val (picker, _) = awaitPicker(activity)
        assertEquals("clip-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))
        settle()
        assertNull("one append, so one picker", shadowOf(activity).nextStartedActivityForResult)
        assertEquals("one append, so one staged copy", 1, recoveryFiles(activity).size)
        assertEquals(0, queued(activity).size)
        assertNull(runningAppend(activity))
    }

    @Test
    fun `a copy picker that cannot open fails the append and leaves nothing pending`() {
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        select(activity, original)
        // The append types the media; building the picker's input types it again, and is refused.
        ReadOnlyMediaProvider.typeQueriesLeft = AtomicInteger(1)
        scanWitness(activity)
        settle()

        assertNull("no picker opens", shadowOf(activity).nextStartedActivityForResult)
        assertNull("nothing is left to place", pending(activity))
        assertEquals(false, field("appending").get(activity))
        assertEquals(0, queued(activity).size)
        assertEquals("the staged copy is gone", emptyList<File>(), recoveryFiles(activity))

        // The next response is not blocked by the failure.
        ReadOnlyMediaProvider.typeQueriesLeft = null
        scanWitness(activity, "SHA256:second")
        awaitPicker(activity)
    }

    private fun boundHash(response: Any?): Any? =
        response!!.javaClass.getDeclaredField("contentHash").apply { isAccessible = true }.get(response)

    @Test
    fun `a recreation while the response scanner is open appends with the hash the witness was shown`() {
        val controller = Robolectric.buildActivity(CoSignActivity::class.java).setup()
        shadowOf(Looper.getMainLooper()).idle()
        select(controller.get(), original)
        val requestCode = openResponseScanner(controller.get())

        // The scanner covers the screen, which is recreated; its reload of the
        // media's signatures has not ended when the scan comes back.
        val gate = CountDownLatch(1)
        ReadOnlyMediaProvider.readGate = gate
        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()
        assertNull(field("currentSignatureData").get(activity))
        answerScanner(activity, requestCode)

        assertEquals("bound to the hash shown when the scan began", ORIGINAL_HASH, boundHash(queued(activity).single()))
        ReadOnlyMediaProvider.readGate = null
        gate.countDown()
        awaitPicker(activity)
        assertEquals(1, recoveryFiles(activity).size)
    }

    @Test
    fun `a recreation while the response scanner is open refuses media whose content changed meanwhile`() {
        val controller = Robolectric.buildActivity(CoSignActivity::class.java).setup()
        shadowOf(Looper.getMainLooper()).idle()
        select(controller.get(), original)
        val requestCode = openResponseScanner(controller.get())

        // While the scanner is open the media is replaced by other content,
        // which the recreated screen reads back before the scan returns.
        val changed = File(folder.root, "clip.png").apply { writeBytes(XmpFixtures.png()) }
        XmpMetadataHelper.writeSignature(changed.path, ContentAuthenticityData.fromJsonString(XmpFixtures.json("d".repeat(64))))
        controller.recreate()
        val activity = controller.get()
        idleUntil { field("currentSignatureData").get(activity) != null }
        answerScanner(activity, requestCode)
        settle()

        assertNull("nothing is co-signed", shadowOf(activity).nextStartedActivityForResult)
        assertEquals(0, queued(activity).size)
        assertEquals("the staged copy is gone", emptyList<File>(), recoveryFiles(activity))
    }

    @Test
    fun `a response with no hash the witness was shown is refused, never appended unchecked`() {
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        select(activity, original)
        // A scan result with no scan begun for it, as after process death
        // dropped the scanner's request: no hash to check the media against.
        val response = CoSignResponse("AAAA", "SHA256:witness", "Witness", "ES256").toJsonString()
        CoSignActivity::class.java.getDeclaredMethod("onResponseScanned", String::class.java)
            .apply { isAccessible = true }.invoke(activity, response)
        settle()

        assertNull("nothing is co-signed", shadowOf(activity).nextStartedActivityForResult)
        assertEquals(0, queued(activity).size)
        assertEquals("the staged copy is gone", emptyList<File>(), recoveryFiles(activity))
    }

    @Test
    fun `a waiter cancelled after its append ended leaves the result for the recreated screen`() {
        val gate = CountDownLatch(1)
        ReadOnlyMediaProvider.readGate = gate
        val controller = Robolectric.buildActivity(CoSignActivity::class.java).setup()
        shadowOf(Looper.getMainLooper()).idle()
        val first = controller.get()
        select(first, original)
        scanWitness(first)
        idleUntil { ReadOnlyMediaProvider.readsStarted.get() >= 1 }
        val id = runningAppend(first) as String

        // The append ends (it needs a copy) before the screen's waiter runs,
        // and the waiter is cancelled, as when the screen goes away then.
        ReadOnlyMediaProvider.readGate = null
        gate.countDown()
        @Suppress("UNCHECKED_CAST")
        val runs = MediaSaveRuns::class.java.getDeclaredField("runs").apply { isAccessible = true }
            .get(null) as Map<String, Deferred<*>>
        val deadline = System.currentTimeMillis() + 10_000
        while (runs[id]?.isCompleted != true) {
            assertTrue("the append never ended", System.currentTimeMillis() < deadline)
            Thread.sleep(10)
        }
        first.lifecycleScope.cancel()
        shadowOf(Looper.getMainLooper()).idle()

        controller.recreate()
        val activity = controller.get()
        val (picker, _) = awaitPicker(activity)
        assertEquals("clip-cosigned.png", picker.getStringExtra(Intent.EXTRA_TITLE))
        settle()
        assertNull("the picker opens once", shadowOf(activity).nextStartedActivityForResult)
        assertEquals("the one staged co-signature waits for it", 1, recoveryFiles(activity).size)
        assertNotNull(pending(activity))
    }

    @Test
    fun `changed media content that kept its old signature data is refused before anything is appended`() {
        // Other pixels under the original's signature data, which still names
        // the hash the witness was shown: only the payload itself tells.
        ReadOnlyMediaProvider.files["clip.png"] =
            signedPng("changed.png", pixels = byteArrayOf(0x78, 0x9C.toByte(), 0x09, 0x09, 0x09))
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        select(activity, original)
        scanWitness(activity)
        settle()

        assertNull("nothing is co-signed", shadowOf(activity).nextStartedActivityForResult)
        assertEquals(0, queued(activity).size)
        assertEquals("the staged copy is gone", emptyList<File>(), recoveryFiles(activity))
    }

    /**
     * A signed JPEG over the automatic capture signer's 32 MiB limit, built
     * segment by segment: SOI, DQT, the scan header, [scanBytes] of
     * entropy-coded data and EOI, signed in its EXIF with [hash].
     */
    private fun signedLargeJpeg(name: String, scanBytes: Int, fill: Byte, hash: String?): Pair<File, String> {
        fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }
        val jpeg = bytes(0xFF, 0xD8) + bytes(0xFF, 0xDB, 0x00, 0x04, 0x01, 0x02) +
            bytes(0xFF, 0xDA, 0x00, 0x04, 0x03, 0x04) + ByteArray(scanBytes) { fill } + bytes(0xFF, 0xD9)
        val own = MediaHasher.hashCanonical(jpeg, "image/jpeg")
        val file = File(folder.root, name).apply { writeBytes(jpeg) }
        XmpMetadataHelper.writeSignature(file.path, ContentAuthenticityData.fromJsonString(XmpFixtures.json(hash ?: own)))
        return file to own
    }

    /** Co-signs content://.../big.jpg, signed for [signedHash], and returns whether the copy picker opened. */
    private fun coSignLargeJpeg(file: File, signedHash: String): Boolean {
        ReadOnlyMediaProvider.files["big.jpg"] = file
        ReadOnlyMediaProvider.types["big.jpg"] = "image/jpeg"
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        select(activity, Uri.parse("content://${ReadOnlyMediaProvider.AUTHORITY}/big.jpg"))
        field("currentSignatureData").set(activity, ContentAuthenticityData.fromJsonString(XmpFixtures.json(signedHash)))
        scanWitness(activity)
        settle()
        val started = shadowOf(activity).nextStartedActivityForResult ?: return false
        return started.intent.action == Intent.ACTION_CREATE_DOCUMENT
    }

    @Test
    fun `a signed JPEG over 32 MiB is co-signed, and altered payload bytes in one are still refused`() {
        val size = AutoSignHash.MAX_CANONICAL_JPEG_BYTES + 1024 * 1024
        val (large, hash) = signedLargeJpeg("big.jpg", size, 0x11, hash = null)
        assertTrue("a valid signed JPEG over 32 MiB reaches the copy picker", coSignLargeJpeg(large, hash))

        // The same signature data, naming the same hash, over other scan bytes.
        val (altered, _) = signedLargeJpeg("altered.jpg", size, 0x12, hash = hash)
        assertTrue("altered payload bytes are refused", !coSignLargeJpeg(altered, hash))
    }

    /** How the screen goes away after a step of [exchangeScenario], and comes back. */
    private enum class Away {
        /** Recreated, as on a rotation. */
        RECREATE,

        /**
         * Its state is saved, then the next step's work ends while it is
         * stopped, and only then is it destroyed and restored from that state.
         */
        SAVED_BEFORE_NEXT_STEP
    }

    /**
     * One witness co-signs the original into a copy the user picks; a second
     * witness's scan opens while the copy writes and returns once it is
     * written. After step [awayAt] the screen goes away as [away] says. It
     * ends with each response appended exactly once: two pickers, the second
     * over the copy, holding both co-signatures.
     */
    private fun exchangeScenario(awayAt: Int, away: Away?) {
        val case = "away after step $awayAt: $away"
        ReadOnlyMediaProvider.readGate = null
        ReadOnlyMediaProvider.readsStarted.set(0)
        val copy = Uri.parse("content://$COPIES/clip-cosigned.png")
        val held = HeldOutput()
        val gate = CountDownLatch(1)
        val readBack = { ByteArrayInputStream(synchronized(held.bytes) { held.bytes.toByteArray() }) }
        var controller = Robolectric.buildActivity(CoSignActivity::class.java).setup()
        val instances = mutableListOf(controller.get())
        recoveryFiles(controller.get()).forEach { it.delete() }
        fun wire(activity: CoSignActivity) {
            register(activity, copy, held)
            shadowOf(activity.contentResolver).registerInputStreamSupplier(copy, readBack)
            shadowOf(activity.applicationContext.contentResolver).registerInputStreamSupplier(copy, readBack)
        }
        // Every copy picker any instance opened, in order.
        val pickers = mutableListOf<Pair<Intent, Int>>()
        fun drainPickers() = instances.forEach { activity ->
            while (true) {
                val started = shadowOf(activity).nextStartedActivityForResult ?: break
                if (started.intent.action == Intent.ACTION_CREATE_DOCUMENT) pickers.add(started.intent to started.requestCode)
            }
        }
        fun awaitPickers(n: Int) = idleUntil { drainPickers(); pickers.size >= n }
        var scanA = 0
        var scanB = 0
        // Each step, and whether it is work that ends on its own (it can end while the screen is away).
        val steps: List<Pair<Boolean, () -> Unit>> = listOf(
            false to { select(controller.get(), original); scanA = openResponseScanner(controller.get()) },
            false to {
                ReadOnlyMediaProvider.readGate = gate
                val before = ReadOnlyMediaProvider.readsStarted.get()
                answerScanner(controller.get(), scanA)
                idleUntil { ReadOnlyMediaProvider.readsStarted.get() > before }
            },
            // The append ends: the original needs a copy.
            true to { ReadOnlyMediaProvider.readGate = null; gate.countDown(); settle() },
            false to {
                awaitPickers(1)
                controller.get().activityResultRegistry.dispatchResult(pickers[0].second, Activity.RESULT_OK, Intent().setData(copy))
                assertTrue("$case: the copy's write started", held.writing.await(10, TimeUnit.SECONDS))
            },
            false to { scanB = openResponseScanner(controller.get()) },
            // The copy is written while the second scan is open.
            true to { held.release(); settle() },
            false to {
                idleUntil { selected(controller.get()) == copy }
                answerScanner(controller.get(), scanB, "SHA256:second")
            }
        )
        try {
            wire(controller.get())
            steps.forEachIndexed { index, (_, step) ->
                step()
                if (index != awayAt || away == null) return@forEachIndexed
                when (away) {
                    Away.RECREATE -> controller.recreate()
                    Away.SAVED_BEFORE_NEXT_STEP -> {
                        val state = android.os.Bundle()
                        controller.pause().stop().saveInstanceState(state)
                        steps.getOrNull(index + 1)?.takeIf { it.first }?.second?.invoke()
                        settle()
                        drainPickers()
                        controller.destroy()
                        controller = Robolectric.buildActivity(CoSignActivity::class.java).setup(state)
                    }
                }
                shadowOf(Looper.getMainLooper()).idle()
                instances.add(controller.get())
                wire(controller.get())
            }
            awaitPickers(2)
            settle()
            drainPickers()
            val activity = controller.get()
            assertEquals("$case: one picker per response", 2, pickers.size)
            assertEquals("$case: the second goes to the copy", "clip-cosigned-cosigned.png", pickers[1].first.getStringExtra(Intent.EXTRA_TITLE))
            val staged = pending(activity)!!.let { p ->
                p.javaClass.getDeclaredField("staged").apply { isAccessible = true }.get(p) as File
            }
            assertEquals(
                "$case: each co-signature appended once, the second to the first",
                listOf("SHA256:testfp", "SHA256:witness", "SHA256:second"),
                XmpMetadataHelper.readSignature(staged.path)!!.signatures.map { it.keyFingerprint }
            )
            assertEquals("$case: no response left", 0, queued(activity).size)
            assertEquals("$case: one staged copy", 1, recoveryFiles(activity).size)
            assertArrayEquals("$case: the original is whole", originalBytes, ReadOnlyMediaProvider.files["clip.png"]!!.readBytes())
        } finally {
            held.release()
            gate.countDown()
            ReadOnlyMediaProvider.readGate = null
        }
    }

    @Test
    fun `a save and recreation at any step of the exchange appends each response once and loses nothing`() {
        exchangeScenario(-1, null)
        for (step in 0..5) exchangeScenario(step, Away.RECREATE)
        // The append, then the copy's write, ending after the state was saved.
        exchangeScenario(1, Away.SAVED_BEFORE_NEXT_STEP)
        exchangeScenario(4, Away.SAVED_BEFORE_NEXT_STEP)
    }
}
