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
package com.automatethethings.xkey.media

import android.Manifest
import android.app.Activity
import android.app.Application
import android.app.PendingIntent
import android.app.RecoverableSecurityException
import android.app.RemoteAction
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
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
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Android 10 enforces scoped storage for xKey (targetSdk above 29, no legacy
 * storage): a capture another app owns is written only through its content
 * URI, never by path. MediaStore refuses that write with a
 * RecoverableSecurityException until the user allows it; the write request
 * screen launches its user action and, once allowed, publishes again.
 *
 * The unit tests run offline against one framework jar, so xKey's code is
 * shown Android 10 through [Build.VERSION.SDK_INT].
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class Android10ForeignCaptureTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var context: Context
    private lateinit var provider: FakeMediaProvider
    private val uri: Uri = Uri.parse("content://media/external/images/media/101")
    private lateinit var capture: File
    private lateinit var original: ByteArray

    /** Whether the user allowed the write MediaStore's user action asked for. */
    private var allowed = false
    private val previousStore = MediaPublisher.mediaStore
    private val previousSdk = Build.VERSION.SDK_INT

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", Build.VERSION_CODES.Q)
        capture = File(folder.newFolder("DCIM", "Camera"), "IMG_0101.png").apply { writeBytes(XmpFixtures.png()) }
        original = capture.readBytes()
        val action = PendingIntent.getActivity(context, 0, Intent("test.ALLOW_WRITE"), PendingIntent.FLAG_IMMUTABLE)
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = folder.newFile("media.png").apply { writeBytes(original) }
            onOpen = { mode ->
                if ('w' in mode && !allowed) {
                    throw RecoverableSecurityException(
                        SecurityException("$uri is not owned by xKey"),
                        "Allow xKey to modify this photo?",
                        RemoteAction(Icon.createWithResource(context, android.R.drawable.ic_menu_edit), "Allow", "Allow", action)
                    )
                }
            }
        }
        MediaPublisher.mediaStore = object : MediaPublisher.MediaStoreAccess {
            override fun ownerPackage(context: Context, uri: Uri): String? = "com.example.camera"
            override fun hasWriteGrant(context: Context, uri: Uri): Boolean = false
            override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent =
                error("MediaStore has no write request below Android 11")
        }
        MediaWriteAuthorizations.clear(context)
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", previousSdk)
        MediaPublisher.mediaStore = previousStore
        MediaWriteAuthorizations.clear(context)
    }

    private fun data() = ContentAuthenticityData(
        contentHash = AutoSignHash.contentHashFile(capture, "image/png"),
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = "b".repeat(64),
                signerName = "Test Signer",
                algorithm = "ES256",
                value = "c2lnbmF0dXJl",
                timestamp = "2026-01-01T00:00:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    private fun awaitMain(done: () -> Boolean): Boolean {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < end) {
            shadowOf(Looper.getMainLooper()).idle()
            if (done()) return true
            Thread.sleep(20)
        }
        return done()
    }

    @Test
    fun `the auto-signer never writes a foreign capture by path on Android 10`() {
        // MediaStore refuses the content-URI write until the user allows it.
        val outcome = runCatching { XmpMetadataHelper.signMedia(context, uri, capture.path, data()) }
        assertEquals("not signed before the user allows it", null, outcome.getOrNull())
        assertEquals(
            "the refusal names the user action",
            "UserActionRequiredException",
            outcome.exceptionOrNull()?.javaClass?.simpleName
        )
        assertTrue("the write went to the content URI", provider.openModes.any { 'w' in it })
        assertArrayEquals("the file is never written by path", original, capture.readBytes())
        assertArrayEquals("the refused write changed nothing", original, provider.media.readBytes())
    }

    @Test
    fun `the write request screen launches MediaStore's user action and publishes once allowed`() {
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data()))
        val controller = Robolectric.buildActivity(MediaWriteRequestActivity::class.java).setup()
        val shadow = shadowOf(controller.get())

        assertTrue("the user action is launched", awaitMain { shadow.lastIntentSenderRequest != null })
        assertEquals("still queued until allowed", 1, MediaWriteAuthorizations.pending(context).size)
        assertArrayEquals("nothing written yet", original, provider.media.readBytes())

        allowed = true
        val request = shadow.lastIntentSenderRequest!!
        shadow.callOnActivityResult(request.requestCode, Activity.RESULT_OK, Intent())

        assertTrue("published once allowed", awaitMain { MediaWriteAuthorizations.pending(context).isEmpty() })
        assertNotNull(
            "the capture carries the signature",
            XmpMetadataHelper.readSignatureFromUri(context.contentResolver, Uri.fromFile(provider.media), "image/png")
        )
        assertArrayEquals("the file is never written by path", original, capture.readBytes())
    }

    @Test
    fun `a user action a publication ends with while the screen is stopped is asked by the recreated screen`() {
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data()))
        val saved = Bundle()
        val first: ActivityController<MediaWriteRequestActivity>
        // The publication waits on the granted-write lock until the screen
        // has saved its state and stopped.
        synchronized(MediaPublisher.grantedWrites) {
            first = Robolectric.buildActivity(MediaWriteRequestActivity::class.java).setup()
            first.pause().saveInstanceState(saved).stop()
        }
        val id = saved.getString("publication") ?: error("the answer names no publication")
        val runs = ReflectionHelpers.getField<Map<String, Job>>(MediaSaveRuns, "runs")
        assertTrue("the publication ends with the user action", awaitMain { runs[id]?.isCompleted == true })
        assertEquals("nothing is asked while stopped", null, shadowOf(first.get()).lastIntentSenderRequest)
        first.destroy()

        // Recreated from the state saved before the publication ended.
        val second = Robolectric.buildActivity(MediaWriteRequestActivity::class.java).setup(saved)
        val shadow = shadowOf(second.get())
        assertTrue("the recreated screen asks", awaitMain { shadow.lastIntentSenderRequest != null })
        assertTrue("and waits on the answer", !second.get().isFinishing)

        allowed = true
        shadow.callOnActivityResult(shadow.lastIntentSenderRequest!!.requestCode, Activity.RESULT_OK, Intent())
        assertTrue("published once allowed", awaitMain { MediaWriteAuthorizations.pending(context).isEmpty() })
    }

    /**
     * What a process killed part-way through an allowed write leaves: the
     * capture mixed, its record and backup on disk. The next process holds
     * no consent ([allowed] false again), as after a restart on Android 10.
     */
    private fun killMidAllowedWrite(): ByteArray {
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data()))
        allowed = true
        val recovery = MediaPublisher.recoveryDirectory(context)
        val atKill = folder.newFolder("recovery-at-kill")
        var mediaAtKill = ByteArray(0)
        var kills = 1
        MediaPublisher.overwriteStep = {
            if (it == "truncate" && kills-- > 0) {
                val written = original.size - 4
                mediaAtKill = provider.media.readBytes().copyOf(written) + original.copyOfRange(written, original.size)
                check(!mediaAtKill.contentEquals(original)) { "the kill must leave mixed bytes" }
                recovery.listFiles()!!.forEach { f -> f.copyTo(File(atKill, f.name)) }
                throw IllegalStateException("process killed")
            }
        }
        try {
            runBlocking { MediaWriteAuthorizations.publishGranted(context) {} }
        } finally {
            MediaPublisher.overwriteStep = {}
        }
        provider.media.writeBytes(mediaAtKill)
        recovery.listFiles()!!.forEach { it.delete() }
        atKill.listFiles()!!.forEach { f -> f.copyTo(File(recovery, f.name)) }
        allowed = false
        assertTrue("the kill left a recovery pending", MediaPublisher.recoveryPending(context, uri))
        return mediaAtKill
    }

    private fun journal() = MediaPublisher.GrantedWriteJournal(MediaPublisher.recoveryDirectory(context), uri)

    @Test
    fun `an interrupted write whose restore needs renewed consent asks for it and keeps its journal`() {
        val mixed = killMidAllowedWrite()

        val refusal = runCatching { MediaPublisher.recoverInterruptedWrite(context, uri) }.exceptionOrNull()

        assertTrue(
            "the restore's refusal is the user action, not a pending recovery: ${refusal?.javaClass?.simpleName}",
            refusal is MediaPublisher.UserActionRequiredException
        )
        assertTrue("the journal is kept", MediaPublisher.recoveryPending(context, uri))
        assertTrue("the backup is kept", journal().backup.isFile)
        assertArrayEquals("nothing was written", mixed, provider.media.readBytes())
    }

    @Test
    fun `the write request screen asks consent for an interrupted write's restore and completes it once allowed`() {
        killMidAllowedWrite()
        val controller = Robolectric.buildActivity(MediaWriteRequestActivity::class.java).setup()
        val shadow = shadowOf(controller.get())

        assertTrue("the user action is launched", awaitMain { shadow.lastIntentSenderRequest != null })
        assertTrue("the journal is kept while the question is open", MediaPublisher.recoveryPending(context, uri))
        assertTrue("the backup is kept while the question is open", journal().backup.isFile)

        allowed = true
        val request = shadow.lastIntentSenderRequest!!
        shadow.callOnActivityResult(request.requestCode, Activity.RESULT_OK, Intent())

        assertTrue("published once allowed", awaitMain { MediaWriteAuthorizations.pending(context).isEmpty() })
        assertTrue("the recovery is complete", !MediaPublisher.recoveryPending(context, uri))
        assertTrue("the backup is gone with it", !journal().backup.isFile)
        assertNotNull(
            "the capture carries the signature",
            XmpMetadataHelper.readSignatureFromUri(context.contentResolver, Uri.fromFile(provider.media), "image/png")
        )
    }

    @Test
    fun `a refused consent for an interrupted write's restore keeps its backup and journal`() {
        val mixed = killMidAllowedWrite()
        val controller = Robolectric.buildActivity(MediaWriteRequestActivity::class.java).setup()
        val shadow = shadowOf(controller.get())

        assertTrue("the user action is launched", awaitMain { shadow.lastIntentSenderRequest != null })
        val request = shadow.lastIntentSenderRequest!!
        shadow.callOnActivityResult(request.requestCode, Activity.RESULT_CANCELED, Intent())

        assertTrue("the screen ends", awaitMain { controller.get().isFinishing })
        assertTrue("the journal is kept", MediaPublisher.recoveryPending(context, uri))
        assertTrue("the backup is kept", journal().backup.isFile)
        assertEquals("the capture stays queued for a later consent", 1, MediaWriteAuthorizations.pending(context).size)
        assertArrayEquals("nothing was written", mixed, provider.media.readBytes())
    }

    @Test
    fun `an unsigned retry waits for the restore's renewed consent and is signed once over the restored bytes`() {
        val wholeHash = data().contentHash
        val mixed = killMidAllowedWrite()
        // A failed publication queued the capture unsigned for a retry.
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", null))
        val signedHashes = mutableListOf<String>()
        val previousSign = AutoSigner.sign
        AutoSigner.sign = { _, _, hash -> signedHashes += hash; data().copy(contentHash = hash) }
        try {
            val refusal = runCatching { runBlocking { MediaWriteAuthorizations.publishGranted(context) {} } }.exceptionOrNull()

            assertTrue(
                "the restore asks for consent: ${refusal?.javaClass?.simpleName}",
                refusal is MediaPublisher.UserActionRequiredException
            )
            assertTrue("nothing is hashed or signed before the restore: $signedHashes", signedHashes.isEmpty())
            assertEquals(
                "the request stays queued, unsigned",
                listOf<ContentAuthenticityData?>(null), MediaWriteAuthorizations.pending(context).map { it.data }
            )
            assertArrayEquals(mixed, provider.media.readBytes())

            allowed = true
            val signed = mutableListOf<PendingMediaWrite>()
            runBlocking { MediaWriteAuthorizations.publishGranted(context) { signed += it } }

            assertEquals("signed once, over the restored bytes", listOf(wholeHash), signedHashes)
            assertEquals(listOf(uri.toString()), signed.map { it.uri })
            assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
            assertTrue(!MediaPublisher.recoveryPending(context, uri))
        } finally {
            AutoSigner.sign = previousSign
        }
    }
}
