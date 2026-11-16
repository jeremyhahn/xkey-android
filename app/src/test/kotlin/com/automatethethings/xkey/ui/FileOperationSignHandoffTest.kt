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

import android.app.Application
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.widget.ArrayAdapter
import android.widget.Spinner
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.XmpContainers
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.google.android.material.button.MaterialButton
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import org.junit.After
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
import org.robolectric.annotation.Config
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * performSign hands its output to a save picker only once its bookkeeping
 * is done: a recreation while that bookkeeping runs leaves no pending save
 * behind, so the restored screen is not held busy by a picker never opened.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class FileOperationSignHandoffTest {

    /** Serves [file] as [type] at content://[AUTHORITY]/…, read-only. */
    class SharedMedia : ContentProvider() {
        override fun onCreate() = true
        override fun getType(uri: Uri): String? = type
        override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor =
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
        override fun query(uri: Uri, p: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor? = null
        override fun insert(uri: Uri, values: ContentValues?): Uri? = null
        override fun delete(uri: Uri, s: String?, a: Array<out String>?) = 0
        override fun update(uri: Uri, v: ContentValues?, s: String?, a: Array<out String>?) = 0

        companion object {
            lateinit var file: File
            var type: String? = null
        }
    }

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase

    @Before
    fun setUp() {
        db = TestDatabase()
        Robolectric.setupContentProvider(SharedMedia::class.java, AUTHORITY)
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun field(name: String) =
        FileOperationActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    /**
     * Sign media of [type] holding [bytes], recreate the screen while
     * keyDao.recordUsage is suspended, and check the restored screen.
     */
    private fun recreateDuringBookkeeping(type: String?, bytes: ByteArray) {
        SharedMedia.file = folder.newFile().apply { writeBytes(bytes) }
        SharedMedia.type = type
        val intent = Intent(Intent.ACTION_SEND)
            .setType(type ?: "*/*")
            .putExtra(Intent.EXTRA_STREAM, Uri.parse("content://$AUTHORITY/media"))
        val controller = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()

        // One signing key; the bookkeeping holds until the screen is recreated.
        val key = KeyEntity(
            keyId = "key-sign",
            keyType = "signing",
            algorithm = "ES256",
            label = "Signer",
            keySizeBits = 256,
            source = "generated"
        )
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signWithAlgorithm(any(), any(), any()) } returns ByteArray(64) { 1 }
        val recording = CountDownLatch(1)
        val never = CompletableDeferred<Unit>()
        val keys = mockk<KeyDao>(relaxed = true)
        coEvery { keys.recordUsage(any(), any()) } coAnswers {
            recording.countDown()
            never.await()
        }
        field("keystoreManager").set(activity, keystore)
        field("keyDao").set(activity, keys)
        field("signingKeys").set(activity, listOf(key))
        (field("keySpinner").get(activity) as Spinner).apply {
            adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_item, listOf(key.label))
            setSelection(0)
        }

        FileOperationActivity::class.java.getDeclaredMethod("performSign").apply { isAccessible = true }.invoke(activity)
        val deadline = System.currentTimeMillis() + 10_000
        while (!recording.await(10, TimeUnit.MILLISECONDS)) {
            assertTrue("the sign reached its bookkeeping", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
        }

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val restored = controller.get()

        assertNull("no signed copy waits on a picker never opened", field("pendingSignedCopy").get(restored))
        assertNull("no sidecar waits on a picker never opened", field("pendingSignatureJson").get(restored))
        assertTrue(
            "the restored screen is not held busy",
            (field("processButton").get(restored) as MaterialButton).isEnabled
        )
    }

    @Test
    fun `a recreation before the signed-copy picker opens leaves the screen free`() {
        val signed = XmpContainers.embed(XmpFixtures.png(), XmpContainers.Format.PNG, XmpFixtures.json())
        recreateDuringBookkeeping("image/png", signed!!)
    }

    @Test
    fun `a recreation before the sidecar picker opens leaves the screen free`() {
        recreateDuringBookkeeping(null, "plain bytes".toByteArray())
    }

    private companion object {
        const val AUTHORITY = "xkey.handoff"
    }
}
