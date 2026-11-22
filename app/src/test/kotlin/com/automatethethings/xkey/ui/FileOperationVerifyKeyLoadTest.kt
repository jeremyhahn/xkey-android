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
import android.view.View
import android.widget.TextView
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.media.AutoSignHash
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.button.MaterialButton
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import kotlinx.coroutines.Dispatchers
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
import java.util.Collections
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicReference

/**
 * The share screen loads its key and contact lists off the main thread
 * when it opens, and that load may end at any time after Verify is
 * pressed. A verify reads none of those lists, so it never waits for them,
 * and the load ending later leaves the result it showed in place.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class FileOperationVerifyKeyLoadTest {

    @get:Rule
    val folder = TemporaryFolder()

    /** Runs the database's queries only once [release] is called, on the caller's thread. */
    private class HeldExecutor : Executor {
        private val queued = ArrayDeque<Runnable>()
        private var released = false

        override fun execute(command: Runnable) {
            val runNow = synchronized(this) { released.also { if (!it) queued.addLast(command) } }
            if (runNow) command.run()
        }

        fun release() {
            while (true) {
                val next = synchronized(this) {
                    released = true
                    queued.removeFirstOrNull()
                } ?: return
                next.run()
            }
        }
    }

    private val queries = HeldExecutor()
    private lateinit var database: XKeyDatabase
    private lateinit var provider: FakeMediaProvider
    private val capture = Uri.parse("content://media/external/images/media/7")
    private val audited: MutableList<Boolean> = Collections.synchronizedList(mutableListOf())

    @Before
    fun setUp() {
        database = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), XKeyDatabase::class.java)
            .setQueryExecutor(queries)
            .setTransactionExecutor(queries)
            .build()
        FakeAndroidKeyStore.install()
        instanceRef().set(database)
        mockkObject(AuditLogger)
        every { AuditLogger.logFileVerified(any(), any(), any()) } answers { audited += thirdArg<Boolean>() }
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        FileOperationActivity.verifyDispatcher = Dispatchers.Main
    }

    @After
    fun tearDown() {
        queries.release()
        FileOperationActivity.verifyDispatcher = Dispatchers.IO
        unmockkObject(AuditLogger)
        instanceRef().set(null)
        database.close()
    }

    @Suppress("UNCHECKED_CAST")
    private fun instanceRef(): AtomicReference<XKeyDatabase?> =
        XKeyDatabase::class.java.getDeclaredField("instanceRef").apply { isAccessible = true }
            .get(null) as AtomicReference<XKeyDatabase?>

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
        shadowOf(Looper.getMainLooper()).idle()
    }

    private fun field(name: String) =
        FileOperationActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    @Test
    fun `a verify pressed while the key list is loading runs at once and keeps its result when the load ends`() {
        val packet = ContentAuthenticityData.fromJsonString(
            XmpFixtures.json(AutoSignHash.contentHash(XmpFixtures.png(), "image/png"))
        ).copy(signatures = emptyList())
        val signed = File(folder.root, "capture.png").apply {
            writeBytes(XmpFixtures.png())
            XmpMetadataHelper.writeSignature(path, packet)
        }
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = signed
            mimeType = "image/png"
        }
        val intent = Intent(Intent.ACTION_SEND).setType(provider.mimeType).putExtra(Intent.EXTRA_STREAM, capture)
        val activity = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        field("selectedOperation").setInt(activity, 1) // OP_VERIFY
        (field("processButton").get(activity) as MaterialButton).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        val resultCard = field("resultCard").get(activity) as View
        assertEquals("the verify ran before the key list loaded", View.VISIBLE, resultCard.visibility)
        assertEquals("one verification is audited", listOf(false), audited.toList())
        val shown = (field("resultText").get(activity) as TextView).text.toString()

        // The database ends the load on its own threads once its queries run.
        queries.release()
        idleUntil { field("keysLoaded").getBoolean(activity) }

        assertEquals("the result stays shown once the key list loads", View.VISIBLE, resultCard.visibility)
        assertEquals("the result is unchanged", shown, (field("resultText").get(activity) as TextView).text.toString())
        assertEquals("the verify ran once", listOf(false), audited.toList())
        assertFalse("nothing is left to run after the load", field("runAfterLoad").getInt(activity) >= 0)
    }
}
