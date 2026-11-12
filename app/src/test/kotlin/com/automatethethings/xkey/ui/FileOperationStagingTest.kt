/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.coroutines.cancellation.CancellationException

/** JVM tests for [FileOperationStaging], the staging files behind sign, encrypt and decrypt. */
class FileOperationStagingTest {

    @get:Rule
    val temp = TemporaryFolder()

    private fun staging(): FileOperationStaging = FileOperationStaging(temp.root)

    private fun FileOperationStaging.stageBytes(displayName: String?): File =
        stage(displayName) { it.writeBytes(byteArrayOf(1, 2, 3)) }

    private fun assertInsideStaging(staging: FileOperationStaging, file: File) {
        assertEquals(staging.directory.canonicalFile, file.canonicalFile.parentFile)
    }

    @Test
    fun `staged name never contains the display name`() {
        val staging = staging()
        val file = staging.stageBytes("holiday-photo.jpg")

        assertFalse(file.name.contains("holiday-photo"))
        // The extension stays, so the XMP helper still sees a JPEG.
        assertTrue(file.name.endsWith(".jpg"))
        assertInsideStaging(staging, file)
    }

    @Test
    fun `a traversal display name stages inside the staging directory`() {
        val staging = staging()
        val file = staging.stageBytes("../../outside/evil.jpg")

        assertInsideStaging(staging, file)
        assertTrue(file.exists())
        assertFalse(File(temp.root.parentFile, "outside").exists())
        assertFalse(File(temp.root, "outside").exists())
        assertEquals(listOf(staging.directory.name), temp.root.list()!!.toList())
    }

    @Test
    fun `staged file is deleted when the write step throws`() {
        val staging = staging()
        var written: File? = null
        try {
            staging.stage("report.pdf") {
                written = it
                it.writeBytes(byteArrayOf(9, 9))
                throw IOException("encrypt failed")
            }
            fail("stage should rethrow the write failure")
        } catch (e: IOException) {
            assertEquals("encrypt failed", e.message)
        }

        assertFalse(written!!.exists())
        assertTrue(staging.directory.list().isNullOrEmpty())
    }

    @Test
    fun `staged file is deleted when the save is cancelled`() {
        val staging = staging()
        val file = staging.stageBytes("secret.txt")
        assertTrue(file.exists())

        staging.release(file)

        assertFalse(file.exists())
        assertTrue(staging.directory.list().isNullOrEmpty())
    }

    @Test
    fun `staged file is deleted when the copy to the target throws`() {
        val staging = staging()
        val file = staging.stageBytes("secret.txt")

        try {
            staging.deliver(file) { throw IOException("target gone") }
            fail("deliver should rethrow the copy failure")
        } catch (e: IOException) {
            assertEquals("target gone", e.message)
        }

        assertFalse(file.exists())
    }

    @Test
    fun `two staged files have different paths`() {
        val staging = staging()
        val first = staging.stageBytes("same.bin")
        val second = staging.stageBytes("same.bin")

        assertNotEquals(first.canonicalPath, second.canonicalPath)
        assertTrue(first.exists())
        assertTrue(second.exists())

        staging.releaseAll()

        assertFalse(first.exists())
        assertFalse(second.exists())
    }

    @Test
    fun `startup sweep deletes leftovers only inside the staging directory`() {
        val directory = File(temp.root, FileOperationStaging.DIRECTORY_NAME)
        val leftover = File(directory, "stage-old.tmp")
        val nested = File(directory, "nested/stage-old.tmp")
        nested.parentFile!!.mkdirs()
        leftover.writeBytes(byteArrayOf(1))
        nested.writeBytes(byteArrayOf(2))
        val sibling = temp.newFile("xkey_enc_temp_keep")
        val otherCache = File(temp.newFolder("image_cache"), "thumb.png").apply { writeBytes(byteArrayOf(3)) }

        staging().sweep()

        assertFalse(leftover.exists())
        assertFalse(nested.exists())
        assertTrue(directory.list().isNullOrEmpty())
        assertTrue(sibling.exists())
        assertTrue(otherCache.exists())
    }

    @Test
    fun `a second instance's sweep keeps the first instance's staged output`() {
        val first = staging()
        val file = first.stageBytes("report.pdf")

        // A second share opens while the first waits on its save picker
        val second = staging()
        second.sweep()
        second.stageBytes("other.pdf")

        assertTrue(file.exists())
        val target = File(temp.newFolder("picked"), "report.pdf")
        first.deliver(file) { it.copyTo(target) }
        assertArrayEquals(byteArrayOf(1, 2, 3), target.readBytes())
        assertFalse(file.exists())
    }

    @Test
    fun `a writer blocked in input at teardown leaves no staged file`() {
        val staging = staging()
        val entered = CountDownLatch(1)
        val inputReady = CountDownLatch(1)
        var failure: Throwable? = null
        val worker = thread {
            try {
                staging.stage("secret.txt") { staged ->
                    // openInputStream blocks in the provider
                    entered.countDown()
                    inputReady.await()
                    FileOutputStream(staged).use { it.write("plaintext".toByteArray()) }
                }
            } catch (e: Throwable) {
                failure = e
            }
        }
        assertTrue(entered.await(5, TimeUnit.SECONDS))

        staging.shutdown()
        assertTrue(staging.directory.list().isNullOrEmpty())

        inputReady.countDown()
        worker.join(5_000)
        assertFalse(worker.isAlive)

        assertTrue(staging.directory.list().isNullOrEmpty())
        assertTrue("stage should end cancelled, got $failure", failure is CancellationException)
        try {
            staging.stageBytes("late.txt")
            fail("stage after shutdown should be refused")
        } catch (e: CancellationException) {
            // refused
        }
        assertTrue(staging.directory.list().isNullOrEmpty())
    }

    @Test
    fun `a destination open paused across teardown still completes from the staged file`() {
        val staging = staging()
        val target = temp.newFile("original.jpg").apply { writeText("original") }
        val file = staging.stage("photo.jpg") { it.writeText("signed") }
        val entered = CountDownLatch(1)
        val resume = CountDownLatch(1)
        var failure: Throwable? = null
        val worker = thread {
            try {
                staging.deliverTo(file) {
                    // openOutputStream blocks in the provider, then truncates the original
                    entered.countDown()
                    resume.await()
                    FileOutputStream(target)
                }
            } catch (e: Throwable) {
                failure = e
            }
        }
        assertTrue(entered.await(5, TimeUnit.SECONDS))

        staging.shutdown()

        resume.countDown()
        worker.join(5_000)
        assertFalse(worker.isAlive)

        assertEquals("delivery should complete, got $failure", null, failure)
        assertEquals("signed", target.readText())
        assertTrue(staging.directory.list().isNullOrEmpty())
    }

    /** An output stream that records its close and, when [failWrite], fails every write. */
    private class TrackedOutput(private val failWrite: Boolean) : ByteArrayOutputStream() {
        var closed = false

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (failWrite) throw IOException("disk full")
            super.write(b, off, len)
        }

        override fun write(b: Int) {
            if (failWrite) throw IOException("disk full")
            super.write(b)
        }

        override fun close() {
            closed = true
            super.close()
        }
    }

    @Test
    fun `deliverTo deletes the staged file when opening the destination throws`() {
        val staging = staging()
        val file = staging.stageBytes("secret.pdf")

        val thrown = assertThrows(SecurityException::class.java) {
            staging.deliverTo(file) { throw SecurityException("no grant") }
        }

        assertEquals("no grant", thrown.message)
        assertFalse(file.exists())
        assertTrue(staging.directory.list().isNullOrEmpty())
    }

    @Test
    fun `deliverTo deletes the staged file when the destination opens as null`() {
        val staging = staging()
        val file = staging.stageBytes("secret.pdf")

        assertThrows(IllegalStateException::class.java) {
            staging.deliverTo(file) { null }
        }

        assertFalse(file.exists())
        assertTrue(staging.directory.list().isNullOrEmpty())
    }

    @Test
    fun `deliverTo closes the destination and deletes the staged file when the write fails`() {
        val staging = staging()
        val file = staging.stageBytes("secret.pdf")
        val target = TrackedOutput(failWrite = true)

        val thrown = assertThrows(IOException::class.java) {
            staging.deliverTo(file) { target }
        }

        assertEquals("disk full", thrown.message)
        assertTrue(target.closed)
        assertFalse(file.exists())
        assertTrue(staging.directory.list().isNullOrEmpty())
    }

    @Test
    fun `deliverTo closes the destination after a successful copy`() {
        val staging = staging()
        val file = staging.stageBytes("secret.pdf")
        val target = TrackedOutput(failWrite = false)

        staging.deliverTo(file) { target }

        assertTrue(target.closed)
        assertArrayEquals(byteArrayOf(1, 2, 3), target.toByteArray())
        assertFalse(file.exists())
    }

    /** One handoff as performDecrypt / performEncrypt run it: stage, [prepare], then the picker [launch]. */
    private fun handOff(
        staging: FileOperationStaging,
        pending: PendingStagedSave,
        displayName: String,
        prepare: () -> Unit = {},
        launch: () -> Unit = {}
    ) = runBlocking {
        stageForSave(
            staging,
            displayName,
            write = { it.writeBytes(byteArrayOf(4, 5, 6)) },
            prepare = prepare,
            handOff = { pending.handOff(it, launch) }
        )
    }

    private fun assertHandOffFailureLeavesNothing(displayName: String, prepare: () -> Unit, launch: () -> Unit) {
        val staging = staging()
        val pending = PendingStagedSave(staging)

        repeat(3) {
            assertThrows(RuntimeException::class.java) {
                handOff(staging, pending, displayName, prepare, launch)
            }
            assertEquals(null, pending.file)
            assertTrue(staging.directory.list().isNullOrEmpty())
        }
    }

    @Test
    fun `decrypt handoff releases the staged plaintext when recordUsage throws`() {
        assertHandOffFailureLeavesNothing(
            "report.pdf",
            prepare = { throw IllegalStateException("database or disk is full") },
            launch = { fail("the picker must not open") }
        )
    }

    @Test
    fun `decrypt handoff releases the staged plaintext when the picker launch throws`() {
        assertHandOffFailureLeavesNothing(
            "report.pdf",
            prepare = {},
            launch = { throw IllegalStateException("no activity handles CREATE_DOCUMENT") }
        )
    }

    @Test
    fun `encrypt handoff releases the staged output when its prepare step throws`() {
        assertHandOffFailureLeavesNothing(
            "report.pdf.xkeyenc",
            prepare = { throw IllegalStateException("audit log write failed") },
            launch = { fail("the picker must not open") }
        )
    }

    @Test
    fun `encrypt handoff releases the staged output when the picker launch throws`() {
        assertHandOffFailureLeavesNothing(
            "report.pdf.xkeyenc",
            prepare = {},
            launch = { throw IllegalStateException("no activity handles CREATE_DOCUMENT") }
        )
    }

    @Test
    fun `a failed handoff after a successful one keeps nothing but the earlier pending file released`() {
        val staging = staging()
        val pending = PendingStagedSave(staging)
        handOff(staging, pending, "report.pdf")
        val first = pending.file!!
        assertTrue(first.exists())

        assertThrows(IllegalStateException::class.java) {
            handOff(staging, pending, "report.pdf", launch = { throw IllegalStateException("launch failed") })
        }

        assertEquals(null, pending.file)
        assertFalse(first.exists())
        assertTrue(staging.directory.list().isNullOrEmpty())
    }

    @Test
    fun `a successful handoff keeps the staged file pending for the save callback`() {
        val staging = staging()
        val pending = PendingStagedSave(staging)
        handOff(staging, pending, "report.pdf")

        val file = pending.take()!!
        assertArrayEquals(byteArrayOf(4, 5, 6), file.readBytes())
        assertEquals(null, pending.file)
    }
}
