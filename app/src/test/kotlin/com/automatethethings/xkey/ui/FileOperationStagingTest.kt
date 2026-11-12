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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
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
}
