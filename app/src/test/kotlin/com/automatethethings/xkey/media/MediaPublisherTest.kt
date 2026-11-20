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

import android.app.Application
import android.net.Uri
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.OutputStream

/**
 * [MediaPublisher] is the one way xKey writes where the user keeps media:
 * the original is replaced atomically or never touched, and what was being
 * published stays on disk until its write and close both succeeded.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class MediaPublisherTest {

    @get:Rule
    val folder = TemporaryFolder()

    private val original = "the user's original media".toByteArray()
    private val signed = "the signed media".toByteArray()

    /** Writes the first [failAfter] bytes and then throws, or throws on close when [failAfter] is null. */
    private class FailingOutput(private val failAfter: Int?) : OutputStream() {
        val written = ByteArrayOutputStream()
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
        override fun write(b: ByteArray, off: Int, len: Int) {
            if (failAfter != null && written.size() + len > failAfter) throw IOException("storage full")
            written.write(b, off, len)
        }
        override fun close() {
            if (failAfter == null) throw IOException("provider disconnected")
        }
    }

    @Test
    fun `a failed replace leaves the original whole and no file beside it`() {
        val dir = folder.newFolder("media")
        val target = File(dir, "clip.png").apply { writeBytes(original) }

        assertThrows(IOException::class.java) {
            MediaPublisher.replaceFile(target) { temp -> temp.writeBytes(signed.copyOf(4)); throw IOException("storage full") }
        }
        assertFalse(MediaPublisher.replaceFile(target) { temp -> temp.writeBytes(signed); false })

        assertArrayEquals(original, target.readBytes())
        assertEquals(listOf("clip.png"), dir.list()!!.toList())
    }

    @Test
    fun `a replace swaps the whole file in`() {
        val dir = folder.newFolder("media")
        val target = File(dir, "clip.png").apply { writeBytes(original) }

        assertTrue(MediaPublisher.replaceFile(target) { temp -> temp.writeBytes(signed); true })

        assertArrayEquals(signed, target.readBytes())
        assertEquals(listOf("clip.png"), dir.list()!!.toList())
    }

    @Test
    fun `a file URI is replaced atomically and its staged bytes go`() {
        val target = File(folder.newFolder("media"), "clip.png").apply { writeBytes(original) }
        val staged = folder.newFile("staged.png").apply { writeBytes(signed) }

        assertTrue(MediaPublisher.replace(Uri.fromFile(target), staged))

        assertArrayEquals(signed, target.readBytes())
        assertFalse(staged.exists())
    }

    @Test
    fun `a provider without an atomic replace is left untouched for a separate copy`() {
        val staged = folder.newFile("staged.png").apply { writeBytes(signed) }

        assertFalse(MediaPublisher.replace(Uri.parse("content://media/external/images/media/7"), staged))

        assertArrayEquals("the staged bytes stay for the copy", signed, staged.readBytes())
    }

    @Test
    fun `a replace that cannot write keeps the staged bytes and names them`() {
        val missing = File(folder.root, "gone/clip.png")
        val staged = folder.newFile("staged.png").apply { writeBytes(signed) }

        val thrown = assertThrows(MediaPublishException::class.java) {
            MediaPublisher.replace(Uri.fromFile(missing), staged)
        }

        assertEquals(staged, thrown.kept)
        assertTrue(thrown.message!!.contains(staged.path))
        assertArrayEquals(signed, staged.readBytes())
    }

    @Test
    fun `a copy whose write or close fails keeps the staged bytes and names them`() {
        for (failAfter in listOf(0, 4, null)) {
            val staged = folder.newFile("staged-$failAfter.png").apply { writeBytes(signed) }

            val thrown = assertThrows("$failAfter", MediaPublishException::class.java) {
                MediaPublisher.writeCopy(staged) { FailingOutput(failAfter) }
            }

            assertEquals("$failAfter", staged, thrown.kept)
            assertTrue("$failAfter", thrown.message!!.contains(staged.path))
            assertArrayEquals("$failAfter", signed, staged.readBytes())
        }
    }

    @Test
    fun `a copy that cannot open its destination keeps the staged bytes`() {
        val staged = folder.newFile("staged.png").apply { writeBytes(signed) }

        assertThrows(MediaPublishException::class.java) {
            MediaPublisher.writeCopy(staged) { throw SecurityException("no write grant") }
        }

        assertArrayEquals(signed, staged.readBytes())
    }

    @Test
    fun `a copy written and closed deletes the staged bytes`() {
        val staged = folder.newFile("staged.png").apply { writeBytes(signed) }
        val out = ByteArrayOutputStream()

        MediaPublisher.writeCopy(staged) { out }

        assertArrayEquals(signed, out.toByteArray())
        assertFalse(staged.exists())
    }

    // -------------------------------------------------------------------------
    // Bypass: nothing writes where the user keeps media except the publisher
    // -------------------------------------------------------------------------

    private fun mainSources(): Map<String, String> {
        val rel = "src/main/kotlin"
        val dir = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        return dir.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }
            .associate { it.relativeTo(dir).path to it.readText() }
    }

    /** Every way to open a content URI for writing, truncating or not, and the truncating modes. */
    private val writingOpens = listOf(
        "openOutputStream(",
        "openFileDescriptor(",
        "openAssetFileDescriptor(",
        "openTypedAssetFileDescriptor(",
        "\"rwt\"",
        "\"wt\""
    )

    @Test
    fun `no code outside the publisher opens a content URI for writing`() {
        val sources = mainSources()
        assertTrue("the scan found the publisher", sources.keys.any { it.endsWith("media/MediaPublisher.kt") })
        val bypasses = sources.filterKeys { !it.endsWith("media/MediaPublisher.kt") }.flatMap { (name, text) ->
            text.lines().withIndex()
                .filter { (_, line) -> writingOpens.any { it in line } }
                .map { (i, line) -> "$name:${i + 1}: ${line.trim()}" }
        }
        assertEquals("writing opens outside MediaPublisher", emptyList<String>(), bypasses)
    }

    @Test
    fun `an in-place EXIF rewrite only ever runs on a file the publisher swaps in`() {
        val bypasses = mainSources().flatMap { (name, text) ->
            val lines = text.lines()
            lines.withIndex().filter { (_, line) -> "saveAttributes()" in line && !line.trim().startsWith("*") }
                .filterNot { (i, _) -> lines.subList(maxOf(0, i - 8), i).any { "MediaPublisher.replaceFile(" in it } }
                .map { (i, line) -> "$name:${i + 1}: ${line.trim()}" }
        }
        assertEquals("saveAttributes outside MediaPublisher.replaceFile", emptyList<String>(), bypasses)
    }

    @Test
    fun `the scan sees a truncating open`() {
        val planted = "contentResolver.openOutputStream(uri, \"rwt\")"
        assertTrue(writingOpens.any { it in planted })
    }


    private fun explains(content: String, written: String, backup: String, restoring: Boolean): Boolean {
        val w = folder.newFile().apply { writeText(written) }
        val b = folder.newFile().apply { writeText(backup) }
        return MediaPublisher.interruptedWriteExplains(content.byteInputStream(), w, b, restoring)
    }

    @Test
    fun `every layout a write longer than its backup and a restore after it leave is explained`() {
        val b = "abcdefgh"
        val w = "ABCDEFGHIJKL"
        // The write stopped inside the backup, past it, or wrote all and was cut.
        for (written in listOf("ABCDEfgh", "ABCDEFGHIJ", w, b)) {
            assertTrue(written, explains(written, w, b, restoring = false))
            assertTrue(written, explains(written, w, b, restoring = true))
        }
        // A restore put back the backup's first bytes over each of those.
        for (restored in listOf("abCDEfgh", "abcDEFGHIJ", "abcdefghIJKL", "abcdeFGHIJKL", b)) {
            assertTrue(restored, explains(restored, w, b, restoring = true))
        }
    }

    @Test
    fun `every layout a write shorter than its backup and a restore after it leave is explained`() {
        val b = "abcdefgh"
        val w = "WXYZ"
        // Written whole but not yet cut (the backup's tail after it), or cut.
        for (written in listOf("WXYZefgh", "WXcdefgh", w)) {
            assertTrue(written, explains(written, w, b, restoring = false))
        }
        // Restored over the uncut write, over the cut one, and past the cut one's end.
        for (restored in listOf("abYZefgh", "abYZ", "abcdef", "abcd", b)) {
            assertTrue(restored, explains(restored, w, b, restoring = true))
        }
    }

    @Test
    fun `an edit is never explained, and a restore layout only once a restore began`() {
        val b = "abcdefgh"
        val w = "ABCDEFGHIJKL"
        assertFalse("a restored prefix with no restore recorded", explains("abCDEfgh", w, b, restoring = false))
        for (edited in listOf("abcdeXgh", "abCDxfgh", "abc", "abcdefghi", "ABCDEfg", "ABCDEFGHIJKLM", "")) {
            assertFalse(edited, explains(edited, w, b, restoring = true))
            assertFalse(edited, explains(edited, w, b, restoring = false))
        }
        assertFalse("a short prefix of the backup", explains("ab", "WXYZ", b, restoring = true))
    }
}
