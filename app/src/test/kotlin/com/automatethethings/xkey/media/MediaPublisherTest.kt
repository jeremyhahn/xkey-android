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

    /** The `{ ... }` block that opens at or after [from] in [text], braces matched. */
    private fun blockAt(text: String, from: Int): String {
        val open = text.indexOf('{', from)
        require(open >= 0) { "no block after offset $from" }
        var depth = 0
        for (i in open until text.length) {
            when (text[i]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return text.substring(open, i + 1)
            }
        }
        error("unbalanced block at offset $open")
    }

    /** Every block that opens with [marker] in [text], with the name of the function it sits in. */
    private fun blocks(text: String, marker: String): List<Pair<String, String>> =
        Regex(Regex.escape(marker)).findAll(text).map { match ->
            val function = Regex("""fun (?:<[^>]*> )?(\w+)\(""").findAll(text.substring(0, match.range.first))
                .lastOrNull()?.groupValues?.get(1) ?: "<top level>"
            function to blockAt(text, match.range.last + 1)
        }.toList()

    /**
     * A provider read under the global publication lock stalls every other
     * capture's publication and recovery for as long as the provider takes.
     * The only reads left under it are a granted or owned write's backup of
     * its own target (a MediaStore item the user granted, or xKey's sidecar),
     * which that write has to read under the lock to restore it.
     */
    @Test
    fun `no untrusted provider read runs under the global publication lock`() {
        val sources = mainSources()
        fun source(name: String) = sources.entries.singleOrNull { it.key.endsWith(name) }?.value
            ?: error("$name not found in the main sources")
        val publisher = source("media/MediaPublisher.kt")
        val helper = source("media/XmpMetadataHelper.kt")
        val targetBackups = setOf("writeGranted", "writeOwned")
        val copies = listOf("copyTo(", ".read(", "readBytes(")

        // grantedSection's own body is one of these: a caller's block is scanned where it is written.
        val locked = blocks(publisher, "synchronized(grantedWrites)")
        assertTrue("the scan found the publisher's locked sections", locked.isNotEmpty())
        val publisherReads = locked.flatMap { (function, body) ->
            val unchecked = body.indexOf("openOriginalUnchecked(")
            listOfNotNull(
                "$function: openOriginal( under grantedWrites".takeIf { "openOriginal(" in body },
                "$function: provider copy under grantedWrites".takeIf {
                    unchecked >= 0 && function !in targetBackups &&
                        copies.any { body.indexOf(it, unchecked) >= 0 }
                }
            )
        }
        val sections = blocks(helper, "MediaPublisher.grantedSection(")
        assertTrue("the scan found signMedia's granted section", sections.isNotEmpty())
        val helperReads = sections
            .filter { (_, body) -> "MediaPublisher.openOriginal(" in body }
            .map { (function, _) -> "$function: MediaPublisher.openOriginal( inside grantedSection" }

        assertEquals("provider reads under the publication lock", emptyList<String>(), publisherReads + helperReads)
    }

    /** Reads of a capture's original that copy it whole, which only an interrupt ends early. */
    private val originalReads = listOf(
        "MediaPublisher.openOriginal(",
        "readSignatureFromUri(applicationContext",
        "readSignatureFromUri(this",
        "MediaHasher.hashCanonicalUri(",
        "checkInBandUri(",
        "checkContentHashUri("
    )

    /**
     * Process-scoped on purpose: the next screen instance waits on them, so a
     * screen's cancel must not end them. appendToMedia runs in
     * MediaSaveRuns.attach, writeSave is static over the application context.
     */
    private val processScopedReads = setOf("appendToMedia", "writeSave")

    /**
     * Every read of [originalReads] in a `lifecycleScope.launch` block of
     * [text] that no `runInterruptible { ... }` block around it wraps, as
     * "function: call". The cancellable helpers are not in [originalReads].
     */
    private fun uninterruptibleScreenReads(text: String): List<String> =
        blocks(text, "lifecycleScope.launch").filter { (function, _) -> function !in processScopedReads }
            .flatMap { (function, body) ->
                val wrapped = Regex("runInterruptible|" + Regex.escape(signalBlock)).findAll(body).map { match ->
                    val open = body.indexOf('{', match.range.last + 1)
                    open until open + blockAt(body, match.range.last + 1).length
                }.toList()
                originalReads.flatMap { read ->
                    Regex(Regex.escape(read)).findAll(body)
                        .filter { match -> wrapped.none { match.range.first in it } }
                        .map { "$function: $read" }.toList()
                }
            }

    /**
     * Leaving or rotating a screen cancels its scope, but a cancel does not
     * end synchronous IO: a screen reads a capture's original through an
     * interruptible call, so its cancel ends the copy and deletes the snapshot.
     */
    @Test
    fun `no screen reads an original outside an interruptible call`() {
        val screens = mainSources().filterKeys { it.startsWith("com/automatethethings/xkey/ui/") }
        assertTrue("the scan found the screens", screens.isNotEmpty())
        val reads = screens.flatMap { (file, text) -> uninterruptibleScreenReads(text).map { "$file: $it" } }
        assertEquals("uninterruptible screen reads of an original", emptyList<String>(), reads)
    }

    @Test
    fun `the scan sees an uninterruptible screen read`() {
        val planted = """
            fun load(u: Uri, m: String?) {
                lifecycleScope.launch(Dispatchers.IO) { XmpMetadataHelper.readSignatureFromUri(applicationContext, u, m) }
            }
            fun loadWrapped(u: Uri, m: String?) {
                lifecycleScope.launch(Dispatchers.IO) { runInterruptible { MediaHasher.hashCanonicalUri(applicationContext, u) } }
            }
        """
        assertEquals(
            listOf("load: readSignatureFromUri(applicationContext"),
            uninterruptibleScreenReads(planted)
        )
    }

    /** The screen's read helper: its block makes the signal each read inside it passes on. */
    private val signalBlock = "MediaPublisher.readCancellable"

    /** Whether [index] in [text] sits on a comment line. */
    private fun inComment(text: String, index: Int): Boolean {
        val line = text.substring(text.lastIndexOf('\n', index) + 1).substringBefore('\n').trim()
        return line.startsWith("*") || line.startsWith("/*") || line.startsWith("//")
    }

    /** The argument text of the call whose `(` is at [open] in [text], parentheses matched. */
    private fun callArguments(text: String, open: Int): String {
        var depth = 0
        for (i in open until text.length) {
            when (text[i]) {
                '(' -> depth++
                ')' -> if (--depth == 0) return text.substring(open + 1, i)
            }
        }
        error("unbalanced call at offset $open")
    }

    /**
     * Every read of an original in [text] outside the process-scoped
     * functions that does not run inside a [signalBlock] block passing that
     * block's signal on, as "function: call".
     */
    private fun unsignalledScreenReads(text: String): List<String> {
        val signalled = Regex(Regex.escape(signalBlock)).findAll(text)
            .filterNot { inComment(text, it.range.first) }
            .map { match ->
                val start = text.indexOf('{', match.range.last + 1)
                val block = blockAt(text, match.range.last + 1)
                val name = Regex("""^\{\s*(\w+)\s*->""").find(block)?.groupValues?.get(1) ?: "it"
                Triple(start, start + block.length, name)
            }.toList()
        return (originalReads + "openOriginalCancellable(").flatMap { read ->
            Regex(Regex.escape(read)).findAll(text).filterNot { inComment(text, it.range.first) }.mapNotNull { match ->
                val function = Regex("""fun (?:<[^>]*> )?(\w+)\(""").findAll(text.substring(0, match.range.first))
                    .lastOrNull()?.groupValues?.get(1) ?: "<top level>"
                if (function in processScopedReads) return@mapNotNull null
                val arguments = callArguments(text, text.indexOf('(', match.range.first))
                val passed = signalled.any { (start, end, name) ->
                    match.range.first in start until end && Regex("""\b${Regex.escape(name)}\b""").containsMatchIn(arguments)
                }
                "$function: $read".takeUnless { passed }
            }.toList()
        }
    }

    /**
     * An interrupt ends work on the screen's own thread only; an open blocked
     * in the provider's process ends only through its CancellationSignal. A
     * screen reads an original inside [signalBlock], whose signal the
     * screen's cancel fires, and hands that signal to the open.
     */
    @Test
    fun `no screen opens an original without its cancel signal`() {
        val sources = mainSources()
        val screens = sources.filterKeys { it.startsWith("com/automatethethings/xkey/ui/") }
        assertTrue("the scan found the screens", screens.isNotEmpty())
        val reads = screens.flatMap { (file, text) -> unsignalledScreenReads(text).map { "$file: $it" } }
        assertEquals("screen reads of an original without a cancel signal", emptyList<String>(), reads)

        val dropped = sources.flatMap { (name, text) ->
            text.lines().withIndex()
                .filter { (_, line) ->
                    "cancel = null" in line || ("openOriginalCancellable(" in line && "fun openOriginalCancellable(" !in line)
                }
                .map { (i, line) -> "$name:${i + 1}: ${line.trim()}" }
        }
        assertEquals("reads that drop the screen's signal", emptyList<String>(), dropped)

        val helper = sources.entries.single { it.key.endsWith("media/XmpMetadataHelper.kt") }.value
        val declared = helper.indexOf("suspend fun readOriginalSignature(")
        assertTrue("readOriginalSignature is declared", declared >= 0)
        val body = helper.substring(declared).substringBefore("\n\n")
        assertTrue("readOriginalSignature reads inside $signalBlock: $body", signalBlock in body)
        assertTrue(
            "readOriginalSignature passes the signal on: $body",
            unsignalledScreenReads(body.replace("readSignatureFromUri(context", "readSignatureFromUri(this")).isEmpty()
        )
    }

    /**
     * A screen that reads an original leaves snapshots in the recovery
     * directory when its process dies part-way; the screen that opens next
     * removes them. Every such screen makes the one start sweep in onCreate,
     * and none reaches the sweep any other way.
     */
    @Test
    fun `every screen that reads an original sweeps the recovery directory when it opens`() {
        val reads = listOf(
            "openOriginal(", "readCancellable", "MediaHasher.", "readOriginalSignature(",
            "readSignatureFromUri(", "recoveryDirectory("
        )
        val screens = mainSources().filterKeys { it.startsWith("com/automatethethings/xkey/ui/") }
        val readers = screens.filterValues { text -> reads.any { it in text } }
        assertTrue("the scan found the screens that read an original", readers.size >= 3)
        val unswept = readers.filterValues { text ->
            val start = text.indexOf("override fun onCreate(")
            if (start < 0) return@filterValues true
            val rest = text.substring(start + 1)
            val end = Regex("\n    (override |private |internal |protected )?(suspend )?fun ").find(rest)?.range?.first
            val onCreate = if (end == null) rest else rest.substring(0, end)
            "MediaSaveRuns.sweepAtScreenStart(" !in onCreate
        }.keys.sorted()
        assertEquals("screens that read an original with no sweep when they open", emptyList<String>(), unswept)
        val direct = screens.filterValues { "MediaSaveRuns.sweep(" in it }.keys.sorted()
        assertEquals("screens that call the sweep directly", emptyList<String>(), direct)
    }

    @Test
    fun `the scan sees a screen read without a cancel signal`() {
        val planted = """
            fun verify(u: Uri, m: String?) {
                lifecycleScope.launch(Dispatchers.IO) { runInterruptible { MediaHasher.checkInBandUri(applicationContext, u, m) } }
            }
            fun verifyDropped(u: Uri, m: String?) {
                lifecycleScope.launch(Dispatchers.IO) { MediaPublisher.readCancellable { signal -> MediaHasher.checkInBandUri(applicationContext, u, m) } }
            }
            fun verifySignalled(u: Uri, m: String?) {
                lifecycleScope.launch(Dispatchers.IO) { MediaPublisher.readCancellable { signal -> MediaHasher.checkInBandUri(applicationContext, u, m, signal) } }
            }
        """
        assertEquals(
            listOf("verify: checkInBandUri(", "verifyDropped: checkInBandUri("),
            unsignalledScreenReads(planted)
        )
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
