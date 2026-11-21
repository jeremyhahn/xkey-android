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
package com.automatethethings.xkey.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException

/**
 * The Share-sheet signed copy is written from the bytes it reads out of the
 * source when the user has picked a destination, which can be long after the
 * signature was made. [XmpMetadataHelper.writeSignedCopy], the one
 * signed-copy write, refuses media that no longer holds what was signed,
 * so a copy is never published under a signature that fails to verify.
 */
class SignedCopySourceChangedTest {

    @get:Rule
    val temp = TemporaryFolder()

    private fun hashOf(bytes: ByteArray, mime: String): String =
        MediaHasher.hashStreamed({ bytes.inputStream() }, mime, kotlin.io.path.createTempDirectory("hash").toFile()).canonical

    private class Output : ByteArrayOutputStream() {
        var opened = false
    }

    /** Signs [signed] as the screen does, then writes the copy from [source], what the source holds by then. */
    private fun write(signed: ByteArray, source: ByteArray, mime: String, output: Output, work: File): Boolean =
        XmpMetadataHelper.writeSignedCopy(
            open = { source.inputStream() },
            openOutput = { output.also { it.opened = true } },
            mimeType = mime,
            data = ContentAuthenticityData.fromJsonString(XmpFixtures.json(hashOf(signed, mime))),
            workDir = work,
            destination = "content://copies/${mime.replace('/', '-')}"
        )

    private val cases = listOf(
        Triple("image/png", XmpFixtures.png(), XmpFixtures.png(XmpFixtures.bytes(0x78, 0x9C, 0x09, 0x09, 0x09))),
        Triple("video/mp4", XmpFixtures.mp4(), XmpFixtures.mp4(XmpFixtures.bytes(0x50, 0x60, 0x70, 0x80)))
    )

    @Test
    fun `a source unchanged since signing gets a copy whose payload is what was signed`() {
        for ((mime, original, _) in cases) {
            val work = temp.newFolder()
            val output = Output()
            assertTrue(mime, write(original, original, mime, output, work))
            assertEquals("$mime: the copy's payload is the signed one", hashOf(original, mime), hashOf(output.toByteArray(), mime))
            assertTrue("$mime: no working file left", work.listFiles()!!.isEmpty())
        }
    }

    @Test
    fun `a source edited after signing is refused and nothing reaches the destination`() {
        for ((mime, original, edited) in cases) {
            val work = temp.newFolder()
            val output = Output()
            val e = assertThrows(IOException::class.java) { write(original, edited, mime, output, work) }
            assertTrue("$mime: names the change, not a write failure: ${e.message}", e.message!!.contains("changed"))
            assertFalse("$mime: the destination is never opened", output.opened)
            assertTrue("$mime: no working file left", work.listFiles()!!.isEmpty())
        }
    }

    /** Every signed copy goes through writeSignedCopy: a direct replaceEmbeddedSignature skips the check. */
    @Test
    fun `no screen or service writes a signed copy past the changed-source check`() {
        val rel = "src/main/kotlin/com/automatethethings/xkey"
        val root = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        val bypasses = root.walkTopDown().filter { it.isFile && it.extension == "kt" && it.name != "XmpMetadataHelper.kt" }
            .filter { "replaceEmbeddedSignature(" in it.readText() }.map { it.name }.toList()
        assertEquals(emptyList<String>(), bypasses)
        val screen = File(root, "ui/FileOperationActivity.kt").readText()
        assertEquals("one signed-copy write in the file operation screen", 1, Regex("writeSignedCopy\\(").findAll(screen).count())
    }
}
