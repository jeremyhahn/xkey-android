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
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * One check per finding class the media-signing review kept returning to,
 * each over the class's one choke point in [XmpMetadataHelper]:
 *
 *  - a failed read of media is an error, never unsigned media, for a JPEG
 *    as for the containers ([XmpMetadataHelper.readSignatureFromSnapshot]);
 *  - a stalled read of one source holds that destination's lock alone,
 *    never the write of another destination;
 *  - every sidecar file the helper names comes from its one authoritative
 *    choice, so a probe can never look where the writer did not write.
 */
class MediaChokePointSweepTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun sampleData(hash: String = "a".repeat(64)) = ContentAuthenticityData(
        contentHash = hash,
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = "SHA256:testfp",
                signerName = "Alice",
                algorithm = "ES256",
                value = "MEUCIQD",
                timestamp = "2026-01-15T10:30:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    @Test
    fun `a JPEG that cannot be read is an error, never unsigned media`() {
        val missing = File(tempFolder.root, "gone.jpg")
        // The containers already refuse to read an unreadable file as unsigned.
        assertThrows(IOException::class.java) {
            XmpMetadataHelper.readSignatureFromSnapshot(File(tempFolder.root, "gone.mp4"), "video/mp4")
        }
        assertThrows("a JPEG whose read failed read as unsigned", IOException::class.java) {
            XmpMetadataHelper.readSignatureFromSnapshot(missing, "image/jpeg")
        }
    }

    @Test
    fun `a stalled read of one source never holds the write of another destination`() {
        val stalled = "content://media.test/stalled/1"
        // A destination that shared a lock with the stalled one when locks
        // were a fixed set of 64 picked by hash.
        val other = (0 until 100_000).asSequence()
            .map { File(tempFolder.root, "media-$it.bin") }
            .first { Math.floorMod(it.canonicalPath.hashCode(), 64) == Math.floorMod(stalled.hashCode(), 64) }
        other.writeBytes(byteArrayOf(1, 2, 3))

        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val reader = thread {
            try {
                XmpMetadataHelper.writeSignedCopy(
                    open = {
                        entered.countDown()
                        release.await(30, TimeUnit.SECONDS)
                        ByteArrayInputStream(ByteArray(16))
                    },
                    openOutput = { ByteArrayOutputStream() },
                    mimeType = "image/png",
                    data = sampleData(),
                    workDir = tempFolder.newFolder("work"),
                    destination = stalled
                )
            } catch (_: Exception) {
                // The copy's own outcome is not under test.
            }
        }
        try {
            assertTrue("the stalled read never started", entered.await(10, TimeUnit.SECONDS))
            val writer = thread { XmpMetadataHelper.writeSignature(other.path, sampleData()) }
            writer.join(5_000)
            assertFalse("a stalled read of another destination held this write", writer.isAlive)
            assertEquals(sampleData().contentHash, XmpMetadataHelper.readSignature(other.path)?.contentHash)
        } finally {
            release.countDown()
            reader.join(10_000)
        }
    }

    @Test
    fun `every sidecar file the helper names comes from its one authoritative choice`() {
        val source = File("src/main/kotlin/com/automatethethings/xkey/media/XmpMetadataHelper.kt").readText()
        val start = source.indexOf("private fun authoritativeSidecar(")
        assertTrue("authoritativeSidecar is gone", start >= 0)
        val body = source.substring(start, source.indexOf("\n    }\n", start))
        val outside = source.removeRange(start, start + body.length)
        val stray = outside.lines().withIndex()
            .filter { (_, line) -> "getSidecarPath(" in line && "fun getSidecarPath(" !in line }
            .map { (i, line) -> "${i + 1}: ${line.trim()}" }
        assertEquals("sidecar files named outside authoritativeSidecar", emptyList<String>(), stray)
    }
}
