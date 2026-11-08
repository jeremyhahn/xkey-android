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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Unit tests for the file-type routing and the failure branches of
 * [XmpMetadataHelper]'s sidecar path.
 *
 * `XmpMetadataHelperTest` proves the happy path for `.mp4` and `.png`; the JPEG
 * / EXIF half lives in `XmpMetadataHelperInstrumentedTest` because it needs a
 * real encoder. What is left, and what this suite covers, is:
 *
 *  - every extension the internal mime-type table knows (`.webp`, `.mkv`,
 *    `.mov`) plus the unknown-extension fallback, since an unrecognised file
 *    must still get a sidecar rather than being silently dropped;
 *  - extension matching being case-insensitive, so a `.MOV` from a camera app
 *    is routed the same way as a `.mov`;
 *  - the reader's swallow-and-return-null branches: a truncated, corrupt, empty
 *    or unreadable sidecar has to read back as "unsigned", never as a partly
 *    populated manifest that a verifier might treat as authentic.
 *
 * Everything is written under a [TemporaryFolder], so no state outlives a test.
 */
class XmpMetadataHelperSidecarBranchTest {

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

    /** Creates an empty media file of the given name and returns its path. */
    private fun mediaFile(name: String): String {
        val file = tempFolder.newFile(name)
        file.writeBytes(ByteArray(32))
        return file.absolutePath
    }

    private fun sidecarOf(path: String) = File(XmpMetadataHelper.getSidecarPath(path))

    // -------------------------------------------------------------------------
    // File-type routing
    // -------------------------------------------------------------------------

    @Test
    fun `every non-JPEG media type round-trips through a sidecar`() {
        val names = listOf(
            "clip.webp", "clip.mkv", "clip.mov", "clip.mp4", "clip.png",
            "clip.heic", "clip", "clip.tar.gz"
        )

        for (name in names) {
            val path = mediaFile(name)
            val data = sampleData(hash = name.hashCode().toString().padStart(64, '0'))

            XmpMetadataHelper.writeSignature(path, data)

            assertTrue("$name must be signed via a sidecar", sidecarOf(path).exists())
            assertEquals(name, data.contentHash, XmpMetadataHelper.readSignature(path)!!.contentHash)
        }
    }

    @Test
    fun `an uppercase extension is routed like its lowercase form`() {
        val upper = mediaFile("CLIP.MOV")

        XmpMetadataHelper.writeSignature(upper, sampleData(hash = "b".repeat(64)))

        assertTrue(sidecarOf(upper).exists())
        assertEquals("b".repeat(64), XmpMetadataHelper.readSignature(upper)!!.contentHash)
    }

    @Test
    fun `getSidecarPath only appends and never rewrites the name`() {
        assertEquals("/a/b/c.mov.xkeysig", XmpMetadataHelper.getSidecarPath("/a/b/c.mov"))
        assertEquals("/a/b/c.xkeysig", XmpMetadataHelper.getSidecarPath("/a/b/c"))
        assertEquals(
            "a sidecar of a sidecar is still just an append",
            "/a/b/c.mp4.xkeysig.xkeysig",
            XmpMetadataHelper.getSidecarPath("/a/b/c.mp4.xkeysig")
        )
        assertEquals("/a/my clip.mp4.xkeysig", XmpMetadataHelper.getSidecarPath("/a/my clip.mp4"))
    }

    // -------------------------------------------------------------------------
    // Reader failure branches
    // -------------------------------------------------------------------------

    @Test
    fun `a sidecar holding malformed JSON reads back as unsigned`() {
        val path = mediaFile("corrupt.mp4")
        sidecarOf(path).writeText("{ this is not json")

        assertNull(XmpMetadataHelper.readSignature(path))
    }

    @Test
    fun `a sidecar that cannot be read reads back as unsigned`() {
        // A directory occupying the sidecar path: it exists, so the reader gets
        // past the existence check and has to survive the I/O failure.
        val path = File(tempFolder.root, "blocked.mp4").absolutePath
        tempFolder.newFolder("blocked.mp4.xkeysig")

        assertNull(XmpMetadataHelper.readSignature(path))
    }

    @Test
    fun `readSignature does not create a sidecar as a side effect`() {
        val path = mediaFile("readonly.mp4")

        assertNull(XmpMetadataHelper.readSignature(path))

        assertFalse(sidecarOf(path).exists())
    }

    // -------------------------------------------------------------------------
    // appendSignature
    // -------------------------------------------------------------------------

    @Test
    fun `appendSignature refuses a corrupt sidecar`() {
        val path = mediaFile("corrupt-append.mp4")
        sidecarOf(path).writeText("not a manifest")

        assertThrows(IllegalStateException::class.java) {
            XmpMetadataHelper.appendSignature(
                path,
                SignatureEntry(
                    keyFingerprint = "fp",
                    signerName = null,
                    algorithm = "ES256",
                    value = "sig",
                    timestamp = "2026-01-01T00:00:00Z"
                )
            )
        }
    }

    @Test
    fun `appendSignature accumulates co-signers in order`() {
        val path = mediaFile("cosign.mkv")
        XmpMetadataHelper.writeSignature(path, sampleData(hash = "c".repeat(64)))

        XmpMetadataHelper.appendSignature(
            path,
            SignatureEntry("fp-w", "Bob", "ES256", "sig-w", "2026-01-02T00:00:00Z", SignerRole.WITNESS)
        )
        XmpMetadataHelper.appendSignature(
            path,
            SignatureEntry("fp-a", "Carol", "ES384", "sig-a", "2026-01-03T00:00:00Z", SignerRole.ATTESTOR)
        )

        val read = XmpMetadataHelper.readSignature(path)!!
        assertEquals("the content hash is never rewritten", "c".repeat(64), read.contentHash)
        assertEquals(3, read.signatures.size)
        assertEquals(listOf("SHA256:testfp", "fp-w", "fp-a"), read.signatures.map { it.keyFingerprint })
        assertEquals(
            listOf(SignerRole.CREATOR, SignerRole.WITNESS, SignerRole.ATTESTOR),
            read.signatures.map { it.role }
        )
    }
}
