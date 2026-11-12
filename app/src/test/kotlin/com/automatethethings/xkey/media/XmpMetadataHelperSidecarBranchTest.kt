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

import org.junit.Assert.assertArrayEquals
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
 *  - every extension the internal mime-type table knows plus the
 *    unknown-extension fallback, since an unrecognised file, or an `.mp4`,
 *    `.mov`, `.png` or `.webp` whose bytes do not parse, must still get a
 *    sidecar rather than being silently dropped;
 *  - a real MP4, MOV, PNG or WebP carrying its signature as embedded XMP, a
 *    co-signer appended in that form, and a legacy sidecar still reading;
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
    fun `every file that cannot embed round-trips through a sidecar`() {
        // HEIC, MKV and unknown types never embed; an mp4, mov, png or webp
        // whose bytes do not parse as that container falls back too.
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

    // -------------------------------------------------------------------------
    // Embedded XMP
    // -------------------------------------------------------------------------

    /** A real container of [mime] under [name], from [XmpFixtures]. */
    private fun fixtureFile(name: String, mime: String): String {
        val file = tempFolder.newFile(name)
        file.writeBytes(XmpFixtures.all.getValue(mime))
        return file.absolutePath
    }

    private val embeddedNames = mapOf(
        "clip.mp4" to "video/mp4",
        "CLIP.MOV" to "video/quicktime",
        "still.png" to "image/png",
        "still.webp" to "image/webp"
    )

    @Test
    fun `an mp4, mov, png or webp carries its signature in the file and writes no sidecar`() {
        for ((name, mime) in embeddedNames) {
            val path = fixtureFile(name, mime)
            val data = sampleData(hash = name.hashCode().toString().padStart(64, '0'))

            XmpMetadataHelper.writeSignature(path, data)

            assertFalse("$name must not get a sidecar", sidecarOf(path).exists())
            assertEquals(name, data, XmpMetadataHelper.readSignature(path))
            assertEquals(
                name,
                data.toJsonString(),
                XmpContainers.extract(File(path).readBytes(), XmpContainers.formatOf(mime)!!)
            )
        }
    }

    @Test
    fun `appendSignature adds a second entry in the embedded form`() {
        for ((name, mime) in embeddedNames) {
            val path = fixtureFile("append-$name", mime)
            XmpMetadataHelper.writeSignature(path, sampleData(hash = "d".repeat(64)))

            XmpMetadataHelper.appendSignature(
                path,
                SignatureEntry("fp-w", "Bob", "ES256", "sig-w", "2026-01-02T00:00:00Z", SignerRole.WITNESS)
            )

            assertFalse(name, sidecarOf(path).exists())
            val embedded = ContentAuthenticityData.fromJsonString(
                XmpContainers.extract(File(path).readBytes(), XmpContainers.formatOf(mime)!!)!!
            )
            assertEquals(name, "d".repeat(64), embedded.contentHash)
            assertEquals(name, listOf("SHA256:testfp", "fp-w"), embedded.signatures.map { it.keyFingerprint })
        }
    }

    @Test
    fun `a legacy sidecar beside a real container still reads and an append stays in it`() {
        for ((name, mime) in embeddedNames) {
            val path = fixtureFile("legacy-$name", mime)
            val original = File(path).readBytes()
            sidecarOf(path).writeText(sampleData(hash = "e".repeat(64)).toJsonString())

            assertEquals(name, "e".repeat(64), XmpMetadataHelper.readSignature(path)!!.contentHash)

            XmpMetadataHelper.appendSignature(
                path,
                SignatureEntry("fp-w", "Bob", "ES256", "sig-w", "2026-01-02T00:00:00Z", SignerRole.WITNESS)
            )

            assertArrayEquals("$name: the media file is untouched", original, File(path).readBytes())
            val sidecar = ContentAuthenticityData.fromJsonString(sidecarOf(path).readText())
            assertEquals(name, 2, sidecar.signatures.size)
        }
    }

    @Test
    fun `an embedded signature wins over a stale sidecar`() {
        val path = fixtureFile("both.mp4", "video/mp4")
        sidecarOf(path).writeText(sampleData(hash = "1".repeat(64)).toJsonString())

        XmpMetadataHelper.writeSignature(path, sampleData(hash = "2".repeat(64)))

        assertEquals("2".repeat(64), XmpMetadataHelper.readSignature(path)!!.contentHash)
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
