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
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException

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
    fun `overlapping embedded writes to one path stage apart and publish one complete output`() {
        val path = fixtureFile("clip.mp4", "video/mp4")
        val file = File(path)
        val original = file.readBytes()
        val first = sampleData(hash = "1".repeat(64))
        // A longer payload, so mixed writes of the two would show as a wrong length.
        val second = sampleData(hash = "2".repeat(64)).let {
            it.copy(signatures = it.signatures + it.signatures.first().copy(signerName = "B".repeat(400)))
        }
        val outputs = listOf(first, second).map {
            XmpContainers.embed(original, XmpContainers.Format.ISO_BMFF, it.toJsonString())!!.toList()
        }
        // Another job's staging file under the name a fixed scheme would pick.
        val foreign = File(file.parentFile, ".clip.mp4.xkeytmp").apply { writeBytes(byteArrayOf(7)) }

        repeat(20) { round ->
            file.writeBytes(original)
            val start = java.util.concurrent.CountDownLatch(1)
            val failures = java.util.Collections.synchronizedList(mutableListOf<Throwable>())
            val jobs = listOf(first, second).map { data ->
                kotlin.concurrent.thread {
                    try {
                        start.await()
                        XmpMetadataHelper.writeSignature(path, data)
                    } catch (e: Throwable) {
                        failures += e
                    }
                }
            }
            start.countDown()
            jobs.forEach { it.join() }

            assertEquals("round $round", emptyList<Throwable>(), failures)
            assertTrue("round $round: a whole output of one write", file.readBytes().toList() in outputs)
            assertTrue("round $round: the other job's staging file survives", foreign.exists())
            assertArrayEquals(byteArrayOf(7), foreign.readBytes())
            assertEquals(
                "round $round: no staging file left behind",
                setOf("clip.mp4", foreign.name),
                file.parentFile!!.list()!!.toSet()
            )
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

    // -------------------------------------------------------------------------
    // Read failures and re-signing
    // -------------------------------------------------------------------------

    @Test
    fun `a media file that cannot be read fails the write and gets no sidecar`() {
        val saved = XmpMetadataHelper.maxEmbedBytes
        try {
            // The default bound reaches the whole-file read; a bound of 1 the oversized probe.
            for (limit in listOf(saved, 1)) {
                XmpMetadataHelper.maxEmbedBytes = limit
                for (name in embeddedNames.keys) {
                    // A directory under a media name has a length, but every read of it fails.
                    val dir = tempFolder.newFolder("unreadable-$limit-$name")
                    File(dir, "entry").writeBytes(ByteArray(64))
                    assertTrue("$limit $name", dir.length() > 1)

                    assertThrows("$limit $name", IOException::class.java) {
                        XmpMetadataHelper.writeSignature(dir.path, sampleData())
                    }
                    assertFalse("$limit $name", sidecarOf(dir.path).exists())
                }
            }
        } finally {
            XmpMetadataHelper.maxEmbedBytes = saved
        }
    }

    @Test
    fun `an append to a media file that cannot be read fails and leaves its sidecar alone`() {
        for (name in embeddedNames.keys) {
            val dir = tempFolder.newFolder("append-unreadable-$name")
            File(dir, "entry").writeBytes(ByteArray(64))
            val legacy = sampleData(hash = "e".repeat(64)).toJsonString()
            sidecarOf(dir.path).writeText(legacy)

            assertThrows(name, IOException::class.java) {
                XmpMetadataHelper.appendSignature(
                    dir.path,
                    SignatureEntry("fp-w", "Bob", "ES256", "sig-w", "2026-01-02T00:00:00Z", SignerRole.WITNESS)
                )
            }
            assertEquals(name, legacy, sidecarOf(dir.path).readText())
        }
    }

    @Test
    fun `a file the parser refuses but the reader finds signed is not given a sidecar`() {
        // A signed mp4 followed by more boxes than the parser walks: embed
        // refuses it, while the stream reader still finds the old signature.
        val signed = XmpContainers.embed(XmpFixtures.mp4(), XmpContainers.Format.ISO_BMFF, sampleData().toJsonString())!!
        val out = ByteArrayOutputStream()
        out.write(signed)
        val free = XmpFixtures.box("free", ByteArray(0))
        repeat(100_000) { out.write(free) }
        val file = tempFolder.newFile("crowded.mp4")
        file.writeBytes(out.toByteArray())

        assertThrows(IOException::class.java) {
            XmpMetadataHelper.writeSignature(file.path, sampleData(hash = "9".repeat(64)))
        }
        assertFalse(sidecarOf(file.path).exists())
    }

    private fun secondSigner(hash: String) = ContentAuthenticityData(
        contentHash = hash,
        signatures = listOf(
            SignatureEntry("SHA256:second", "Bob", "ES256", "sig-2", "2026-01-03T00:00:00Z", SignerRole.CREATOR)
        )
    )

    /** What the Share-sheet signer does with a shared stream, here over a plain file. */
    private fun replace(path: String, mime: String, data: ContentAuthenticityData, work: File) =
        XmpMetadataHelper.replaceEmbeddedSignature(
            open = { File(path).inputStream() },
            openOutput = { File(path).outputStream() },
            format = XmpContainers.formatOf(mime)!!,
            data = data,
            workDir = work
        )

    @Test
    fun `re-signing auto-signed media with a second key replaces the embedded signer`() {
        for ((name, mime) in embeddedNames) {
            val path = fixtureFile("resign-$name", mime)
            XmpMetadataHelper.writeSignature(path, sampleData(hash = "f".repeat(64)))
            val second = secondSigner("f".repeat(64))
            val work = tempFolder.newFolder("work-$name")

            assertTrue(name, replace(path, mime, second, work))

            assertFalse(name, sidecarOf(path).exists())
            assertEquals(name, second, XmpMetadataHelper.readSignature(path))
            val format = XmpContainers.formatOf(mime)!!
            assertEquals(name, second.toJsonString(), File(path).inputStream().use { XmpContainers.read(it, format) })
            assertTrue("$name: the working copy is removed", work.listFiles()!!.isEmpty())
        }
    }

    @Test
    fun `re-signing media above the embed bound refuses a carried signature and otherwise embeds nothing`() {
        val saved = XmpMetadataHelper.maxEmbedBytes
        try {
            for ((name, mime) in embeddedNames) {
                val signedPath = fixtureFile("big-signed-$name", mime)
                XmpMetadataHelper.writeSignature(signedPath, sampleData())
                val unsignedPath = fixtureFile("big-unsigned-$name", mime)
                val unsigned = File(unsignedPath).readBytes()
                val work = tempFolder.newFolder("big-work-$name")
                XmpMetadataHelper.maxEmbedBytes = 8

                assertThrows(name, IOException::class.java) { replace(signedPath, mime, secondSigner("a".repeat(64)), work) }
                assertFalse(name, replace(unsignedPath, mime, secondSigner("a".repeat(64)), work))
                assertArrayEquals(name, unsigned, File(unsignedPath).readBytes())
                assertTrue(name, work.listFiles()!!.isEmpty())
                XmpMetadataHelper.maxEmbedBytes = saved
            }
        } finally {
            XmpMetadataHelper.maxEmbedBytes = saved
        }
    }
}
