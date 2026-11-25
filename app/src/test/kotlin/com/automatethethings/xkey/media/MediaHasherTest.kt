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
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

/**
 * Fixed SHA-256 vectors (FIPS 180-2) for [MediaHasher]: the algorithm and the
 * lowercase hex form must match existing SHA-256 manifests.
 */
class MediaHasherTest {

    @Test
    fun `hashBytes gives the lowercase hex SHA-256 of abc`() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            MediaHasher.hashBytes("abc".toByteArray(Charsets.US_ASCII))
        )
    }

    @Test
    fun `hashStream gives the lowercase hex SHA-256 of an empty stream`() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            MediaHasher.hashStream(ByteArrayInputStream(ByteArray(0)))
        )
    }

    /** The main Kotlin source root, from the module or the repository directory. */
    private fun mainSources(): File {
        val relative = "src/main/kotlin/com/automatethethings/xkey"
        val cwd = File(System.getProperty("user.dir") ?: ".")
        return listOf(File(cwd, relative), File(cwd, "app/$relative")).first { it.isDirectory }
    }

    /** A JPEG type or extension string compared outside the classifier. */
    private val jpegComparison = Regex("""(?i)"(image/)?jpe?g"|startsWith\("image/jpe?g|contains\("jpe?g""")

    /** [text] with [MediaHasher.isJpeg]'s body and the JPEG type constant left out. */
    private fun withoutClassifier(text: String): String {
        val start = text.indexOf("    fun isJpeg(")
        val end = text.indexOf("\n    }\n", start)
        require(start >= 0 && end > start) { "MediaHasher.isJpeg not found" }
        return (text.substring(0, start) + text.substring(end))
            .lines().filterNot { it.contains("const val JPEG_MIME_TYPE") }.joinToString("\n")
    }

    /** Every JPEG comparison in the hash and signature sources, outside the classifier. */
    private fun jpegComparisons(override: Pair<String, String>? = null): List<String> {
        val root = mainSources()
        val files = File(root, "media").listFiles { f -> f.extension == "kt" }!!.toList() +
            File(root, "ui/VerifiedMediaViewerActivity.kt") + File(root, "ui/FileOperationActivity.kt")
        return files.flatMap { file ->
            val raw = if (override?.first == file.name) override.second else file.readText()
            val text = if (file.name == "MediaHasher.kt") withoutClassifier(raw) else raw
            jpegComparison.findAll(text).map { "${file.name}: ${it.value}" }.toList()
        }
    }

    @Test
    fun `no JPEG type comparison bypasses the MediaHasher classifier`() {
        assertEquals(emptyList<String>(), jpegComparisons())
    }

    @Test
    fun `the bypass scan catches a reintroduced JPEG type comparison`() {
        val helper = File(mainSources(), "media/XmpMetadataHelper.kt").readText()
        val bypass = helper + "\nval bypass = \"x\".startsWith(\"image/jpeg\")\n"

        val found = jpegComparisons("XmpMetadataHelper.kt" to bypass)

        assertTrue(found.toString(), found.any { it.startsWith("XmpMetadataHelper.kt") })
    }
}
