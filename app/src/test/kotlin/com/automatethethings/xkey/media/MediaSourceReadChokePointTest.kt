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
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Every read of source media bytes for signing, staging, verification or
 * co-signing goes through [MediaPublisher.openOriginal]: a plain
 * `openInputStream` of a MediaStore capture gets the redacted view, which
 * hashes as other media. This scan of ui/ and media/ fails on any plain
 * read the allowlist below does not name with its reason.
 */
class MediaSourceReadChokePointTest {

    private val root = listOf(
        File("src/main/kotlin/com/automatethethings/xkey"),
        File("app/src/main/kotlin/com/automatethethings/xkey")
    ).first { it.isDirectory }

    /** Plain reads that are not source media bytes, by file, with how many each holds. */
    private val plainReads = mapOf(
        // A contact card or trust-store file the user picks: key material, not media.
        "ui/ContactManagementActivity.kt" to 1,
        "ui/TrustStoreActivity.kt" to 1,
        // The signed copy xKey itself wrote, read back to check it.
        "ui/CoSignActivity.kt" to 1,
        // A .xkeysig sidecar, and the ciphertext a decrypt reads.
        "ui/FileOperationActivity.kt" to 2,
        // The image shown on screen (twice: bounds, then pixels).
        "ui/VerifiedMediaViewerActivity.kt" to 2,
        // The redacted view hashed on purpose, to tell a redacted signature apart.
        "media/MediaSigningService.kt" to 1,
        // The resolver overloads instrumented tests call; app code takes the Context ones.
        "media/MediaHasher.kt" to 1,
        // XmpMetadataHelper also reads a .xkeysig sidecar beside a document (readSidecar).
        "media/XmpMetadataHelper.kt" to 2,
        // The choke point itself.
        "media/MediaPublisher.kt" to 1,
    )

    private fun sources(): List<File> =
        listOf("ui", "media").flatMap { dir -> File(root, dir).walk().filter { it.extension == "kt" }.toList() }

    private fun count(text: String, needle: Regex) = needle.findAll(text).count()

    @Test
    fun `no source media read in ui or media bypasses openOriginal`() {
        val found = sources()
            .associate { it.relativeTo(root).path to count(it.readText(), Regex("""openInputStream\(""")) }
            .filterValues { it > 0 }
        assertTrue("the scan found the sources", found.isNotEmpty())
        assertEquals("plain reads outside the allowlist", plainReads, found)
    }

    @Test
    fun `app code reads signatures and hashes through the Context overloads`() {
        val resolverCalls = Regex("""(readSignatureFromUri|hashUri)\(\s*(contentResolver|resolver|[a-zA-Z.]*contentResolver)\b""")
        val found = sources()
            .filter { it.relativeTo(root).path.startsWith("ui/") }
            .associate { it.relativeTo(root).path to count(it.readText(), resolverCalls) }
            .filterValues { it > 0 }
        // copyInPlace checks the document xKey wrote, through its resolver.
        assertEquals("resolver reads of source media in ui/", mapOf("ui/CoSignActivity.kt" to 1), found)
    }
}
