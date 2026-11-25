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

package com.automatethethings.xkey.crypto

import android.content.Context
import io.mockk.every
import io.mockk.mockk
import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [SoftwareKeyStore.delete] fails loudly when a key's material file is still
 * there afterwards, so no caller reads a failed removal as a deleted key.
 */
class SoftwareKeyStoreDeleteFailureTest {

    private val filesDir: File = Files.createTempDirectory("xkey-files").toFile().apply { deleteOnExit() }
    private val context = mockk<Context>().also { every { it.filesDir } returns filesDir }

    @Test
    fun `a material file that cannot be removed fails the delete`() {
        val store = SoftwareKeyStore(context)
        // A non-empty directory in place of the material file: File.delete
        // refuses it whoever runs the test.
        val material = File(filesDir, "software_keys/${fileId("k")}.key").apply { mkdirs() }
        File(material, "pinned").writeText("x")
        assertTrue(store.contains("k"))

        assertThrows(KeyDeletionException::class.java) { store.delete("k") }

        assertTrue(store.contains("k"))
    }

    @Test
    fun `a missing key deletes quietly`() {
        val store = SoftwareKeyStore(context)

        store.delete("missing")

        assertFalse(store.contains("missing"))
    }

    private fun fileId(keyId: String): String = SyncCodec.sha256Hex(keyId.toByteArray(Charsets.UTF_8))
}
