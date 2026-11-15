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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Key creation refuses an ID the software store already holds, so the store
 * answers "does this key exist" without opening the Keystore: on the JVM
 * there is no AndroidKeyStore, and building one just to look for a file
 * failed every creation with an internal error.
 */
class SoftwareKeyStoreExistenceTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun context(): Context {
        val files = tmp.newFolder("files")
        return mockk(relaxed = true) { every { filesDir } returns files }
    }

    @Test
    fun `contains and delete need no Keystore`() {
        val context = context()
        val store = SoftwareKeyStore(context)
        assertFalse(store.contains("k"))

        // A record another build wrote: only its files exist.
        val dir = File(context.filesDir, "software_keys")
        val stem = SyncCodec.sha256Hex("k".toByteArray(Charsets.UTF_8))
        File(dir, "$stem.key").writeBytes(byteArrayOf(1))
        File(dir, "$stem.meta").writeText("""{"keyId":"k"}""")

        assertTrue(SoftwareKeyStore(context).contains("k"))
        SoftwareKeyStore(context).delete("k")
        assertFalse(SoftwareKeyStore(context).contains("k"))
    }
}
