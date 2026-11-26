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

package com.automatethethings.xkey.crypto

import android.content.Context
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/**
 * #255 review r5: a record under one key's digest name whose metadata names
 * another key contradicts its own name. It was indexed under the key its
 * metadata names, so that key's generation took in the other key's
 * material and its delete unlinked both. A record under a digest name is
 * only ever the record of the id that digest names: it is never read,
 * counted or deleted as another id's.
 */
class SoftwareKeyDigestIdentityTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var filesDir: File
    private lateinit var store: SoftwareKeyStore

    @Before
    fun setUp() {
        mockkStatic(android.util.Log::class)
        every { android.util.Log.d(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        filesDir = tmp.newFolder()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg<ByteArray>().copyOf() }
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().copyOf() }
        store = SoftwareKeyStore(context, cipher)
        store.put(key(A, 1))
        store.put(key(B, 2))
        // A's record now claims to be B's.
        val meta = file(A, ".meta")
        meta.writeText(JSONObject(meta.readText()).put("keyId", B).toString())
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun aDigestRecordNamingAnotherKeyIsNeverThatKeysMaterial() {
        assertEquals("B's generation took in A's material", digest(file(B, ".key").readBytes()), store.generation(B))
    }

    @Test
    fun aDeleteOfAGenerationLeavesTheRecordThatNamesItUnderAnotherDigest() {
        assertTrue("B's delete did not finish", store.deleteGeneration(B, store.generation(B)!!))
        assertAIsLeft()
    }

    @Test
    fun aDeleteLeavesTheRecordThatNamesItUnderAnotherDigest() {
        store.delete(B)
        assertAIsLeft()
    }

    private fun assertAIsLeft() {
        assertTrue("A's material went with B's delete", file(A, ".key").isFile)
        assertTrue("A's metadata went with B's delete", file(A, ".meta").isFile)
        assertTrue("B's own record was left", !file(B, ".key").exists() && !file(B, ".meta").exists())
    }

    private fun key(id: String, fill: Int) =
        SoftwareKey(id, "AES", "symmetric", 256, exportable = true, shareable = true, material = ByteArray(32) { fill.toByte() })

    private fun file(id: String, suffix: String) =
        File(File(filesDir, "software_keys"), digest(id.toByteArray(Charsets.UTF_8)) + suffix)

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private companion object {
        const val A = "key-a"
        const val B = "key-b"
    }
}
