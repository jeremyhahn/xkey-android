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
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom

/**
 * Instrumented tests for the parts of [SoftwareKeyStore] that `SoftwareKeyStoreTest`
 * does not reach: existence checks, replacement, the file-name sanitiser, and the
 * metadata defaults a partially written record falls back to.
 *
 * The store is the only place raw, exportable key material lives -- hardware keys
 * stay in the Keystore and are non-exportable by design -- so the at-rest
 * encryption is asserted directly against the files on disk.
 *
 * Each run uses its own [KeystoreAeadCipher] alias so it cannot disturb the
 * shared `xkey_software_key_store` key, and removes that alias afterwards.
 */
@RunWith(AndroidJUnit4::class)
class SoftwareKeyStoreCoverageTest {

    private val suffix = System.nanoTime()
    private val cipherAlias = "test_software_key_store_$suffix"

    private lateinit var context: Context
    private lateinit var store: SoftwareKeyStore
    private lateinit var directory: File

    private val storedIds = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        store = SoftwareKeyStore(context, KeystoreAeadCipher(cipherAlias))
        directory = File(context.filesDir, "software_keys")
    }

    @After
    fun tearDown() {
        storedIds.forEach { store.delete(it) }
        storedIds.clear()
        runCatching {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(cipherAlias)
        }
    }

    private fun newKeyId(label: String): String =
        "sw-$label-$suffix".also { storedIds.add(it) }

    private fun softwareKey(
        keyId: String,
        algorithm: String = "AES-256",
        keyType: String = "symmetric",
        keySize: Int = 256,
        exportable: Boolean = true,
        shareable: Boolean = true,
        material: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    ) = SoftwareKey(keyId, algorithm, keyType, keySize, exportable, shareable, material)

    /**
     * Files are named by a SHA-256 digest of the key id, not by mangling it.
     * The old `[^A-Za-z0-9._-] -> _` scheme mapped `a/b` and `a:b` onto one
     * name, so `put` could silently overwrite an unrelated key's material.
     */
    private fun sanitized(keyId: String) =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(keyId.toByteArray())
            .joinToString("") { "%02x".format(it) }

    @Test
    fun replacesAKeyStoredUnderTheSameIdentifier() {
        val keyId = newKeyId("replace")
        val replacement = ByteArray(16) { 0x2A }

        store.put(softwareKey(keyId, keySize = 256))
        store.put(
            softwareKey(
                keyId,
                algorithm = "HMAC-SHA256",
                keyType = "private",
                keySize = 128,
                exportable = false,
                shareable = false,
                material = replacement
            )
        )

        val stored = store.get(keyId)!!
        assertArrayEquals(replacement, stored.material)
        assertEquals("HMAC-SHA256", stored.algorithm)
        assertEquals("private", stored.keyType)
        assertEquals(128, stored.keySize)
        assertFalse(stored.exportable)
        assertFalse(stored.shareable)
    }

    @Test
    fun storesMaterialEncryptedAtRest() {
        val keyId = newKeyId("at-rest")
        val material = ByteArray(32) { 0x11 }

        store.put(softwareKey(keyId, material = material))

        val onDisk = File(directory, "${sanitized(keyId)}.key").readBytes()
        assertFalse(
            "raw material must never touch the filesystem",
            onDisk.asList().windowed(material.size).any { it.toByteArray().contentEquals(material) }
        )
        assertTrue("an IV and a GCM tag are added", onDisk.size > material.size)
        assertArrayEquals(material, store.get(keyId)!!.material)
    }

    @Test
    fun readingAKeyWithoutItsMetadataYieldsNothing() {
        val keyId = newKeyId("orphan-material")
        store.put(softwareKey(keyId))

        assertTrue(File(directory, "${sanitized(keyId)}.meta").delete())

        assertNull(store.get(keyId))
        assertTrue("the material file alone still counts as present", store.contains(keyId))
    }

    @Test
    fun metadataFallsBackToConservativeDefaults() {
        val keyId = newKeyId("bare-metadata")
        val material = ByteArray(32) { 0x7F }
        store.put(softwareKey(keyId, material = material))

        // A record written by an older build, or truncated mid-write, carries no
        // fields; the store must not infer that the key is exportable.
        File(directory, "${sanitized(keyId)}.meta").writeText("{}")

        val stored = store.get(keyId)!!
        assertEquals(keyId, stored.keyId)
        assertEquals("", stored.algorithm)
        assertEquals("symmetric", stored.keyType)
        assertEquals(0, stored.keySize)
        assertFalse(stored.exportable)
        assertFalse(stored.shareable)
        assertArrayEquals(material, stored.material)
    }

    @Test
    fun deletingAnAbsentKeyIsHarmless() {
        val keyId = newKeyId("absent")

        store.delete(keyId)

        assertFalse(store.contains(keyId))
        assertNull(store.get(keyId))
    }
}
