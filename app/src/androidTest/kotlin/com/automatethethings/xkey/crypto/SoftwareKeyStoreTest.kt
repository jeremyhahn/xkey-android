// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.

package com.automatethethings.xkey.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

/**
 * Instrumented tests for [SoftwareKeyStore]: the Keystore-encrypted store for
 * exportable software-backed keys. Runs on a device/emulator (uses the real
 * Android Keystore via KeystoreAeadCipher).
 */
@RunWith(AndroidJUnit4::class)
class SoftwareKeyStoreTest {

    private val keyId = "test-sw-${System.nanoTime()}"
    private lateinit var store: SoftwareKeyStore

    @Before
    fun setUp() {
        store = SoftwareKeyStore(ApplicationProvider.getApplicationContext())
    }

    @After
    fun tearDown() {
        store.delete(keyId)
    }

    @Test
    fun putGetRoundTrip() {
        val material = ByteArray(32).also { SecureRandom().nextBytes(it) }
        store.put(
            SoftwareKey(
                keyId = keyId,
                algorithm = "AES-256",
                keyType = "symmetric",
                keySize = 256,
                exportable = true,
                shareable = true,
                material = material
            )
        )
        val got = store.get(keyId)
        assertNotNull(got)
        assertArrayEquals(material, got!!.material)
        assertEquals("AES-256", got.algorithm)
        assertEquals("symmetric", got.keyType)
        assertEquals(256, got.keySize)
        assertTrue(got.exportable)
        assertTrue(got.shareable)
    }

    @Test
    fun getMissingReturnsNull() {
        assertNull(store.get("does-not-exist-$keyId"))
    }

    @Test
    fun deleteRemoves() {
        store.put(SoftwareKey(keyId, "AES-256", "symmetric", 256, true, true, ByteArray(32)))
        assertNotNull(store.get(keyId))
        store.delete(keyId)
        assertNull(store.get(keyId))
    }
}
