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
package com.automatethethings.xkey.ui

import android.util.Log
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.MlDsaParameterSet
import com.automatethethings.xkey.crypto.PqcBacking
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The key screen's ML-DSA create path: the key it makes and the row that
 * records it are stored together or not at all.
 */
class KeyManagementMlDsaCreateTest {

    private val set = MlDsaParameterSet.ML_DSA_65
    private val spki = ByteArray(set.publicKeyBytes + 22) { (it % 251).toByte() }
    private val material: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())
    private val rows: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())
    private lateinit var keystore: KeystoreManager
    private lateinit var keyDao: KeyDao

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        keystore = mockk(relaxed = true)
        every { keystore.deleteGeneralKey(any()) } answers { material.remove(firstArg<String>()) }
        keyDao = mockk(relaxed = true)
        coEvery { keyDao.insert(any()) } answers {
            rows += firstArg<KeyEntity>().keyId
            1L
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun row(keyId: String, der: ByteArray) = KeyEntity(
        keyId = keyId,
        keyType = "signing",
        algorithm = set.wireName,
        label = keyId,
        publicKeyDer = der,
        keySizeBits = set.publicKeyBytes * 8,
        source = "local"
    )

    private suspend fun create(keyId: String) =
        createMlDsaKeyRow(keystore, keyDao, keyId, set, PqcBacking.SOFTWARE, -1) { row(keyId, it) }

    @Test
    fun `closing the screen while an ML-DSA key is made leaves both the key and its row or neither`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        coEvery { keystore.generateMlDsaKey("c", any(), any(), any(), any()) } answers {
            entered.countDown()
            release.await(10, TimeUnit.SECONDS)
            material += "c"
            spki
        }

        val screen = CoroutineScope(Dispatchers.Default).launch { create("c") }
        assertTrue("generation never started", entered.await(10, TimeUnit.SECONDS))
        screen.cancel()
        release.countDown()
        runBlocking { screen.join() }

        assertEquals("key material $material, rows $rows", "c" in material, "c" in rows)
    }

    @Test
    fun `an ML-DSA key whose row cannot be stored is removed`() {
        coEvery { keystore.generateMlDsaKey("f", any(), any(), any(), any()) } answers {
            material += "f"
            spki
        }
        coEvery { keyDao.insert(match { it.keyId == "f" }) } throws IllegalStateException("database is full")

        val failure = runCatching { runBlocking { create("f") } }

        assertTrue("the create must fail", failure.isFailure)
        assertFalse("the unrecorded key must be removed", "f" in material)
    }

    @Test
    fun `a created ML-DSA key has its row`() {
        coEvery { keystore.generateMlDsaKey("k", any(), any(), any(), any()) } answers {
            material += "k"
            spki
        }

        val der = runBlocking { create("k") }

        assertTrue(der.contentEquals(spki))
        assertTrue("k" in material && "k" in rows)
    }
}
