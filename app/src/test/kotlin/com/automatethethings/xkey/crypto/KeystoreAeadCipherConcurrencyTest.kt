/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The first use of a Keystore AEAD alias from several [KeystoreAeadCipher]
 * instances at once makes one key: a lookup that misses and the generation
 * that follows run under one process-wide lock per alias, so no instance
 * replaces a key another has already sealed with.
 */
class KeystoreAeadCipherConcurrencyTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** The fake Keystore's entries. */
    private val keys = ConcurrentHashMap<String, SecretKey>()
    /** Every key generation that ran. */
    private val generations = AtomicInteger()

    @Before
    fun setUp() {
        val keyStore = mockk<KeyStore>(relaxed = true)
        every { keyStore.getKey(any(), any()) } answers { keys[firstArg<String>()] }
        every { keyStore.containsAlias(any()) } answers { keys.containsKey(firstArg<String>()) }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore

        mockkConstructor(KeyGenParameterSpec.Builder::class)
        val builder = { b: Any? -> b as KeyGenParameterSpec.Builder }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setKeySize(any()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setBlockModes(*anyVararg()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setEncryptionPaddings(*anyVararg()) } answers {
            builder(self)
        }
        every { anyConstructed<KeyGenParameterSpec.Builder>().build() } returns mockk()

        // Each generation stores a fresh AES-256 key under the alias, after a
        // pause wide enough for every racing instance to miss the lookup.
        val generator = mockk<KeyGenerator>(relaxed = true)
        every { generator.init(any<AlgorithmParameterSpec>()) } returns Unit
        every { generator.generateKey() } answers {
            generations.incrementAndGet()
            Thread.sleep(GENERATION_PAUSE_MS)
            val key = SecretKeySpec(ByteArray(32).also { SecureRandom().nextBytes(it) }, "AES")
            keys[PqcSoftwareKeyStore.WRAP_KEY_ALIAS] = key
            key
        }
        mockkStatic(KeyGenerator::class)
        every { KeyGenerator.getInstance(any<String>(), "AndroidKeyStore") } returns generator
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `concurrent first use through separate ciphers creates one key and every ciphertext opens`() {
        val start = CountDownLatch(1)
        val sealed = ConcurrentHashMap<Int, ByteArray>()
        val failures = Collections.synchronizedList(mutableListOf<Throwable>())
        val threads = (0 until THREADS).map { i ->
            Thread {
                try {
                    val cipher = KeystoreAeadCipher(PqcSoftwareKeyStore.WRAP_KEY_ALIAS)
                    start.await()
                    sealed[i] = cipher.encrypt(plaintext(i))
                } catch (e: Throwable) {
                    failures += e
                }
            }
        }
        threads.forEach { it.start() }
        start.countDown()
        threads.forEach { it.join(TimeUnit.SECONDS.toMillis(30)) }

        assertTrue("no thread failed: $failures", failures.isEmpty())
        assertEquals("one wrap key is generated", 1, generations.get())
        val reader = KeystoreAeadCipher(PqcSoftwareKeyStore.WRAP_KEY_ALIAS)
        for (i in 0 until THREADS) {
            assertArrayEquals("ciphertext $i opens", plaintext(i), reader.decrypt(sealed.getValue(i)))
        }
    }

    @Test
    fun `software stores built apart generate at once and every key still signs`() {
        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        val start = CountDownLatch(1)
        val failures = Collections.synchronizedList(mutableListOf<Throwable>())
        val threads = (0 until THREADS).map { i ->
            Thread {
                try {
                    val store = PqcSoftwareKeyStore(context, KeystoreAeadCipher(PqcSoftwareKeyStore.WRAP_KEY_ALIAS))
                    start.await()
                    store.generate("xkey_key_race$i", MlDsaParameterSet.ML_DSA_44)
                } catch (e: Throwable) {
                    failures += e
                }
            }
        }
        threads.forEach { it.start() }
        start.countDown()
        threads.forEach { it.join(TimeUnit.SECONDS.toMillis(30)) }

        assertTrue("no thread failed: $failures", failures.isEmpty())
        assertEquals("one wrap key is generated", 1, generations.get())
        val store = PqcSoftwareKeyStore(context, KeystoreAeadCipher(PqcSoftwareKeyStore.WRAP_KEY_ALIAS))
        for (i in 0 until THREADS) {
            val signature = store.sign("xkey_key_race$i", MlDsaParameterSet.ML_DSA_44, byteArrayOf(i.toByte()))
            assertEquals(MlDsaParameterSet.ML_DSA_44.signatureBytes, signature.size)
        }
    }

    private fun plaintext(i: Int): ByteArray = "plaintext $i".toByteArray()

    private companion object {
        const val THREADS = 8
        const val GENERATION_PAUSE_MS = 200L
    }
}
