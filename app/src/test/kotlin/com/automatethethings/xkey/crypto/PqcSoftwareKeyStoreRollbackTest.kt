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
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * A deleted or replaced software ML-DSA key stays gone when its files are
 * rolled back: putting back an old sealed record, with its generation file
 * removed or put back too, never makes it sign again, and a delete that
 * cannot revoke the key or advance its generation reports it.
 *
 * The store runs on its production wrapping path over a fake AndroidKeyStore,
 * whose entries outlive any file rollback as the real Keystore's do.
 */
class PqcSoftwareKeyStoreRollbackTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** The fake Keystore's entries. */
    private val keys = HashMap<String, SecretKey>()
    /** The alias the last lookup missed: the one the next generation makes. */
    private var lastMiss: String? = null
    /** When set, deleteEntry leaves the entry in place. */
    private var failKeystoreDeletes = false

    private lateinit var store: PqcSoftwareKeyStore
    private val set = MlDsaParameterSet.ML_DSA_44
    private val data = "message".toByteArray()

    @Before
    fun setUp() {
        val keyStore = mockk<KeyStore>(relaxed = true)
        every { keyStore.getKey(any(), any()) } answers {
            val alias = firstArg<String>()
            keys[alias] ?: run { lastMiss = alias; null }
        }
        every { keyStore.containsAlias(any()) } answers { keys.containsKey(firstArg<String>()) }
        every { keyStore.deleteEntry(any()) } answers {
            if (!failKeystoreDeletes) keys.remove(firstArg<String>())
            Unit
        }
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

        val generator = mockk<KeyGenerator>(relaxed = true)
        every { generator.init(any<AlgorithmParameterSpec>()) } returns Unit
        every { generator.generateKey() } answers {
            val key = SecretKeySpec(ByteArray(32).also { SecureRandom().nextBytes(it) }, "AES")
            keys[checkNotNull(lastMiss)] = key
            key
        }
        mockkStatic(KeyGenerator::class)
        every { KeyGenerator.getInstance(any<String>(), "AndroidKeyStore") } returns generator

        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        store = PqcSoftwareKeyStore(context)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `a deleted key's record put back with its generation file removed does not sign`() {
        store.generate(ALIAS, set)
        val record = store.fileFor(ALIAS).readBytes()
        assertTrue(store.delete(ALIAS))

        store.fileFor(ALIAS).writeBytes(record)
        store.generationFileFor(ALIAS).delete()

        assertThrows(PqcKeyRecordException::class.java) { store.sign(ALIAS, set, data) }
    }

    @Test
    fun `a deleted key's record put back with its older generation file does not sign`() {
        store.generate(ALIAS, set)
        val record = store.fileFor(ALIAS).readBytes()
        val generation = store.generationFileFor(ALIAS).readBytes()
        assertTrue(store.delete(ALIAS))

        store.fileFor(ALIAS).writeBytes(record)
        store.generationFileFor(ALIAS).writeBytes(generation)

        assertThrows(PqcKeyRecordException::class.java) { store.sign(ALIAS, set, data) }
    }

    @Test
    fun `a replaced key's record put back with its older generation file does not sign`() {
        store.generate(ALIAS, set)
        val record = store.fileFor(ALIAS).readBytes()
        val generation = store.generationFileFor(ALIAS).readBytes()
        store.generate(ALIAS, set)

        store.fileFor(ALIAS).writeBytes(record)
        store.generationFileFor(ALIAS).writeBytes(generation)

        assertThrows(PqcKeyRecordException::class.java) { store.sign(ALIAS, set, data) }
    }

    @Test
    fun `a live key whose generation file is missing does not sign`() {
        store.generate(ALIAS, set)
        store.generationFileFor(ALIAS).delete()

        assertThrows(PqcKeyRecordException::class.java) { store.sign(ALIAS, set, data) }
    }

    @Test
    fun `a delete that cannot revoke the key throws and the key is not deleted`() {
        store.generate(ALIAS, set)
        failKeystoreDeletes = true

        assertThrows(Exception::class.java) { store.delete(ALIAS) }

        failKeystoreDeletes = false
        assertNotNull(store.sign(ALIAS, set, data))
        assertTrue(store.delete(ALIAS))
        assertThrows(PqcKeyRecordException::class.java) { store.sign(ALIAS, set, data) }
    }

    @Test
    fun `a delete that cannot advance the generation throws and the deleted key does not sign`() {
        store.generate(ALIAS, set)
        val record = store.fileFor(ALIAS).readBytes()
        val generation = store.generationFileFor(ALIAS)
        // A directory where the generation's temporary file goes makes its write fail.
        assertTrue(File(generation.parentFile, generation.name + ".tmp").mkdirs())

        assertThrows(Exception::class.java) { store.delete(ALIAS) }

        store.fileFor(ALIAS).writeBytes(record)
        assertThrows(PqcKeyRecordException::class.java) { store.sign(ALIAS, set, data) }
    }

    private companion object {
        const val ALIAS = "xkey_general_rollback"
    }
}
