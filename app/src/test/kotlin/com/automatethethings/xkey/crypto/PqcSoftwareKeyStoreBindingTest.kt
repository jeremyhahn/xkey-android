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
import io.mockk.every
import io.mockk.mockk
import java.io.File
import java.security.GeneralSecurityException
import java.security.SecureRandom
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * A software ML-DSA record opens only as a whole: its alias, parameter set,
 * public key and generation are sealed with the private key. A record whose
 * clear public key was swapped, whose public key is not its private key's,
 * or that is older than the alias's stored generation is refused by every
 * reader.
 */
class PqcSoftwareKeyStoreBindingTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var store: PqcSoftwareKeyStore

    @Before
    fun setUp() {
        val cipher = mockk<KeystoreAeadCipher>()
        // A stand-in seal: the bytes reversed.
        every { cipher.encrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        store = PqcSoftwareKeyStore(context, cipher)
    }

    @Test
    fun `a record whose public key was substituted is refused`() {
        store.generate(A, SET)
        val other = store.generate(B, SET)
        val record = PqcSoftwareKeyStore.Record.decode(store.fileFor(A).readBytes())
        store.fileFor(A).writeBytes(record.copy(spki = other).encode())

        assertRefused(A)
    }

    @Test
    fun `a replayed older record of the same alias is refused`() {
        store.generate(A, SET)
        val older = store.fileFor(A).readBytes()
        store.generate(A, SET)
        store.fileFor(A).writeBytes(older)

        assertRefused(A)
    }

    @Test
    fun `a record replayed after its key was deleted is refused`() {
        store.generate(A, SET)
        val older = store.fileFor(A).readBytes()
        store.delete(A)
        store.fileFor(A).writeBytes(older)

        assertRefused(A)
    }

    @Test
    fun `a record whose sealed private key is another key's is refused`() {
        store.generate(A, SET)
        store.generate(B, SET)
        val a = PqcSoftwareKeyStore.Record.decode(store.fileFor(A).readBytes())
        val b = PqcSoftwareKeyStore.Record.decode(store.fileFor(B).readBytes())
        val pkcs8Size = PrivateKeyInfoFactory.createPrivateKeyInfo(
            MLDSAKeyPairGenerator().apply {
                init(MLDSAKeyGenerationParameters(SecureRandom(), PqcSoftwareKeyStore.bcParameters(SET)))
            }.generateKeyPair().private
        ).encoded.size
        // A's sealed header (alias, set, its own SPKI, generation, policy) over B's private key.
        val aPlain = a.sealed.reversedArray()
        val bPlain = b.sealed.reversedArray()
        bPlain.copyInto(aPlain, aPlain.size - pkcs8Size, bPlain.size - pkcs8Size)
        store.fileFor(A).writeBytes(a.copy(sealed = aPlain.reversedArray()).encode())

        assertRefused(A)
    }

    @Test
    fun `a regenerated key still opens and signs`() {
        store.generate(A, SET)
        val spki = store.generate(A, SET)

        assertTrue(spki.contentEquals(store.publicKeyDer(A)))
        assertEquals(-1, store.authDurationSeconds(A))
        assertEquals(SET.signatureBytes, store.sign(A, SET, byteArrayOf(1)).size)
    }

    @Test
    fun `the sealed record is opened in one place that checks the public key and the generation`() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val text = File(root, "com/automatethethings/xkey/crypto/PqcSoftwareKeyStore.kt").readText()
        val fn = Regex("""\bfun\s+(?:<[^>]*>\s*)?([A-Za-z0-9_]+)\s*\(""")
        val openers = Regex("""cipher\.decrypt\(""").findAll(text).map { call ->
            fn.findAll(text.substring(0, call.range.first)).lastOrNull()?.groupValues?.get(1)
        }.toSet()
        assertEquals(setOf("openRecord"), openers)

        val start = text.indexOf("fun <T> openRecord(")
        assertTrue("openRecord is the one opener", start >= 0)
        val body = text.substring(start, text.indexOf("\n    }\n", start))
        assertTrue("the sealed SPKI is checked against the record's", body.contains("sealedSpki.contentEquals(record.spki)"))
        assertTrue("the generation is checked against the stored one", body.contains("storedGeneration(alias)"))
        assertTrue("the private key's own public key is checked", body.contains("derivedSpki.contentEquals(record.spki)"))
    }

    private fun assertRefused(alias: String) {
        assertNull("publicKeyDer", store.publicKeyDer(alias))
        assertThrows(GeneralSecurityException::class.java) { store.authDurationSeconds(alias) }
        assertThrows(GeneralSecurityException::class.java) { store.sign(alias, SET, byteArrayOf(1)) }
    }

    private companion object {
        val SET = MlDsaParameterSet.ML_DSA_44
        const val A = "xkey_key_a"
        const val B = "xkey_key_b"
    }
}
