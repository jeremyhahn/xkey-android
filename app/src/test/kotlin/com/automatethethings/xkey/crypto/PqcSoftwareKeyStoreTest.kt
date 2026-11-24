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
import java.security.GeneralSecurityException
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.signers.MLDSASigner
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Software ML-DSA keys: the private key is sealed by the Keystore AEAD key
 * before it reaches the disk, every plaintext copy is zeroed after use, and a
 * record only signs under the alias and parameter set it was sealed for.
 */
class PqcSoftwareKeyStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** Every plaintext handed to encrypt, as the same array (to check it is zeroed). */
    private val sealedPlaintexts = mutableListOf<ByteArray>()
    /** A copy of each, taken before the store could zero it. */
    private val plaintextCopies = mutableListOf<ByteArray>()
    /** Every plaintext decrypt returned. */
    private val openedPlaintexts = mutableListOf<ByteArray>()

    private lateinit var store: PqcSoftwareKeyStore

    @Before
    fun setUp() {
        val cipher = mockk<KeystoreAeadCipher>()
        // A stand-in seal: the bytes reversed, so the plaintext never appears as is.
        every { cipher.encrypt(any()) } answers {
            val plaintext = firstArg<ByteArray>()
            sealedPlaintexts += plaintext
            plaintextCopies += plaintext.copyOf()
            plaintext.reversedArray()
        }
        every { cipher.decrypt(any()) } answers {
            firstArg<ByteArray>().reversedArray().also { openedPlaintexts += it }
        }
        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        store = PqcSoftwareKeyStore(context, cipher)
    }

    @Test
    fun `each set makes a key whose SPKI names the set and whose signature verifies`() {
        for (set in MlDsaParameterSet.entries) {
            val alias = "xkey_key_${set.name}"
            val spki = store.generate(alias, set)

            val info = SubjectPublicKeyInfo.getInstance(spki)
            assertEquals(set.oid, info.algorithm.algorithm.id)
            assertNull("FIPS 204 SPKIs carry no parameters", info.algorithm.parameters)
            assertEquals(set.publicKeyBytes, info.publicKeyData.bytes.size)
            assertArrayEquals(spki, store.publicKeyDer(alias))
            assertEquals(set, store.parameterSet(alias))
            assertTrue(store.contains(alias))

            val data = "message for ${set.wireName}".toByteArray()
            val signature = store.sign(alias, set, data)
            assertEquals(set.signatureBytes, signature.size)
            val verifier = MLDSASigner()
            verifier.init(false, PublicKeyFactory.createKey(spki))
            verifier.update(data, 0, data.size)
            assertTrue("${set.wireName} signature must verify", verifier.verifySignature(signature))
        }
    }

    @Test
    fun `the private key never reaches the disk unsealed and every plaintext is zeroed`() {
        val alias = "xkey_key_disk"
        store.generate(alias, MlDsaParameterSet.ML_DSA_65)
        assertEquals(1, sealedPlaintexts.size)

        val onDisk = store.fileFor(alias).readBytes()
        val privateTail = plaintextCopies.single().copyOfRange(plaintextCopies.single().size - 64, plaintextCopies.single().size)
        assertFalse("PKCS#8 bytes on disk", contains(onDisk, privateTail))
        assertTrue("the sealed plaintext is zeroed after generate", sealedPlaintexts.single().all { it == 0.toByte() })

        store.sign(alias, MlDsaParameterSet.ML_DSA_65, byteArrayOf(1, 2, 3))
        assertEquals(1, openedPlaintexts.size)
        assertTrue("the opened plaintext is zeroed after sign", openedPlaintexts.single().all { it == 0.toByte() })
    }

    @Test
    fun `a record moved to another alias is refused`() {
        store.generate("xkey_key_a", MlDsaParameterSet.ML_DSA_44)
        store.fileFor("xkey_key_a").copyTo(store.fileFor("xkey_key_b"))

        assertFalse(store.contains("xkey_key_b"))
        assertNull(store.publicKeyDer("xkey_key_b"))
        assertThrows(GeneralSecurityException::class.java) { store.sign("xkey_key_b", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1)) }
    }

    @Test
    fun `a record holding another key's sealed blob is refused on sign`() {
        store.generate("xkey_key_a", MlDsaParameterSet.ML_DSA_44)
        store.generate("xkey_key_b", MlDsaParameterSet.ML_DSA_44)
        val a = PqcSoftwareKeyStore.Record.decode(store.fileFor("xkey_key_a").readBytes())
        val b = PqcSoftwareKeyStore.Record.decode(store.fileFor("xkey_key_b").readBytes())
        store.fileFor("xkey_key_a").writeBytes(a.copy(sealed = b.sealed).encode())

        assertThrows(GeneralSecurityException::class.java) { store.sign("xkey_key_a", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1)) }
    }

    @Test
    fun `a key that does not exist does not sign`() {
        assertFalse(store.contains("xkey_key_none"))
        assertNull(store.parameterSet("xkey_key_none"))
        assertThrows(GeneralSecurityException::class.java) { store.sign("xkey_key_none", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1)) }
    }

    @Test
    fun `a record of another set than the one asked does not sign`() {
        store.generate("xkey_key_87", MlDsaParameterSet.ML_DSA_87)

        assertThrows(PqcKeyRecordException::class.java) {
            store.sign("xkey_key_87", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1))
        }
        assertThrows(PqcKeyRecordException::class.java) {
            store.sign("xkey_key_87", MlDsaParameterSet.ML_DSA_65, byteArrayOf(1))
        }
        assertEquals(
            MlDsaParameterSet.ML_DSA_87.signatureBytes,
            store.sign("xkey_key_87", MlDsaParameterSet.ML_DSA_87, byteArrayOf(1)).size
        )
    }

    @Test
    fun `a key's user-authentication policy is sealed with it and enforced on sign`() {
        val defaultClock = PqcSoftwareKeyStore.clock
        PqcSoftwareKeyStore.clock = { 500_000L }
        try {
            store.generate("xkey_key_auth", MlDsaParameterSet.ML_DSA_44, authDurationSeconds = 0)
            store.generate("xkey_key_open", MlDsaParameterSet.ML_DSA_44)

            assertEquals(0, store.authDurationSeconds("xkey_key_auth"))
            assertEquals(-1, store.authDurationSeconds("xkey_key_open"))
            assertNull(store.authDurationSeconds("xkey_key_none"))
            assertThrows(BiometricRequiredException::class.java) { store.sign("xkey_key_auth", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1)) }
            store.sign("xkey_key_auth", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1), userAuthenticatedAt = 500_000L)
            store.sign("xkey_key_open", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1))
        } finally {
            PqcSoftwareKeyStore.clock = defaultClock
        }
    }

    @Test
    fun `a record in the earlier format is refused`() {
        store.generate("xkey_key_old", MlDsaParameterSet.ML_DSA_44)
        val bytes = store.fileFor("xkey_key_old").readBytes()
        "XPQ1".toByteArray().copyInto(bytes)
        store.fileFor("xkey_key_old").writeBytes(bytes)

        assertFalse(store.contains("xkey_key_old"))
        assertThrows(GeneralSecurityException::class.java) { store.sign("xkey_key_old", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1)) }
    }

    @Test
    fun `delete removes the key once`() {
        store.generate("xkey_key_del", MlDsaParameterSet.ML_DSA_87)
        assertTrue(store.delete("xkey_key_del"))
        assertFalse(store.contains("xkey_key_del"))
        assertFalse(store.fileFor("xkey_key_del").exists())
        assertFalse(store.delete("xkey_key_del"))
    }

    @Test
    fun `a record that cannot be removed makes delete throw and the key stays usable`() {
        store.generate("xkey_key_stuck", MlDsaParameterSet.ML_DSA_44)
        store.removeFile = { false }

        assertThrows(java.io.IOException::class.java) { store.delete("xkey_key_stuck") }
        assertTrue(store.contains("xkey_key_stuck"))
        store.sign("xkey_key_stuck", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1))
    }

    @Test
    fun `deleting a missing key is a no-op even when removal would fail`() {
        store.removeFile = { false }

        assertFalse(store.delete("xkey_key_absent"))
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean =
        (0..haystack.size - needle.size).any { start ->
            needle.indices.all { haystack[start + it] == needle[it] }
        }
}
