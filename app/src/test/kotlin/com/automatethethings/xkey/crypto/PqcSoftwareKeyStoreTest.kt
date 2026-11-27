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

    @Test
    fun `under a real AES-GCM seal no record file holds any run of its PKCS#8 bytes`() {
        val aes = javax.crypto.spec.SecretKeySpec(ByteArray(32) { (it * 7).toByte() }, "AES")
        val plaintexts = mutableListOf<ByteArray>()
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers {
            val plaintext = firstArg<ByteArray>()
            plaintexts += plaintext.copyOf()
            val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
            val gcm = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            gcm.init(javax.crypto.Cipher.ENCRYPT_MODE, aes, javax.crypto.spec.GCMParameterSpec(128, iv))
            iv + gcm.doFinal(plaintext)
        }
        every { cipher.decrypt(any()) } answers {
            val sealed = firstArg<ByteArray>()
            val gcm = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            gcm.init(javax.crypto.Cipher.DECRYPT_MODE, aes, javax.crypto.spec.GCMParameterSpec(128, sealed, 0, 12))
            gcm.doFinal(sealed, 12, sealed.size - 12)
        }
        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.newFolder("aes")
        val aesStore = PqcSoftwareKeyStore(context, cipher)

        for (set in MlDsaParameterSet.entries) {
            val alias = "xkey_key_aes_${set.name}"
            aesStore.generate(alias, set)
            val pkcs8 = pkcs8Of(plaintexts.last())
            assertTrue("${set.wireName} plaintext holds a PKCS#8 key", pkcs8.size > 32)
            val onDisk = aesStore.fileFor(alias).readBytes() + aesStore.generationFileFor(alias).readBytes()

            assertFalse("${set.wireName} PKCS#8 on disk", contains(onDisk, pkcs8))
            val spki = aesStore.publicKeyDer(alias)!!
            var secretWindows = 0
            for (start in 0..pkcs8.size - 16 step 16) {
                val window = pkcs8.copyOfRange(start, start + 16)
                // The PKCS#8 encoding repeats public bytes (rho) that the clear SPKI holds.
                if (contains(spki, window)) continue
                secretWindows++
                assertFalse(
                    "${set.wireName} PKCS#8 bytes $start..${start + 15} on disk",
                    contains(onDisk, window)
                )
            }
            assertTrue("${set.wireName} PKCS#8 has secret bytes to check", secretWindows * 16 > pkcs8.size / 2)
            assertEquals(set.signatureBytes, aesStore.sign(alias, set, byteArrayOf(1)).size)
        }
    }

    @Test
    fun `each key has its own wrap key and delete or replace removes it`() {
        val sealedUnder = mutableListOf<String>()
        val destroyed = mutableListOf<String>()
        val keyring = object : PqcWrapKeyring {
            private val live = mutableSetOf<String>()
            override fun newId() = PqcWrapKeyring.randomId()
            override fun seal(id: String, plaintext: ByteArray): ByteArray {
                sealedUnder += id
                live += id
                return plaintext.reversedArray()
            }
            override fun open(id: String, sealed: ByteArray): ByteArray {
                if (id !in live) throw PqcKeyRecordException("ML-DSA key was deleted")
                return sealed.reversedArray()
            }
            override fun destroy(id: String) {
                destroyed += id
                live -= id
            }
        }
        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.newFolder("ring")
        val ringStore = PqcSoftwareKeyStore(context, keyring)

        ringStore.generate("xkey_key_a", MlDsaParameterSet.ML_DSA_44)
        ringStore.generate("xkey_key_b", MlDsaParameterSet.ML_DSA_44)
        val a = PqcSoftwareKeyStore.Record.decode(ringStore.fileFor("xkey_key_a").readBytes())
        val b = PqcSoftwareKeyStore.Record.decode(ringStore.fileFor("xkey_key_b").readBytes())
        assertEquals(listOf(a.wrapId, b.wrapId), sealedUnder)
        assertTrue("two keys never share a wrap key", a.wrapId != b.wrapId)

        val saved = ringStore.fileFor("xkey_key_a").readBytes()
        assertTrue(ringStore.delete("xkey_key_a"))
        assertEquals(listOf(a.wrapId), destroyed)
        ringStore.fileFor("xkey_key_a").writeBytes(saved)
        assertThrows(PqcKeyRecordException::class.java) {
            ringStore.sign("xkey_key_a", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1))
        }

        ringStore.generate("xkey_key_b", MlDsaParameterSet.ML_DSA_44)
        assertEquals(listOf(a.wrapId, b.wrapId), destroyed)
        val b2 = PqcSoftwareKeyStore.Record.decode(ringStore.fileFor("xkey_key_b").readBytes())
        assertTrue("a replacing key gets a fresh wrap key", b2.wrapId != b.wrapId)
        ringStore.sign("xkey_key_b", MlDsaParameterSet.ML_DSA_44, byteArrayOf(1))
    }

    /** The PKCS#8 tail of a sealed plaintext: `len|alias|len|set|len|spki|generation|policy|pkcs8`. */
    private fun pkcs8Of(plaintext: ByteArray): ByteArray {
        val buffer = java.nio.ByteBuffer.wrap(plaintext)
        repeat(3) { buffer.position(buffer.position() + 4 + buffer.getInt(buffer.position())) }
        buffer.position(buffer.position() + 8 + 4)
        return ByteArray(buffer.remaining()).also { buffer.get(it) }
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean =
        (0..haystack.size - needle.size).any { start ->
            needle.indices.all { haystack[start + it] == needle[it] }
        }
}
