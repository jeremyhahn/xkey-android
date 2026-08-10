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

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.SecureRandom

/**
 * Instrumented tests for [FileEncryptor], the hardware-backed ECIES wrapper
 * behind the `.xkeyenc` file format.
 *
 * The whole point of the class is that key agreement happens inside the Android
 * Keystore, so this can only be proven on a device: the tests generate real
 * P-256 keys with `PURPOSE_AGREE_KEY`, encrypt to the recipient's public key and
 * decrypt with the recipient's Keystore-resident private key.
 *
 * Coverage is split between the happy path (round trip of small, empty and
 * multi-buffer payloads plus the on-the-wire header layout) and the rejection
 * paths a trust boundary needs: an unknown recipient key, a foreign key, a bad
 * version byte and a truncated header.
 *
 * All keys use a per-run id and are deleted in `@After`, including any ephemeral
 * `xkey_key_ephemeral_*` aliases the production code leaves behind (see
 * [encryptForRecipientDeletesItsEphemeralKey]).
 */
@RunWith(AndroidJUnit4::class)
class FileEncryptorInstrumentedTest {

    private val suffix = System.nanoTime()
    private val recipientKeyId = "xkeyenc-recipient-$suffix"
    private val foreignKeyId = "xkeyenc-foreign-$suffix"

    private lateinit var keystoreManager: KeystoreManager
    private lateinit var encryptor: FileEncryptor
    private lateinit var recipientPublicKeyDer: ByteArray

    /** Ephemeral aliases that already existed, so teardown only removes ours. */
    private lateinit var preExistingEphemerals: Set<String>

    private val versionSize = 1
    private val lengthPrefixSize = 2
    private val saltSize = 32
    private val ivSize = 12
    private val gcmTagSize = 16

    @Before
    fun setUp() = runBlocking<Unit> {
        keystoreManager = KeystoreManager(ApplicationProvider.getApplicationContext())
        encryptor = FileEncryptor(keystoreManager)
        preExistingEphemerals = ephemeralAliases()

        keystoreManager.generateKeyForAlgorithm(
            keyId = recipientKeyId,
            algorithm = "ES256",
            authDurationSeconds = -1,
            preferStrongBox = false
        )
        recipientPublicKeyDer = keystoreManager.getPublicKeyDER(recipientKeyId)!!
        Unit
    }

    @After
    fun tearDown() = runBlocking<Unit> {
        keystoreManager.deleteGeneralKey(recipientKeyId)
        keystoreManager.deleteGeneralKey(foreignKeyId)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ephemeralAliases() - preExistingEphemerals).forEach { keyStore.deleteEntry(it) }

        // KeystoreManager audit-logs key creation/deletion; drop those rows too.
        val dao = XKeyDatabase.getInstance(
            ApplicationProvider.getApplicationContext()
        ).auditLogDao()
        dao.deleteByKeyId(recipientKeyId)
        dao.deleteByKeyId(foreignKeyId)
        Unit
    }

    private fun ephemeralAliases(): Set<String> =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .aliases().toList()
            .filter { it.startsWith("xkey_key_ephemeral_") }
            .toSet()

    private fun encrypt(plaintext: ByteArray): ByteArray = runBlocking {
        val out = ByteArrayOutputStream()
        encryptor.encryptForRecipient(recipientPublicKeyDer, ByteArrayInputStream(plaintext), out)
        out.toByteArray()
    }

    private fun decrypt(keyId: String, ciphertext: ByteArray): ByteArray = runBlocking {
        val out = ByteArrayOutputStream()
        encryptor.decryptWithKey(keyId, ByteArrayInputStream(ciphertext), out)
        out.toByteArray()
    }

    private fun randomBytes(size: Int) = ByteArray(size).also { SecureRandom().nextBytes(it) }

    @Test
    fun encryptThenDecryptRecoversThePlaintext() {
        val plaintext = "the quick brown fox jumps over the lazy dog".toByteArray()

        val encrypted = encrypt(plaintext)

        assertFalse("output must not contain the plaintext", encrypted.contentEquals(plaintext))
        assertArrayEquals(plaintext, decrypt(recipientKeyId, encrypted))
    }

    @Test
    fun payloadsLargerThanTheStreamingBufferRoundTrip() {
        // 8 KiB is the internal buffer size; use several buffers plus a remainder.
        val plaintext = randomBytes(8192 * 3 + 137)

        assertArrayEquals(plaintext, decrypt(recipientKeyId, encrypt(plaintext)))
    }

    @Test
    fun anEmptyPayloadRoundTrips() {
        val encrypted = encrypt(ByteArray(0))

        assertEquals(0, decrypt(recipientKeyId, encrypted).size)
    }

    @Test
    fun theHeaderMatchesTheDocumentedXkeyencLayout() {
        val plaintext = randomBytes(100)

        val encrypted = encrypt(plaintext)

        assertEquals("version byte", 0x01.toByte(), encrypted[0])
        val ephemeralLen = ((encrypted[1].toInt() and 0xFF) shl 8) or (encrypted[2].toInt() and 0xFF)
        assertTrue("ephemeral public key must be present", ephemeralLen > 0)

        val expectedSize = versionSize + lengthPrefixSize + ephemeralLen +
            saltSize + ivSize + plaintext.size + gcmTagSize
        assertEquals(expectedSize, encrypted.size)

        // The ephemeral public key is a DER SubjectPublicKeyInfo SEQUENCE.
        assertEquals(0x30.toByte(), encrypted[3])
    }

    @Test
    fun eachEncryptionUsesAFreshEphemeralKeySaltAndIv() {
        val plaintext = "same message".toByteArray()

        val first = encrypt(plaintext)
        val second = encrypt(plaintext)

        assertFalse("headers must differ", first.contentEquals(second))
        assertArrayEquals(plaintext, decrypt(recipientKeyId, first))
        assertArrayEquals(plaintext, decrypt(recipientKeyId, second))
    }

    @Test
    fun decryptingWithAForeignKeyDoesNotYieldThePlaintext() = runBlocking {
        keystoreManager.generateKeyForAlgorithm(
            keyId = foreignKeyId,
            algorithm = "ES256",
            authDurationSeconds = -1,
            preferStrongBox = false
        )
        val plaintext = "for the recipient only".toByteArray()
        val encrypted = encrypt(plaintext)

        val recovered = try {
            decrypt(foreignKeyId, encrypted)
        } catch (_: Exception) {
            // A GCM tag failure surfacing as an exception is the ideal outcome.
            ByteArray(0)
        }

        assertFalse(
            "a non-recipient key must never recover the plaintext",
            recovered.contentEquals(plaintext)
        )
    }

    @Test
    fun decryptingWithAnUnknownKeyIdIsRejected() {
        val encrypted = encrypt("payload".toByteArray())

        assertThrows(KeyNotFoundException::class.java) {
            decrypt("no-such-key-$suffix", encrypted)
        }
    }

    @Test
    fun anUnsupportedVersionByteIsRejected() {
        val encrypted = encrypt("payload".toByteArray())
        encrypted[0] = 0x02

        val error = assertThrows(DecryptionException::class.java) {
            decrypt(recipientKeyId, encrypted)
        }
        assertTrue(error.message!!.contains("Unsupported file version"))
    }

    @Test
    fun anEmptyStreamIsRejectedAsAnUnsupportedVersion() {
        // read() returns -1 on an empty stream, which is not the version byte.
        assertThrows(DecryptionException::class.java) {
            decrypt(recipientKeyId, ByteArray(0))
        }
    }

    @Test
    fun aHeaderTruncatedAtTheLengthPrefixIsRejected() {
        assertThrows(DecryptionException::class.java) {
            decrypt(recipientKeyId, byteArrayOf(0x01, 0x00))
        }
    }

    @Test
    fun aFileTruncatedInsideTheSaltIsRejected() {
        val encrypted = encrypt("payload".toByteArray())
        val ephemeralLen = ((encrypted[1].toInt() and 0xFF) shl 8) or (encrypted[2].toInt() and 0xFF)
        val cutInsideSalt = versionSize + lengthPrefixSize + ephemeralLen + (saltSize / 2)

        assertThrows(DecryptionException::class.java) {
            decrypt(recipientKeyId, encrypted.copyOfRange(0, cutInsideSalt))
        }
    }

    /**
     * Documents a production defect rather than asserting current behaviour.
     *
     * `encryptForRecipient` creates its ephemeral key under the *general* alias
     * `xkey_key_<id>` (see `FileEncryptor.generateEphemeralKey`) but cleans up
     * with `KeystoreManager.deleteKey`, which resolves the *credential* alias
     * `xkey_credential_<id>`. The delete is therefore a no-op and every file
     * encryption leaks one EC key into the Android Keystore forever;
     * `deleteGeneralKey` is the matching call. Un-ignore this test once the
     * production code is fixed.
     */
    @Test
    @Ignore("Known defect: ephemeral key is deleted under the wrong alias prefix")
    fun encryptForRecipientDeletesItsEphemeralKey() {
        val before = ephemeralAliases()

        encrypt("payload".toByteArray())

        assertEquals("no ephemeral key may survive encryption", before, ephemeralAliases())
    }
}
