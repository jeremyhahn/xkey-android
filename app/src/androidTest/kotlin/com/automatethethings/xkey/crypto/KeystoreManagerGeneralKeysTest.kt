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
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * Instrumented tests for the general-purpose (non-FIDO2) half of
 * [KeystoreManager]: multi-algorithm generation, algorithm-aware signing,
 * AES-GCM, HMAC, ECDH and RSA decryption.
 *
 * `KeystoreManagerTest` covers the FIDO2 credential path. Everything here is
 * reached through `xkey_key_<id>` aliases and is what the `local.*` protocol
 * family calls into, so a break shows up as a silently failing pairing session
 * rather than as a failing passkey.
 *
 * The emulator has no StrongBox and no enrolled biometric, so every key is
 * generated with `authDurationSeconds = -1` (no user authentication): an
 * auth-bound key cannot be created at all when no authenticator is enrolled,
 * and an auth-bound key that did exist could not be exercised headlessly.
 * Each test uses a nanoTime-suffixed id and removes both the key and its audit
 * rows afterwards, because other suites assert on live key counts.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreManagerGeneralKeysTest {

    private lateinit var context: Context
    private lateinit var keystoreManager: KeystoreManager

    private val generatedKeyIds = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        keystoreManager = KeystoreManager(context)
    }

    @After
    fun tearDown() {
        val dao = XKeyDatabase.getInstance(context).auditLogDao()
        generatedKeyIds.forEach { keyId ->
            runCatching { keystoreManager.deleteGeneralKey(keyId) }
            runCatching { runBlocking { dao.deleteByKeyId(keyId) } }
        }
        generatedKeyIds.clear()
    }

    private fun newKeyId(label: String): String =
        "gk-$label-${System.nanoTime()}".also { generatedKeyIds.add(it) }

    private fun generate(algorithm: String, label: String = algorithm.lowercase()): Pair<String, ByteArray> {
        val keyId = newKeyId(label)
        val der = runBlocking {
            keystoreManager.generateKeyForAlgorithm(
                keyId = keyId,
                algorithm = algorithm,
                authDurationSeconds = -1,
                preferStrongBox = false
            )
        }
        return keyId to der
    }

    private fun publicKeyOf(der: ByteArray, algorithm: String) =
        KeyFactory.getInstance(if (algorithm.startsWith("RS")) "RSA" else "EC")
            .generatePublic(X509EncodedKeySpec(der))

    private fun jcaSignatureName(algorithm: String) = when (algorithm) {
        "ES256" -> "SHA256withECDSA"
        "ES384" -> "SHA384withECDSA"
        "ES512" -> "SHA512withECDSA"
        "RS256" -> "SHA256withRSA"
        "RS384" -> "SHA384withRSA"
        else -> "SHA512withRSA"
    }

    private fun randomBytes(size: Int) = ByteArray(size).also { SecureRandom().nextBytes(it) }

    // ------------------------------------------------------------- generation

    @Test
    fun generatesAnEcKeyOnTheCurveEachEsAlgorithmNames() {
        val expectedFieldSizes = mapOf("ES256" to 256, "ES384" to 384, "ES512" to 521)

        expectedFieldSizes.forEach { (algorithm, fieldSize) ->
            val (keyId, der) = generate(algorithm)
            val publicKey = publicKeyOf(der, algorithm) as ECPublicKey

            assertEquals(algorithm, fieldSize, publicKey.params.curve.field.fieldSize)
            assertTrue(algorithm, keystoreManager.generalKeyExists(keyId))
        }
    }

    @Test
    fun generatesAnRsaKeyOfTheSizeEachRsAlgorithmNames() {
        val expectedModulusBits = mapOf("RS256" to 2048, "RS384" to 3072, "RS512" to 4096)

        expectedModulusBits.forEach { (algorithm, bits) ->
            val (keyId, der) = generate(algorithm)
            val publicKey = publicKeyOf(der, algorithm) as RSAPublicKey

            assertEquals(algorithm, bits, publicKey.modulus.bitLength())
            assertTrue(algorithm, keystoreManager.generalKeyExists(keyId))
        }
    }

    @Test
    fun rejectsAnAlgorithmItDoesNotSupport() {
        val keyId = newKeyId("unsupported")

        assertThrows(UnsupportedAlgorithmException::class.java) {
            runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "PS256", -1, false) }
        }
        assertFalse(keystoreManager.generalKeyExists(keyId))
    }

    @Test
    fun regeneratingUnderTheSameIdReplacesTheKey() {
        val keyId = newKeyId("regenerated")
        val first = runBlocking {
            keystoreManager.generateKeyForAlgorithm(keyId, "ES256", -1, false)
        }
        val second = runBlocking {
            keystoreManager.generateKeyForAlgorithm(keyId, "ES256", -1, false)
        }

        assertFalse("regeneration must mint a new key", first.contentEquals(second))
        assertArrayEquals(second, keystoreManager.getPublicKeyDER(keyId))
    }

    @Test
    fun generatesASymmetricKeyAtBothSupportedSizes() {
        listOf(128, 256).forEach { bits ->
            val keyId = newKeyId("aes$bits")
            runBlocking { keystoreManager.generateSymmetricKey(keyId, bits, -1) }

            assertTrue("AES-$bits", keystoreManager.generalKeyExists(keyId))

            val plaintext = "aes-$bits round trip".toByteArray()
            val sealed = runBlocking { keystoreManager.symmetricEncrypt(keyId, plaintext) }
            assertArrayEquals(
                plaintext,
                runBlocking { keystoreManager.symmetricDecrypt(keyId, sealed) }
            )
        }
    }

    @Test
    fun rejectsASymmetricKeySizeAesDoesNotDefine() {
        val keyId = newKeyId("aes192")

        val failure = assertThrows(KeyGenerationException::class.java) {
            runBlocking { keystoreManager.generateSymmetricKey(keyId, 192, -1) }
        }
        assertTrue(failure.message!!, failure.message!!.contains("128 or 256"))
        assertFalse(keystoreManager.generalKeyExists(keyId))
    }

    @Test
    fun generatesHmacKeysForBothSupportedDigests() {
        val sha256 = newKeyId("hmac256")
        val sha512 = newKeyId("hmac512")
        runBlocking {
            keystoreManager.generateHMACKey(sha256, "HMAC-SHA256")
            keystoreManager.generateHMACKey(sha512, "HMAC-SHA512")
        }

        val data = "authenticate me".toByteArray()
        assertEquals(32, runBlocking { keystoreManager.computeHMAC(sha256, data) }.size)
        assertEquals(64, runBlocking { keystoreManager.computeHMAC(sha512, data) }.size)
    }

    @Test
    fun rejectsAnHmacDigestItDoesNotSupport() {
        val keyId = newKeyId("hmac1")

        assertThrows(UnsupportedAlgorithmException::class.java) {
            runBlocking { keystoreManager.generateHMACKey(keyId, "HMAC-SHA1") }
        }
        assertFalse(keystoreManager.generalKeyExists(keyId))
    }

    // ---------------------------------------------------------------- signing

    @Test
    fun signsAndVerifiesWithEveryEcAlgorithm() {
        listOf("ES256", "ES384", "ES512").forEach { algorithm ->
            val (keyId, der) = generate(algorithm)
            val data = "signed with $algorithm".toByteArray()

            val signature = runBlocking { keystoreManager.signWithAlgorithm(keyId, data, algorithm) }

            val verifier = Signature.getInstance(jcaSignatureName(algorithm)).apply {
                initVerify(publicKeyOf(der, algorithm))
                update(data)
            }
            assertTrue(algorithm, verifier.verify(signature))
        }
    }

    @Test
    fun signsAndVerifiesWithRsa() {
        val (keyId, der) = generate("RS256", label = "rsa-signing")
        val data = "signed with RS256".toByteArray()

        val signature = runBlocking { keystoreManager.signWithAlgorithm(keyId, data, "RS256") }

        val verifier = Signature.getInstance("SHA256withRSA").apply {
            initVerify(publicKeyOf(der, "RS256"))
            update(data)
        }
        assertTrue(verifier.verify(signature))
    }

    @Test
    fun signingWithAnUnknownKeyIsRejected() {
        assertThrows(KeyNotFoundException::class.java) {
            runBlocking { keystoreManager.signWithAlgorithm("absent-${System.nanoTime()}", ByteArray(4), "ES256") }
        }
    }

    @Test
    fun signingWithAnUnsupportedAlgorithmIsRejected() {
        val (keyId, _) = generate("ES256", label = "bad-signing-algorithm")

        val failure = assertThrows(SigningException::class.java) {
            runBlocking { keystoreManager.signWithAlgorithm(keyId, ByteArray(4), "HS256") }
        }
        assertTrue(failure.message!!, failure.message!!.contains("HS256"))
    }

    // ------------------------------------------------------------- AES-GCM

    @Test
    fun sealedOutputIsIvPlusCiphertextPlusTag() {
        val keyId = newKeyId("aes-layout")
        runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, -1) }
        val plaintext = randomBytes(40)

        val sealed = runBlocking { keystoreManager.symmetricEncrypt(keyId, plaintext) }

        assertEquals(12 + plaintext.size + 16, sealed.size)
    }

    @Test
    fun everyEncryptionUsesAFreshIv() {
        val keyId = newKeyId("aes-iv")
        runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, -1) }
        val plaintext = "same every time".toByteArray()

        val first = runBlocking { keystoreManager.symmetricEncrypt(keyId, plaintext) }
        val second = runBlocking { keystoreManager.symmetricEncrypt(keyId, plaintext) }

        assertFalse(first.copyOfRange(0, 12).contentEquals(second.copyOfRange(0, 12)))
        assertFalse(first.contentEquals(second))
    }

    @Test
    fun associatedDataIsAuthenticatedButNotEncrypted() {
        val keyId = newKeyId("aes-aad")
        runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, -1) }
        val plaintext = "bound to a context".toByteArray()
        val aad = "context-v1".toByteArray()

        val sealed = runBlocking { keystoreManager.symmetricEncrypt(keyId, plaintext, aad) }

        assertArrayEquals(
            plaintext,
            runBlocking { keystoreManager.symmetricDecrypt(keyId, sealed, aad) }
        )
        assertThrows(DecryptionException::class.java) {
            runBlocking { keystoreManager.symmetricDecrypt(keyId, sealed, "context-v2".toByteArray()) }
        }
        assertThrows(DecryptionException::class.java) {
            runBlocking { keystoreManager.symmetricDecrypt(keyId, sealed) }
        }
    }

    @Test
    fun aTamperedCiphertextFailsTheGcmTag() {
        val keyId = newKeyId("aes-tamper")
        runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, -1) }
        val sealed = runBlocking { keystoreManager.symmetricEncrypt(keyId, randomBytes(24)) }
        sealed[sealed.size - 1] = (sealed[sealed.size - 1].toInt() xor 0x01).toByte()

        assertThrows(DecryptionException::class.java) {
            runBlocking { keystoreManager.symmetricDecrypt(keyId, sealed) }
        }
    }

    @Test
    fun decryptionRejectsInputTooShortToHoldAnIv() {
        val failure = assertThrows(DecryptionException::class.java) {
            runBlocking { keystoreManager.symmetricDecrypt("irrelevant", ByteArray(8)) }
        }
        assertTrue(failure.message!!, failure.message!!.contains("too short"))
    }

    @Test
    fun symmetricOperationsOnAnUnknownKeyAreRejected() {
        val absent = "absent-${System.nanoTime()}"

        assertThrows(KeyNotFoundException::class.java) {
            runBlocking { keystoreManager.symmetricEncrypt(absent, ByteArray(4)) }
        }
        assertThrows(KeyNotFoundException::class.java) {
            runBlocking { keystoreManager.symmetricDecrypt(absent, ByteArray(32)) }
        }
    }

    // ------------------------------------------------------------------- HMAC

    @Test
    fun computeHmacIsDeterministicForTheSameInput() {
        val keyId = newKeyId("hmac-deterministic")
        runBlocking { keystoreManager.generateHMACKey(keyId, "HMAC-SHA256") }
        val data = "stable input".toByteArray()

        assertArrayEquals(
            runBlocking { keystoreManager.computeHMAC(keyId, data) },
            runBlocking { keystoreManager.computeHMAC(keyId, data) }
        )
        assertNotEquals(
            runBlocking { keystoreManager.computeHMAC(keyId, data) }.toList(),
            runBlocking { keystoreManager.computeHMAC(keyId, "other input".toByteArray()) }.toList()
        )
    }

    @Test
    fun computeHmacOnAnUnknownKeyIsRejected() {
        assertThrows(KeyNotFoundException::class.java) {
            runBlocking { keystoreManager.computeHMAC("absent-${System.nanoTime()}", ByteArray(4)) }
        }
    }

    @Test
    fun computeHmacOnAKeyThatIsNotAnHmacKeyFails() {
        val keyId = newKeyId("hmac-on-aes")
        runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, -1) }

        assertThrows(HMACException::class.java) {
            runBlocking { keystoreManager.computeHMAC(keyId, ByteArray(4)) }
        }
    }

    // ------------------------------------------------------------------- ECDH

    @Test
    fun bothSidesOfAnEcdhExchangeDeriveTheSameSecret() {
        val (localId, localDer) = generate("ES256", label = "ecdh-local")
        val (peerId, peerDer) = generate("ES256", label = "ecdh-peer")

        val fromLocal = runBlocking { keystoreManager.performECDH(localId, peerDer) }
        val fromPeer = runBlocking { keystoreManager.performECDH(peerId, localDer) }

        assertArrayEquals(fromLocal, fromPeer)
        assertEquals(32, fromLocal.size)
    }

    @Test
    fun ecdhWithAnUnknownKeyIsRejected() {
        val (_, peerDer) = generate("ES256", label = "ecdh-orphan-peer")

        assertThrows(KeyNotFoundException::class.java) {
            runBlocking { keystoreManager.performECDH("absent-${System.nanoTime()}", peerDer) }
        }
    }

    @Test
    fun ecdhWithAMalformedPeerKeyIsRejected() {
        val (keyId, _) = generate("ES256", label = "ecdh-bad-peer")

        assertThrows(ECDHException::class.java) {
            runBlocking { keystoreManager.performECDH(keyId, byteArrayOf(1, 2, 3, 4)) }
        }
    }

    /**
     * An EC key generated before an upgrade to API 31 has no agree purpose:
     * performECDH must say so rather than report a generic failure.
     */
    @Test
    fun ecdhWithALegacyKeyWithoutTheAgreePurposeNamesThePurpose() {
        assumeTrue("Keystore ECDH is API 31+", Build.VERSION.SDK_INT >= 31)
        val (_, peerDer) = generate("ES256", label = "ecdh-legacy-peer")
        val keyId = newKeyId("ecdh-legacy")
        // The alias performECDH reads (KeystoreManager's general key prefix).
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(
                KeyGenParameterSpec.Builder("xkey_key_$keyId", KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            generateKeyPair()
        }

        val error = assertThrows(ECDHException::class.java) {
            runBlocking { keystoreManager.performECDH(keyId, peerDer) }
        }
        assertTrue(error.message.orEmpty(), error.message.orEmpty().contains("not generated with PURPOSE_AGREE_KEY"))
    }

    // ------------------------------------------------------------ RSA decrypt

    @Test
    fun rsaDecryptWithAnUnknownKeyIsRejected() {
        assertThrows(KeyNotFoundException::class.java) {
            runBlocking { keystoreManager.rsaDecrypt("absent-${System.nanoTime()}", randomBytes(256)) }
        }
    }

    @Test
    fun rsaDecryptRejectsCiphertextItCannotUnwrap() {
        val (keyId, _) = generate("RS256", label = "rsa-decrypt")

        assertThrows(DecryptionException::class.java) {
            runBlocking { keystoreManager.rsaDecrypt(keyId, randomBytes(256)) }
        }
    }
}
