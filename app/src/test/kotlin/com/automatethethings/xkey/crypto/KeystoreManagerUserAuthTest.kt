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

package com.automatethethings.xkey.crypto

import android.content.Context
import android.security.keystore.KeyInfo
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.cert.Certificate
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A Keystore refusal for want of user authentication reaches the prompt
 * (or [BiometricRequiredException]) in both of the shapes devices use:
 * [UserNotAuthenticatedException] from `initSign`, and a
 * [SignatureException]/[ProviderException] whose cause is an
 * `android.security.KeyStoreException` with
 * `ERROR_USER_AUTHENTICATION_REQUIRED`, raised as late as `sign()`.
 */
class KeystoreManagerUserAuthTest {

    private val silent = mockk<Signature>(relaxed = true)
    private val prompted = mockk<Signature>(relaxed = true)
    private val promptSignature = byteArrayOf(1, 2, 3)
    private val biometricHelper = mockk<BiometricHelper>(relaxed = true)
    private lateinit var keystoreManager: KeystoreManager
    private val keyStore = mockk<KeyStore>(relaxed = true)

    @Before
    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        every { keyStore.containsAlias(any()) } answers {
            firstArg<String>() in setOf("xkey_credential_c", "xkey_key_k", "xkey_key_aes")
        }
        every { keyStore.getKey("xkey_credential_c", null) } returns mockk<PrivateKey>()
        every { keyStore.getKey("xkey_key_k", null) } returns mockk<PrivateKey>()
        every { keyStore.getKey("xkey_key_aes", null) } returns mockk<SecretKey>()
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore

        mockkStatic(Signature::class)
        every { Signature.getInstance(any<String>()) } returnsMany listOf(silent, prompted)
        every { prompted.sign() } returns promptSignature

        // An API 33+ device: android.security.KeyStoreException carries the
        // numeric error code from API 33.
        keystoreManager = KeystoreManager(mockk<Context>(relaxed = true), sdkInt = 34)
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    private fun keystoreError(code: Int): android.security.KeyStoreException =
        mockk(relaxed = true) {
            every { numericErrorCode } returns code
            every { cause } returns null
        }

    private fun authRequiredAtSign() =
        SignatureException(
            "Key user not authenticated",
            keystoreError(android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED)
        )

    private fun userNotAuthenticated(): UserNotAuthenticatedException =
        mockk(relaxed = true) { every { cause } returns null }

    @Test
    fun `sign prompts when the silent sign fails with the Keystore auth error`() = runBlocking {
        every { silent.sign() } throws authRequiredAtSign()

        val result = keystoreManager.sign("c", UserKeyKind.CREDENTIAL, ByteArray(32), biometricHelper)

        assertArrayEquals(promptSignature, result)
        coVerify(exactly = 1) { biometricHelper.authenticate(any(), any(), any(), any(), any()) }
        verify { prompted.initSign(any<PrivateKey>()) }
    }

    @Test
    fun `sign prompts when initSign fails with a ProviderException of the Keystore auth error`() = runBlocking {
        every { silent.initSign(any<PrivateKey>()) } throws ProviderException(
            "Key user not authenticated",
            keystoreError(android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED)
        )

        val result = keystoreManager.sign("c", UserKeyKind.CREDENTIAL, ByteArray(32), biometricHelper)

        assertArrayEquals(promptSignature, result)
        coVerify(exactly = 1) { biometricHelper.authenticate(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `sign prompts on UserNotAuthenticatedException from initSign`() = runBlocking {
        every { silent.initSign(any<PrivateKey>()) } throws userNotAuthenticated()

        val result = keystoreManager.sign("c", UserKeyKind.CREDENTIAL, ByteArray(32), biometricHelper)

        assertArrayEquals(promptSignature, result)
        coVerify(exactly = 1) { biometricHelper.authenticate(any(), any(), any(), any(), any()) }
    }

    /**
     * A time-window key (auth timeout > 0) whose Keystore refuses every
     * operation, the fresh Signature's included, until the user has
     * authenticated: [refuse] is thrown by whichever step refuses.
     */
    private fun timeWindowKeyRefusingUntilAuthenticated(refuse: () -> Exception) {
        val keyInfo = mockk<KeyInfo> {
            @Suppress("DEPRECATION")
            every { userAuthenticationValidityDurationSeconds } returns 5
        }
        keystoreManager.keyInfoReader = { _, _ -> keyInfo }
        var authenticated = false
        coEvery {
            biometricHelper.authenticateWithoutCrypto(any(), any(), any(), any())
        } answers { authenticated = true }
        for (signature in listOf(silent, prompted)) {
            every { signature.initSign(any<PrivateKey>()) } answers {
                if (!authenticated) throw refuse()
            }
        }
    }

    @Test
    fun `sign authenticates a time-window key before initSign when init refuses`() = runBlocking {
        timeWindowKeyRefusingUntilAuthenticated { userNotAuthenticated() }

        val result = keystoreManager.sign("c", UserKeyKind.CREDENTIAL, ByteArray(32), biometricHelper)

        assertArrayEquals(promptSignature, result)
        coVerify(exactly = 1) { biometricHelper.authenticateWithoutCrypto(any(), any(), any(), any()) }
        coVerify(exactly = 0) { biometricHelper.authenticate(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `sign authenticates a time-window key before initSign on the Keystore auth error`() = runBlocking {
        timeWindowKeyRefusingUntilAuthenticated {
            ProviderException(
                "Key user not authenticated",
                keystoreError(android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED)
            )
        }

        val result = keystoreManager.sign("c", UserKeyKind.CREDENTIAL, ByteArray(32), biometricHelper)

        assertArrayEquals(promptSignature, result)
        coVerify(exactly = 1) { biometricHelper.authenticateWithoutCrypto(any(), any(), any(), any()) }
    }

    @Test
    fun `sign binds a per-operation key to the prompt with a CryptoObject`() = runBlocking {
        val keyInfo = mockk<KeyInfo> {
            @Suppress("DEPRECATION")
            every { userAuthenticationValidityDurationSeconds } returns 0
        }
        keystoreManager.keyInfoReader = { _, _ -> keyInfo }
        every { silent.sign() } throws authRequiredAtSign()

        val result = keystoreManager.sign("c", UserKeyKind.CREDENTIAL, ByteArray(32), biometricHelper)

        assertArrayEquals(promptSignature, result)
        coVerify(exactly = 1) { biometricHelper.authenticate(any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { biometricHelper.authenticateWithoutCrypto(any(), any(), any(), any()) }
    }

    private fun certificateOf(der: ByteArray): Certificate = mockk {
        every { publicKey } returns mockk<PublicKey> { every { encoded } returns der }
    }

    /**
     * On API 28-30 a Keystore key handle names its alias, not the key: once
     * the alias is deleted and regenerated, `initSign` on the old handle
     * signs with the replacement. Here the alias is replaced while the
     * prompt that comes before `initSign` waits; the call must refuse rather
     * than sign with a key the user never selected.
     */
    private fun assertRefusesKeyReplacedDuringPrompt(sdk: Int, keyInfoReadable: Boolean) {
        val original = mockk<PrivateKey>()
        val replacement = mockk<PrivateKey>()
        val originalCertificate = certificateOf(byteArrayOf(10))
        val replacementCertificate = certificateOf(byteArrayOf(20))
        var replaced = false
        every { keyStore.getKey("xkey_credential_c", null) } answers { if (replaced) replacement else original }
        every { keyStore.getCertificate("xkey_credential_c") } answers {
            if (replaced) replacementCertificate else originalCertificate
        }

        val silentSignature = mockk<Signature>(relaxed = true)
        val freshSignature = mockk<Signature>(relaxed = true)
        every { Signature.getInstance(any<String>()) } returnsMany listOf(silentSignature, freshSignature)
        // Both Signatures refuse initSign until the user has authenticated,
        // so an unreadable KeyInfo still ends in the prompt-first fallback.
        for (signature in listOf(silentSignature, freshSignature)) {
            every { signature.initSign(any<PrivateKey>()) } answers {
                if (!replaced) throw userNotAuthenticated()
            }
        }
        every { freshSignature.sign() } answers { if (replaced) byteArrayOf(6, 6, 6) else promptSignature }

        val helper = mockk<BiometricHelper>(relaxed = true)
        coEvery { helper.authenticateWithoutCrypto(any(), any(), any(), any()) } answers { replaced = true }

        val manager = KeystoreManager(mockk<Context>(relaxed = true), sdkInt = sdk)
        val keyInfo = mockk<KeyInfo> {
            @Suppress("DEPRECATION")
            every { userAuthenticationValidityDurationSeconds } returns 5
        }
        manager.keyInfoReader = { _, _ ->
            if (!keyInfoReadable) throw IllegalStateException("KeyInfo unreadable")
            keyInfo
        }

        assertThrows("API $sdk, KeyInfo readable: $keyInfoReadable", ApprovedKeyChangedException::class.java) {
            runBlocking { manager.sign("c", UserKeyKind.CREDENTIAL, ByteArray(32), helper) }
        }
        coVerify(exactly = 1) { helper.authenticateWithoutCrypto(any(), any(), any(), any()) }
    }

    @Test
    fun `sign refuses a time-window key replaced under its alias while the prompt waits`() {
        for (sdk in 28..30) assertRefusesKeyReplacedDuringPrompt(sdk, keyInfoReadable = true)
    }

    @Test
    fun `sign refuses a key replaced under its alias while the fallback prompt waits`() {
        for (sdk in 28..30) assertRefusesKeyReplacedDuringPrompt(sdk, keyInfoReadable = false)
    }

    @Test
    fun `sign raises SigningException for any other Keystore error`() {
        every { silent.sign() } throws SignatureException(
            "Key does not exist",
            keystoreError(android.security.KeyStoreException.ERROR_KEY_DOES_NOT_EXIST)
        )

        assertThrows(SigningException::class.java) {
            runBlocking { keystoreManager.sign("c", UserKeyKind.CREDENTIAL, ByteArray(32), biometricHelper) }
        }
        coVerify(exactly = 0) { biometricHelper.authenticate(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `signWithoutBiometric requires biometric on the Keystore auth error at sign`() {
        every { silent.sign() } throws authRequiredAtSign()

        assertThrows(BiometricRequiredException::class.java) {
            runBlocking { keystoreManager.signWithoutBiometric("c", UserKeyKind.CREDENTIAL, ByteArray(32)) }
        }
    }

    @Test
    fun `signWithoutBiometric requires biometric on UserNotAuthenticatedException`() {
        every { silent.initSign(any<PrivateKey>()) } throws userNotAuthenticated()

        assertThrows(BiometricRequiredException::class.java) {
            runBlocking { keystoreManager.signWithoutBiometric("c", UserKeyKind.CREDENTIAL, ByteArray(32)) }
        }
    }

    @Test
    fun `signWithAlgorithm requires biometric on the Keystore auth error at sign`() {
        every { silent.sign() } throws authRequiredAtSign()

        assertThrows(BiometricRequiredException::class.java) {
            runBlocking { keystoreManager.signWithAlgorithm("k", ByteArray(32), "ES256") }
        }
    }

    @Test
    fun `symmetricEncrypt requires biometric on the Keystore auth error at doFinal`() {
        val cipher = mockk<Cipher>(relaxed = true)
        mockkStatic(Cipher::class)
        every { Cipher.getInstance(any<String>()) } returns cipher
        every { cipher.doFinal(any<ByteArray>()) } throws IllegalBlockSizeException("Key user not authenticated").apply {
            initCause(keystoreError(android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED))
        }

        assertThrows(BiometricRequiredException::class.java) {
            runBlocking { keystoreManager.symmetricEncrypt("aes", ByteArray(16)) }
        }
    }

    /** The wrappers devices put a Keystore refusal in. */
    private val wrappers: List<Pair<String, (Throwable) -> Exception>> = listOf(
        "SignatureException" to { cause -> SignatureException("refused", cause) },
        "InvalidKeyException" to { cause -> InvalidKeyException("refused", cause) },
        "ProviderException" to { cause -> ProviderException("refused", cause) },
    )

    /**
     * Runs [call] on an API 32 and an API 34 device with every refusal shape
     * [inject]ed into the operation, and asserts which become
     * [BiometricRequiredException] and which stay [failure]:
     * - [UserNotAuthenticatedException], bare or wrapped: biometric on both;
     * - a wrapped Keystore ERROR_USER_AUTHENTICATION_REQUIRED: biometric on
     *   API 33+ only, where the error code exists; [failure] below it;
     * - a wrapped Keystore error of any other code, or an unrelated
     *   exception: [failure] on both.
     */
    private fun assertAuthClassification(
        operation: String,
        failure: Class<out Throwable>,
        inject: (Exception) -> Unit,
        call: suspend (KeystoreManager) -> Unit
    ) {
        for (sdk in listOf(32, 34)) {
            val manager = KeystoreManager(mockk<Context>(relaxed = true), sdkInt = sdk)
            fun expect(expected: Class<out Throwable>, case: String, error: Exception) {
                inject(error)
                assertThrows("$operation, API $sdk, $case", expected) { runBlocking { call(manager) } }
            }

            expect(BiometricRequiredException::class.java, "UserNotAuthenticatedException", userNotAuthenticated())
            for ((name, wrap) in wrappers) {
                expect(
                    BiometricRequiredException::class.java,
                    "$name(UserNotAuthenticatedException)",
                    wrap(userNotAuthenticated())
                )
                expect(
                    if (sdk >= 33) BiometricRequiredException::class.java else failure,
                    "$name(KEY_USER_NOT_AUTHENTICATED)",
                    wrap(keystoreError(android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED))
                )
                expect(
                    failure,
                    "$name(KEY_DOES_NOT_EXIST)",
                    wrap(keystoreError(android.security.KeyStoreException.ERROR_KEY_DOES_NOT_EXIST))
                )
            }
            expect(failure, "unrelated IllegalStateException", IllegalStateException("unrelated"))
        }
    }

    @Test
    fun `signApproved classifies authentication-required errors at sign`() {
        val der = byteArrayOf(7, 7, 7)
        val approvedCertificate = certificateOf(der)
        every { keyStore.getCertificate("xkey_key_k") } returns approvedCertificate
        val signature = mockk<Signature>(relaxed = true)
        every { Signature.getInstance(any<String>()) } returns signature

        assertAuthClassification(
            "signApproved",
            SigningException::class.java,
            inject = { e -> every { signature.sign() } throws e },
            call = { it.signApproved("xkey_key_k", der, ByteArray(32), "SHA256withECDSA") }
        )
    }

    @Test
    fun `signApproved classifies authentication-required errors at initSign`() {
        val der = byteArrayOf(7, 7, 7)
        val approvedCertificate = certificateOf(der)
        every { keyStore.getCertificate("xkey_key_k") } returns approvedCertificate
        val signature = mockk<Signature>(relaxed = true)
        every { Signature.getInstance(any<String>()) } returns signature

        assertAuthClassification(
            "signApproved initSign",
            SigningException::class.java,
            inject = { e -> every { signature.initSign(any<PrivateKey>()) } throws e },
            call = { it.signApproved("xkey_key_k", der, ByteArray(32), "SHA256withECDSA") }
        )
    }

    @Test
    fun `rsaDecryptWithAlgorithm classifies authentication-required errors at doFinal`() {
        val cipher = mockk<Cipher>(relaxed = true)
        mockkStatic(Cipher::class)
        every { Cipher.getInstance(any<String>()) } returns cipher

        assertAuthClassification(
            "rsaDecryptWithAlgorithm",
            DecryptionException::class.java,
            inject = { e -> every { cipher.doFinal(any<ByteArray>()) } throws e },
            call = { it.rsaDecryptWithAlgorithm("k", ByteArray(256)) }
        )
    }

    @Test
    fun `symmetricDecrypt classifies authentication-required errors at doFinal`() {
        val cipher = mockk<Cipher>(relaxed = true)
        mockkStatic(Cipher::class)
        every { Cipher.getInstance(any<String>()) } returns cipher

        assertAuthClassification(
            "symmetricDecrypt",
            DecryptionException::class.java,
            inject = { e -> every { cipher.doFinal(any<ByteArray>()) } throws e },
            call = { it.symmetricDecrypt("aes", ByteArray(28)) }
        )
    }

    private fun peerPublicKeyDer(): ByteArray =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair().public.encoded

    /**
     * ECDH refusals at `KeyAgreement.init` pass through its inner
     * [InvalidKeyException] handler first: an authentication failure must
     * leave it intact for the outer classifier, not become the
     * "not generated with PURPOSE_AGREE_KEY" [ECDHException].
     */
    @Test
    fun `performECDH keeps authentication-required errors through the init handler`() {
        val agreement = mockk<KeyAgreement>(relaxed = true)
        mockkStatic(KeyAgreement::class)
        every { KeyAgreement.getInstance("ECDH") } returns agreement
        val peer = peerPublicKeyDer()

        assertAuthClassification(
            "performECDH init",
            ECDHException::class.java,
            inject = { e -> every { agreement.init(any<Key>()) } throws e },
            call = { it.performECDH("k", peer) }
        )
    }

    @Test
    fun `performECDH classifies authentication-required errors at generateSecret`() {
        val agreement = mockk<KeyAgreement>(relaxed = true)
        mockkStatic(KeyAgreement::class)
        every { KeyAgreement.getInstance("ECDH") } returns agreement
        val peer = peerPublicKeyDer()

        assertAuthClassification(
            "performECDH generateSecret",
            ECDHException::class.java,
            inject = { e -> every { agreement.generateSecret() } throws e },
            call = { it.performECDH("k", peer) }
        )
    }

    @Test
    fun `performECDH init handler reports a non-agreeing key, not an auth failure`() {
        val agreement = mockk<KeyAgreement>(relaxed = true)
        mockkStatic(KeyAgreement::class)
        every { KeyAgreement.getInstance("ECDH") } returns agreement
        every { agreement.init(any<Key>()) } throws InvalidKeyException("incompatible purpose")

        val error = assertThrows(ECDHException::class.java) {
            runBlocking { keystoreManager.performECDH("k", peerPublicKeyDer()) }
        }
        assertTrue(error.message.orEmpty().contains("PURPOSE_AGREE_KEY"))
    }
}
