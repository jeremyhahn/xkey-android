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
import android.security.keystore.KeyInfo
import android.util.Log
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.MLDSASigner
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A per-operation Keystore key (authentication required, validity 0) signs
 * only through a [CryptoObjectSigner]: a Signature initialised for the key,
 * passed to the prompt as its CryptoObject, and signed with once the prompt
 * has authorized it. The approved signers never initialise a fresh Signature
 * for such a key, and the signature returned must verify under the approved
 * public key.
 */
class KeystoreManagerPerOperationSignTest {

    private val keyStore = mockk<KeyStore>(relaxed = true)
    private lateinit var manager: KeystoreManager
    private val savedBackend = PqcHardware.backend
    private val data = "to sign".toByteArray()

    private val ecPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()
    private val mlDsaPair = MLDSAKeyPairGenerator().apply {
        init(MLDSAKeyGenerationParameters(SecureRandom(), PqcSoftwareKeyStore.bcParameters(SET)))
    }.generateKeyPair()
    private val mlDsaSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(mlDsaPair.public).encoded

    /** Every call the signer got: alias and JCA algorithm. */
    private val signerCalls = mutableListOf<Pair<String, String>>()

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

        every { keyStore.containsAlias(any()) } answers { firstArg<String>() in setOf(EC_ALIAS, PQ_ALIAS) }
        // A Keystore handle the JVM cannot sign with: a fresh initSign on it fails.
        every { keyStore.getKey(EC_ALIAS, null) } returns mockk<PrivateKey>(relaxed = true)
        every { keyStore.getKey(PQ_ALIAS, null) } returns mockk<PrivateKey>(relaxed = true)
        every { keyStore.getCertificate(EC_ALIAS) } returns certificate(ecPair.public.encoded)
        every { keyStore.getCertificate(PQ_ALIAS) } returns certificate(mlDsaSpki)
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore

        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns File(System.getProperty("java.io.tmpdir"), "per-op-${System.nanoTime()}")
        manager = KeystoreManager(context, sdkInt = 34)
        manager.keyInfoReader = { _, _ -> perOperationKeyInfo() }
        PqcHardware.backend = object : PqcHardwareBackend {
            override fun supportedParameterSets() = setOf(SET)
            override fun generate(alias: String, set: MlDsaParameterSet, authDurationSeconds: Int, preferStrongBox: Boolean) =
                throw UnsupportedOperationException()
            override fun jcaSignatureAlgorithm(set: MlDsaParameterSet) = "ML-DSA"
        }
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        PqcHardware.backend = savedBackend
        unmockkAll()
    }

    @Test
    fun `a per-operation key is recognised from its KeyInfo`() {
        assertTrue(manager.isPerOperationKey(EC_ALIAS))
        manager.keyInfoReader = { _, _ -> keyInfo(required = true, validity = 30) }
        assertFalse(manager.isPerOperationKey(EC_ALIAS))
        manager.keyInfoReader = { _, _ -> keyInfo(required = false, validity = 0) }
        assertFalse(manager.isPerOperationKey(EC_ALIAS))
        assertFalse(manager.isPerOperationKey("xkey_key_absent"))
    }

    @Test
    fun `signApproved signs a per-operation key through the CryptoObject signer`() = runBlocking {
        val result = manager.signApproved(EC_ALIAS, ecPair.public.encoded, data, JCA_EC, ecSigner())

        assertEquals(listOf(EC_ALIAS to JCA_EC), signerCalls)
        assertTrue(verifiesEc(result))
    }

    @Test
    fun `signApproved refuses a per-operation key with no CryptoObject signer`() {
        assertThrows(BiometricRequiredException::class.java) {
            runBlocking { manager.signApproved(EC_ALIAS, ecPair.public.encoded, data, JCA_EC) }
        }
    }

    @Test
    fun `signApproved refuses a CryptoObject signature the approved key did not make`() {
        val other = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val signer = CryptoObjectSigner { _, alg, bytes ->
            Signature.getInstance(alg).run { initSign(other.private); update(bytes); sign() }
        }

        assertThrows(ApprovedKeyChangedException::class.java) {
            runBlocking { manager.signApproved(EC_ALIAS, ecPair.public.encoded, data, JCA_EC, signer) }
        }
    }

    @Test
    fun `signApproved refuses before the prompt when the key is not the approved one`() {
        val other = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

        assertThrows(ApprovedKeyChangedException::class.java) {
            runBlocking { manager.signApproved(EC_ALIAS, other.public.encoded, data, JCA_EC, ecSigner()) }
        }
        assertEquals(emptyList<Pair<String, String>>(), signerCalls)
    }

    @Test
    fun `signApprovedMlDsa signs a per-operation hardware key through the CryptoObject signer`() = runBlocking {
        val result = manager.signApprovedMlDsa(PQ_ALIAS, mlDsaSpki, data, SET, null, mlDsaSigner())

        assertEquals(listOf(PQ_ALIAS to "ML-DSA"), signerCalls)
        assertTrue(verifiesMlDsa(result))
    }

    @Test
    fun `signApprovedMlDsa refuses a per-operation hardware key with no CryptoObject signer`() {
        assertThrows(BiometricRequiredException::class.java) {
            runBlocking { manager.signApprovedMlDsa(PQ_ALIAS, mlDsaSpki, data, SET) }
        }
    }

    @Test
    fun `a key that is not per-operation never reaches the CryptoObject signer`() {
        manager.keyInfoReader = { _, _ -> keyInfo(required = true, validity = 30) }

        // The fresh Signature cannot initialise on the mock handle: the time-window path ran.
        assertThrows(SigningException::class.java) {
            runBlocking { manager.signApproved(EC_ALIAS, ecPair.public.encoded, data, JCA_EC, ecSigner()) }
        }
        assertEquals(emptyList<Pair<String, String>>(), signerCalls)
    }

    private fun ecSigner() = CryptoObjectSigner { alias, alg, bytes ->
        signerCalls += alias to alg
        Signature.getInstance(alg).run { initSign(ecPair.private); update(bytes); sign() }
    }

    private fun mlDsaSigner() = CryptoObjectSigner { alias, alg, bytes ->
        signerCalls += alias to alg
        MLDSASigner().run {
            init(true, ParametersWithRandom(mlDsaPair.private, SecureRandom()))
            update(bytes, 0, bytes.size)
            generateSignature()
        }
    }

    private fun verifiesEc(signature: ByteArray) = Signature.getInstance(JCA_EC).run {
        initVerify(ecPair.public); update(data); verify(signature)
    }

    private fun verifiesMlDsa(signature: ByteArray) = MLDSASigner().run {
        init(false, mlDsaPair.public)
        update(data, 0, data.size)
        verifySignature(signature)
    }

    private fun certificate(der: ByteArray) = mockk<Certificate> {
        every { publicKey } returns mockk { every { encoded } returns der }
    }

    private fun perOperationKeyInfo() = keyInfo(required = true, validity = 0)

    private fun keyInfo(required: Boolean, validity: Int) = mockk<KeyInfo> {
        every { isUserAuthenticationRequired } returns required
        @Suppress("DEPRECATION")
        every { userAuthenticationValidityDurationSeconds } returns validity
    }

    private companion object {
        val SET = MlDsaParameterSet.ML_DSA_65
        const val EC_ALIAS = "xkey_key_ec"
        const val PQ_ALIAS = "xkey_key_pq"
        const val JCA_EC = "SHA256withECDSA"
    }
}
