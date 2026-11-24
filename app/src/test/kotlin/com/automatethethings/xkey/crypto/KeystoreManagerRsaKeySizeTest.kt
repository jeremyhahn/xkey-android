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
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.interfaces.RSAPublicKey
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * The RSA modulus of [KeystoreManager.generateKeyForAlgorithm]: the size a
 * request names, or the hash's size only when it names none. The Keystore
 * generator is a software RSA generator of whatever size the spec asked for,
 * so the returned key shows the size the Keystore was asked for.
 */
class KeystoreManagerRsaKeySizeTest {

    private val keyStore = mockk<KeyStore>(relaxed = true)
    private var requestedBits = 0
    private val context = mockk<Context>(relaxed = true)
    private lateinit var keystoreManager: KeystoreManager

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        every { keyStore.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore

        mockkObject(AuditLogger)
        every { AuditLogger.logKeyCreated(any(), any(), any(), any(), any()) } returns Unit

        mockkConstructor(KeyGenParameterSpec.Builder::class)
        val builder = { b: Any? -> b as KeyGenParameterSpec.Builder }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setKeySize(any()) } answers {
            requestedBits = firstArg()
            builder(self)
        }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setDigests(*anyVararg()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setSignaturePaddings(*anyVararg()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setEncryptionPaddings(*anyVararg()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setUserAuthenticationRequired(any()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setIsStrongBoxBacked(any()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setAttestationChallenge(any()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().build() } returns mockk()

        val generator = mockk<KeyPairGenerator>(relaxed = true)
        every { generator.initialize(any<AlgorithmParameterSpec>()) } returns Unit
        every { generator.generateKeyPair() } answers {
            KeyPairGenerator.getInstance("RSA").apply { initialize(requestedBits) }.generateKeyPair()
        }
        mockkStatic(KeyPairGenerator::class)
        every { KeyPairGenerator.getInstance(any<String>(), "AndroidKeyStore") } returns generator

        keystoreManager = KeystoreManager(context, sdkInt = 34)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun modulusBits(publicKeyDer: ByteArray): Int =
        (KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(publicKeyDer)) as RSAPublicKey)
            .modulus.bitLength()

    @Test
    fun `an RS256 request with keySizeBits 4096 yields a 4096-bit key`() = runBlocking {
        val der = keystoreManager.generateKeyForAlgorithm("k", "RS256", -1, false, keySizeBits = 4096)
        assertEquals(4096, modulusBits(der))
    }

    @Test
    fun `an RS512 request with keySizeBits 3072 yields a 3072-bit key`() = runBlocking {
        val der = keystoreManager.generateKeyForAlgorithm("k", "RS512", -1, false, keySizeBits = 3072)
        assertEquals(3072, modulusBits(der))
    }

    @Test
    fun `without keySizeBits the hash still names the size`() = runBlocking {
        assertEquals(2048, modulusBits(keystoreManager.generateKeyForAlgorithm("a", "RS256", -1, false)))
        assertEquals(3072, modulusBits(keystoreManager.generateKeyForAlgorithm("b", "RS384", -1, false)))
    }

    @Test
    fun `a size the Keystore cannot make is refused, never another size`() = runBlocking {
        for (bits in listOf(1024, 2047, 8192)) {
            requestedBits = 0
            try {
                keystoreManager.generateKeyForAlgorithm("k", "RS256", -1, false, keySizeBits = bits)
                fail("RSA $bits must be refused")
            } catch (_: KeyGenerationException) {
                assertEquals("no key was asked for", 0, requestedBits)
            }
        }
    }

    private fun withStrongBox() {
        every { context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) } returns true
    }

    @Test
    fun `an RSA-OAEP 3072 or 4096 key is made in the TEE even when StrongBox is present`() = runBlocking {
        withStrongBox()
        for (bits in listOf(3072, 4096)) {
            val der = keystoreManager.generateRSAEncryptionKey("e$bits", bits, -1)
            assertEquals(bits, modulusBits(der))
        }
        verify(exactly = 0) { anyConstructed<KeyGenParameterSpec.Builder>().setIsStrongBoxBacked(any()) }
    }

    @Test
    fun `an RSA-OAEP 2048 key still asks for StrongBox when it is present`() = runBlocking {
        withStrongBox()
        assertEquals(2048, modulusBits(keystoreManager.generateRSAEncryptionKey("e", 2048, -1)))
        verify(exactly = 1) { anyConstructed<KeyGenParameterSpec.Builder>().setIsStrongBoxBacked(true) }
    }

    @Test
    fun `an RS256 4096 key is made in the TEE even when StrongBox is present`() = runBlocking {
        withStrongBox()
        assertEquals(4096, modulusBits(keystoreManager.generateKeyForAlgorithm("k", "RS256", -1, true, keySizeBits = 4096)))
        verify(exactly = 0) { anyConstructed<KeyGenParameterSpec.Builder>().setIsStrongBoxBacked(any()) }
    }
}
