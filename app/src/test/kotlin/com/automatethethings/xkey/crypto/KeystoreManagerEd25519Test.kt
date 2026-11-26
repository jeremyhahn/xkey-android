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
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/** Ed25519 general keys come from the Android Keystore on API 33+ and from nowhere else. */
class KeystoreManagerEd25519Test {

    private val keyStore = mockk<KeyStore>(relaxed = true)
    private val context = mockk<Context>(relaxed = true)
    private val requestedSpecs = mutableListOf<AlgorithmParameterSpec>()
    private val generator = mockk<KeyPairGenerator>(relaxed = true)
    // The stand-in Keystore pair is made before KeyPairGenerator is mocked, so no call is recorded for it.
    private val standInPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    @Before
    fun setUp() {
        PqcSoftwareKeyStore.clearSharedForTest()
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        every { context.applicationContext } returns context
        every { context.filesDir } returns java.nio.file.Files.createTempDirectory("xkey-files").toFile().apply { deleteOnExit() }
        every { keyStore.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore

        mockkObject(AuditLogger)
        every { AuditLogger.logKeyCreated(any(), any(), any(), any(), any()) } returns Unit
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit

        mockkConstructor(KeyGenParameterSpec.Builder::class)
        val builder = { b: Any? -> b as KeyGenParameterSpec.Builder }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setAlgorithmParameterSpec(any()) } answers {
            requestedSpecs += firstArg<AlgorithmParameterSpec>()
            builder(self)
        }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setKeySize(any()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setDigests(*anyVararg()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setUserAuthenticationRequired(any()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setUserAuthenticationParameters(any(), any()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setIsStrongBoxBacked(any()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setAttestationChallenge(any()) } answers { builder(self) }
        every { anyConstructed<KeyGenParameterSpec.Builder>().build() } returns mockk()

        every { generator.initialize(any<AlgorithmParameterSpec>()) } returns Unit
        every { generator.generateKeyPair() } returns standInPair
        mockkStatic(KeyPairGenerator::class)
        every { KeyPairGenerator.getInstance(any<String>(), "AndroidKeyStore") } returns generator
    }

    @After
    fun tearDown() {
        PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    /** A manager on [sdk] whose legacy software Ed25519 store is [prefs]. */
    private fun manager(sdk: Int, prefs: InMemorySharedPreferences = InMemorySharedPreferences()): KeystoreManager {
        val manager = spyk(KeystoreManager(context, sdkInt = sdk, pqcStore = noPqcKeys()))
        every { manager.softwareEd25519Supported() } returns (sdk >= 33)
        every { manager.ed25519Prefs() } returns prefs
        return manager
    }

    @Test
    fun `EdDSA on API 33+ is an AndroidKeyStore EC generator with the ed25519 spec and returns SPKI DER`() = runBlocking {
        val prefs = InMemorySharedPreferences()
        val der = manager(34, prefs).generateKeyForAlgorithm("k", "EdDSA", -1, true)

        verify { KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore") }
        verify(exactly = 0) { KeyPairGenerator.getInstance("Ed25519") }
        assertEquals(listOf("ed25519"), requestedSpecs.map { (it as ECGenParameterSpec).name })
        verify(exactly = 0) { anyConstructed<KeyGenParameterSpec.Builder>().setIsStrongBoxBacked(true) }
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der))
        assertEquals("X.509", key.format)
        assertTrue("no software key is written", prefs.all.isEmpty())
    }

    @Test
    fun `the UI name Ed25519 makes the same Keystore key`() = runBlocking {
        val prefs = InMemorySharedPreferences()
        manager(34, prefs).generateKeyForAlgorithm("k", "Ed25519", -1, false)

        verify { KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore") }
        assertEquals(listOf("ed25519"), requestedSpecs.map { (it as ECGenParameterSpec).name })
        assertTrue(prefs.all.isEmpty())
    }

    @Test
    fun `EdDSA on API 32 is refused as an unsupported algorithm and makes no key`() {
        assertThrows(UnsupportedAlgorithmException::class.java) {
            runBlocking { manager(32).generateKeyForAlgorithm("k", "EdDSA", -1, false) }
        }
        verify(exactly = 0) { generator.generateKeyPair() }
    }

    @Test
    fun `a legacy software Ed25519 key holding the id is not overwritten by a new key`() {
        val prefs = InMemorySharedPreferences()
        prefs.edit().putString("xkey_key_ed", "encoded-private-key").commit()

        assertThrows(KeyGenerationException::class.java) {
            runBlocking { manager(34, prefs).generateKeyForAlgorithm("ed", "EdDSA", -1, false) }
        }
        verify(exactly = 0) { generator.generateKeyPair() }
        assertTrue(prefs.contains("xkey_key_ed"))
    }

    @Test
    fun `a legacy software Ed25519 key is listed software and its delete removes the prefs entry`() {
        val prefs = InMemorySharedPreferences()
        prefs.edit().putString("xkey_key_ed", "encoded-private-key").commit()
        val manager = manager(34, prefs)

        assertTrue(manager.hasSoftwareEd25519Key("xkey_key_ed"))
        assertEquals(KeySecurityLevel.SOFTWARE, manager.generalKeySecurityLevel("ed"))
        assertTrue(manager.deleteGeneralKey("ed"))
        assertFalse(prefs.contains("xkey_key_ed"))
        assertNull(manager.resolveKeystoreAlias("ed", UserKeyKind.GENERAL))
    }

    @Test
    fun `EdDSA and Ed25519 sign with the JCA Ed25519 signature`() {
        assertEquals("Ed25519", KeystoreManager.jcaSignatureAlgorithm("EdDSA"))
        assertEquals("Ed25519", KeystoreManager.jcaSignatureAlgorithm("Ed25519"))
    }
}
